package com.anpahn.staffguard;

import com.anpahn.staffguard.commands.StaffGuardCommand;
import com.anpahn.staffguard.config.Messages;
import com.anpahn.staffguard.config.StaffGuardConfig;
import com.anpahn.staffguard.database.Database;
import com.anpahn.staffguard.discord.DiscordService;
import com.anpahn.staffguard.listeners.CommandAuditListener;
import com.anpahn.staffguard.listeners.LoginListener;
import com.anpahn.staffguard.listeners.PrivacyListener;
import com.anpahn.staffguard.model.ProxyMode;
import com.anpahn.staffguard.security.LockdownManager;
import com.anpahn.staffguard.security.SecurityState;
import com.anpahn.staffguard.service.AccountService;
import com.anpahn.staffguard.service.AuditService;
import com.anpahn.staffguard.service.BanService;
import com.anpahn.staffguard.service.TrustedIpService;
import com.anpahn.staffguard.service.VerificationService;
import com.anpahn.staffguard.util.SecurityUtil;
import org.bukkit.Bukkit;
import org.bukkit.plugin.java.JavaPlugin;

import java.io.File;
import java.util.List;
import java.util.Objects;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;

public final class StaffGuardPlugin extends JavaPlugin {
    private StaffGuardConfig config;
    private Messages messages;
    private Database db;
    private AccountService accounts;
    private TrustedIpService ips;
    private BanService bans;
    private AuditService audit;
    private VerificationService verification;
    private DiscordService discord;
    private LockdownManager lockdown;
    private final SecurityState securityState = new SecurityState();
    private volatile boolean stopping;
    private final ScheduledExecutorService scheduler = Executors.newSingleThreadScheduledExecutor(r -> {
        Thread t = new Thread(r, "AP-StaffGuard-Scheduler");
        t.setDaemon(true);
        return t;
    });

    @Override
    public void onEnable() {
        stopping = false;
        securityState.set(SecurityState.Status.STARTING);
        printBanner();

        // Register the security login gate BEFORE parsing user configuration.
        // This preserves the fail-closed invariant even when startup configuration is malformed.
        try {
            getServer().getPluginManager().registerEvents(new LoginListener(this), this);
            getLogger().info("  ✓ Cổng kiểm soát đăng nhập đã được đăng ký (fail-closed).");
        } catch (Exception ex) {
            securityState.set(SecurityState.Status.FAIL_CLOSED);
            getLogger().log(Level.SEVERE, "Không thể đăng ký LoginListener. AP-StaffGuard không thể đảm bảo chính sách bảo vệ đăng nhập.", ex);
            Bukkit.getPluginManager().disablePlugin(this);
            return;
        }

        try {
            saveDefaultConfig();
            config = StaffGuardConfig.from(getConfig());
            messages = Messages.from(getConfig());
            lockdown = new LockdownManager();
            final boolean securityEnabled = config.securityEnabled();

            byte[] secret = null;
            if (securityEnabled) {
                // Validation is already performed by StaffGuardConfig.from(); this is the actual decode.
                secret = SecurityUtil.parseServerSecret(config.serverSecretValue());
            }

            db = new Database(this, new File(getDataFolder(), config.databaseFile()));
            bans = new BanService(db, config.temporaryBanDuration(), getLogger());
            final TrustedIpService trustedIps;
            if (securityEnabled) {
                trustedIps = new TrustedIpService(db, secret, config.maxTrustedIps());
                ips = trustedIps;
            } else {
                trustedIps = null;
                ips = null;
            }

            accounts = new AccountService(db, uuid -> {
                if (trustedIps != null) trustedIps.invalidate(uuid);
                if (bans != null) bans.invalidate(uuid);
            });
            audit = new AuditService(db, getLogger());

            if (securityEnabled) {
                verification = new VerificationService(db, accounts, ips, audit, config, lockdown, secret);
                if (config.discordEnabled()) {
                    discord = new DiscordService(config, verification, getLogger());
                }
            }

            registerOperationalListenersAndCommands();
            logRuntimeConfiguration();

            CompletableFuture<Void> init = db.startAsync()
                    .thenCompose(v -> accounts.load())
                    .thenCompose(v -> bans.load(protectedUuids()));
            if (securityEnabled) {
                init = init.thenCompose(v -> ips.load(protectedUuids()));
            }

            final boolean configurationReady = !securityEnabled || (ips != null && verification != null);
            init.whenComplete((ignored, error) -> {
                if (stopping) return;
                Bukkit.getScheduler().runTask(this, () -> {
                    if (stopping) return;
                if (error != null) {
                    securityState.set(SecurityState.Status.FAIL_CLOSED);
                    getLogger().log(Level.SEVERE, "❌ Khởi tạo backend bảo mật thất bại. Protected account sẽ bị từ chối.", unwrap(error));
                    return;
                }
                if (!configurationReady) {
                    securityState.set(SecurityState.Status.FAIL_CLOSED);
                    getLogger().severe("❌ Security backend chưa đủ thành phần. Vui lòng kiểm tra cấu hình.");
                    return;
                }

                securityState.set(SecurityState.Status.READY);
                getLogger().info("✓ Database/account inventory đã sẵn sàng: " + accounts.all().size() + " protected account(s).");
                getLogger().info("✓ Security backend READY — Discord không được phép làm yếu chính sách đăng nhập.");
                getLogger().info("✓ Login policy: ACTIVE + trusted IP → ALLOW; ACTIVE + IP mới → cần verification; LOCKED/REVOKED → DENY.");

                if (config.discordEnabled() && discord != null) {
                    discord.start().whenComplete((ok, startError) -> {
                        if (startError != null || !Boolean.TRUE.equals(ok)) {
                            getLogger().warning("⚠ Discord verification CHƯA SẴN SÀNG. Security backend vẫn READY; IP chưa trusted sẽ bị từ chối cho tới khi Discord hoạt động.");
                            if (startError != null) {
                                getLogger().log(Level.WARNING, "  ↳ Discord startup reason: " + safeReason(startError), unwrap(startError));
                            }
                        }
                    });
                } else if (securityEnabled) {
                    getLogger().info("ℹ Discord verification đang TẮT. IP mới chỉ có thể được trust bằng thao tác quản trị phù hợp.");
                }
                });
            });

            scheduleMaintenance();
            getLogger().info("✓ AP-StaffGuard đã được nạp; đang chờ backend security hoàn tất khởi tạo.");
        } catch (IllegalArgumentException ex) {
            securityState.set(SecurityState.Status.FAIL_CLOSED);
            logConfigurationFailure(ex);
        } catch (Exception ex) {
            securityState.set(SecurityState.Status.FAIL_CLOSED);
            getLogger().log(Level.SEVERE, "❌ AP-StaffGuard khởi tạo thất bại. Protected account sẽ bị FAIL-CLOSED.", ex);
        }
    }

    private void registerOperationalListenersAndCommands() {
        try {
            var command = Objects.requireNonNull(getCommand("staffguard"), "staffguard command missing from plugin.yml");
            StaffGuardCommand handler = new StaffGuardCommand(this);
            command.setExecutor(handler);
            command.setTabCompleter(handler);
            getServer().getPluginManager().registerEvents(new CommandAuditListener(this), this);
            getServer().getPluginManager().registerEvents(new PrivacyListener(this), this);
        } catch (Exception ex) {
            getLogger().log(Level.SEVERE, "❌ Không thể đăng ký command/audit/privacy listener của AP-StaffGuard.", ex);
            getLogger().warning("⚠ Operational listener/command registration chưa hoàn tất; security login gate vẫn đang hoạt động.");
        }
    }

    private void scheduleMaintenance() {
        scheduler.scheduleAtFixedRate(() -> {
            if (db == null || config == null) return;
            try {
                CompletableFuture<Integer> expired = verification == null
                        ? CompletableFuture.completedFuture(0)
                        : verification.expire();
                CompletableFuture<Void> bansFuture = db.cleanupExpiredBans();
                CompletableFuture<Integer> auditCleanup = db.cleanupAudit(config.auditRetentionDays() * 24L * 60L * 60L * 1000L);
                if (verification != null) verification.cleanupRateLimiters();
                if (discord != null) discord.cleanupRateLimiter();
                CompletableFuture.allOf(expired, bansFuture, auditCleanup).whenComplete((v, error) -> {
                    if (stopping) return;
                    if (error != null) {
                        securityState.set(SecurityState.Status.DEGRADED);
                        getLogger().log(Level.WARNING, "⚠ Bảo trì security gặp lỗi; state=DEGRADED. Login authorization vẫn chạy DB-backed và sẽ FAIL-CLOSED nếu operation bảo mật thất bại.", unwrap(error));
                    } else {
                        if (securityState.status() == SecurityState.Status.DEGRADED) {
                            getLogger().info("✓ Security maintenance đã hồi phục; state=READY.");
                        }
                        if (securityState.isStopping()) return;
                        securityState.set(SecurityState.Status.READY);
                        if (discord != null && config.discordEnabled() && discord.needsStart()) {
                            if (stopping) return;
                            discord.start().whenComplete((ok, startError) -> {
                                if (startError != null || !Boolean.TRUE.equals(ok)) {
                                    getLogger().warning("⚠ Discord verification vẫn chưa khởi động lại được; sẽ thử lại ở chu kỳ maintenance tiếp theo.");
                                }
                            });
                        }
                    }
                });
            } catch (Exception ex) {
                securityState.set(SecurityState.Status.DEGRADED);
                getLogger().log(Level.WARNING, "⚠ Security maintenance gặp exception; state=DEGRADED.", ex);
            }
        }, 30, 30, TimeUnit.SECONDS);
    }

    private List<UUID> protectedUuids() {
        return accounts == null ? List.of() : accounts.all().stream().map(a -> a.uuid()).toList();
    }

    private void printBanner() {
        getLogger().info("┌──────────────────────────────────────────────┐");
        String version = getDescription().getVersion();
        getLogger().info("│              AP-StaffGuard " + version + "            │");
        getLogger().info("│      Security-first account protection      │");
        getLogger().info("└──────────────────────────────────────────────┘");
        getLogger().info("→ Bắt đầu kiểm tra cấu hình và khởi tạo...");
    }

    private void logRuntimeConfiguration() {
        getLogger().info("── Cấu hình runtime ───────────────────────────");
        getLogger().info("  Security        : " + (config.securityEnabled() ? "BẬT" : "TẮT"));
        getLogger().info("  Database        : SQLite / " + config.databaseFile());
        getLogger().info("  Discord         : " + (config.discordEnabled() ? "BẬT" : "TẮT"));
        getLogger().info("  Proxy mode      : " + config.proxyMode());
        if (config.proxyMode() == ProxyMode.BUNGEECORD) {
            getLogger().warning("⚠ BungeeCord forwarding không tự cung cấp cryptographic authenticity; backend phải được cô lập và firewall đúng trusted proxy.");
        }
        getLogger().info("  Self approval   : " + (config.discordAllowSelfApproval() ? "CHO PHÉP (Staff tự xác thực account của chính họ)" : "TẮT (Staff không tự xác thực)"));
        getLogger().info("───────────────────────────────────────────────");
    }

    private void logConfigurationFailure(IllegalArgumentException ex) {
        getLogger().severe("╔════════ AP-StaffGuard: CẤU HÌNH CHƯA HỢP LỆ ════════╗");
        for (String line : ex.getMessage().split("\\R")) {
            getLogger().severe("║ " + line);
        }
        getLogger().severe("╚══════════════════════════════════════════════════════╝");
        getLogger().severe("→ Không tự sinh secret và không bỏ qua kiểm tra bảo mật.");
        getLogger().severe("→ Sửa plugins/AP-StaffGuard/config.yml rồi restart server.");
    }

    public CompletableFuture<Void> reloadSafely() {
        CompletableFuture<Void> result = new CompletableFuture<>();
        Bukkit.getScheduler().runTask(this, () -> {
            try {
                reloadConfig();
                messages = Messages.from(getConfig());
                getLogger().info("/staffguard reload: chỉ reload messages. Security/Discord/proxy/secret/database yêu cầu restart.");
                result.complete(null);
            } catch (Exception e) {
                getLogger().log(Level.SEVERE, "Reload messages thất bại; cấu hình message đang hoạt động được giữ nguyên.", e);
                result.completeExceptionally(e);
            }
        });
        return result;
    }

    public boolean commandDependenciesReady() {
        if (config == null || messages == null || db == null || accounts == null || bans == null || audit == null || lockdown == null) return false;
        return !config.securityEnabled() || (ips != null && verification != null && (!config.discordEnabled() || discord != null));
    }

    public String safeOperationFailedMessage() {
        return messages == null ? "§cAP-StaffGuard chưa khởi tạo xong. Hãy kiểm tra console." : messages.operationFailed();
    }

    public String safeNoPermissionMessage() {
        return messages == null ? "§cBạn không có quyền thực hiện thao tác này." : messages.noPermission();
    }

    @Override
    public void onDisable() {
        stopping = true;
        securityState.set(SecurityState.Status.STOPPING);
        scheduler.shutdownNow();
        if (verification != null) verification.shutdown();
        if (discord != null) discord.shutdown();
        if (db != null) db.close();
        getLogger().info("✓ AP-StaffGuard đã dừng sạch sẽ.");
    }

    public StaffGuardConfig config() { return config; }
    public Messages messages() { return messages; }
    public Database db() { return db; }
    public AccountService accounts() { return accounts; }
    public TrustedIpService ips() { return ips; }
    public BanService banService() { return bans; }
    public AuditService audit() { return audit; }
    public VerificationService verification() { return verification; }
    public DiscordService discord() { return discord; }
    public LockdownManager lockdown() { return lockdown; }
    public SecurityState securityState() { return securityState; }

    private static String safeReason(Throwable error) {
        Throwable root = unwrap(error);
        if (root == null) return "unknown";
        String message = root.getMessage();
        if (message == null || message.isBlank()) return root.getClass().getSimpleName();
        message = message.replaceAll("\\s+", " ").trim();
        return message.substring(0, Math.min(240, message.length()));
    }

    private static Throwable unwrap(Throwable error) {
        if (error instanceof CompletionException && error.getCause() != null) return error.getCause();
        return error;
    }
}
