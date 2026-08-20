package com.anpahn.staffguard;

import com.anpahn.staffguard.commands.StaffGuardCommand;
import com.anpahn.staffguard.config.Messages;
import com.anpahn.staffguard.config.StaffGuardConfig;
import com.anpahn.staffguard.database.Database;
import com.anpahn.staffguard.discord.DiscordService;
import com.anpahn.staffguard.listeners.LoginListener;
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
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;

/** Main plugin lifecycle. SecurityState is fail-closed until the complete backend is ready. */
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

    private final ScheduledExecutorService scheduler = Executors.newSingleThreadScheduledExecutor(r -> {
        Thread t = new Thread(r, "AP-StaffGuard-Scheduler");
        t.setDaemon(true);
        return t;
    });

    @Override
    public void onEnable() {
        securityState.setReady(false);
        saveDefaultConfig();

        // Register the guard and command before parsing security-sensitive configuration.
        // LoginListener is deliberately safe while config/services are null and denies logins
        // until securityState becomes ready.
        try {
            var command = Objects.requireNonNull(getCommand("staffguard"), "staffguard command missing from plugin.yml");
            StaffGuardCommand commandHandler = new StaffGuardCommand(this);
            command.setExecutor(commandHandler);
            command.setTabCompleter(commandHandler);
            getServer().getPluginManager().registerEvents(new LoginListener(this), this);
        } catch (Exception e) {
            getLogger().log(Level.SEVERE, "AP-StaffGuard could not register its fail-closed guard/command.", e);
            return;
        }

        try {
            config = StaffGuardConfig.from(getConfig());
            messages = Messages.from(getConfig());
            lockdown = new LockdownManager();

            String secret = resolveSecret();
            boolean secretValid = secret.length() >= 32;
            if (!secretValid) {
                getLogger().severe("Server secret is missing/too short. Protected accounts will remain FAIL-CLOSED until this is fixed.");
                secret = SecurityUtil.randomToken(32);
            }

            db = new Database(this, new File(getDataFolder(), config.databaseFile()));
            accounts = new AccountService(db);
            ips = new TrustedIpService(db, secret, config.maxTrustedIps());
            bans = new BanService(db, config.temporaryBanDuration(), getLogger());
            audit = new AuditService(db, getLogger());
            verification = new VerificationService(db, accounts, ips, audit, config, lockdown, secret);
            discord = new DiscordService(config, verification, getLogger());

            if (config.proxyMode() != com.anpahn.staffguard.model.ProxyMode.NONE) {
                getLogger().info("Proxy mode: " + config.proxyMode() + "; client IP is read from Paper's forwarded player address and the raw transport address is checked against trusted proxy ranges.");
                if (config.proxyMode() == com.anpahn.staffguard.model.ProxyMode.BUNGEECORD) {
                    getLogger().warning("BungeeCord legacy forwarding is not cryptographically secure. Protect this backend with a firewall/private network and trusted proxy address allow-list.");
                }
            }

            scheduleMaintenance();

            CompletableFuture<Void> init = db.startAsync()
                    .thenCompose(v -> accounts.load())
                    .thenCompose(v -> ips.load(protectedUuids()))
                    .thenCompose(v -> bans.load(protectedUuids()));

            CompletableFuture<Boolean> discordFuture = init.thenCompose(v -> {
                if (!config.discordEnabled()) return CompletableFuture.completedFuture(true);
                return discord.start();
            });

            init.thenCombine(discordFuture, (ignored, discordOk) ->
                            !config.securityEnabled() || (secretValid && (!config.discordEnabled() || discordOk)))
                    .whenComplete((ready, error) -> Bukkit.getScheduler().runTask(this, () -> {
                        if (error != null) {
                            securityState.setReady(false);
                            getLogger().log(Level.SEVERE, "AP-StaffGuard initialization failed; all logins remain FAIL-CLOSED.", unwrap(error));
                            return;
                        }
                        securityState.setReady(Boolean.TRUE.equals(ready));
                        if (Boolean.TRUE.equals(ready)) {
                            getLogger().info("AP-StaffGuard security backend ready.");
                        } else {
                            getLogger().warning("AP-StaffGuard security backend is not ready; protected accounts and startup logins fail closed.");
                        }
                    }));

            getLogger().info("AP-StaffGuard enabled — AnPahn");
        } catch (Exception e) {
            securityState.setReady(false);
            getLogger().log(Level.SEVERE, "AP-StaffGuard initialization failed; the fail-closed login guard remains active.", e);
        }
    }

    private void scheduleMaintenance() {
        scheduler.scheduleAtFixedRate(() -> {
            Database localDb = db;
            VerificationService localVerification = verification;
            if (localDb == null || localVerification == null) return;

            try {
                CompletableFuture<Integer> expiredSessions = localVerification.expire();
                CompletableFuture<Void> expiredBans = localDb.cleanupExpiredBans();
                localVerification.cleanupRateLimiters();
                if (discord != null) discord.cleanupRateLimiter();

                CompletableFuture.allOf(expiredSessions, expiredBans).whenComplete((ignored, error) -> {
                    if (error != null) {
                        securityState.setReady(false);
                        getLogger().log(Level.SEVERE, "Scheduled security maintenance failed; login protection remains FAIL-CLOSED.", unwrap(error));
                    }
                });
            } catch (Exception e) {
                securityState.setReady(false);
                getLogger().log(Level.SEVERE, "Scheduled security maintenance failed; login protection remains FAIL-CLOSED.", e);
            }
        }, 30, 30, TimeUnit.SECONDS);
    }

    private List<java.util.UUID> protectedUuids() {
        return accounts == null ? List.of() : accounts.all().stream().map(a -> a.uuid()).toList();
    }

    private String resolveSecret() {
        return getConfig().getString("server-secret.value", "").trim();
    }

    private static Throwable unwrap(Throwable error) {
        if (error instanceof CompletionException && error.getCause() != null) return error.getCause();
        return error;
    }

    public CompletableFuture<Void> reloadSafely() {
        CompletableFuture<Void> future = new CompletableFuture<>();
        Bukkit.getScheduler().runTask(this, () -> {
            try {
                // Security-critical services capture configuration at construction time (HMAC secret, Discord authorization,
                // rate limits and proxy trust rules). Hot-swapping only messages avoids an inconsistent runtime security boundary.
                reloadConfig();
                messages = Messages.from(getConfig());
                future.complete(null);
                getLogger().info("Messages reloaded. Security/Discord configuration changes require a full plugin/server restart.");
            } catch (Exception e) {
                getLogger().log(Level.SEVERE, "Reload failed; active messages retained.", e);
                future.completeExceptionally(e);
            }
        });
        return future;
    }

    public boolean commandDependenciesReady() {
        return config != null && messages != null && db != null && accounts != null && ips != null
                && bans != null && audit != null && verification != null && discord != null && lockdown != null;
    }

    public String safeOperationFailedMessage() {
        return messages == null ? "§cAP-StaffGuard operation failed. Check console." : messages.operationFailed();
    }

    public String safeNoPermissionMessage() {
        return messages == null ? "§cBạn không có quyền thực hiện thao tác này." : messages.noPermission();
    }

    @Override
    public void onDisable() {
        securityState.setReady(false);
        scheduler.shutdownNow();
        if (verification != null) verification.shutdown();
        if (discord != null) discord.shutdown();
        if (db != null) db.close();
        getLogger().info("AP-StaffGuard disabled cleanly.");
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
}
