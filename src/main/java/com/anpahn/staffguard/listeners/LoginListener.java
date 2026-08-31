package com.anpahn.staffguard.listeners;

import com.anpahn.staffguard.StaffGuardPlugin;
import com.anpahn.staffguard.config.Messages;
import com.anpahn.staffguard.database.Database;
import com.anpahn.staffguard.model.AccountStatus;
import com.anpahn.staffguard.model.ProtectedAccount;
import com.anpahn.staffguard.model.SecurityEventType;
import com.anpahn.staffguard.util.ClientIpResolver;
import net.kyori.adventure.text.Component;
import net.kyori.adventure.text.serializer.legacy.LegacyComponentSerializer;
import org.bukkit.event.EventHandler;
import org.bukkit.event.EventPriority;
import org.bukkit.event.Listener;
import org.bukkit.event.player.AsyncPlayerPreLoginEvent;

import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.logging.Level;






public final class LoginListener implements Listener {
    private static final LegacyComponentSerializer LEGACY = LegacyComponentSerializer.legacySection();

    private final StaffGuardPlugin plugin;
    private volatile ClientIpResolver resolver;

    public LoginListener(StaffGuardPlugin plugin) {
        this.plugin = plugin;
    }

    @EventHandler(priority = EventPriority.HIGHEST)
    public void onPreLogin(AsyncPlayerPreLoginEvent event) {
        
        if (event.getLoginResult() != AsyncPlayerPreLoginEvent.Result.ALLOWED) {
            plugin.getLogger().fine("Login gate skipped because another plugin already denied the connection; player="
                    + event.getName() + ", reason=" + event.getLoginResult());
            return;
        }

        final var uuid = event.getUniqueId();
        try {
            handlePreLogin(event, uuid);
        } catch (Exception ex) {
            
            var messages = plugin.messages();
            deny(event, messages == null
                    ? "§cKhông thể hoàn tất kiểm tra bảo mật. §fVui lòng liên hệ quản trị viên."
                    : messages.securityUnavailable());
            plugin.getLogger().log(Level.SEVERE,
                    "[SECURITY-FAILSAFE] Login denied because an unexpected exception occurred; player="
                            + event.getName() + ", uuid=" + uuid, ex);
        }
    }

    private void handlePreLogin(AsyncPlayerPreLoginEvent event, java.util.UUID uuid) {
        var messages = plugin.messages();
        var cfg = plugin.config();

        if (cfg == null) {
            deny(event, messages == null
                    ? "§cAP-StaffGuard chưa thể xác thực cấu hình. §fQuản trị viên cần kiểm tra console."
                    : messages.securityUnavailable());
            plugin.getLogger().severe("Login denied for " + uuid + ": configuration is unavailable during the security gate.");
            return;
        }

        if (!cfg.securityEnabled()) return;

        if (plugin.accounts() == null || !plugin.accounts().isLoaded()) {
            deny(event, messages == null ? "§cHệ thống bảo mật đang khởi động. §fVui lòng thử lại sau." : messages.securityUnavailable());
            plugin.getLogger().warning("[AUTH][DENY][STARTING] account inventory chưa tải xong; uuid=" + uuid);
            return;
        }

        ProtectedAccount account = plugin.accounts().getCached(uuid);
        if (account == null || account.status() == AccountStatus.REMOVED) return;

        if (account.status() == AccountStatus.LOCKED) {
            deny(event, messages == null ? "§cTài khoản StaffGuard đang bị khóa." : messages.accountLocked());
            plugin.getLogger().warning("Login denied: account is LOCKED; player=" + account.username() + ", uuid=" + uuid);
            audit(uuid, account, SecurityEventType.AUTH_FAILURE, "DENIED", "account status=LOCKED", null, null);
            return;
        }

        if (account.status() == AccountStatus.REVOKED) {
            deny(event, messages == null ? "§cQuyền bảo vệ của tài khoản đã bị thu hồi." : messages.accountRevoked());
            plugin.getLogger().warning("Login denied: account is REVOKED; player=" + account.username() + ", uuid=" + uuid);
            audit(uuid, account, SecurityEventType.AUTH_FAILURE, "DENIED", "account status=REVOKED", null, null);
            return;
        }

        if (plugin.ips() == null || plugin.db() == null || plugin.audit() == null || plugin.lockdown() == null) {
            deny(event, messages == null ? "§cHệ thống bảo mật chưa sẵn sàng." : messages.securityUnavailable());
            plugin.getLogger().severe("[AUTH][DENY][SERVICE_UNAVAILABLE] thiếu security service bắt buộc; uuid=" + uuid
                    + ", db=" + (plugin.db() != null) + ", ips=" + (plugin.ips() != null)
                    + ", audit=" + (plugin.audit() != null) + ", lockdown=" + (plugin.lockdown() != null));
            return;
        }

        var securityStatus = plugin.securityState().status();
        if (!plugin.securityState().isOperational()) {
            deny(event, messages == null ? "§cHệ thống bảo mật chưa sẵn sàng." : messages.securityUnavailable());
            plugin.getLogger().warning("[AUTH][DENY][SECURITY_STATE] state=" + securityStatus + ", player=" + account.username() + ", uuid=" + uuid);
            audit(uuid, account, SecurityEventType.AUTH_FAILURE, "DENIED", "security backend unavailable: " + securityStatus, null, null);
            return;
        }

        ClientIpResolver.Resolution resolved = resolver().resolve(event);
        if (!resolved.valid()) {
            deny(event, messages == null ? "§cKhông thể xác định IP đăng nhập an toàn." : messages.ipResolutionFailed());
            plugin.getLogger().warning("[AUTH][DENY][IP_RESOLUTION] player=" + account.username()
                    + ", uuid=" + uuid + ", reason=" + resolved.reason()
                    + ", proxyMode=" + cfg.proxyMode());
            audit(uuid, account, SecurityEventType.AUTH_FAILURE, "DENIED", "IP resolution failed: " + resolved.reason(), null, null);
            return;
        }

        String ip = resolved.ip();
        String ipHash = plugin.ips().hash(ip);

        try {
            Database.TrustedLoginDecision decision = plugin.db().authorizeTrustedLogin(uuid, ipHash, System.currentTimeMillis())
                    .get(3, TimeUnit.SECONDS);
            if (decision == Database.TrustedLoginDecision.TRUSTED) {
                plugin.accounts().refresh(uuid);
                plugin.audit().log(uuid, account.role(), SecurityEventType.LOGIN_ATTEMPT,
                        "ALLOWED", "trusted IP", null, null);
                plugin.getLogger().fine("Login allowed: trusted IP; player=" + account.username() + ", uuid=" + uuid);
                return;
            }

            if (decision == Database.TrustedLoginDecision.TEMPORARY_SECURITY_BLOCK) {
                deny(event, messages == null ? "§cĐăng nhập đang tạm thời bị chặn." : messages.temporaryBan());
                plugin.getLogger().warning("Login denied: active temporary security block; player=" + account.username() + ", uuid=" + uuid);
                audit(uuid, account, SecurityEventType.AUTH_FAILURE, "DENIED", "active temporary security block", null, ipHash);
                return;
            }

            if (decision == Database.TrustedLoginDecision.ACCOUNT_NOT_AUTHORIZABLE) {
                deny(event, messages == null ? "§cKhông thể xác thực tài khoản một cách an toàn." : messages.securityUnavailable());
                plugin.getLogger().warning("Login denied: account authorization state changed during DB authorization; player=" + account.username() + ", uuid=" + uuid);
                audit(uuid, account, SecurityEventType.AUTH_FAILURE, "DENIED", "account authorization state changed during login", null, ipHash);
                return;
            }

            audit(uuid, account, SecurityEventType.NEW_IP, "DENIED", "untrusted IP", null, ipHash);

            if (plugin.lockdown().isEnabled()) {
                deny(event, messages == null ? "§cStaffGuard đang ở chế độ LOCKDOWN." : cfg.lockdownMessage());
                audit(uuid, account, SecurityEventType.LOCKDOWN_ENABLED, "DENIED", "new IP during lockdown", null, ipHash);
                plugin.getLogger().warning("Login denied: LOCKDOWN blocked an untrusted IP; player=" + account.username() + ", uuid=" + uuid);
                return;
            }

            if (plugin.verification() == null || plugin.discord() == null || !plugin.config().discordEnabled()) {
                deny(event, messages == null ? "§cXác minh Discord hiện không khả dụng." : messages.discordUnavailable());
                plugin.getLogger().warning("[AUTH][DENY][DISCORD_UNAVAILABLE] untrusted IP cần Discord verification nhưng Discord đang tắt/không khả dụng; player="
                        + account.username() + ", uuid=" + uuid);
                audit(uuid, account, SecurityEventType.AUTH_FAILURE, "DENIED", "Discord verification unavailable", null, ipHash);
                return;
            }

            var created = plugin.verification().create(uuid, ip).get(3, TimeUnit.SECONDS).orElse(null);
            if (created == null) {
                deny(event, messages == null ? "§cKhông thể tạo yêu cầu xác minh lúc này." : messages.verificationUnavailable());
                plugin.getLogger().warning("[AUTH][DENY][VERIFICATION_CREATE] không tạo được verification session; player="
                        + account.username() + ", uuid=" + uuid);
                audit(uuid, account, SecurityEventType.AUTH_FAILURE, "DENIED", "verification session creation returned empty", null, ipHash);
                return;
            }

            plugin.accounts().find(uuid).whenComplete((current, error) -> {
                if (error != null) {
                    plugin.getLogger().log(Level.WARNING, "Verification notification skipped: account lookup failed for " + uuid, unwrap(error));
                    return;
                }
                if (current == null || !current.active()) {
                    plugin.getLogger().warning("Verification notification skipped: account is no longer ACTIVE; uuid=" + uuid);
                    return;
                }
                plugin.discord().sendVerification(current, ip, created).whenComplete((sent, sendError) -> {
                    if (sendError != null) {
                        plugin.getLogger().log(Level.WARNING, "Discord verification notification failed; session="
                                + created.session().sessionId() + ", uuid=" + uuid, unwrap(sendError));
                        return;
                    }
                    if (Boolean.FALSE.equals(sent)) {
                        plugin.getLogger().warning("Discord verification notification was not delivered; session="
                                + created.session().sessionId() + ", player=" + current.username() + ", uuid=" + uuid);
                        audit(uuid, current, SecurityEventType.AUTH_FAILURE, "DENIED", "Discord notification unavailable",
                                created.session().sessionId(), ipHash);
                    }
                });
            });

            deny(event, messages == null ? "§cTài khoản đang dùng IP chưa được tin cậy." : cfg.differentIpMessage());
            plugin.getLogger().info("Login denied: untrusted IP; verification session created; player=" + account.username()
                    + ", uuid=" + uuid + ", session=" + created.session().sessionId());
        } catch (TimeoutException ex) {
            deny(event, messages == null ? "§cHệ thống bảo mật đang bận. §fVui lòng thử lại sau." : messages.databaseTimeout());
            plugin.getLogger().warning("Login denied after security database timeout; player=" + account.username() + ", uuid=" + uuid);
            audit(uuid, account, SecurityEventType.AUTH_FAILURE, "DENIED", "security operation timeout", null, ipHash);
        } catch (Exception ex) {
            deny(event, messages == null ? "§cHệ thống bảo mật gặp lỗi. §fQuản trị viên cần kiểm tra console." : messages.securityUnavailable());
            plugin.getLogger().log(Level.SEVERE, "Login denied because a security operation failed; player=" + account.username() + ", uuid=" + uuid, unwrap(ex));
            audit(uuid, account, SecurityEventType.AUTH_FAILURE, "DENIED", "security operation failure: " + safeReason(ex), null, ipHash);
        }
    }

    private ClientIpResolver resolver() {
        ClientIpResolver current = resolver;
        if (current != null) return current;
        synchronized (this) {
            if (resolver == null && plugin.config() != null) resolver = new ClientIpResolver(plugin.config());
            return resolver;
        }
    }

    private void audit(java.util.UUID uuid, ProtectedAccount account, SecurityEventType event, String result,
                       String reason, java.util.UUID verificationId, String ipHash) {
        if (plugin.audit() != null) plugin.audit().log(uuid, account.role(), event, result, reason, verificationId, ipHash);
    }

    private static void deny(AsyncPlayerPreLoginEvent event, String message) {
        event.disallow(AsyncPlayerPreLoginEvent.Result.KICK_OTHER, LEGACY.deserialize(message == null ? "§cĐăng nhập bị từ chối." : message));
    }

    private static String safeReason(Throwable error) {
        Throwable cause = unwrap(error);
        String text = cause == null ? "unknown" : cause.getMessage();
        if (text == null || text.isBlank()) return cause == null ? "unknown" : cause.getClass().getSimpleName();
        return text.replaceAll("\\s+", " ").substring(0, Math.min(240, text.replaceAll("\\s+", " ").length()));
    }

    private static Throwable unwrap(Throwable error) {
        Throwable current = error;
        while (current instanceof java.util.concurrent.CompletionException && current.getCause() != null) current = current.getCause();
        return current;
    }
}
