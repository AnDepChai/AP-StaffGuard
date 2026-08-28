package com.anpahn.staffguard.listeners;

import com.anpahn.staffguard.StaffGuardPlugin;
import com.anpahn.staffguard.model.ProtectedAccount;
import com.anpahn.staffguard.model.SecurityEventType;
import com.anpahn.staffguard.util.IpMatcher;
import org.bukkit.event.EventHandler;
import org.bukkit.event.EventPriority;
import org.bukkit.event.Listener;
import org.bukkit.event.player.AsyncPlayerPreLoginEvent;

import java.net.InetAddress;
import java.util.UUID;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

public final class LoginListener implements Listener {
    private final StaffGuardPlugin plugin;

    public LoginListener(StaffGuardPlugin plugin) {
        this.plugin = plugin;
    }

    @EventHandler(priority = EventPriority.HIGHEST)
    public void onPreLogin(AsyncPlayerPreLoginEvent event) {
        if (plugin.config() == null) {
            deny(event, "§cAP-StaffGuard chưa khởi tạo xong. §fVui lòng thử lại sau.");
            return;
        }
        if (plugin.accounts() == null || !plugin.accounts().isLoaded()) {
            deny(event, plugin.config().securityUnavailableMessage());
            return;
        }

        if (!plugin.config().securityEnabled()) return;

        UUID uuid = event.getUniqueId();
        ProtectedAccount account = plugin.accounts().getCached(uuid);
        if (account == null || !account.active()) return;

        if (!plugin.securityState().isReady()) {
            deny(event, plugin.config().securityUnavailableMessage());
            plugin.audit().log(uuid, account.role(), SecurityEventType.AUTH_FAILURE, "DENIED", "security backend not ready", null, null);
            return;
        }

        InetAddress clientAddress = event.getAddress();
        InetAddress rawAddress = event.getRawAddress();
        if (!proxyConnectionIsTrusted(rawAddress)) {
            deny(event, plugin.config().securityUnavailableMessage());
            plugin.audit().log(uuid, account.role(), SecurityEventType.AUTH_FAILURE, "DENIED", "untrusted proxy connection", null, null);
            return;
        }
        if (clientAddress == null) {
            deny(event, plugin.config().differentIpMessage());
            plugin.audit().log(uuid, account.role(), SecurityEventType.AUTH_FAILURE, "DENIED", "client address unavailable", null, null);
            return;
        }
        String ip = clientAddress.getHostAddress();
        try {
            if (plugin.ips().isTrusted(uuid, ip).get(3, TimeUnit.SECONDS)) {
                plugin.banService().markManagedBanRemoved(uuid);
                plugin.accounts().setLastSeen(uuid, plugin.ips().hash(ip));
                plugin.audit().log(uuid, account.role(), SecurityEventType.LOGIN_ATTEMPT, "ALLOWED", "trusted IP", null, plugin.ips().hash(ip));
                return;
            }

            plugin.audit().log(uuid, account.role(), SecurityEventType.NEW_IP, "DENIED", "untrusted IP", null, plugin.ips().hash(ip));
            if (plugin.lockdown().isEnabled()) {
                plugin.banService().create(uuid).get(3, TimeUnit.SECONDS);
                plugin.audit().log(uuid, account.role(), SecurityEventType.LOCKDOWN_ENABLED, "DENIED", "new IP during lockdown", null, plugin.ips().hash(ip));
                deny(event, plugin.config().lockdownMessage());
                return;
            }

            var created = plugin.verification().create(uuid, ip).get(4, TimeUnit.SECONDS).orElse(null);
            if (created == null) {
                plugin.banService().create(uuid).get(3, TimeUnit.SECONDS);
                deny(event, plugin.config().differentIpMessage());
                return;
            }

            boolean wasAlreadyBanned = plugin.banService().isBanned(uuid);

            boolean sent = plugin.discord().sendVerification(account, ip, created).get(7, TimeUnit.SECONDS);
            if (!sent) {
                plugin.banService().create(uuid).get(3, TimeUnit.SECONDS);
                deny(event, plugin.config().differentIpMessage());
                plugin.audit().log(uuid, account.role(), SecurityEventType.AUTH_FAILURE, "DENIED", "Discord unavailable", created.session().sessionId(), plugin.ips().hash(ip));
                return;
            }

            if (!wasAlreadyBanned) {
                plugin.banService().create(uuid).get(3, TimeUnit.SECONDS);
                plugin.audit().log(uuid, account.role(), SecurityEventType.TEMPBAN_CREATED, "SUCCESS", "untrusted IP verification required", created.session().sessionId(), plugin.ips().hash(ip));
            }
            deny(event, plugin.config().differentIpMessage());
        } catch (TimeoutException ex) {
            deny(event, plugin.config().differentIpMessage());
            plugin.audit().log(uuid, account.role(), SecurityEventType.AUTH_FAILURE, "DENIED", "security operation timeout", null, null);
        } catch (Exception ex) {
            plugin.getLogger().log(java.util.logging.Level.SEVERE, "Protected login processing failed for " + uuid, ex);
            deny(event, plugin.config().differentIpMessage());
            plugin.audit().log(uuid, account.role(), SecurityEventType.AUTH_FAILURE, "DENIED", "unexpected error", null, null);
        }
    }

    private boolean proxyConnectionIsTrusted(InetAddress rawAddress) {
        if (plugin.config().proxyMode() == com.anpahn.staffguard.model.ProxyMode.NONE) return true;
        if (rawAddress == null) return false;
        return new IpMatcher(plugin.config().trustedProxyAddresses()).isAllowed(rawAddress);
    }

    private static void deny(AsyncPlayerPreLoginEvent event, String message) {
        event.disallow(AsyncPlayerPreLoginEvent.Result.KICK_OTHER, message);
    }
}
