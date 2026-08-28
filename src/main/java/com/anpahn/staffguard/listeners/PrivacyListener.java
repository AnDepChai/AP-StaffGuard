package com.anpahn.staffguard.listeners;

import com.anpahn.staffguard.StaffGuardPlugin;
import com.anpahn.staffguard.model.ProtectedAccount;
import org.bukkit.event.EventHandler;
import org.bukkit.event.EventPriority;
import org.bukkit.event.Listener;
import org.bukkit.event.player.PlayerJoinEvent;

public final class PrivacyListener implements Listener {
    private final StaffGuardPlugin plugin;
    public PrivacyListener(StaffGuardPlugin plugin) { this.plugin = plugin; }
    @EventHandler(priority = EventPriority.HIGHEST)
    public void onJoin(PlayerJoinEvent event) {
        if (plugin.config() == null || !plugin.config().privacy().enabled() || !plugin.config().privacy().suppressProtectedJoinMessage()) return;
        ProtectedAccount account = plugin.accounts() == null ? null : plugin.accounts().getCached(event.getPlayer().getUniqueId());
        boolean protectedAccount = account != null && account.active();
        boolean privileged = event.getPlayer().hasPermission("staffguard.admin") || event.getPlayer().hasPermission("staffguard.owner");
        if (protectedAccount || privileged) event.setJoinMessage(null);
    }
}
