package com.anpahn.staffguard.listeners;

import com.anpahn.staffguard.StaffGuardPlugin;
import com.anpahn.staffguard.model.SecurityEventType;
import com.anpahn.staffguard.model.ProtectedAccount;
import com.anpahn.staffguard.model.Role;
import com.anpahn.staffguard.util.AuditCommandSanitizer;
import org.bukkit.command.CommandSender;
import org.bukkit.command.ConsoleCommandSender;
import org.bukkit.event.EventHandler;
import org.bukkit.event.EventPriority;
import org.bukkit.event.Listener;
import org.bukkit.event.player.PlayerCommandPreprocessEvent;
import org.bukkit.event.server.ServerCommandEvent;
import org.bukkit.entity.Player;

import java.util.Locale;

public final class CommandAuditListener implements Listener {
    private final StaffGuardPlugin plugin;

    public CommandAuditListener(StaffGuardPlugin plugin) {
        this.plugin = plugin;
    }

    @EventHandler(priority = EventPriority.MONITOR, ignoreCancelled = true)
    public void onPlayerCommand(PlayerCommandPreprocessEvent event) {
        Player player = event.getPlayer();
        boolean tracked = player.hasPermission("staffguard.admin") || player.hasPermission("staffguard.owner") || (plugin.config() != null && plugin.config().commandAudit().logOpCommands() && player.isOp());
        if (!tracked) return;
        String command = event.getMessage();
        audit(player, command, player.hasPermission("staffguard.owner") ? "OWNER" : player.hasPermission("staffguard.admin") ? "ADMIN" : "OP", "PLAYER");
    }

    @EventHandler(priority = EventPriority.MONITOR, ignoreCancelled = true)
    public void onConsoleCommand(ServerCommandEvent event) {
        if (plugin.config() == null || !plugin.config().commandAudit().logConsoleCommands()) return;
        CommandSender sender = event.getSender();
        if (!(sender instanceof ConsoleCommandSender)) return;
        audit(sender, "/" + event.getCommand(), "CONSOLE", "CONSOLE");
    }

    private void audit(CommandSender sender, String rawCommand, String permission, String source) {
        if (plugin.discord() == null || plugin.config() == null || !plugin.config().commandAudit().enabled()) return;
        if (sender instanceof Player player) {
            boolean admin = player.hasPermission("staffguard.admin") || player.hasPermission("staffguard.owner");
            boolean op = player.isOp();
            if (!admin && !(op && plugin.config().commandAudit().logOpCommands())) return;
            if (admin && !plugin.config().commandAudit().logAdminCommands()) return;
        }
        String sanitized = AuditCommandSanitizer.sanitize(rawCommand, plugin.config());
        boolean dangerous = AuditCommandSanitizer.isDangerous(rawCommand, plugin.config().commandAudit().dangerousCommands());
        ProtectedAccount account = sender instanceof Player p ? plugin.accounts() == null ? null : plugin.accounts().getCached(p.getUniqueId()) : null;
        Role role = account == null ? null : account.role();
        if (plugin.audit() != null) plugin.audit().log(account == null ? null : account.uuid(), role, SecurityEventType.ADMIN_ACTION, dangerous ? "DANGER" : "SUCCESS", "command=" + sanitized, null, null);
        plugin.discord().logCommandAudit(sender.getName(), sanitized, permission, source, dangerous, plugin.config().serverName(), plugin.config().commandAudit().channelId());
    }
}
