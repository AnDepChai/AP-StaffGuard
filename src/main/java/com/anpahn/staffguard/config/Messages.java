package com.anpahn.staffguard.config;

import org.bukkit.configuration.file.FileConfiguration;

public record Messages(
        String prefix,
        String noPermission,
        String playerOnly,
        String operationFailed,
        String notFound,
        String invalidRole,
        String invalidDiscordId,
        String usage
) {
    public static Messages from(FileConfiguration c) {
        return new Messages(
                c.getString("messages.prefix", "§8[§bAP-StaffGuard§8] §r"),
                c.getString("messages.no-permission", "§cBạn không có quyền thực hiện thao tác này."),
                c.getString("messages.player-only", "§cThao tác này yêu cầu player."),
                c.getString("messages.operation-failed", "§cThao tác thất bại. Kiểm tra console để biết chi tiết."),
                c.getString("messages.not-found", "§cKhông tìm thấy protected account."),
                c.getString("messages.invalid-role", "§cRole phải là OWNER hoặc STAFF."),
                c.getString("messages.invalid-discord-id", "§cDiscord User ID không hợp lệ."),
                c.getString("messages.usage", "§e/staffguard help")
        );
    }
    public String noPermission() { return prefix + noPermission; }
    public String playerOnly() { return prefix + playerOnly; }
    public String operationFailed() { return prefix + operationFailed; }
    public String notFound() { return prefix + notFound; }
    public String invalidRole() { return prefix + invalidRole; }
    public String invalidDiscordId() { return prefix + invalidDiscordId; }
    public String usage() { return prefix + usage; }
}
