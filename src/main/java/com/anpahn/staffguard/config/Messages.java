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
        String usage,
        String securityUnavailable,
        String accountLocked,
        String accountRevoked,
        String ipResolutionFailed,
        String databaseTimeout,
        String verificationUnavailable,
        String discordUnavailable,
        String temporaryBan
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
                c.getString("messages.usage", "§e/staffguard help"),
                c.getString("messages.security-unavailable", "§cHệ thống bảo mật chưa sẵn sàng. §fQuản trị viên cần kiểm tra console."),
                c.getString("messages.account-locked", "§cTài khoản StaffGuard đang bị khóa. §fVui lòng liên hệ quản trị viên."),
                c.getString("messages.account-revoked", "§cQuyền bảo vệ của tài khoản này đã bị thu hồi. §fVui lòng liên hệ quản trị viên."),
                c.getString("messages.ip-resolution-failed", "§cKhông thể xác định IP đăng nhập an toàn. §fVui lòng liên hệ quản trị viên."),
                c.getString("messages.database-timeout", "§cHệ thống bảo mật đang bận. §fVui lòng thử lại sau."),
                c.getString("messages.verification-unavailable", "§cKhông thể tạo yêu cầu xác minh lúc này. §fVui lòng liên hệ quản trị viên."),
                c.getString("messages.discord-unavailable", "§cXác minh Discord hiện không khả dụng. §fVui lòng liên hệ quản trị viên để xác minh IP."),
                c.getString("messages.temporary-ban", "§cĐăng nhập đang tạm thời bị chặn do một yêu cầu xác minh đang chờ xử lý. §fVui lòng chờ hoặc hoàn tất xác minh Discord.")
        );
    }
    public String noPermission() { return prefix + noPermission; }
    public String playerOnly() { return prefix + playerOnly; }
    public String operationFailed() { return prefix + operationFailed; }
    public String notFound() { return prefix + notFound; }
    public String invalidRole() { return prefix + invalidRole; }
    public String invalidDiscordId() { return prefix + invalidDiscordId; }
    public String usage() { return prefix + usage; }
    public String securityUnavailable() { return prefix + securityUnavailable; }
    public String accountLocked() { return prefix + accountLocked; }
    public String accountRevoked() { return prefix + accountRevoked; }
    public String ipResolutionFailed() { return prefix + ipResolutionFailed; }
    public String databaseTimeout() { return prefix + databaseTimeout; }
    public String verificationUnavailable() { return prefix + verificationUnavailable; }
    public String discordUnavailable() { return prefix + discordUnavailable; }
    public String temporaryBan() { return prefix + temporaryBan; }
}
