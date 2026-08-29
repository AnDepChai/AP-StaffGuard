package com.anpahn.staffguard.config;

import com.anpahn.staffguard.model.ProxyMode;
import com.anpahn.staffguard.util.DurationParser;
import com.anpahn.staffguard.util.IpMatcher;
import org.bukkit.configuration.file.FileConfiguration;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

public record StaffGuardConfig(
        boolean securityEnabled,
        Duration temporaryBanDuration,
        Duration verificationTimeout,
        int maxTrustedIps,
        int maxVerificationRequestsAccount,
        int maxVerificationRequestsIp,
        int maxPendingSessions,
        int maxDiscordInteractionsPerMinute,
        int maxDiscordAccountsPerUser,
        int tokenBytes,
        int maxVerificationNotifications,
        Duration verificationNotificationCooldown,
        int auditRetentionDays,
        boolean maskIpInDiscord,
        boolean discordEnabled,
        String discordChannelId,
        String discordToken,
        List<String> discordOwnerUserIds,
        List<String> discordStaffUserIds,
        boolean discordSendDm,
        boolean discordAllowSelfApproval,
        String databaseFile,
        String serverName,
        String serverSecretValue,
        ProxyMode proxyMode,
        List<String> trustedProxyAddresses,
        String differentIpMessage,
        String lockdownMessage,
        String securityUnavailableMessage,
        PrivacyConfig privacy,
        VerificationEmbedConfig verificationEmbed,
        CommandAuditConfig commandAudit,
        CommandAuditEmbedConfig commandAuditEmbed
) {
    private static final Pattern DISCORD_ID = Pattern.compile("\\d{17,20}");

    public static StaffGuardConfig from(FileConfiguration c) {
        Duration temp = DurationParser.parse(c.getString("security.temporary-ban-duration", "5m"));
        Duration timeout = DurationParser.parse(c.getString("security.verification-timeout", "2m"));
        if (temp.compareTo(Duration.ofDays(30)) > 0) throw new IllegalArgumentException("security.temporary-ban-duration must be <= 30d");
        if (timeout.compareTo(Duration.ofHours(1)) > 0) throw new IllegalArgumentException("security.verification-timeout must be <= 1h");

        int tokenBytes = c.getInt("security.token-bytes", 32);
        if (tokenBytes < 16 || tokenBytes > 128) throw new IllegalArgumentException("security.token-bytes must be 16..128");
        int notificationMax = c.getInt("security.max-verification-notifications", 3);
        Duration notificationCooldown = DurationParser.parse(c.getString("security.verification-notification-cooldown", "30s"));
        int auditRetentionDays = c.getInt("security.audit-retention-days", 30);
        if (notificationMax < 1 || notificationMax > 20) throw new IllegalArgumentException("security.max-verification-notifications must be 1..20");
        if (notificationCooldown.compareTo(Duration.ofMinutes(10)) > 0) throw new IllegalArgumentException("security.verification-notification-cooldown must be <= 10m");
        if (auditRetentionDays < 1 || auditRetentionDays > 3650) throw new IllegalArgumentException("security.audit-retention-days must be 1..3650");

        int maxTrusted = c.getInt("security.max-trusted-ips-per-account", 10);
        int perAccount = c.getInt("security.max-verification-requests-per-10-minutes", 3);
        int perIp = c.getInt("security.max-verification-requests-per-ip-per-10-minutes", 5);
        int pending = c.getInt("security.max-pending-sessions", 100);
        int interactions = c.getInt("security.max-discord-interactions-per-minute", 30);
        int maxDiscord = c.getInt("security.max-discord-accounts-per-user", 2);
        if (maxTrusted < 1 || perAccount < 1 || perIp < 1 || pending < 1 || interactions < 1 || maxDiscord < 1) {
            throw new IllegalArgumentException("Security limits must be positive");
        }

        ProxyMode proxyMode = ProxyMode.parse(c.getString("proxy.mode", "NONE"));
        boolean requireTrustedProxy = c.getBoolean("proxy.require-trusted-proxy", true);
        List<String> trustedProxyAddresses = c.getStringList("proxy.trusted-proxy-addresses").stream().filter(v -> v != null && !v.isBlank()).map(String::trim).distinct().toList();
        if (proxyMode != ProxyMode.NONE && !requireTrustedProxy) throw new IllegalArgumentException("Proxy mode requires trusted proxy enforcement");
        if (proxyMode != ProxyMode.NONE && trustedProxyAddresses.isEmpty()) throw new IllegalArgumentException("Proxy mode requires at least one trusted proxy address");
        if (!trustedProxyAddresses.isEmpty()) new IpMatcher(trustedProxyAddresses);

        List<String> ownerIds = validateDiscordIds(c.getStringList("discord.owner-user-ids"), "discord.owner-user-ids");
        List<String> staffIds = validateDiscordIds(c.getStringList("discord.staff-user-ids"), "discord.staff-user-ids");
        for (String ownerId : ownerIds) {
            if (staffIds.contains(ownerId)) throw new IllegalArgumentException("Discord User ID " + ownerId + " cannot be listed as both owner and staff");
        }
        boolean discordEnabled = c.getBoolean("discord.enabled", false);
        boolean selfApproval = c.getBoolean("discord.allow-self-approval", false);
        String discordChannelId = c.getString("discord.channel-id", "");
        if (discordEnabled && !DISCORD_ID.matcher(discordChannelId).matches()) throw new IllegalArgumentException("discord.channel-id must be a Discord snowflake (17..20 digits)");
        if (discordEnabled && ownerIds.isEmpty() && staffIds.isEmpty() && !selfApproval) throw new IllegalArgumentException("At least one Discord approver is required when self approval is disabled");

        PrivacyConfig privacy = new PrivacyConfig(
                c.getBoolean("privacy.enabled", true),
                c.getBoolean("privacy.suppress-protected-join-message", true),
                c.getBoolean("privacy.redact-ip-in-command-audit", true),
                c.getBoolean("privacy.redact-coordinates-in-command-audit", true)
        );

        VerificationEmbedConfig verificationEmbed = new VerificationEmbedConfig(
                c.getString("discord.embeds.verification.title", "🔐 AP-STAFFGUARD • Xác thực đăng nhập"),
                parseColor(c.getString("discord.embeds.verification.color", "#F5A623")),
                c.getString("discord.embeds.verification.description", "Phát hiện đăng nhập từ IP chưa được tin cậy. Hãy kiểm tra thông tin bên dưới trước khi xác nhận."),
                c.getString("discord.embeds.verification.minecraft-field", "👤 Minecraft"),
                c.getString("discord.embeds.verification.role-field", "🛡️ Role"),
                c.getString("discord.embeds.verification.ip-field", "🌐 IP"),
                c.getString("discord.embeds.verification.verification-field", "🆔 Verification"),
                c.getString("discord.embeds.verification.expiry-field", "⏱️ Hết hạn"),
                c.getString("discord.embeds.verification.server-field", "🏠 Server"),
                c.getString("discord.embeds.verification.footer", "AP-StaffGuard • Owner có thể xác nhận mọi request; Staff chỉ xác nhận request của chính mình."),
                c.getString("discord.embeds.verification.approve-button", "✅ Xác nhận"),
                c.getString("discord.embeds.verification.deny-button", "❌ Từ chối")
        );

        CommandAuditConfig commandAudit = new CommandAuditConfig(
                c.getBoolean("discord.command-audit.enabled", false),
                c.getString("discord.command-audit.channel-id", ""),
                c.getBoolean("discord.command-audit.log-admin-commands", true),
                c.getBoolean("discord.command-audit.log-op-commands", true),
                c.getBoolean("discord.command-audit.log-console-commands", true),
                c.getStringList("discord.command-audit.dangerous-commands").stream().filter(v -> v != null && !v.isBlank()).map(String::trim).distinct().toList(),
                c.getBoolean("discord.command-audit.redact-sensitive-arguments", true)
        );
        if (commandAudit.enabled() && !discordEnabled) throw new IllegalArgumentException("discord.command-audit requires discord.enabled=true");
        if (commandAudit.enabled() && !DISCORD_ID.matcher(commandAudit.channelId()).matches()) throw new IllegalArgumentException("discord.command-audit.channel-id must be a Discord snowflake (17..20 digits)");
        validateCommandAudit(commandAudit);

        validateTextLengths(verificationEmbed);
        CommandAuditEmbedConfig commandAuditEmbed = new CommandAuditEmbedConfig(
                c.getString("discord.embeds.command-audit.title", "🛡️ AP-StaffGuard • Admin Command Audit"),
                parseColor(c.getString("discord.embeds.command-audit.safe-color", "#3498DB")),
                parseColor(c.getString("discord.embeds.command-audit.danger-color", "#E74C3C")),
                c.getString("discord.embeds.command-audit.description", "Ghi nhận thao tác command của admin/operator trên server."),
                c.getString("discord.embeds.command-audit.command-field", "💻 Command"),
                c.getString("discord.embeds.command-audit.sender-field", "👤 Người thực hiện"),
                c.getString("discord.embeds.command-audit.permission-field", "🔐 Quyền"),
                c.getString("discord.embeds.command-audit.server-field", "🏠 Server"),
                c.getString("discord.embeds.command-audit.channel-field", "📍 Nguồn"),
                c.getString("discord.embeds.command-audit.footer", "AP-StaffGuard • Command audit")
        );

        return new StaffGuardConfig(
                c.getBoolean("security.enabled", true), temp, timeout, maxTrusted, perAccount, perIp, pending, interactions, maxDiscord,
                tokenBytes, notificationMax, notificationCooldown, auditRetentionDays, c.getBoolean("security.mask-ip-in-discord", true), discordEnabled,
                discordChannelId, c.getString("discord.bot-token", ""), ownerIds, staffIds,
                c.getBoolean("discord.send-dm", true), selfApproval,
                c.getString("database.file", "staffguard.db"), c.getString("server.display-name", "Minecraft Server"),
                c.getString("server-secret.value", ""), proxyMode, trustedProxyAddresses,
                c.getString("messages.different-ip", "§cTài khoản đang đăng nhập từ IP chưa được tin cậy. §fVui lòng xác minh qua Discord rồi đăng nhập lại."),
                c.getString("messages.lockdown", "§cStaffGuard đang ở chế độ LOCKDOWN. §fVui lòng liên hệ quản trị viên."),
                c.getString("messages.security-unavailable", "§cBảo mật StaffGuard chưa sẵn sàng. §fVui lòng liên hệ quản trị viên."),
                privacy, verificationEmbed, commandAudit, commandAuditEmbed
        );
    }

    private static void validateTextLengths(VerificationEmbedConfig e) {
        if (e.title().length() > 256 || e.description().length() > 4096 || e.footer().length() > 2048) throw new IllegalArgumentException("Verification embed text exceeds Discord limits");
        for (String field : List.of(e.minecraftField(), e.roleField(), e.ipField(), e.verificationField(), e.expiryField(), e.serverField())) {
            if (field == null || field.length() > 256) throw new IllegalArgumentException("Verification embed field name exceeds Discord limit");
        }
        if (e.approveButton().length() > 80 || e.denyButton().length() > 80) throw new IllegalArgumentException("Verification button label exceeds Discord limit");
    }

    private static void validateCommandAudit(CommandAuditConfig c) {
        for (String p : c.dangerousCommands()) if (p.length() > 64 || p.indexOf('\n') >= 0 || p.indexOf('\r') >= 0) throw new IllegalArgumentException("Invalid dangerous command pattern: " + p);
    }

    private static List<String> validateDiscordIds(List<String> raw, String path) {
        List<String> result = new ArrayList<>();
        for (String id : raw) {
            if (id == null || id.isBlank()) continue;
            String normalized = id.trim();
            if (!DISCORD_ID.matcher(normalized).matches()) throw new IllegalArgumentException(path + " contains invalid Discord User ID: " + normalized);
            if (!result.contains(normalized)) result.add(normalized);
        }
        return List.copyOf(result);
    }

    private static int parseColor(String value) {
        String normalized = value == null ? "" : value.trim();
        if (normalized.startsWith("#")) normalized = normalized.substring(1);
        if (!normalized.matches("[0-9a-fA-F]{6}")) throw new IllegalArgumentException("Invalid Discord embed color: " + value);
        return Integer.parseInt(normalized, 16);
    }

    public boolean isDiscordApprover(String discordUserId) { return isDiscordOwner(discordUserId) || isDiscordStaff(discordUserId); }
    public boolean isDiscordOwner(String discordUserId) { return discordOwnerUserIds.contains(discordUserId); }
    public boolean isDiscordStaff(String discordUserId) { return discordStaffUserIds.contains(discordUserId); }

    public record PrivacyConfig(boolean enabled, boolean suppressProtectedJoinMessage, boolean redactIpInCommandAudit, boolean redactCoordinatesInCommandAudit) { }

    public record VerificationEmbedConfig(int color, String title, String description, String minecraftField, String roleField,
                                          String ipField, String verificationField, String expiryField, String serverField,
                                          String footer, String approveButton, String denyButton) {
        public VerificationEmbedConfig(String title, int color, String description, String minecraftField, String roleField,
                                       String ipField, String verificationField, String expiryField, String serverField,
                                       String footer, String approveButton, String denyButton) {
            this(color, title, description, minecraftField, roleField, ipField, verificationField, expiryField, serverField, footer, approveButton, denyButton);
        }
    }

    public record CommandAuditConfig(boolean enabled, String channelId, boolean logAdminCommands, boolean logOpCommands,
                                     boolean logConsoleCommands, List<String> dangerousCommands, boolean redactSensitiveArguments) { }

    public record CommandAuditEmbedConfig(String title, int safeColor, int dangerColor, String description,
                                          String commandField, String senderField, String permissionField,
                                          String serverField, String channelField, String footer) { }
}
