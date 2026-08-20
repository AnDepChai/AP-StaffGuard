package com.anpahn.staffguard.config;

import com.anpahn.staffguard.model.ProxyMode;
import com.anpahn.staffguard.util.DurationParser;
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
        String securityUnavailableMessage
) {
    private static final Pattern DISCORD_ID = Pattern.compile("\\d{17,20}");

    public static StaffGuardConfig from(FileConfiguration c) {
        Duration temp = DurationParser.parse(c.getString("security.temporary-ban-duration", "5m"));
        Duration timeout = DurationParser.parse(c.getString("security.verification-timeout", "2m"));
        if (temp.compareTo(Duration.ofDays(30)) > 0) {
            throw new IllegalArgumentException("security.temporary-ban-duration must be <= 30d");
        }
        if (timeout.compareTo(Duration.ofHours(1)) > 0) {
            throw new IllegalArgumentException("security.verification-timeout must be <= 1h");
        }
        int tokenBytes = c.getInt("security.token-bytes", 32);
        if (tokenBytes < 16 || tokenBytes > 128) {
            throw new IllegalArgumentException("security.token-bytes must be 16..128");
        }

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
        List<String> trustedProxyAddresses = List.copyOf(c.getStringList("proxy.trusted-proxy-addresses"));
        if (proxyMode != ProxyMode.NONE && !requireTrustedProxy) {
            throw new IllegalArgumentException("Proxy mode must require trusted proxies for secure client-IP verification. Set proxy.require-trusted-proxy=true.");
        }
        if (proxyMode != ProxyMode.NONE && trustedProxyAddresses.isEmpty()) {
            throw new IllegalArgumentException("Proxy mode requires at least one proxy.trusted-proxy-addresses entry");
        }

        List<String> ownerIds = validateDiscordIds(c.getStringList("discord.owner-user-ids"), "discord.owner-user-ids");
        List<String> staffIds = validateDiscordIds(c.getStringList("discord.staff-user-ids"), "discord.staff-user-ids");
        List<String> allApprovers = new ArrayList<>(ownerIds);
        allApprovers.addAll(staffIds);
        for (String ownerId : ownerIds) {
            if (staffIds.contains(ownerId)) {
                throw new IllegalArgumentException("Discord User ID " + ownerId + " cannot be listed as both owner and staff");
            }
        }
        if (c.getBoolean("discord.enabled", true) && c.getString("discord.channel-id", "").isBlank()) {
            throw new IllegalArgumentException("discord.channel-id is required when Discord integration is enabled");
        }
        if (c.getBoolean("discord.enabled", true) && allApprovers.isEmpty() && !c.getBoolean("discord.allow-self-approval", true)) {
            throw new IllegalArgumentException("At least one Discord owner/staff user ID is required when self approval is disabled");
        }

        return new StaffGuardConfig(
                c.getBoolean("security.enabled", true),
                temp,
                timeout,
                maxTrusted,
                perAccount,
                perIp,
                pending,
                interactions,
                maxDiscord,
                tokenBytes,
                c.getBoolean("security.mask-ip-in-discord", true),
                c.getBoolean("discord.enabled", true),
                c.getString("discord.channel-id", ""),
                c.getString("discord.bot-token", ""),
                ownerIds,
                staffIds,
                c.getBoolean("discord.send-dm", true),
                c.getBoolean("discord.allow-self-approval", true),
                c.getString("database.file", "staffguard.db"),
                c.getString("server.display-name", "Minecraft Server"),
                c.getString("server-secret.value", ""),
                proxyMode,
                trustedProxyAddresses,
                c.getString("messages.different-ip", "Tài khoản khác IP, vui lòng xác minh!"),
                c.getString("messages.lockdown", "StaffGuard đang ở chế độ lockdown. Vui lòng liên hệ quản trị viên."),
                c.getString("messages.security-unavailable", "Bảo mật StaffGuard chưa sẵn sàng. Vui lòng liên hệ quản trị viên.")
        );
    }

    private static List<String> validateDiscordIds(List<String> raw, String path) {
        List<String> result = new ArrayList<>();
        for (String id : raw) {
            if (id == null || id.isBlank()) continue;
            String normalized = id.trim();
            if (!DISCORD_ID.matcher(normalized).matches()) {
                throw new IllegalArgumentException(path + " contains invalid Discord User ID: " + normalized);
            }
            if (!result.contains(normalized)) result.add(normalized);
        }
        return List.copyOf(result);
    }

    public boolean isDiscordApprover(String discordUserId) {
        return isDiscordOwner(discordUserId) || isDiscordStaff(discordUserId);
    }

    public boolean isDiscordOwner(String discordUserId) {
        return discordOwnerUserIds.contains(discordUserId);
    }

    public boolean isDiscordStaff(String discordUserId) {
        return discordStaffUserIds.contains(discordUserId);
    }

}
