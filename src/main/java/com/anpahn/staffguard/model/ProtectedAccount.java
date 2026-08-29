package com.anpahn.staffguard.model;

import java.util.UUID;

public record ProtectedAccount(
        UUID uuid,
        String username,
        Role role,
        String discordId,
        AccountStatus status,
        String lastSeenIpHash,
        long createdAt,
        long updatedAt,
        Long lastSeenAt,
        long securityGeneration
) {
    public boolean active() {
        return status == AccountStatus.ACTIVE;
    }
}
