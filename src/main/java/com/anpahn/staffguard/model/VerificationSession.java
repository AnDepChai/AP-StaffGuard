package com.anpahn.staffguard.model;

import java.util.UUID;

public record VerificationSession(
        UUID sessionId,
        UUID uuid,
        String discordId,
        String ipHash,
        String tokenHash,
        VerificationState state,
        long createdAt,
        long expiresAt,
        Long processedAt,
        String processedBy,
        long accountGeneration,
        int notificationCount,
        Long lastNotificationAt
) {
    public boolean pendingAndUnexpired(long now) {
        return state == VerificationState.PENDING && expiresAt > now;
    }
}
