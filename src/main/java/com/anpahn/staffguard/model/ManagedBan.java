package com.anpahn.staffguard.model;
import java.util.UUID;
public record ManagedBan(UUID uuid, String marker, long expiresAt, boolean active, long createdAt, Long removedAt) {
    public boolean activeAt(long now) { return active && expiresAt > now; }
}
