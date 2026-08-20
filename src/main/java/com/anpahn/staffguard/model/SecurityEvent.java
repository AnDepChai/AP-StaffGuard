package com.anpahn.staffguard.model;
import java.util.UUID;
public record SecurityEvent(long timestamp, UUID uuid, Role role, SecurityEventType event, String result,
                            String reason, UUID verificationId, String ipHash) { }
