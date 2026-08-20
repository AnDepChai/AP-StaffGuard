package com.anpahn.staffguard.service;

import com.anpahn.staffguard.database.Database;
import com.anpahn.staffguard.model.*;

import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.logging.Level;
import java.util.logging.Logger;

/** Persists security events and makes audit-write failures observable. */
public final class AuditService {
    private final Database db;
    private final Logger logger;

    public AuditService(Database db, Logger logger) {
        this.db = db;
        this.logger = logger;
    }

    public void log(UUID u, Role r, SecurityEventType e, String result, String reason, UUID verification, String ipHash) {
        db.audit(new SecurityEvent(System.currentTimeMillis(), u, r, e, result, reason, verification, ipHash))
                .exceptionally(ex -> {
                    logger.log(Level.WARNING, "Failed to write AP-StaffGuard audit event " + e + " for " + u, unwrap(ex));
                    return null;
                });
    }

    public CompletableFuture<java.util.List<String>> logs(UUID u, int limit) {
        return db.logs(u, limit);
    }

    private static Throwable unwrap(Throwable error) {
        if (error instanceof java.util.concurrent.CompletionException && error.getCause() != null) return error.getCause();
        return error;
    }
}
