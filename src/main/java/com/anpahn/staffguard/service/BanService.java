package com.anpahn.staffguard.service;

import com.anpahn.staffguard.database.Database;
import com.anpahn.staffguard.model.ManagedBan;

import java.time.Duration;
import java.util.Collection;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.logging.Level;
import java.util.logging.Logger;

public final class BanService {
    public static final String MARKER = "AP-StaffGuard";

    private final Database db;
    private final Duration duration;
    private final Logger logger;
    private final ConcurrentHashMap<UUID, Long> cache = new ConcurrentHashMap<>();

    public BanService(Database db, Duration duration, Logger logger) {
        this.db = db;
        this.duration = duration;
        this.logger = logger;
    }

    public CompletableFuture<Void> load(Collection<UUID> ids) {
        return CompletableFuture.allOf(ids.stream()
                .map(u -> db.findBan(u).thenAccept(o -> o
                        .filter(b -> b.activeAt(System.currentTimeMillis()))
                        .ifPresent(b -> cache.put(u, b.expiresAt())))
                        )
                .toArray(CompletableFuture[]::new));
    }

    public boolean isBanned(UUID u) {
        Long expires = cache.get(u);
        if (expires == null) return false;
        if (expires <= System.currentTimeMillis()) {
            cache.remove(u);
            db.removeBan(u).whenComplete((removed, error) -> {
                if (error != null) logger.log(Level.WARNING, "Failed to persist expired ban removal for " + u, unwrap(error));
            });
            return false;
        }
        return true;
    }

    public CompletableFuture<Void> create(UUID u) {
        long expires = System.currentTimeMillis() + duration.toMillis();
        cache.put(u, expires);
        return db.setBan(u, MARKER, expires).thenApply(x -> null);
    }

    public CompletableFuture<Void> remove(UUID u) {
        cache.remove(u);
        return db.removeBan(u).thenApply(x -> null);
    }

    private static Throwable unwrap(Throwable error) {
        if (error instanceof java.util.concurrent.CompletionException && error.getCause() != null) return error.getCause();
        return error;
    }
}
