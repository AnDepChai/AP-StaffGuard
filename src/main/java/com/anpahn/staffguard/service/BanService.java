package com.anpahn.staffguard.service;

import com.anpahn.staffguard.database.Database;
import com.anpahn.staffguard.model.ManagedBan;

import java.time.Duration;
import java.util.Collection;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.logging.Logger;

public final class BanService {
    public static final String MARKER = "AP-StaffGuard";
    private final Database db;
    private final Duration duration;
    private final Logger logger;
    private final ConcurrentHashMap<UUID, Long> cache = new ConcurrentHashMap<>();

    public BanService(Database db, Duration duration, Logger logger) { this.db=db;this.duration=duration;this.logger=logger; }
    public CompletableFuture<Void> load(Collection<UUID> ids) { cache.clear(); return CompletableFuture.allOf(ids.stream().map(u -> refresh(u)).toArray(CompletableFuture[]::new)); }
    public CompletableFuture<Boolean> isBanned(UUID u) {
        return db.findBan(u).thenApply(o -> o.isPresent() && o.get().activeAt(System.currentTimeMillis()));
    }
    public CompletableFuture<Void> create(UUID u) { long expires=System.currentTimeMillis()+duration.toMillis(); return db.setBan(u,MARKER,expires).thenAccept(ok->{ if(!ok) throw new IllegalStateException("Cannot create managed security block for non-active account"); cache.put(u,expires); }); }
    public CompletableFuture<Void> remove(UUID u) { return db.removeBan(u).thenApply(x->{cache.remove(u);return null;}); }
    public void invalidate(UUID u){cache.remove(u);}
    public CompletableFuture<Void> refresh(UUID u){return db.findBan(u).thenAccept(o->{if(o.isPresent()&&o.get().activeAt(System.currentTimeMillis()))cache.put(u,o.get().expiresAt());else cache.remove(u);});}
}
