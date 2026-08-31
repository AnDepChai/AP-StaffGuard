package com.anpahn.staffguard.service;

import com.anpahn.staffguard.database.Database;
import com.anpahn.staffguard.util.SecurityUtil;

import java.util.Collection;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;

public final class TrustedIpService {
    private final Database db;
    private final byte[] secret;
    private final int max;
    private final ConcurrentHashMap<UUID, Set<String>> cache = new ConcurrentHashMap<>();

    public TrustedIpService(Database db, byte[] secret, int max) { this.db=db;this.secret=secret.clone();this.max=max; }

    public CompletableFuture<Void> load(Collection<UUID> uuids) {
        cache.clear();
        return CompletableFuture.allOf(uuids.stream().map(this::refresh).toArray(CompletableFuture[]::new));
    }

    public String hash(String ip) { return SecurityUtil.hmacSha256Hex(secret, ip); }

    
    public CompletableFuture<Boolean> isTrusted(UUID uuid, String ip) {
        String hash = hash(ip);
        return db.loadTrustedIps(uuid).thenApply(values -> { putCache(uuid, values); return values.contains(hash); });
    }

    public CompletableFuture<Boolean> add(UUID uuid, String ip) {
        return db.addTrustedIpHash(uuid, hash(ip), System.currentTimeMillis(), max)
                .thenCompose(ok -> refresh(uuid).thenApply(v -> ok));
    }

    public CompletableFuture<Boolean> addHash(UUID uuid, String hash) {
        return db.addTrustedIpHash(uuid, hash, System.currentTimeMillis(), max)
                .thenCompose(ok -> refresh(uuid).thenApply(v -> ok));
    }

    public CompletableFuture<Boolean> remove(UUID uuid, String ip) {
        return db.submit(c -> {
            try (var p=c.prepareStatement("DELETE FROM trusted_ips WHERE uuid=? AND ip_hash=?")) {
                p.setString(1,uuid.toString());p.setString(2,hash(ip));return p.executeUpdate()>0;
            }
        }).thenCompose(ok -> refresh(uuid).thenApply(v -> ok));
    }

    public void invalidate(UUID uuid) { cache.remove(uuid); }
    public CompletableFuture<Void> refresh(UUID uuid) { return db.loadTrustedIps(uuid).thenAccept(values -> putCache(uuid, values)); }
    private void putCache(UUID uuid, Collection<String> values) { Set<String> copy=ConcurrentHashMap.newKeySet();copy.addAll(values);cache.put(uuid,copy); }
}
