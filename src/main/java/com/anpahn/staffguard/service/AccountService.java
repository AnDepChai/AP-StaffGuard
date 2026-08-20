package com.anpahn.staffguard.service;

import com.anpahn.staffguard.database.Database;
import com.anpahn.staffguard.model.ProtectedAccount;

import java.util.Collection;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;

public final class AccountService {
    private final Database db;
    private final ConcurrentHashMap<UUID, ProtectedAccount> cache = new ConcurrentHashMap<>();
    private final AtomicBoolean loaded = new AtomicBoolean(false);

    public AccountService(Database db) { this.db = db; }

    public CompletableFuture<Void> load() {
        loaded.set(false);
        return db.loadAccounts().thenAccept(list -> {
            cache.clear();
            list.forEach(a -> cache.put(a.uuid(), a));
            loaded.set(true);
        });
    }

    public boolean isLoaded() { return loaded.get(); }

    public ProtectedAccount getCached(UUID uuid) { return cache.get(uuid); }

    public ProtectedAccount getByUsername(String name) {
        for (ProtectedAccount a : cache.values()) {
            if (a.username().equalsIgnoreCase(name)) return a;
        }
        return null;
    }

    public Collection<ProtectedAccount> all() { return List.copyOf(cache.values()); }

    public CompletableFuture<ProtectedAccount> add(UUID uuid, String username, com.anpahn.staffguard.model.Role role, String discord) {
        return db.upsertAccount(uuid, username, role, discord).thenApply(a -> { cache.put(uuid, a); return a; });
    }

    public CompletableFuture<Boolean> remove(UUID uuid) {
        return db.removeAccount(uuid).thenApply(ok -> { if (ok) cache.remove(uuid); return ok; });
    }

    public CompletableFuture<Void> refresh(UUID uuid) {
        return db.findAccount(uuid).thenAccept(o -> {
            if (o.isPresent() && o.get().active()) cache.put(uuid, o.get());
            else cache.remove(uuid);
        });
    }

    public CompletableFuture<Void> setLastSeen(UUID uuid, String ipHash) {
        return db.updateLastSeen(uuid, ipHash).thenCompose(v -> db.findAccount(uuid)).thenAccept(o -> o.ifPresent(a -> cache.put(uuid, a)));
    }
}
