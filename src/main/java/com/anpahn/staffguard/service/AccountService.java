package com.anpahn.staffguard.service;

import com.anpahn.staffguard.database.Database;
import com.anpahn.staffguard.model.AccountStatus;
import com.anpahn.staffguard.model.ProtectedAccount;
import com.anpahn.staffguard.model.Role;

import java.util.Collection;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Consumer;

public final class AccountService {
    private final Database db;
    private final ConcurrentHashMap<UUID, ProtectedAccount> cache = new ConcurrentHashMap<>();
    private final AtomicBoolean loaded = new AtomicBoolean(false);
    private final Consumer<UUID> securityStateInvalidator;

    public AccountService(Database db) { this(db, uuid -> {}); }
    public AccountService(Database db, Consumer<UUID> securityStateInvalidator) {
        this.db = db;
        this.securityStateInvalidator = securityStateInvalidator == null ? uuid -> {} : securityStateInvalidator;
    }

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
    public Collection<ProtectedAccount> all() { return List.copyOf(cache.values()); }
    public ProtectedAccount getByUsername(String name) { for (ProtectedAccount a : cache.values()) if (a.username().equalsIgnoreCase(name)) return a; return null; }

    public CompletableFuture<ProtectedAccount> add(UUID uuid, String username, Role role, String discord, int maxDiscordAccounts) {
        return db.upsertAccount(uuid, username, role, discord, maxDiscordAccounts).thenApply(a -> { cache.put(uuid, a); securityStateInvalidator.accept(uuid); return a; });
    }

    public CompletableFuture<Boolean> remove(UUID uuid) {
        return db.removeAccount(uuid).thenApply(ok -> { if (ok) { cache.remove(uuid); securityStateInvalidator.accept(uuid); } return ok; });
    }

    public CompletableFuture<Boolean> resetSecurity(UUID uuid) {
        return db.resetSecurity(uuid).thenCompose(ok -> {
            if (!ok) return CompletableFuture.completedFuture(false);
            return refresh(uuid).thenApply(v -> { securityStateInvalidator.accept(uuid); return true; });
        });
    }

    public CompletableFuture<Boolean> setStatus(UUID uuid, AccountStatus status) {
        return db.transitionStatus(uuid, status).thenCompose(ok -> {
            if (!ok) return CompletableFuture.completedFuture(false);
            return refresh(uuid).thenApply(v -> { securityStateInvalidator.accept(uuid); return true; });
        });
    }

    public CompletableFuture<Void> refresh(UUID uuid) {
        return db.findAccount(uuid).thenAccept(o -> {
            if (o.isPresent() && o.get().active()) cache.put(uuid, o.get());
            else cache.remove(uuid);
        });
    }

    public CompletableFuture<ProtectedAccount> find(UUID uuid) {
        return db.findAccount(uuid).thenApply(o -> o.orElse(null));
    }

    public CompletableFuture<ProtectedAccount> findByUsername(String username) {
        return db.findAccountByUsername(username).thenApply(o -> o.orElse(null));
    }
}
