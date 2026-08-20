package com.anpahn.staffguard.service;

import com.anpahn.staffguard.config.StaffGuardConfig;
import com.anpahn.staffguard.database.Database;
import com.anpahn.staffguard.model.*;
import com.anpahn.staffguard.security.LockdownManager;
import com.anpahn.staffguard.security.RateLimiter;
import com.anpahn.staffguard.util.SecurityUtil;

import java.time.Duration;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;

public final class VerificationService {
    public record Created(VerificationSession session) { }

    private final Database db;
    private final AccountService accounts;
    private final TrustedIpService ips;
    private final AuditService audit;
    private final StaffGuardConfig cfg;
    private final LockdownManager lockdown;
    private final BanService bans;
    private final String serverSecret;
    private final RateLimiter<UUID> accountLimiter;
    private final RateLimiter<String> ipLimiter;

    public VerificationService(Database db, AccountService accounts, TrustedIpService ips,
                               AuditService audit, StaffGuardConfig cfg, LockdownManager lockdown, BanService bans, String serverSecret) {
        this.db = db;
        this.accounts = accounts;
        this.ips = ips;
        this.audit = audit;
        this.cfg = cfg;
        this.lockdown = lockdown;
        this.bans = bans;
        this.serverSecret = serverSecret;
        this.accountLimiter = new RateLimiter<>(cfg.maxVerificationRequestsAccount(), Duration.ofMinutes(10));
        this.ipLimiter = new RateLimiter<>(cfg.maxVerificationRequestsIp(), Duration.ofMinutes(10));
    }

    public CompletableFuture<Optional<Created>> create(UUID uuid, String ip) {
        ProtectedAccount account = accounts.getCached(uuid);
        if (account == null || !account.active() || lockdown.isEnabled()) {
            return CompletableFuture.completedFuture(Optional.empty());
        }

        String ipHash = ips.hash(ip);

        // Reconnecting with the same untrusted IP while a verification is already pending
        // should reuse that session instead of consuming another rate-limit slot. This keeps
        // the account recoverable after a denied login while still enforcing limits for new
        // verification attempts. The atomic DB create path remains the final authority.
        return db.findPendingSession(uuid).thenCompose(existing -> {
            if (existing.isPresent() && existing.get().ipHash().equals(ipHash)) {
                audit.log(uuid, account.role(), SecurityEventType.VERIFICATION_CREATED, "SUCCESS",
                        "reused pending verification", existing.get().sessionId(), ipHash);
                return CompletableFuture.completedFuture(existing.map(Created::new));
            }

            // Both limiters have stateful side effects, so they must always be evaluated independently.
            boolean accountAllowed = accountLimiter.tryAcquire(uuid);
            boolean ipAllowed = ipLimiter.tryAcquire(ip);
            if (!accountAllowed || !ipAllowed) {
                audit.log(uuid, account.role(), SecurityEventType.RATE_LIMIT, "DENIED", "verification rate limit", null, ipHash);
                return CompletableFuture.completedFuture(Optional.empty());
            }

            String rawToken = SecurityUtil.randomToken(cfg.tokenBytes());
            String tokenHash = SecurityUtil.sha256Hex(rawToken);
            long now = System.currentTimeMillis();

            return db.createVerificationSession(
                            uuid,
                            account.discordId(),
                            ipHash,
                            tokenHash,
                            now,
                            now + cfg.verificationTimeout().toMillis(),
                            cfg.maxPendingSessions())
                    .thenApply(session -> {
                        session.ifPresent(created -> {
                            String reason = created.ipHash().equals(ipHash) ? "new/pending IP request" : "new IP";
                            audit.log(uuid, account.role(), SecurityEventType.VERIFICATION_CREATED, "SUCCESS", reason, created.sessionId(), ipHash);
                        });
                        return session.map(Created::new);
                    });
        });
    }

    /**
     * Returns a 128-bit truncated HMAC so the Discord component custom_id stays safely below Discord's 100-char limit.
     */
    public String componentProof(VerificationSession session, String action) {
        String full = SecurityUtil.hmacSha256Hex(serverSecret, action + ":" + session.sessionId() + ":" + session.tokenHash());
        return full.substring(0, 32);
    }

    public CompletableFuture<Optional<VerificationSession>> approve(UUID sessionId, String actionProof, String actor) {
        if (actionProof == null || actionProof.isBlank()) return CompletableFuture.completedFuture(Optional.empty());
        return db.findSession(sessionId).thenCompose(found -> {
            if (found.isEmpty()) return CompletableFuture.completedFuture(Optional.empty());
            VerificationSession session = found.get();
            if (!session.pendingAndUnexpired(System.currentTimeMillis())
                    || !SecurityUtil.constantTimeEquals(componentProof(session, "a"), actionProof)) {
                ProtectedAccount account = accounts.getCached(session.uuid());
                audit.log(session.uuid(), account == null ? null : account.role(), SecurityEventType.AUTH_FAILURE,
                        "DENIED", "invalid verification proof", sessionId, null);
                return CompletableFuture.completedFuture(Optional.empty());
            }
            return db.approveSession(sessionId, actor, System.currentTimeMillis(), cfg.maxTrustedIps())
                    .thenCompose(result -> {
                        if (result.isEmpty()) return CompletableFuture.completedFuture(Optional.empty());
                        ProtectedAccount account = accounts.getCached(session.uuid());
                        Role role = account == null ? null : account.role();
                        return ips.load(List.of(session.uuid()))
                                .thenApply(v -> {
                                    // Database.approveSession() atomically persisted the new trusted IP
                                    // and removed the AP-StaffGuard ban. Synchronize in-memory caches only
                                    // after that transaction has committed successfully.
                                    ips.markTrustedHash(session.uuid(), session.ipHash());
                                    bans.markManagedBanRemoved(session.uuid());
                                    audit.log(session.uuid(), role, SecurityEventType.VERIFICATION_APPROVED, "SUCCESS", "Discord approval", sessionId, session.ipHash());
                                    audit.log(session.uuid(), role, SecurityEventType.TRUSTED_IP_ADDED, "SUCCESS", "verification approval", sessionId, session.ipHash());
                                    audit.log(session.uuid(), role, SecurityEventType.TEMPBAN_REMOVED, "SUCCESS", "verification approval", sessionId, null);
                                    return result;
                                });
                    });
        });
    }

    public CompletableFuture<Optional<VerificationSession>> denyWithProof(UUID id, String proof, String actor, String action) {
        return db.findSession(id).thenCompose(found -> {
            if (found.isEmpty()) return CompletableFuture.completedFuture(Optional.empty());
            VerificationSession session = found.get();
            if (!session.pendingAndUnexpired(System.currentTimeMillis())
                    || !SecurityUtil.constantTimeEquals(componentProof(session, action), proof)) {
                ProtectedAccount a = accounts.getCached(session.uuid());
                audit.log(session.uuid(), a == null ? null : a.role(), SecurityEventType.AUTH_FAILURE,
                        "DENIED", "invalid verification denial proof", id, null);
                return CompletableFuture.completedFuture(Optional.empty());
            }
            return db.consumeSession(id, VerificationState.DENIED, actor).thenApply(o -> {
                o.ifPresent(s -> {
                    ProtectedAccount a = accounts.getCached(s.uuid());
                    if (a != null) audit.log(s.uuid(), a.role(), SecurityEventType.VERIFICATION_DENIED, "SUCCESS", "discord denial", id, null);
                });
                return o;
            });
        });
    }

    public CompletableFuture<Boolean> revoke(UUID id, String actor) {
        return db.findSession(id)
                .thenCompose(o -> o.map(s -> db.consumeSession(id, VerificationState.REVOKED, actor).thenApply(Optional::isPresent))
                        .orElseGet(() -> CompletableFuture.completedFuture(false)));
    }

    public CompletableFuture<Optional<VerificationSession>> getSession(UUID sessionId) {
        return db.findSession(sessionId);
    }

    public CompletableFuture<Integer> expireForAccount(UUID uuid) {
        return db.expirePendingForUuid(uuid);
    }

    public CompletableFuture<Integer> expire() {
        return db.expireSessions();
    }

    public void cleanupRateLimiters() {
        accountLimiter.cleanup();
        ipLimiter.cleanup();
    }

    public void shutdown() {
        cleanupRateLimiters();
    }
}
