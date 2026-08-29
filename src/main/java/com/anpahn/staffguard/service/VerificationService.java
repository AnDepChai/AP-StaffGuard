package com.anpahn.staffguard.service;

import com.anpahn.staffguard.config.StaffGuardConfig;
import com.anpahn.staffguard.database.Database;
import com.anpahn.staffguard.model.*;
import com.anpahn.staffguard.security.CompositeRateLimiter;
import com.anpahn.staffguard.security.LockdownManager;
import com.anpahn.staffguard.util.SecurityUtil;

import java.time.Duration;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;

public final class VerificationService {
    public record Created(VerificationSession session) {}

    private final Database db;
    private final AccountService accounts;
    private final TrustedIpService ips;
    private final AuditService audit;
    private final StaffGuardConfig cfg;
    private final LockdownManager lockdown;
    private final byte[] serverSecret;
    private final CompositeRateLimiter requestLimiter;

    public VerificationService(Database db, AccountService accounts, TrustedIpService ips, AuditService audit,
                               StaffGuardConfig cfg, LockdownManager lockdown, byte[] serverSecret) {
        this.db=db;this.accounts=accounts;this.ips=ips;this.audit=audit;this.cfg=cfg;this.lockdown=lockdown;this.serverSecret=serverSecret.clone();
        this.requestLimiter=new CompositeRateLimiter(cfg.maxVerificationRequestsAccount(),cfg.maxVerificationRequestsIp(),Duration.ofMinutes(10),Math.max(128,cfg.maxPendingSessions()*4));
    }

    public CompletableFuture<Optional<Created>> create(UUID uuid, String ip) {
        if (lockdown.isEnabled()) return CompletableFuture.completedFuture(Optional.empty());
        return accounts.find(uuid).thenCompose(account -> {
            if (account == null || !account.active()) return CompletableFuture.completedFuture(Optional.empty());
            String ipHash=ips.hash(ip);
            return db.findPendingSession(uuid).thenCompose(existing -> {
                if (existing.isPresent()) {
                    VerificationSession s=existing.get();
                    if (s.accountGeneration()==account.securityGeneration() && s.discordId().equals(account.discordId()) && s.ipHash().equals(ipHash)) {
                        audit.log(uuid,account.role(),SecurityEventType.VERIFICATION_CREATED,"SUCCESS","reused pending verification",s.sessionId(),ipHash);
                        return CompletableFuture.completedFuture(Optional.of(new Created(s)));
                    }
                }
                CompositeRateLimiter.Reservation reservation=requestLimiter.tryReserve(uuid,ip);
                if (!reservation.accepted()) {
                    audit.log(uuid,account.role(),SecurityEventType.RATE_LIMIT,"DENIED","verification rate limit",null,ipHash);
                    return CompletableFuture.completedFuture(Optional.empty());
                }
                String rawToken=SecurityUtil.randomToken(cfg.tokenBytes());
                String tokenHash=SecurityUtil.sha256Hex(rawToken);
                long now=System.currentTimeMillis();
                long expires=now+cfg.verificationTimeout().toMillis();
                return db.createVerificationSession(uuid,account.discordId(),ipHash,tokenHash,now,expires,cfg.maxPendingSessions(),now+cfg.temporaryBanDuration().toMillis())
                        .handle((result,error)->{
                            if(error!=null || result.isEmpty()) { reservation.rollback(); if(error!=null) audit.log(uuid,account.role(),SecurityEventType.AUTH_FAILURE,"FAILED","verification session creation failed",null,ipHash); return Optional.<Created>empty(); }
                            reservation.commit();
                            VerificationSession s=result.get();
                            audit.log(uuid,account.role(),SecurityEventType.VERIFICATION_CREATED,"SUCCESS","new verification session",s.sessionId(),ipHash);
                            return Optional.of(new Created(s));
                        });
            });
        });
    }

    public String componentProof(VerificationSession session, String action) {
        String full=SecurityUtil.hmacSha256Hex(serverSecret,action+":"+session.sessionId()+":"+session.tokenHash());
        return full.substring(0,32);
    }

    public CompletableFuture<Optional<VerificationSession>> approve(UUID sessionId,String actionProof,String actor) {
        if(actionProof==null||actionProof.isBlank()) return CompletableFuture.completedFuture(Optional.empty());
        return db.findSession(sessionId).thenCompose(found-> {
            if(found.isEmpty()) return CompletableFuture.completedFuture(Optional.empty());
            VerificationSession session=found.get();
            if(!session.pendingAndUnexpired(System.currentTimeMillis()) || !SecurityUtil.constantTimeEquals(componentProof(session,"a"),actionProof)) {
                audit.log(session.uuid(),null,SecurityEventType.AUTH_FAILURE,"DENIED","invalid verification proof",sessionId,null);
                return CompletableFuture.completedFuture(Optional.empty());
            }
            return db.findAccount(session.uuid()).thenCompose(accountOpt->{
                if(accountOpt.isEmpty() || !accountOpt.get().active() || !authorizedApprover(accountOpt.get(),actor)) return CompletableFuture.completedFuture(Optional.empty());
                return db.approveSession(sessionId,actor,System.currentTimeMillis(),cfg.maxTrustedIps()).thenApply(result->{
                    result.ifPresent(s->audit.log(s.uuid(),accountOpt.get().role(),SecurityEventType.VERIFICATION_APPROVED,"SUCCESS","Discord approval",sessionId,s.ipHash()));
                    return result;
                });
            });
        });
    }

    public CompletableFuture<Optional<VerificationSession>> denyWithProof(UUID id,String proof,String actor,String action) {
        if(proof==null||proof.isBlank()) return CompletableFuture.completedFuture(Optional.empty());
        return db.findSession(id).thenCompose(found->{
            if(found.isEmpty()) return CompletableFuture.completedFuture(Optional.empty());
            VerificationSession session=found.get();
            if(!session.pendingAndUnexpired(System.currentTimeMillis()) || !SecurityUtil.constantTimeEquals(componentProof(session,action),proof)) return CompletableFuture.completedFuture(Optional.empty());
            return db.findAccount(session.uuid()).thenCompose(accountOpt->{
                if(accountOpt.isEmpty() || !accountOpt.get().active() || !authorizedApprover(accountOpt.get(),actor)) return CompletableFuture.completedFuture(Optional.empty());
                return db.consumeSession(id,VerificationState.DENIED,actor).thenApply(result->{
                    result.ifPresent(s->audit.log(s.uuid(),accountOpt.get().role(),SecurityEventType.VERIFICATION_DENIED,"SUCCESS","Discord denial",id,null));
                    return result;
                });
            });
        });
    }

    private boolean authorizedApprover(ProtectedAccount account,String actor) {
        if(cfg.isDiscordOwner(actor)) return true;
        return cfg.discordAllowSelfApproval() && cfg.isDiscordStaff(actor) && account.discordId().equals(actor);
    }

    public CompletableFuture<Optional<VerificationSession>> claimNotification(UUID sessionId) {
        return db.claimNotification(sessionId,System.currentTimeMillis(),cfg.verificationNotificationCooldown().toMillis(),cfg.maxVerificationNotifications());
    }

    public CompletableFuture<Boolean> revoke(UUID id,String actor) {
        return db.consumeSession(id,VerificationState.REVOKED,actor).thenApply(Optional::isPresent);
    }
    public CompletableFuture<Optional<VerificationSession>> getSession(UUID sessionId){return db.findSession(sessionId);}
    public CompletableFuture<Integer> expireForAccount(UUID uuid){return db.expirePendingForUuid(uuid,"system:account-reset");}
    public CompletableFuture<Integer> expire(){return db.expireSessions();}
    public void cleanupRateLimiters(){requestLimiter.cleanup();}
    public void shutdown(){requestLimiter.cleanup();}
}
