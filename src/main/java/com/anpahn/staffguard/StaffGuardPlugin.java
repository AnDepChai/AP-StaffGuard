package com.anpahn.staffguard;

import com.anpahn.staffguard.commands.StaffGuardCommand;
import com.anpahn.staffguard.config.Messages;
import com.anpahn.staffguard.config.StaffGuardConfig;
import com.anpahn.staffguard.database.Database;
import com.anpahn.staffguard.discord.DiscordService;
import com.anpahn.staffguard.listeners.CommandAuditListener;
import com.anpahn.staffguard.listeners.LoginListener;
import com.anpahn.staffguard.listeners.PrivacyListener;
import com.anpahn.staffguard.security.LockdownManager;
import com.anpahn.staffguard.security.SecurityState;
import com.anpahn.staffguard.service.AccountService;
import com.anpahn.staffguard.service.AuditService;
import com.anpahn.staffguard.service.BanService;
import com.anpahn.staffguard.service.TrustedIpService;
import com.anpahn.staffguard.service.VerificationService;
import com.anpahn.staffguard.util.SecurityUtil;
import org.bukkit.Bukkit;
import org.bukkit.plugin.java.JavaPlugin;

import java.io.File;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;

public final class StaffGuardPlugin extends JavaPlugin {
    private StaffGuardConfig config;
    private Messages messages;
    private Database db;
    private AccountService accounts;
    private TrustedIpService ips;
    private BanService bans;
    private AuditService audit;
    private VerificationService verification;
    private DiscordService discord;
    private LockdownManager lockdown;
    private final SecurityState securityState=new SecurityState();
    private final ScheduledExecutorService scheduler=Executors.newSingleThreadScheduledExecutor(r->{Thread t=new Thread(r,"AP-StaffGuard-Scheduler");t.setDaemon(true);return t;});

    @Override public void onEnable(){
        securityState.set(SecurityState.Status.STARTING);
        saveDefaultConfig();
        try {
            config=StaffGuardConfig.from(getConfig());
            messages=Messages.from(getConfig());
            lockdown=new LockdownManager();

            byte[] secret=null;
            boolean secretValid=true;
            try { secret=SecurityUtil.parseServerSecret(config.serverSecretValue()); }
            catch(IllegalArgumentException ex){
                secretValid=false;
                getLogger().log(Level.SEVERE,"Invalid server-secret.value; protected accounts will remain FAIL-CLOSED until a valid persistent 256-bit secret is configured.",ex);
            }

            db=new Database(this,new File(getDataFolder(),config.databaseFile()));
            ips=secretValid ? new TrustedIpService(db,secret,config.maxTrustedIps()) : null;
            bans=new BanService(db,config.temporaryBanDuration(),getLogger());
            final TrustedIpService trustedIps=ips;
            accounts=new AccountService(db, uuid -> { if(trustedIps!=null) trustedIps.invalidate(uuid); bans.invalidate(uuid); });
            audit=new AuditService(db,getLogger());
            if(secretValid){
                verification=new VerificationService(db,accounts,ips,audit,config,lockdown,secret);
                discord=new DiscordService(config,verification,getLogger());
            }

            registerCommandsAndListeners();
            if(config.proxyMode()!=com.anpahn.staffguard.model.ProxyMode.NONE){
                getLogger().info("Proxy mode: "+config.proxyMode()+"; trusted proxy CIDRs are enforced against the raw transport address.");
                if(config.proxyMode()==com.anpahn.staffguard.model.ProxyMode.BUNGEECORD)
                    getLogger().warning("Legacy BungeeCord forwarding is not cryptographically secure. Isolate the backend and firewall it to the trusted proxy addresses.");
            }

            CompletableFuture<Void> init=db.startAsync().thenCompose(v->accounts.load()).thenCompose(v->bans.load(protectedUuids()));
            if(secretValid) init=init.thenCompose(v->ips.load(protectedUuids()));
            final boolean configurationReady=secretValid;
            init.whenComplete((ignored,error)->Bukkit.getScheduler().runTask(this,()->{
                if(error!=null){securityState.set(SecurityState.Status.FAIL_CLOSED);getLogger().log(Level.SEVERE,"AP-StaffGuard initialization failed; protected logins remain FAIL-CLOSED.",unwrap(error));return;}
                if(!configurationReady){securityState.set(SecurityState.Status.FAIL_CLOSED);getLogger().severe("AP-StaffGuard database/account inventory is loaded, but protected security operations remain FAIL-CLOSED because server-secret.value is invalid.");return;}
                securityState.set(SecurityState.Status.READY);
                if(config.discordEnabled()){
                    discord.start().whenComplete((ok,startError)->{
                        if(startError!=null||!Boolean.TRUE.equals(ok)) getLogger().warning("Discord is unavailable. Protected untrusted logins remain denied and approvals are disabled until Discord recovers.");
                    });
                }
                getLogger().info("AP-StaffGuard security backend ready. Discord availability does not weaken login authorization.");
            }));
            scheduleMaintenance();
            getLogger().info("AP-StaffGuard enabled — AnPahn");
        } catch(Exception ex){securityState.set(SecurityState.Status.FAIL_CLOSED);getLogger().log(Level.SEVERE,"AP-StaffGuard initialization failed; protected logins remain FAIL-CLOSED.",ex);}
    }

    private void registerCommandsAndListeners(){
        try{
            var command=Objects.requireNonNull(getCommand("staffguard"),"staffguard command missing from plugin.yml");
            StaffGuardCommand handler=new StaffGuardCommand(this);command.setExecutor(handler);command.setTabCompleter(handler);
            getServer().getPluginManager().registerEvents(new LoginListener(this),this);
            getServer().getPluginManager().registerEvents(new CommandAuditListener(this),this);
            getServer().getPluginManager().registerEvents(new PrivacyListener(this),this);
        }catch(Exception e){getLogger().log(Level.SEVERE,"Failed to register AP-StaffGuard command/listeners",e);securityState.set(SecurityState.Status.FAIL_CLOSED);}
    }

    private void scheduleMaintenance(){
        scheduler.scheduleAtFixedRate(()->{
            if(db==null)return;
            try{
                CompletableFuture<Integer> expired=verification==null?CompletableFuture.completedFuture(0):verification.expire();
                CompletableFuture<Void> bansFuture=db.cleanupExpiredBans();
                CompletableFuture<Integer> auditCleanup=db.cleanupAudit(config.auditRetentionDays()*24L*60L*60L*1000L);
                if(verification!=null)verification.cleanupRateLimiters(); if(discord!=null)discord.cleanupRateLimiter();
                CompletableFuture.allOf(expired,bansFuture,auditCleanup).whenComplete((v,error)->{
                    if(error!=null){securityState.set(SecurityState.Status.DEGRADED);getLogger().log(Level.WARNING,"Security maintenance entered DEGRADED; login authorization will continue using the DB-backed path and fail closed only if that path fails.",unwrap(error));}
                    else {
                        securityState.set(SecurityState.Status.READY);
                        if(discord!=null&&config.discordEnabled()&&!discord.isConnected()) discord.start();
                    }
                });
            }catch(Exception e){securityState.set(SecurityState.Status.DEGRADED);getLogger().log(Level.WARNING,"Security maintenance entered DEGRADED; login authorization will continue using the DB-backed path and fail closed only if that path fails.",e);}
        },30,30,TimeUnit.SECONDS);
    }

    private List<java.util.UUID> protectedUuids(){return accounts==null?List.of():accounts.all().stream().map(a->a.uuid()).toList();}
    private static Throwable unwrap(Throwable error){return error instanceof CompletionException&&error.getCause()!=null?error.getCause():error;}

    public CompletableFuture<Void> reloadSafely(){
        CompletableFuture<Void> result=new CompletableFuture<>();
        Bukkit.getScheduler().runTask(this,()->{
            try {
                reloadConfig();
                messages=Messages.from(getConfig());
                getLogger().info("/staffguard reload only hot-reloads messages. Security, proxy, database, secret and Discord configuration require a restart and were not applied.");
                result.complete(null);
            } catch(Exception e) {
                getLogger().log(Level.SEVERE,"Reload failed; active messages retained.",e);
                result.completeExceptionally(e);
            }
        });
        return result;
    }

    public boolean commandDependenciesReady(){return config!=null&&messages!=null&&db!=null&&accounts!=null&&ips!=null&&bans!=null&&audit!=null&&verification!=null&&discord!=null&&lockdown!=null;}
    public String safeOperationFailedMessage(){return messages==null?"§cAP-StaffGuard operation failed. Check console.":messages.operationFailed();}
    public String safeNoPermissionMessage(){return messages==null?"§cBạn không có quyền thực hiện thao tác này.":messages.noPermission();}
    @Override public void onDisable(){securityState.set(SecurityState.Status.STOPPING);scheduler.shutdownNow();if(verification!=null)verification.shutdown();if(discord!=null)discord.shutdown();if(db!=null)db.close();getLogger().info("AP-StaffGuard disabled cleanly.");}

    public StaffGuardConfig config(){return config;} public Messages messages(){return messages;} public Database db(){return db;} public AccountService accounts(){return accounts;} public TrustedIpService ips(){return ips;} public BanService banService(){return bans;} public AuditService audit(){return audit;} public VerificationService verification(){return verification;} public DiscordService discord(){return discord;} public LockdownManager lockdown(){return lockdown;} public SecurityState securityState(){return securityState;}
}
