package com.anpahn.staffguard.listeners;

import com.anpahn.staffguard.StaffGuardPlugin;
import com.anpahn.staffguard.model.ProtectedAccount;
import com.anpahn.staffguard.model.SecurityEventType;
import com.anpahn.staffguard.util.ClientIpResolver;
import org.bukkit.event.EventHandler;
import org.bukkit.event.EventPriority;
import org.bukkit.event.Listener;
import org.bukkit.event.player.AsyncPlayerPreLoginEvent;

import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

public final class LoginListener implements Listener {
    private final StaffGuardPlugin plugin;
    private final ClientIpResolver resolver;

    public LoginListener(StaffGuardPlugin plugin) { this.plugin=plugin; this.resolver=new ClientIpResolver(plugin.config()); }

    @EventHandler(priority=EventPriority.LOWEST)
    public void onPreLogin(AsyncPlayerPreLoginEvent event) {
        var uuid=event.getUniqueId();
        if (plugin.config() == null || !plugin.config().securityEnabled()) return;
        ProtectedAccount account=plugin.accounts()==null?null:plugin.accounts().getCached(uuid);
        if (account==null || !account.active()) return;
        if (!plugin.securityState().isReady()) {
            deny(event,plugin.config().securityUnavailableMessage());
            plugin.audit().log(uuid,account.role(),SecurityEventType.AUTH_FAILURE,"DENIED","security backend not ready",null,null);
            return;
        }
        ClientIpResolver.Resolution resolved=resolver.resolve(event);
        if (!resolved.valid()) {
            deny(event,plugin.config().securityUnavailableMessage());
            plugin.audit().log(uuid,account.role(),SecurityEventType.AUTH_FAILURE,"DENIED",resolved.reason(),null,null);
            return;
        }
        String ip=resolved.ip();
        String ipHash=plugin.ips().hash(ip);
        try {
            boolean trusted=plugin.db().authorizeTrustedLogin(uuid,ipHash,System.currentTimeMillis()).get(3,TimeUnit.SECONDS);
            if (trusted) {
                plugin.accounts().refresh(uuid);
                plugin.audit().log(uuid,account.role(),SecurityEventType.LOGIN_ATTEMPT,"ALLOWED","trusted IP",null,plugin.config().privacy().redactIpInCommandAudit()?null:ipHash);
                return;
            }
            plugin.audit().log(uuid,account.role(),SecurityEventType.NEW_IP,"DENIED","untrusted IP",null,ipHash);
            if (plugin.lockdown().isEnabled()) {
                deny(event,plugin.config().lockdownMessage());
                plugin.audit().log(uuid,account.role(),SecurityEventType.LOCKDOWN_ENABLED,"DENIED","new IP during lockdown",null,ipHash);
                return;
            }
            var created=plugin.verification().create(uuid,ip).get(3,TimeUnit.SECONDS).orElse(null);
            if(created==null){
                deny(event,plugin.config().differentIpMessage());
                return;
            }
            // Discord is deliberately not on the critical login path. The session + managed block are DB-backed before denial.
            plugin.accounts().find(uuid).whenComplete((current,error)->{
                if(error!=null || current==null || !current.active()) {
                    if(error!=null) plugin.getLogger().warning("Could not refresh protected account before verification notification: "+error.getMessage());
                    return;
                }
                plugin.discord().sendVerification(current,ip,created).whenComplete((sent,sendError)->{
                    if(sendError!=null) plugin.getLogger().warning("Verification notification failed: "+sendError.getMessage());
                    if(Boolean.FALSE.equals(sent)) plugin.audit().log(uuid,current.role(),SecurityEventType.AUTH_FAILURE,"DENIED","Discord notification unavailable",created.session().sessionId(),ipHash);
                });
            });
            deny(event,plugin.config().differentIpMessage());
        } catch (TimeoutException ex) {
            deny(event,plugin.config().securityUnavailableMessage());
            plugin.audit().log(uuid,account.role(),SecurityEventType.AUTH_FAILURE,"DENIED","security operation timeout",null,null);
        } catch (Exception ex) {
            plugin.getLogger().log(java.util.logging.Level.SEVERE,"Protected login processing failed for "+uuid,ex);
            deny(event,plugin.config().securityUnavailableMessage());
            plugin.audit().log(uuid,account.role(),SecurityEventType.AUTH_FAILURE,"DENIED","security operation failure",null,null);
        }
    }

    private static void deny(AsyncPlayerPreLoginEvent event,String message){event.disallow(AsyncPlayerPreLoginEvent.Result.KICK_OTHER,message);}
}
