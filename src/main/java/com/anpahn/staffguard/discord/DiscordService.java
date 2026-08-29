package com.anpahn.staffguard.discord;

import com.anpahn.staffguard.config.StaffGuardConfig;
import com.anpahn.staffguard.model.ProtectedAccount;
import com.anpahn.staffguard.model.VerificationSession;
import com.anpahn.staffguard.security.RateLimiter;
import com.anpahn.staffguard.service.VerificationService;
import net.dv8tion.jda.api.EmbedBuilder;
import net.dv8tion.jda.api.JDA;
import net.dv8tion.jda.api.JDABuilder;
import net.dv8tion.jda.api.components.actionrow.ActionRow;
import net.dv8tion.jda.api.components.buttons.Button;
import net.dv8tion.jda.api.entities.channel.concrete.TextChannel;
import net.dv8tion.jda.api.events.interaction.component.ButtonInteractionEvent;
import net.dv8tion.jda.api.hooks.ListenerAdapter;

import java.awt.Color;
import java.time.Duration;
import java.time.Instant;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicReference;
import java.util.logging.Level;
import java.util.logging.Logger;

public final class DiscordService extends ListenerAdapter implements AutoCloseable {
    private final StaffGuardConfig cfg;
    private final VerificationService verification;
    private final RateLimiter<String> interactionLimiter;
    private final Logger logger;
    private final ExecutorService startupExecutor=Executors.newSingleThreadExecutor(r->{Thread t=new Thread(r,"AP-StaffGuard-Discord-Startup");t.setDaemon(true);return t;});
    private final AtomicReference<CompletableFuture<Boolean>> startupFuture=new AtomicReference<>();
    private volatile JDA jda;

    public DiscordService(StaffGuardConfig cfg,VerificationService verification,Logger logger){this.cfg=cfg;this.verification=verification;this.logger=logger;this.interactionLimiter=new RateLimiter<>(cfg.maxDiscordInteractionsPerMinute(),Duration.ofMinutes(1),4096);}

    public CompletableFuture<Boolean> start(){
        if(!cfg.discordEnabled())return CompletableFuture.completedFuture(true);
        CompletableFuture<Boolean> existing=startupFuture.get(); if(existing!=null&&!existing.isDone())return existing;
        CompletableFuture<Boolean> future=CompletableFuture.supplyAsync(()->{
            JDA local=null;
            try{
                String token=resolveToken(); if(token.isBlank())return false;
                local=JDABuilder.createDefault(token).addEventListeners(this).build();
                local.awaitReady();
                TextChannel channel=local.getTextChannelById(cfg.discordChannelId());
                if(channel==null)throw new IllegalStateException("Configured verification channel is unavailable");
                jda=local;logger.info("Discord verification connected. Channel="+channel.getId());return true;
            }catch(Exception ex){
                if(local!=null)try{local.shutdownNow();}catch(Exception ignored){}
                jda=null;logger.log(Level.SEVERE,"Discord verification failed to start",ex);return false;
            }
        },startupExecutor);
        if(!startupFuture.compareAndSet(existing,future))return startupFuture.get();
        future.whenComplete((v,e)->{if(startupFuture.get()==future)startupFuture.set(null);});
        return future;
    }

    private String resolveToken(){return cfg.discordToken()==null?"":cfg.discordToken().trim();}

    public CompletableFuture<Boolean> sendVerification(ProtectedAccount account,String ip,VerificationService.Created created){
        JDA local=jda;if(local==null)return CompletableFuture.completedFuture(false);
        UUID sid=created.session().sessionId();
        return verification.claimNotification(sid).thenCompose(claimed->{
            if(claimed.isEmpty())return CompletableFuture.completedFuture(true); // cooldown/upper bound: no duplicate message
            VerificationSession session=claimed.get();
            String approveProof=verification.componentProof(session,"a");
            String denyProof=verification.componentProof(session,"d");
            String displayIp=cfg.maskIpInDiscord()?com.anpahn.staffguard.util.SecurityUtil.maskIp(ip):ip;
            EmbedBuilder embed=buildVerificationEmbed(account,displayIp,session);
            ActionRow controls=ActionRow.of(Button.success("sg:a:"+sid+":"+approveProof,cfg.verificationEmbed().approveButton()),Button.danger("sg:d:"+sid+":"+denyProof,cfg.verificationEmbed().denyButton()));
            TextChannel channel=local.getTextChannelById(cfg.discordChannelId());
            if(channel==null)return CompletableFuture.completedFuture(false);
            return channel.sendMessageEmbeds(embed.build()).setComponents(controls).submit().thenApply(m->{
                if(cfg.discordSendDm())sendDmIfEnabled(account,embed,controls,sid.toString());
                return true;
            }).exceptionally(ex->{logger.log(Level.WARNING,"Failed to send verification message to Discord for "+sid,ex);return false;});
        });
    }

    private CompletableFuture<Boolean> sendDmIfEnabled(ProtectedAccount account,EmbedBuilder embed,ActionRow controls,String sid){
        if(!cfg.discordSendDm()||jda==null)return CompletableFuture.completedFuture(false);
        return jda.retrieveUserById(account.discordId()).submit().thenCompose(user->user.openPrivateChannel().submit()).thenCompose(ch->ch.sendMessageEmbeds(embed.build()).setComponents(controls).submit()).thenApply(m->true).exceptionally(ex->{logger.log(Level.WARNING,"Could not DM Discord user for verification "+sid,ex);return false;});
    }

    private EmbedBuilder buildVerificationEmbed(ProtectedAccount account,String displayIp,VerificationSession session){
        StaffGuardConfig.VerificationEmbedConfig e=cfg.verificationEmbed();
        return new EmbedBuilder().setTitle(e.title()).setColor(new Color(e.color())).setDescription(e.description())
                .addField(e.minecraftField(),account.username(),true).addField(e.roleField(),account.role().name(),true).addField(e.ipField(),displayIp,true)
                .addField(e.verificationField(),session.sessionId().toString(),false).addField(e.expiryField(),relative(session.expiresAt()),true)
                .addField(e.serverField(),cfg.serverName(),true).setFooter(e.footer()).setTimestamp(Instant.now());
    }

    public CompletableFuture<Boolean> logCommandAudit(String sender,String command,String permission,String source,boolean dangerous,String serverName,String channelId){
        JDA local=jda;if(local==null||!cfg.commandAudit().enabled()||channelId==null||channelId.isBlank())return CompletableFuture.completedFuture(false);
        TextChannel channel=local.getTextChannelById(channelId);if(channel==null)return CompletableFuture.completedFuture(false);
        StaffGuardConfig.CommandAuditEmbedConfig e=cfg.commandAuditEmbed();
        String bounded=command.length()>1000?command.substring(0,997)+"...":command;
        EmbedBuilder embed=new EmbedBuilder().setTitle(e.title()).setColor(new Color(dangerous?e.dangerColor():e.safeColor())).setDescription(e.description())
                .addField(e.commandField(),bounded,false).addField(e.senderField(),bound(sender,256),true).addField(e.permissionField(),bound(permission,256),true)
                .addField(e.serverField(),bound(serverName,256),true).addField(e.channelField(),bound(source,256),true).setFooter(e.footer()).setTimestamp(Instant.now());
        return channel.sendMessageEmbeds(embed.build()).submit().thenApply(m->true).exceptionally(ex->{logger.log(Level.WARNING,"Failed to send command audit embed",ex);return false;});
    }

    @Override public void onButtonInteraction(ButtonInteractionEvent event){
        String id=event.getComponentId();if(id==null||!id.startsWith("sg:"))return;
        String userId=event.getUser().getId();if(!interactionLimiter.tryAcquire(userId)){event.reply("🚨 Quá nhiều thao tác xác thực. Vui lòng thử lại sau.").setEphemeral(true).queue();return;}
        String[] parts=id.split(":",4);if(parts.length!=4||!(parts[1].equals("a")||parts[1].equals("d"))){event.reply("❌ Verification không hợp lệ.").setEphemeral(true).queue();return;}
        UUID sessionId;try{sessionId=UUID.fromString(parts[2]);}catch(IllegalArgumentException ex){event.reply("❌ Verification không hợp lệ.").setEphemeral(true).queue();return;}
        if(parts[3].length()<16||parts[3].length()>128){event.reply("❌ Verification không hợp lệ.").setEphemeral(true).queue();return;}
        final String action=parts[1],proof=parts[3];
        verification.getSession(sessionId).whenComplete((found,error)->{
            if(error!=null){event.reply("❌ Không thể kiểm tra verification. Vui lòng thử lại sau.").setEphemeral(true).queue();return;}
            if(found.isEmpty()||!found.get().pendingAndUnexpired(System.currentTimeMillis())){event.reply("❌ Verification không tồn tại hoặc đã hết hạn/được xử lý.").setEphemeral(true).queue();return;}
            VerificationSession session=found.get();
            boolean configuredChannel=event.isFromGuild()&&event.getChannel().getId().equals(cfg.discordChannelId());
            boolean ownDm=!event.isFromGuild()&&session.discordId().equals(userId);
            if(!configuredChannel&&!ownDm){event.reply("⛔ Context verification không hợp lệ.").setEphemeral(true).queue();return;}
            // Service performs the authoritative actor/account/generation check again inside the DB transition.
            event.deferReply(true).queue(hook->{
                CompletableFuture<?> result=action.equals("a")?verification.approve(sessionId,proof,userId):verification.denyWithProof(sessionId,proof,userId,"d");
                result.whenComplete((value,ex)->{
                    if(ex!=null){logger.log(Level.SEVERE,"Discord verification action failed for "+sessionId,unwrap(ex));editHook(hook,"❌ Lỗi hệ thống. Verification không được approve.");return;}
                    boolean ok=value instanceof java.util.Optional<?> o&&o.isPresent();
                    editHook(hook,ok?(action.equals("a")?"✅ Đã xác minh thành công. Hãy đăng nhập lại bằng IP này.":"❌ Đã từ chối. IP mới không được trusted."):"❌ Verification đã được xử lý, hết hạn hoặc không còn hợp lệ.");
                });
            },ex->logger.log(Level.WARNING,"Failed to defer Discord interaction",ex));
        });
    }

    private static String bound(String v,int max){if(v==null)return "";return v.length()>max?v.substring(0,max-3)+"...":v;}
    private void editHook(net.dv8tion.jda.api.interactions.InteractionHook hook,String content){hook.editOriginal(content).queue(null,ex->logger.log(Level.WARNING,"Failed to edit Discord response",ex));}
    private static String relative(long epoch){return "~"+Math.max(0,(epoch-System.currentTimeMillis())/1000)+" giây";}
    private static Throwable unwrap(Throwable error){return error instanceof java.util.concurrent.CompletionException&&error.getCause()!=null?error.getCause():error;}
    public boolean isConnected(){return jda!=null;}
    public void cleanupRateLimiter(){interactionLimiter.cleanup();}
    public synchronized void shutdown(){JDA local=jda;jda=null;if(local!=null)try{local.shutdownNow();}catch(Exception ignored){}CompletableFuture<Boolean> f=startupFuture.getAndSet(null);if(f!=null&&!f.isDone())f.cancel(true);interactionLimiter.cleanup();startupExecutor.shutdownNow();}
    @Override public void close(){shutdown();}
}
