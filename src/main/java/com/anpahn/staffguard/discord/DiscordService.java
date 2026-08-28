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
import net.dv8tion.jda.api.entities.User;
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
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.logging.Level;
import java.util.logging.Logger;

public final class DiscordService extends ListenerAdapter implements AutoCloseable {
    private final StaffGuardConfig cfg;
    private final VerificationService verification;
    private final AtomicBoolean started = new AtomicBoolean(false);
    private final RateLimiter<String> interactionLimiter;
    private final Logger logger;
    private final ExecutorService startupExecutor = Executors.newSingleThreadExecutor(r -> {
        Thread t = new Thread(r, "AP-StaffGuard-Discord-Startup");
        t.setDaemon(true);
        return t;
    });
    private volatile JDA jda;

    public DiscordService(StaffGuardConfig cfg, VerificationService verification, Logger logger) {
        this.cfg = cfg;
        this.verification = verification;
        this.logger = logger;
        this.interactionLimiter = new RateLimiter<>(cfg.maxDiscordInteractionsPerMinute(), Duration.ofMinutes(1));
    }

    public CompletableFuture<Boolean> start() {
        if (!cfg.discordEnabled()) return CompletableFuture.completedFuture(true);
        if (cfg.discordChannelId().isBlank()) return CompletableFuture.completedFuture(false);
        String token = resolveToken();
        if (token.isBlank()) return CompletableFuture.completedFuture(false);
        return CompletableFuture.supplyAsync(() -> {
            if (!started.compareAndSet(false, true)) return jda != null;
            try {
                JDA local = JDABuilder.createDefault(token).addEventListeners(this).build();
                local.awaitReady();
                TextChannel channel = local.getTextChannelById(cfg.discordChannelId());
                if (channel == null) throw new IllegalStateException("Configured verification channel is unavailable");
                jda = local;
                logger.info("Discord verification connected. Channel=" + channel.getId());
                return true;
            } catch (Exception ex) {
                started.set(false);
                jda = null;
                logger.log(Level.SEVERE, "Discord verification failed to start", ex);
                return false;
            }
        }, startupExecutor);
    }

    private String resolveToken() { return cfg.discordToken() == null ? "" : cfg.discordToken().trim(); }

    public CompletableFuture<Boolean> sendVerification(ProtectedAccount account, String ip, VerificationService.Created created) {
        JDA local = jda;
        if (local == null) return CompletableFuture.completedFuture(false);
        VerificationSession session = created.session();
        String sid = session.sessionId().toString();
        String approveProof = verification.componentProof(session, "a");
        String denyProof = verification.componentProof(session, "d");
        String displayIp = cfg.maskIpInDiscord() ? com.anpahn.staffguard.util.SecurityUtil.maskIp(ip) : ip;
        EmbedBuilder embed = buildVerificationEmbed(account, displayIp, session);
        ActionRow controls = ActionRow.of(
                Button.success("sg:a:" + sid + ":" + approveProof, cfg.verificationEmbed().approveButton()),
                Button.danger("sg:d:" + sid + ":" + denyProof, cfg.verificationEmbed().denyButton())
        );
        TextChannel channel = local.getTextChannelById(cfg.discordChannelId());
        CompletableFuture<Boolean> channelFuture = channel == null ? CompletableFuture.completedFuture(false)
                : channel.sendMessageEmbeds(embed.build()).setComponents(controls).submit().thenApply(message -> true)
                .exceptionally(ex -> { logger.log(Level.WARNING, "Failed to send verification message to Discord channel for " + sid, ex); return false; });
        return channelFuture.thenApply(channelSent -> {
            if (!channelSent) return false;
            if (cfg.discordSendDm()) {
                sendDmIfEnabled(account, embed, controls, sid).thenAccept(dmSent -> {
                    if (!dmSent) logger.warning("Verification DM failed for " + sid);
                });
            }
            return true;
        });
    }

    private CompletableFuture<Boolean> sendDmIfEnabled(ProtectedAccount account, EmbedBuilder embed, ActionRow controls, String sid) {
        if (!cfg.discordSendDm() || jda == null) return CompletableFuture.completedFuture(false);
        return jda.retrieveUserById(account.discordId()).submit()
                .thenCompose(user -> user.openPrivateChannel().submit())
                .thenCompose(channel -> channel.sendMessageEmbeds(embed.build()).setComponents(controls).submit())
                .thenApply(message -> true)
                .exceptionally(ex -> { logger.log(Level.WARNING, "Could not DM Discord user for verification " + sid, ex); return false; });
    }

    private EmbedBuilder buildVerificationEmbed(ProtectedAccount account, String displayIp, VerificationSession session) {
        StaffGuardConfig.VerificationEmbedConfig e = cfg.verificationEmbed();
        return new EmbedBuilder()
                .setTitle(e.title())
                .setColor(new Color(e.color()))
                .setDescription(e.description())
                .addField(e.minecraftField(), account.username(), true)
                .addField(e.roleField(), account.role().name(), true)
                .addField(e.ipField(), displayIp, true)
                .addField(e.verificationField(), session.sessionId().toString(), false)
                .addField(e.expiryField(), relative(session.expiresAt()), true)
                .addField(e.serverField(), cfg.serverName(), true)
                .setFooter(e.footer())
                .setTimestamp(Instant.now());
    }

    public CompletableFuture<Boolean> logCommandAudit(String sender, String command, String permission, String source, boolean dangerous, String serverName, String channelId) {
        JDA local = jda;
        if (local == null || !cfg.commandAudit().enabled() || channelId == null || channelId.isBlank()) return CompletableFuture.completedFuture(false);
        TextChannel channel = local.getTextChannelById(channelId);
        if (channel == null) return CompletableFuture.completedFuture(false);
        StaffGuardConfig.CommandAuditEmbedConfig e = cfg.commandAuditEmbed();
        EmbedBuilder embed = new EmbedBuilder()
                .setTitle(e.title())
                .setColor(new Color(dangerous ? e.dangerColor() : e.safeColor()))
                .setDescription(e.description())
                .addField(e.commandField(), command, false)
                .addField(e.senderField(), sender, true)
                .addField(e.permissionField(), permission, true)
                .addField(e.serverField(), serverName, true)
                .addField(e.channelField(), source, true)
                .setFooter(e.footer())
                .setTimestamp(Instant.now());
        return channel.sendMessageEmbeds(embed.build()).submit().thenApply(message -> true)
                .exceptionally(ex -> { logger.log(Level.WARNING, "Failed to send command audit embed", ex); return false; });
    }

    @Override
    public void onButtonInteraction(ButtonInteractionEvent event) {
        String componentId = event.getComponentId();
        if (!componentId.startsWith("sg:")) return;
        event.deferReply(true).queue(hook -> {
            String[] parts = componentId.split(":", 4);
            if (parts.length != 4 || !(parts[1].equals("a") || parts[1].equals("d"))) { hook.editOriginal("❌ Verification không hợp lệ.").queue(); return; }
            UUID sessionId;
            try { sessionId = UUID.fromString(parts[2]); } catch (IllegalArgumentException ex) { hook.editOriginal("❌ Verification không hợp lệ.").queue(); return; }
            final String action = parts[1];
            final String proof = parts[3];
            final String discordId = event.getUser().getId();
            if (!interactionLimiter.tryAcquire(discordId)) { hook.editOriginal("🚨 Quá nhiều thao tác xác thực. Vui lòng thử lại sau.").queue(); return; }
            verification.getSession(sessionId).whenComplete((found, lookupError) -> {
                if (lookupError != null) { logger.log(Level.WARNING, "Failed to load verification session " + sessionId, unwrap(lookupError)); editHook(hook, "❌ Không thể kiểm tra verification. Vui lòng thử lại sau."); return; }
                if (found.isEmpty()) { editHook(hook, "❌ Verification không tồn tại hoặc đã hết hạn."); return; }
                VerificationSession session = found.get();
                if (!session.pendingAndUnexpired(System.currentTimeMillis())) { editHook(hook, "❌ Verification đã hết hạn hoặc đã được xử lý."); return; }
                boolean inConfiguredChannel = event.isFromGuild() && event.getChannel().getId().equals(cfg.discordChannelId());
                boolean inOwnDm = !event.isFromGuild() && session.discordId().equals(discordId);
                if (!inConfiguredChannel && !inOwnDm) { editHook(hook, "⛔ Nút xác thực này chỉ hoạt động trong kênh StaffGuard đã cấu hình hoặc DM của chính tài khoản được yêu cầu xác thực."); return; }
                boolean owner = cfg.isDiscordOwner(discordId);
                boolean staffOwnRequest = cfg.isDiscordStaff(discordId) && session.discordId().equals(discordId) && cfg.discordAllowSelfApproval();
                boolean linkedSelf = cfg.discordAllowSelfApproval() && session.discordId().equals(discordId);
                if (!(owner || staffOwnRequest || linkedSelf)) { editHook(hook, "⛔ Bạn không được cấp quyền xử lý verification này."); return; }
                CompletableFuture<?> result = action.equals("a") ? verification.approve(sessionId, proof, discordId) : verification.denyWithProof(sessionId, proof, discordId, "d");
                result.whenComplete((value, error) -> {
                    if (error != null) { logger.log(Level.SEVERE, "Discord verification interaction failed for session " + sessionId, unwrap(error)); editHook(hook, "❌ Có lỗi hệ thống. Vui lòng kiểm tra log server."); }
                    else if (value instanceof java.util.Optional<?> optional && optional.isPresent()) editHook(hook, action.equals("a") ? "✅ Đã xác minh thành công. IP mới đã được trusted và ban StaffGuard đã được gỡ. Hãy đăng nhập lại bằng IP này." : "❌ Đã từ chối. IP mới không được trusted và vẫn bị chặn.");
                    else editHook(hook, "❌ Verification không hợp lệ, đã hết hạn hoặc đã được xử lý.");
                });
            });
        }, ex -> logger.log(Level.WARNING, "Failed to defer Discord interaction", ex));
    }

    private void editHook(net.dv8tion.jda.api.interactions.InteractionHook hook, String content) { hook.editOriginal(content).queue(null, ex -> logger.log(Level.WARNING, "Failed to edit Discord interaction response", ex)); }
    private static String relative(long epoch) { long seconds = Math.max(0, (epoch - System.currentTimeMillis()) / 1000); return "~" + seconds + " giây"; }
    private static Throwable unwrap(Throwable error) { return error instanceof java.util.concurrent.CompletionException && error.getCause() != null ? error.getCause() : error; }
    public boolean isConnected() { return jda != null; }
    public void cleanupRateLimiter() { interactionLimiter.cleanup(); }
    public void shutdown() { JDA local = jda; jda = null; started.set(false); if (local != null) local.shutdownNow(); interactionLimiter.cleanup(); startupExecutor.shutdownNow(); }
    @Override public void close() { shutdown(); }
}
