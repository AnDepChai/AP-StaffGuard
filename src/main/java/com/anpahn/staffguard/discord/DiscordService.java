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
import java.util.logging.Level;
import java.util.logging.Logger;

public final class DiscordService extends ListenerAdapter implements AutoCloseable {
    private final StaffGuardConfig cfg;
    private final VerificationService verification;
    private final RateLimiter<String> interactionLimiter;
    private final Logger logger;
    private final ExecutorService startupExecutor = Executors.newSingleThreadExecutor(r -> {
        Thread t = new Thread(r, "AP-StaffGuard-Discord-Startup");
        t.setDaemon(true);
        return t;
    });
    private volatile CompletableFuture<Boolean> startupFuture;
    private volatile JDA jda;

    public DiscordService(StaffGuardConfig cfg, VerificationService verification, Logger logger) {
        this.cfg = cfg;
        this.verification = verification;
        this.logger = logger;
        this.interactionLimiter = new RateLimiter<>(cfg.maxDiscordInteractionsPerMinute(), Duration.ofMinutes(1), 4096);
    }

    public synchronized CompletableFuture<Boolean> start() {
        if (!cfg.discordEnabled()) return CompletableFuture.completedFuture(true);
        CompletableFuture<Boolean> existing = startupFuture;
        if (existing != null && !existing.isDone()) return existing;

        CompletableFuture<Boolean> future = CompletableFuture.supplyAsync(() -> {
            JDA local = null;
            try {
                String token = resolveToken();
                if (token.isBlank()) {
                    logger.severe("Discord verification không thể khởi động: discord.bot-token đang trống.");
                    return false;
                }
                local = JDABuilder.createDefault(token).addEventListeners(this).build();
                local.awaitReady();

                TextChannel channel = local.getTextChannelById(cfg.discordChannelId());
                if (channel == null) {
                    throw new IllegalStateException("Không tìm thấy verification channel hoặc bot không có quyền truy cập: " + cfg.discordChannelId());
                }

                jda = local;
                logger.info("✓ Discord verification đã kết nối. Channel=" + channel.getId());
                return true;
            } catch (Exception ex) {
                if (local != null) {
                    try { local.shutdownNow(); } catch (Exception ignored) { }
                }
                jda = null;
                logger.log(Level.SEVERE, "❌ Discord verification khởi động thất bại: " + safeReason(ex), ex);
                return false;
            }
        }, startupExecutor);

        startupFuture = future;
        future.whenComplete((v, e) -> {
            synchronized (DiscordService.this) {
                if (startupFuture == future) startupFuture = null;
            }
        });
        return future;
    }

    private String resolveToken() { return cfg.discordToken() == null ? "" : cfg.discordToken().trim(); }

    public CompletableFuture<Boolean> sendVerification(ProtectedAccount account, String ip, VerificationService.Created created) {
        JDA local = jda;
        if (local == null) return CompletableFuture.completedFuture(false);
        UUID sid = created.session().sessionId();
        return verification.claimNotification(sid).thenCompose(claimed -> {
            if (claimed.isEmpty()) return CompletableFuture.completedFuture(true);
            VerificationSession session = claimed.get();
            String approveProof = verification.componentProof(session, "a");
            String denyProof = verification.componentProof(session, "d");
            String displayIp = cfg.maskIpInDiscord() ? com.anpahn.staffguard.util.SecurityUtil.maskIp(ip) : ip;
            EmbedBuilder embed = buildVerificationEmbed(account, displayIp, session);
            ActionRow controls = ActionRow.of(
                    Button.success("sg:a:" + sid + ":" + approveProof, cfg.verificationEmbed().approveButton()),
                    Button.danger("sg:d:" + sid + ":" + denyProof, cfg.verificationEmbed().denyButton())
            );
            TextChannel channel = local.getTextChannelById(cfg.discordChannelId());
            if (channel == null) return CompletableFuture.completedFuture(false);
            return channel.sendMessageEmbeds(embed.build()).setComponents(controls).submit()
                    .thenApply(m -> {
                        if (cfg.discordSendDm()) sendDmIfEnabled(account, embed, controls, sid.toString());
                        return true;
                    })
                    .exceptionally(ex -> {
                        logger.log(Level.WARNING, "Không gửi được verification message; session=" + sid, unwrap(ex));
                        return false;
                    });
        });
    }

    private CompletableFuture<Boolean> sendDmIfEnabled(ProtectedAccount account, EmbedBuilder embed, ActionRow controls, String sid) {
        if (!cfg.discordSendDm() || jda == null) return CompletableFuture.completedFuture(false);
        return jda.retrieveUserById(account.discordId()).submit()
                .thenCompose(user -> user.openPrivateChannel().submit())
                .thenCompose(ch -> ch.sendMessageEmbeds(embed.build()).setComponents(controls).submit())
                .thenApply(m -> true)
                .exceptionally(ex -> {
                    logger.log(Level.WARNING, "Không gửi được DM verification; session=" + sid, unwrap(ex));
                    return false;
                });
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

    public CompletableFuture<Boolean> logCommandAudit(String sender, String command, String permission, String source,
                                                       boolean dangerous, String serverName, String channelId) {
        JDA local = jda;
        if (local == null || !cfg.commandAudit().enabled() || channelId == null || channelId.isBlank()) return CompletableFuture.completedFuture(false);
        TextChannel channel = local.getTextChannelById(channelId);
        if (channel == null) return CompletableFuture.completedFuture(false);
        StaffGuardConfig.CommandAuditEmbedConfig e = cfg.commandAuditEmbed();
        String bounded = command.length() > 1000 ? command.substring(0, 997) + "..." : command;
        EmbedBuilder embed = new EmbedBuilder()
                .setTitle(e.title())
                .setColor(new Color(dangerous ? e.dangerColor() : e.safeColor()))
                .setDescription(e.description())
                .addField(e.commandField(), bounded, false)
                .addField(e.senderField(), bound(sender, 256), true)
                .addField(e.permissionField(), bound(permission, 256), true)
                .addField(e.serverField(), bound(serverName, 256), true)
                .addField(e.channelField(), bound(source, 256), true)
                .setFooter(e.footer())
                .setTimestamp(Instant.now());
        return channel.sendMessageEmbeds(embed.build()).submit().thenApply(m -> true).exceptionally(ex -> {
            logger.log(Level.WARNING, "Không gửi được command audit embed", ex);
            return false;
        });
    }

    @Override
    public void onButtonInteraction(ButtonInteractionEvent event) {
        String id = event.getComponentId();
        if (id == null || !id.startsWith("sg:")) return;

        String userId = event.getUser().getId();
        if (!interactionLimiter.tryAcquire(userId)) {
            event.reply("🚨 Quá nhiều thao tác xác thực. Vui lòng thử lại sau.").setEphemeral(true).queue();
            return;
        }

        String[] parts = id.split(":", 4);
        if (parts.length != 4 || !(parts[1].equals("a") || parts[1].equals("d"))) {
            event.reply("❌ Verification không hợp lệ.").setEphemeral(true).queue();
            return;
        }

        UUID sessionId;
        try {
            sessionId = UUID.fromString(parts[2]);
        } catch (IllegalArgumentException ex) {
            event.reply("❌ Verification không hợp lệ.").setEphemeral(true).queue();
            return;
        }
        if (parts[3].length() < 16 || parts[3].length() > 128) {
            event.reply("❌ Verification không hợp lệ.").setEphemeral(true).queue();
            return;
        }

        final String action = parts[1];
        final String proof = parts[3];
        final UUID finalSessionId = sessionId;

        
        
        event.deferReply(true).queue(hook -> verification.getSession(finalSessionId).whenComplete((found, error) -> {
            if (error != null) {
                logger.log(Level.WARNING, "Không thể tải verification session=" + finalSessionId, unwrap(error));
                editHook(hook, "❌ Không thể kiểm tra verification lúc này.");
                return;
            }
            if (found.isEmpty() || !found.get().pendingAndUnexpired(System.currentTimeMillis())) {
                editHook(hook, "❌ Verification không tồn tại hoặc đã hết hạn/được xử lý.");
                return;
            }

            VerificationSession session = found.get();
            boolean configuredChannel = event.isFromGuild()
                    && event.getChannel().getId().equals(cfg.discordChannelId());
            boolean ownDm = !event.isFromGuild() && session.discordId().equals(userId);
            if (!configuredChannel && !ownDm) {
                editHook(hook, "⛔ Verification không hợp lệ ở context này.");
                return;
            }

            CompletableFuture<?> result = action.equals("a")
                    ? verification.approve(finalSessionId, proof, userId)
                    : verification.denyWithProof(finalSessionId, proof, userId, "d");
            result.whenComplete((value, ex) -> {
                if (ex != null) {
                    logger.log(Level.SEVERE, "Discord verification action failed for " + finalSessionId, unwrap(ex));
                    editHook(hook, "❌ Lỗi hệ thống. Verification chưa được xử lý.");
                    return;
                }
                boolean ok = value instanceof java.util.Optional<?> o && o.isPresent();
                editHook(hook, ok
                        ? (action.equals("a") ? "✅ Đã xác minh thành công. Hãy đăng nhập lại bằng IP này." : "❌ Đã từ chối. IP mới không được trusted.")
                        : "❌ Verification đã được xử lý, hết hạn hoặc không còn hợp lệ.");
            });
        }), ex -> logger.log(Level.WARNING, "Không ACK được Discord verification interaction=" + finalSessionId, unwrap(ex)));
    }

    private static String bound(String v, int max) { if (v == null) return ""; return v.length() > max ? v.substring(0, max - 3) + "..." : v; }
    private void editHook(net.dv8tion.jda.api.interactions.InteractionHook hook, String content) { hook.editOriginal(content).queue(null, ex -> logger.log(Level.WARNING, "Không cập nhật được Discord interaction response", ex)); }
    private static String relative(long epoch) { return "~" + Math.max(0, (epoch - System.currentTimeMillis()) / 1000) + " giây"; }
    private static Throwable unwrap(Throwable error) { while (error instanceof java.util.concurrent.CompletionException && error.getCause() != null) error = error.getCause(); return error; }
    private static String safeReason(Throwable error) { Throwable e = unwrap(error); String m = e == null ? null : e.getMessage(); if (m == null || m.isBlank()) return e == null ? "unknown" : e.getClass().getSimpleName(); return m.replaceAll("\\s+", " ").substring(0, Math.min(240, m.replaceAll("\\s+", " ").length())); }
    public boolean isConnected() { return jda != null && jda.getStatus() == JDA.Status.CONNECTED; }
    public boolean needsStart() { return jda == null; }
    public void cleanupRateLimiter() { interactionLimiter.cleanup(); }

    public synchronized void shutdown() {
        JDA local = jda;
        jda = null;
        if (local != null) try { local.shutdownNow(); } catch (Exception ignored) { }
        CompletableFuture<Boolean> f = startupFuture;
        startupFuture = null;
        if (f != null && !f.isDone()) f.cancel(true);
        interactionLimiter.cleanup();
        startupExecutor.shutdownNow();
    }

    @Override public void close() { shutdown(); }
}
