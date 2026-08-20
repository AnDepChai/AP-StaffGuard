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

/** Discord boundary for StaffGuard verification. Authorization is based on Discord User IDs, not names. */
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
        if (cfg.discordChannelId().isBlank()) {
            logger.severe("Discord verification channel is empty.");
            return CompletableFuture.completedFuture(false);
        }

        String token = resolveToken();
        if (token.isBlank()) {
            logger.severe("Discord bot token is missing.");
            return CompletableFuture.completedFuture(false);
        }

        return CompletableFuture.supplyAsync(() -> {
            if (!started.compareAndSet(false, true)) return jda != null;
            try {
                JDA local = JDABuilder.createDefault(token).addEventListeners(this).build();
                local.awaitReady();

                TextChannel channel = local.getTextChannelById(cfg.discordChannelId());
                if (channel == null) {
                    throw new IllegalStateException("Configured verification channel does not exist or is inaccessible: " + cfg.discordChannelId());
                }

                jda = local;
                logger.info("Discord verification connected. Channel=" + channel.getId());
                return true;
            } catch (Exception ex) {
                started.set(false);
                jda = null;
                logger.log(Level.SEVERE, "Discord verification failed to start; protected accounts remain fail-closed.", ex);
                return false;
            }
        }, startupExecutor);
    }

    private String resolveToken() {
        return cfg.discordToken() == null ? "" : cfg.discordToken().trim();
    }

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
                Button.success("sg:a:" + sid + ":" + approveProof, "✅ Xác nhận"),
                Button.danger("sg:d:" + sid + ":" + denyProof, "❌ Từ chối")
        );

        TextChannel channel = local.getTextChannelById(cfg.discordChannelId());
        CompletableFuture<Boolean> channelFuture = channel == null
                ? CompletableFuture.completedFuture(false)
                : channel.sendMessageEmbeds(embed.build()).setComponents(controls).submit()
                    .thenApply(message -> true)
                    .exceptionally(ex -> {
                        logger.log(Level.WARNING, "Failed to send verification message to Discord channel for " + sid, ex);
                        return false;
                    });

        // The verification channel is authoritative. DM is best-effort and must never block login verification.
        return channelFuture.thenApply(channelSent -> {
            if (!channelSent) {
                logger.warning("Verification request " + sid + " could not be posted to the configured verification channel.");
                return false;
            }
            if (cfg.discordSendDm()) {
                sendDmIfEnabled(account, embed, controls, sid)
                        .thenAccept(dmSent -> {
                            if (!dmSent) {
                                logger.warning("Verification request " + sid + " was posted to the channel, but DM to Discord user " + account.discordId() + " failed.");
                            }
                        });
            }
            return true;
        });
    }

    private CompletableFuture<Boolean> sendDmIfEnabled(ProtectedAccount account, EmbedBuilder embed, ActionRow controls, String sid) {
        if (!cfg.discordSendDm() || jda == null) return CompletableFuture.completedFuture(false);
        return jda.retrieveUserById(account.discordId()).submit()
                .thenCompose(User -> User.openPrivateChannel().submit())
                .thenCompose(channel -> channel.sendMessageEmbeds(embed.build()).setComponents(controls).submit())
                .thenApply(message -> true)
                .exceptionally(ex -> {
                    logger.log(Level.WARNING, "Could not DM Discord user " + account.discordId() + " for verification " + sid, ex);
                    return false;
                });
    }

    private EmbedBuilder buildVerificationEmbed(ProtectedAccount account, String displayIp, VerificationSession session) {
        return new EmbedBuilder()
                .setTitle("🔐 AP-STAFFGUARD • Xác thực đăng nhập")
                .setColor(new Color(245, 166, 35))
                .setDescription("Phát hiện đăng nhập từ IP chưa được tin cậy. Hãy kiểm tra thông tin bên dưới trước khi xác nhận.")
                .addField("👤 Minecraft", account.username(), true)
                .addField("🛡️ Role", account.role().name(), true)
                .addField("🌐 IP", displayIp, true)
                .addField("🆔 Verification", session.sessionId().toString(), false)
                .addField("⏱️ Hết hạn", relative(session.expiresAt()), true)
                .addField("🏠 Server", cfg.serverName(), true)
                .setFooter("AP-StaffGuard • Owner có thể xác nhận mọi request; Staff chỉ xác nhận request của chính mình.")
                .setTimestamp(Instant.now());
    }

    @Override
    public void onButtonInteraction(ButtonInteractionEvent event) {
        String componentId = event.getComponentId();
        if (!componentId.startsWith("sg:")) return;

        String[] parts = componentId.split(":", 4);
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

        final UUID finalSessionId = sessionId;
        final String action = parts[1];
        final String proof = parts[3];
        final String discordId = event.getUser().getId();

        // ACK immediately. All DB/business logic happens after the defer so Discord's 3-second deadline is safe.
        event.deferReply(true).queue(hook -> {
            if (!interactionLimiter.tryAcquire(discordId)) {
                hook.editOriginal("🚨 Quá nhiều thao tác xác thực. Vui lòng thử lại sau.")
                        .queue(null, ex -> logger.log(Level.WARNING, "Failed to send Discord rate-limit response", ex));
                return;
            }

            verification.getSession(finalSessionId).whenComplete((found, lookupError) -> {
                if (lookupError != null) {
                    logger.log(Level.WARNING, "Failed to load verification session " + finalSessionId, unwrap(lookupError));
                    editHook(hook, "❌ Không thể kiểm tra verification. Vui lòng thử lại sau.");
                    return;
                }
                if (found.isEmpty()) {
                    editHook(hook, "❌ Verification không tồn tại hoặc đã hết hạn.");
                    return;
                }

                VerificationSession session = found.get();
                if (!session.pendingAndUnexpired(System.currentTimeMillis())) {
                    editHook(hook, "❌ Verification đã hết hạn hoặc đã được xử lý.");
                    return;
                }

                boolean inConfiguredChannel = event.isFromGuild() && event.getChannel().getId().equals(cfg.discordChannelId());
                boolean inOwnDm = !event.isFromGuild() && session.discordId().equals(discordId);
                if (!inConfiguredChannel && !inOwnDm) {
                    editHook(hook, "⛔ Nút xác thực này chỉ hoạt động trong kênh StaffGuard đã cấu hình hoặc DM của chính tài khoản được yêu cầu xác thực.");
                    return;
                }

                boolean owner = cfg.isDiscordOwner(discordId);
                boolean staffOwnRequest = cfg.isDiscordStaff(discordId)
                        && session.discordId().equals(discordId)
                        && cfg.discordAllowSelfApproval();
                boolean linkedSelf = cfg.discordAllowSelfApproval() && session.discordId().equals(discordId);
                boolean authorized = owner || staffOwnRequest || linkedSelf;
                if (!authorized) {
                    logger.warning("Unauthorized Discord verification interaction: user=" + discordId + ", session=" + finalSessionId);
                    editHook(hook, "⛔ Bạn không được cấp quyền xử lý verification này.");
                    return;
                }

                CompletableFuture<?> result = action.equals("a")
                        ? verification.approve(finalSessionId, proof, discordId)
                        : verification.denyWithProof(finalSessionId, proof, discordId, "d");

                result.whenComplete((value, error) -> {
                    if (error != null) {
                        logger.log(Level.SEVERE, "Discord verification interaction failed for session " + finalSessionId, unwrap(error));
                        editHook(hook, "❌ Có lỗi hệ thống. Verification vẫn được xử lý theo cơ chế fail-safe; kiểm tra log để biết chi tiết.");
                    } else if (value instanceof java.util.Optional<?> optional && optional.isPresent()) {
                        editHook(hook, action.equals("a")
                                ? "✅ Đã xác minh. Hãy đăng nhập lại Minecraft."
                                : "❌ Đã từ chối. IP mới không được trusted.");
                    } else {
                        editHook(hook, "❌ Verification không hợp lệ, đã hết hạn hoặc đã được xử lý.");
                    }
                });
            });
        }, ex -> logger.log(Level.WARNING, "Failed to defer Discord interaction", ex));
    }

    private void editHook(net.dv8tion.jda.api.interactions.InteractionHook hook, String content) {
        hook.editOriginal(content).queue(null, ex -> logger.log(Level.WARNING, "Failed to edit Discord interaction response", ex));
    }

    private static String relative(long epoch) {
        long seconds = Math.max(0, (epoch - System.currentTimeMillis()) / 1000);
        return "~" + seconds + " giây";
    }

    private static Throwable unwrap(Throwable error) {
        if (error instanceof java.util.concurrent.CompletionException && error.getCause() != null) return error.getCause();
        return error;
    }

    public boolean isConnected() { return jda != null; }

    public void cleanupRateLimiter() {
        interactionLimiter.cleanup();
    }

    public void shutdown() {
        JDA local = jda;
        jda = null;
        started.set(false);
        if (local != null) local.shutdownNow();
        interactionLimiter.cleanup();
        startupExecutor.shutdownNow();
    }

    @Override
    public void close() { shutdown(); }
}
