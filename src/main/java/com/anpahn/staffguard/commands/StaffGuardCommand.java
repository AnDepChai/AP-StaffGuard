package com.anpahn.staffguard.commands;

import com.anpahn.staffguard.StaffGuardPlugin;
import com.anpahn.staffguard.model.ProtectedAccount;
import com.anpahn.staffguard.model.Role;
import com.anpahn.staffguard.model.SecurityEventType;
import com.anpahn.staffguard.util.IpAddressUtil;
import org.bukkit.Bukkit;
import org.bukkit.command.Command;
import org.bukkit.command.CommandExecutor;
import org.bukkit.command.CommandSender;
import org.bukkit.command.ConsoleCommandSender;
import org.bukkit.command.TabCompleter;
import org.bukkit.entity.Player;

import java.net.InetAddress;
import java.util.List;
import java.util.Locale;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.function.Consumer;
import java.util.logging.Level;

public final class StaffGuardCommand implements CommandExecutor, TabCompleter {
    private static final List<String> OWNER_COMMANDS = List.of(
            "add", "remove", "info", "trust", "untrust", "reset", "verify", "revoke", "lockdown", "unlock", "logs", "reload", "help"
    );
    private static final List<String> ADMIN_COMMANDS = List.of("help", "info", "logs");

    private final StaffGuardPlugin plugin;

    public StaffGuardCommand(StaffGuardPlugin plugin) {
        this.plugin = plugin;
    }

    private boolean owner(CommandSender sender) {
        return sender instanceof ConsoleCommandSender || sender.hasPermission("staffguard.owner");
    }

    private boolean admin(CommandSender sender) {
        return owner(sender) || sender.hasPermission("staffguard.admin");
    }

    @Override
    public boolean onCommand(CommandSender sender, Command command, String label, String[] args) {
        if (args.length == 0 || args[0].equalsIgnoreCase("help")) {
            sendHelp(sender);
            return true;
        }
        if (!plugin.commandDependenciesReady()) {
            sender.sendMessage("§cAP-StaffGuard chưa khởi tạo xong. §fKiểm tra console để biết lỗi.");
            return true;
        }

        String sub = args[0].toLowerCase(Locale.ROOT);
        try {
            switch (sub) {
                case "add" -> add(sender, args);
                case "remove" -> remove(sender, args);
                case "info" -> info(sender, args);
                case "trust" -> trust(sender, args, true);
                case "untrust" -> trust(sender, args, false);
                case "reset" -> reset(sender, args);
                case "verify" -> verify(sender, args);
                case "revoke" -> revoke(sender, args);
                case "lockdown" -> lockdown(sender, true);
                case "unlock" -> lockdown(sender, false);
                case "logs" -> logs(sender, args);
                case "reload" -> reload(sender);
                default -> sendHelp(sender);
            }
        } catch (Exception ex) {
            plugin.getLogger().log(Level.SEVERE, "Command failed synchronously: " + sub, ex);
            sender.sendMessage(plugin.safeOperationFailedMessage());
        }
        return true;
    }

    private void sendHelp(CommandSender sender) {
        if (!admin(sender)) {
            sender.sendMessage(plugin.safeNoPermissionMessage());
            return;
        }

        sender.sendMessage("§b§lAP-StaffGuard §7— §f/staffguard <command>");
        sender.sendMessage("§8────────────────────────────");
        sender.sendMessage("§b/help §7Xem danh sách lệnh");
        sender.sendMessage("§b/info <player|uuid> §7Xem protected account");
        sender.sendMessage("§b/logs <player|uuid> §7Xem audit log");

        if (owner(sender)) {
            sender.sendMessage("§8§m────────────────────────────");
            sender.sendMessage("§6Owner commands:");
            sender.sendMessage("§e/add <player> <owner|staff> <discordId> [--confirm]");
            sender.sendMessage("§e/remove <player|uuid>");
            sender.sendMessage("§e/trust <player|uuid> <ip>");
            sender.sendMessage("§e/untrust <player|uuid> <ip>");
            sender.sendMessage("§e/reset <player|uuid>");
            sender.sendMessage("§e/verify <player>");
            sender.sendMessage("§e/revoke <verificationId>");
            sender.sendMessage("§e/lockdown");
            sender.sendMessage("§e/unlock");
            sender.sendMessage("§e/reload");
        }
        sender.sendMessage("§8────────────────────────────");
        sender.sendMessage("§7Alias: §f/sg");
    }

    private void add(CommandSender sender, String[] args) {
        if (!requireOwner(sender)) return;
        if (args.length < 4) {
            sender.sendMessage("§e/staffguard add <player> <owner|staff> <discordId> [--confirm]");
            return;
        }

        Player target = Bukkit.getPlayerExact(args[1]);
        if (target == null) {
            sender.sendMessage("§cPlayer phải online để lấy UUID chính xác.");
            return;
        }

        Role role;
        try {
            role = Role.valueOf(args[2].toUpperCase(Locale.ROOT));
        } catch (IllegalArgumentException ex) {
            sender.sendMessage(plugin.messages().invalidRole());
            return;
        }

        String discordId = args[3].trim();
        if (!discordId.matches("\\d{17,20}")) {
            sender.sendMessage(plugin.messages().invalidDiscordId());
            return;
        }

        boolean confirmed = args.length >= 5 && "--confirm".equalsIgnoreCase(args[4]);
        ProtectedAccount existing = plugin.accounts().getCached(target.getUniqueId());
        if (existing != null && !confirmed) {
            sender.sendMessage("§eAccount đã tồn tại: §f" + existing.username() + " §7/ role=§f" + existing.role()
                    + " §7/ Discord=§f" + existing.discordId());
            sender.sendMessage("§eNếu thực sự muốn cập nhật, dùng §f/staffguard add " + target.getName() + " "
                    + role.name().toLowerCase(Locale.ROOT) + " " + discordId + " --confirm");
            return;
        }

        CompletableFuture<ProtectedAccount> operation = plugin.db().countAccountsForDiscordExcept(discordId, target.getUniqueId())
                .thenCompose(count -> {
                    if (count >= plugin.config().maxDiscordAccountsPerUser()) {
                        throw new IllegalStateException("Discord User ID đã đạt giới hạn protected accounts");
                    }
                    return plugin.accounts().add(target.getUniqueId(), target.getName(), role, discordId);
                })
                .thenCompose(account -> plugin.ips().load(List.of(account.uuid())).thenApply(v -> account));

        runAsync(sender, "add protected account", operation, account -> {
            sender.sendMessage("§aĐã " + (existing == null ? "đăng ký" : "cập nhật") + " §f" + account.username()
                    + " §7→ §f" + account.role() + " §7/ Discord §f" + account.discordId());
            plugin.audit().log(account.uuid(), account.role(), SecurityEventType.ADMIN_ACTION,
                    "SUCCESS", (existing == null ? "add by " : "update by ") + sender.getName(), null, null);
        });
    }

    private void remove(CommandSender sender, String[] args) {
        if (!requireOwner(sender)) return;
        if (args.length < 2) {
            sender.sendMessage("§e/staffguard remove <player|uuid>");
            return;
        }
        UUID uuid = lookup(args[1]);
        if (uuid == null) {
            sender.sendMessage(plugin.messages().notFound());
            return;
        }
        runAsync(sender, "remove protected account", plugin.accounts().remove(uuid), ok ->
                sender.sendMessage(ok ? "§aĐã remove protected account." : plugin.messages().notFound()));
    }

    private void info(CommandSender sender, String[] args) {
        if (!requireAdmin(sender)) return;
        if (args.length < 2) {
            sender.sendMessage("§e/staffguard info <player|uuid>");
            return;
        }
        UUID uuid = lookup(args[1]);
        if (uuid == null) {
            sender.sendMessage(plugin.messages().notFound());
            return;
        }
        ProtectedAccount account = plugin.accounts().getCached(uuid);
        if (account == null) {
            sender.sendMessage(plugin.messages().notFound());
            return;
        }
        sender.sendMessage("§b§lAP-StaffGuard");
        sender.sendMessage("§7Player: §f" + account.username());
        sender.sendMessage("§7UUID: §f" + account.uuid());
        sender.sendMessage("§7Role: §f" + account.role());
        sender.sendMessage("§7Discord: §f" + account.discordId());
        sender.sendMessage("§7Status: §f" + account.status());
        sender.sendMessage("§7Last seen: §f" + (account.lastSeenAt() == null ? "never" : account.lastSeenAt()));
    }

    private void trust(CommandSender sender, String[] args, boolean add) {
        if (!requireOwner(sender)) return;
        if (args.length < 3) {
            sender.sendMessage("§e/staffguard " + (add ? "trust" : "untrust") + " <player|uuid> <ip>");
            return;
        }
        UUID uuid = lookup(args[1]);
        if (uuid == null) {
            sender.sendMessage(plugin.messages().notFound());
            return;
        }

        String ip = args[2];
        InetAddress parsed = IpAddressUtil.parseLiteral(ip);
        if (parsed == null) {
            sender.sendMessage("§cIP không hợp lệ. Chỉ chấp nhận IPv4/IPv6 literal, không chấp nhận hostname.");
            return;
        }
        String normalizedIp = parsed.getHostAddress();

        CompletableFuture<Boolean> future = add ? plugin.ips().add(uuid, normalizedIp) : plugin.ips().remove(uuid, normalizedIp);
        runAsync(sender, add ? "trust IP" : "untrust IP", future, ok ->
                sender.sendMessage(ok
                        ? (add ? "§aTrusted IP đã được thêm." : "§aTrusted IP đã được xóa.")
                        : (add ? "§cKhông thể thêm Trusted IP." : "§cKhông tìm thấy Trusted IP.")));
    }

    private void reset(CommandSender sender, String[] args) {
        if (!requireOwner(sender)) return;
        if (args.length < 2) {
            sender.sendMessage("§e/staffguard reset <player|uuid>");
            return;
        }
        UUID uuid = lookup(args[1]);
        if (uuid == null) {
            sender.sendMessage(plugin.messages().notFound());
            return;
        }
        CompletableFuture<Void> operation = plugin.banService().remove(uuid)
                .thenCompose(v -> plugin.verification().expireForAccount(uuid)
                        .thenApply(ignored -> (Void) null));
        runAsync(sender, "reset account", operation, ignored ->
                sender.sendMessage("§aĐã reset ban và verification đang chờ của account."));
    }

    private void verify(CommandSender sender, String[] args) {
        if (!requireOwner(sender)) return;
        if (args.length < 2) {
            sender.sendMessage("§e/staffguard verify <player>");
            return;
        }
        Player target = Bukkit.getPlayerExact(args[1]);
        if (target == null) {
            sender.sendMessage("§cPlayer phải online.");
            return;
        }
        ProtectedAccount account = plugin.accounts().getCached(target.getUniqueId());
        if (account == null) {
            sender.sendMessage(plugin.messages().notFound());
            return;
        }
        String ip = target.getAddress() == null ? null : target.getAddress().getAddress().getHostAddress();
        if (ip == null) {
            sender.sendMessage("§cKhông lấy được connection address.");
            return;
        }
        CompletableFuture<Void> operation = plugin.ips().add(account.uuid(), ip)
                .thenCompose(v -> plugin.banService().remove(account.uuid()));
        runAsync(sender, "manual verify", operation, ignored ->
                sender.sendMessage("§aĐã manual verify và trust IP hiện tại."));
    }

    private void revoke(CommandSender sender, String[] args) {
        if (!requireOwner(sender)) return;
        if (args.length < 2) {
            sender.sendMessage("§e/staffguard revoke <verificationId>");
            return;
        }
        try {
            UUID id = UUID.fromString(args[1]);
            runAsync(sender, "revoke verification", plugin.verification().revoke(id, sender.getName()), ok ->
                    sender.sendMessage(ok ? "§aĐã revoke verification session." : "§cKhông tìm thấy verification session."));
        } catch (IllegalArgumentException ex) {
            sender.sendMessage("§cVerification ID không hợp lệ.");
        }
    }

    private void lockdown(CommandSender sender, boolean enable) {
        if (!requireOwner(sender)) return;
        boolean changed = enable ? plugin.lockdown().enable() : plugin.lockdown().disable();
        sender.sendMessage(changed ? (enable ? "§cLOCKDOWN enabled." : "§aLOCKDOWN disabled.") : "§eTrạng thái không thay đổi.");
        plugin.audit().log(null, null, enable ? SecurityEventType.LOCKDOWN_ENABLED : SecurityEventType.LOCKDOWN_DISABLED,
                "SUCCESS", "by " + sender.getName(), null, null);
    }

    private void logs(CommandSender sender, String[] args) {
        if (!requireAdmin(sender)) return;
        if (args.length < 2) {
            sender.sendMessage("§e/staffguard logs <player|uuid>");
            return;
        }
        UUID uuid = lookup(args[1]);
        if (uuid == null) {
            sender.sendMessage(plugin.messages().notFound());
            return;
        }
        runAsync(sender, "load audit logs", plugin.audit().logs(uuid, 20), lines -> {
            sender.sendMessage("§b§lStaffGuard Audit §7— §f" + uuid);
            if (lines.isEmpty()) {
                sender.sendMessage("§7Không có audit log.");
                return;
            }
            lines.forEach(line -> sender.sendMessage("§8• §7" + line));
        });
    }

    private void reload(CommandSender sender) {
        if (!requireOwner(sender)) return;
        plugin.reloadSafely().whenComplete((ignored, error) -> Bukkit.getScheduler().runTask(plugin, () -> {
            if (error != null) {
                plugin.getLogger().log(Level.SEVERE, "Reload failed", error);
                sender.sendMessage(plugin.messages().operationFailed());
            } else {
                sender.sendMessage("§aĐã reload messages trong config.yml. §eThay đổi bảo mật/Discord cần restart plugin/server.");
            }
        }));
    }

    private <T> void runAsync(CommandSender sender, String operation, CompletableFuture<T> future, Consumer<T> success) {
        future.whenComplete((value, error) -> Bukkit.getScheduler().runTask(plugin, () -> {
            if (error != null) {
                plugin.getLogger().log(Level.SEVERE, "Async command operation failed: " + operation, unwrap(error));
                sender.sendMessage(plugin.messages().operationFailed());
                return;
            }
            try {
                success.accept(value);
            } catch (Exception ex) {
                plugin.getLogger().log(Level.SEVERE, "Command response failed: " + operation, ex);
                sender.sendMessage(plugin.messages().operationFailed());
            }
        }));
    }

    private static Throwable unwrap(Throwable error) {
        if (error instanceof java.util.concurrent.CompletionException && error.getCause() != null) return error.getCause();
        return error;
    }

    private boolean requireOwner(CommandSender sender) {
        if (owner(sender)) return true;
        sender.sendMessage(plugin.safeNoPermissionMessage());
        return false;
    }

    private boolean requireAdmin(CommandSender sender) {
        if (admin(sender)) return true;
        sender.sendMessage(plugin.safeNoPermissionMessage());
        return false;
    }

    private UUID lookup(String input) {
        try {
            return UUID.fromString(input);
        } catch (IllegalArgumentException ignored) {
        }
        ProtectedAccount account = plugin.accounts().getByUsername(input);
        if (account != null) return account.uuid();
        Player player = Bukkit.getPlayerExact(input);
        return player == null ? null : player.getUniqueId();
    }

    @Override
    public List<String> onTabComplete(CommandSender sender, Command command, String alias, String[] args) {
        if (args.length == 1) {
            List<String> commands = owner(sender) ? OWNER_COMMANDS : admin(sender) ? ADMIN_COMMANDS : List.of();
            String prefix = args[0].toLowerCase(Locale.ROOT);
            return commands.stream().filter(x -> x.startsWith(prefix)).toList();
        }
        if (args.length == 3 && args[0].equalsIgnoreCase("add") && owner(sender)) {
            return List.of("owner", "staff").stream().filter(x -> x.startsWith(args[2].toLowerCase(Locale.ROOT))).toList();
        }
        return List.of();
    }
}
