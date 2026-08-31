package com.anpahn.staffguard.database;

import com.anpahn.staffguard.model.*;
import org.bukkit.plugin.java.JavaPlugin;

import java.io.File;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.sql.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.function.Function;

public final class Database implements AutoCloseable {
    private final JavaPlugin plugin;
    private final File file;
    private final ExecutorService executor;
    private final Function<String, InputStream> resourceLoader;
    private volatile Connection connection;

    public Database(JavaPlugin plugin, File file) {
        this(plugin, file, plugin::getResource);
    }

    Database(JavaPlugin plugin, File file, Function<String, InputStream> resourceLoader) {
        this.plugin = plugin;
        this.file = Objects.requireNonNull(file);
        this.resourceLoader = Objects.requireNonNull(resourceLoader);
        this.executor = Executors.newSingleThreadExecutor(r -> {
            Thread t = new Thread(r, "AP-StaffGuard-DB");
            t.setDaemon(true);
            return t;
        });
    }

    public void start() throws SQLException {
        File parent = file.getParentFile();
        if (parent != null && !parent.exists() && !parent.mkdirs() && !parent.isDirectory()) {
            throw new SQLException("Cannot create database directory: " + parent);
        }
        Connection c = DriverManager.getConnection("jdbc:sqlite:" + file.getAbsolutePath());
        try {
            try (Statement s = c.createStatement()) {
                s.execute("PRAGMA foreign_keys=ON");
                s.execute("PRAGMA journal_mode=WAL");
                s.execute("PRAGMA synchronous=NORMAL");
                s.execute("PRAGMA busy_timeout=5000");
            }
            connection = c;
            migrate();
        } catch (SQLException ex) {
            try { c.close(); } catch (SQLException ignored) { }
            connection = null;
            throw ex;
        }
    }

    public CompletableFuture<Void> startAsync() {
        return CompletableFuture.runAsync(() -> {
            try { start(); } catch (SQLException e) { throw new CompletionException(e); }
        }, executor);
    }

    private static List<String> splitSqlStatements(String sql) {
        List<String> statements = new ArrayList<>();
        StringBuilder current = new StringBuilder();
        boolean single = false, doubleQuote = false, lineComment = false, blockComment = false;
        for (int i = 0; i < sql.length(); i++) {
            char ch = sql.charAt(i), next = i + 1 < sql.length() ? sql.charAt(i + 1) : '\0';
            if (lineComment) { current.append(ch); if (ch == '\n' || ch == '\r') lineComment = false; continue; }
            if (blockComment) { current.append(ch); if (ch == '*' && next == '/') { current.append(next); i++; blockComment = false; } continue; }
            if (!single && !doubleQuote && ch == '-' && next == '-') { current.append(ch).append(next); i++; lineComment = true; continue; }
            if (!single && !doubleQuote && ch == '/' && next == '*') { current.append(ch).append(next); i++; blockComment = true; continue; }
            if (ch == '\'' && !doubleQuote) { current.append(ch); if (single && next == '\'') { current.append(next); i++; } else single = !single; continue; }
            if (ch == '"' && !single) { current.append(ch); if (doubleQuote && next == '"') { current.append(next); i++; } else doubleQuote = !doubleQuote; continue; }
            if (ch == ';' && !single && !doubleQuote) { if (!current.toString().isBlank()) statements.add(current.toString()); current.setLength(0); }
            else current.append(ch);
        }
        if (!current.toString().isBlank()) statements.add(current.toString());
        return statements;
    }

    private void migrate() throws SQLException {
        ensureConnection();
        try (Statement s = connection.createStatement()) {
            s.execute("CREATE TABLE IF NOT EXISTS schema_version(version INTEGER PRIMARY KEY)");
        }
        int version = 0;
        try (PreparedStatement q = connection.prepareStatement("SELECT COALESCE(MAX(version),0) FROM schema_version"); ResultSet rs = q.executeQuery()) {
            rs.next(); version = rs.getInt(1);
        }
        if (version >= 2) return;
        connection.setAutoCommit(false);
        try {
            if (version < 1) applyMigration(1, "migrations/001_initial.sql");
            if (version < 2) applyMigration(2, "migrations/002_security_generation.sql");
            validateSchema();
            connection.commit();
        } catch (Exception e) {
            try { connection.rollback(); } catch (SQLException ignored) { }
            throw e instanceof SQLException ? (SQLException) e : new SQLException("Migration failed", e);
        } finally {
            connection.setAutoCommit(true);
        }
    }

    private void applyMigration(int version, String resource) throws Exception {
        InputStream stream = resourceLoader.apply(resource);
        if (stream == null) throw new SQLException("Missing database migration resource: " + resource);
        String sql;
        try (stream) { sql = new String(stream.readAllBytes(), StandardCharsets.UTF_8); }
        for (String statement : splitSqlStatements(sql)) if (!statement.isBlank()) { try (Statement s=connection.createStatement()) { s.execute(statement); } }
        try (PreparedStatement p = connection.prepareStatement("INSERT INTO schema_version(version) VALUES(?)")) {
            p.setInt(1, version); p.executeUpdate();
        }
    }

    private void validateSchema() throws SQLException {
        requireColumn("protected_accounts", "security_generation");
        requireColumn("trusted_ips", "security_generation");
        requireColumn("verification_sessions", "account_generation");
        requireColumn("verification_sessions", "notification_count");
        requireColumn("verification_sessions", "last_notification_at");
        requireColumn("verification_sessions", "processed_at");
        requireColumn("verification_sessions", "processed_by");
    }

    private void requireColumn(String table, String column) throws SQLException {
        try (PreparedStatement p = connection.prepareStatement("PRAGMA table_info(" + table + ")"); ResultSet r = p.executeQuery()) {
            while (r.next()) if (column.equalsIgnoreCase(r.getString("name"))) return;
        }
        throw new SQLException("Database schema validation failed: missing " + table + "." + column);
    }

    public <T> CompletableFuture<T> submit(SqlFunction<T> fn) {
        return CompletableFuture.supplyAsync(() -> {
            try {
                ensureConnection();
                return fn.apply(connection);
            } catch (Exception e) {
                throw new CompletionException(e);
            }
        }, executor);
    }

    private void ensureConnection() throws SQLException {
        Connection c = connection;
        if (c == null || c.isClosed()) throw new SQLException("Database is not ready");
    }

    public CompletableFuture<Void> execute(SqlConsumer fn) { return submit(c -> { fn.accept(c); return null; }); }
    @FunctionalInterface public interface SqlFunction<T> { T apply(Connection c) throws Exception; }
    @FunctionalInterface public interface SqlConsumer { void accept(Connection c) throws Exception; }

    @Override public void close() {
        executor.shutdown();
        try {
            if (!executor.awaitTermination(5, TimeUnit.SECONDS)) executor.shutdownNow();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            executor.shutdownNow();
        }
        Connection c = connection;
        connection = null;
        if (c != null) try { c.close(); } catch (SQLException ignored) { }
    }

    private static ProtectedAccount account(ResultSet r) throws SQLException {
        return new ProtectedAccount(
                UUID.fromString(r.getString(1)), r.getString(2), Role.valueOf(r.getString(3)), r.getString(4),
                AccountStatus.valueOf(r.getString(5)), r.getString(6), r.getLong(7), r.getLong(8),
                (Long) r.getObject(9), r.getLong(10));
    }

    private static VerificationSession session(ResultSet r) throws SQLException {
        return new VerificationSession(
                UUID.fromString(r.getString(1)), UUID.fromString(r.getString(2)), r.getString(3), r.getString(4), r.getString(5),
                VerificationState.valueOf(r.getString(6)), r.getLong(7), r.getLong(8), (Long) r.getObject(9), r.getString(10),
                r.getLong(11), r.getInt(12), (Long) r.getObject(13));
    }

    private static final String ACCOUNT_COLUMNS =
            "uuid,username,role,discord_id,status,last_seen_ip_hash,created_at,updated_at,last_seen_at,security_generation";
    private static final String SESSION_COLUMNS =
            "session_id,uuid,discord_id,ip_hash,token_hash,state,created_at,expires_at,processed_at,processed_by,account_generation,notification_count,last_notification_at";

    public CompletableFuture<List<ProtectedAccount>> loadAccounts() {
        return submit(c -> {
            List<ProtectedAccount> out = new ArrayList<>();
            try (PreparedStatement p = c.prepareStatement("SELECT " + ACCOUNT_COLUMNS + " FROM protected_accounts WHERE status<>'REMOVED' ORDER BY uuid"))
            { try (ResultSet r = p.executeQuery()) { while (r.next()) out.add(account(r)); } }
            return out;
        });
    }

    public CompletableFuture<Optional<ProtectedAccount>> findAccount(UUID uuid) {
        return submit(c -> queryAccount(c, uuid));
    }

    private Optional<ProtectedAccount> queryAccount(Connection c, UUID uuid) throws SQLException {
        try (PreparedStatement p = c.prepareStatement("SELECT " + ACCOUNT_COLUMNS + " FROM protected_accounts WHERE uuid=?")) {
            p.setString(1, uuid.toString());
            try (ResultSet r = p.executeQuery()) { return r.next() ? Optional.of(account(r)) : Optional.empty(); }
        }
    }

    public CompletableFuture<Optional<ProtectedAccount>> findAccountByUsername(String username) {
        return submit(c -> {
            try (PreparedStatement p = c.prepareStatement("SELECT " + ACCOUNT_COLUMNS + " FROM protected_accounts WHERE username=? COLLATE NOCASE AND status<>'REMOVED' LIMIT 1")) {
                p.setString(1, username);
                try (ResultSet r = p.executeQuery()) { return r.next() ? Optional.of(account(r)) : Optional.empty(); }
            }
        });
    }

    public CompletableFuture<Boolean> addTrustedIpHash(UUID uuid, String hash, long now, int max) {
        return submit(c -> {
            c.setAutoCommit(false);
            try {
                Optional<ProtectedAccount> account = queryAccount(c, uuid);
                if (account.isEmpty() || !account.get().active()) { c.rollback(); return false; }
                long generation = account.get().securityGeneration();
                try (PreparedStatement exists = c.prepareStatement("SELECT 1 FROM trusted_ips WHERE uuid=? AND ip_hash=? AND security_generation=?")) {
                    exists.setString(1, uuid.toString()); exists.setString(2, hash); exists.setLong(3, generation);
                    try (ResultSet r = exists.executeQuery()) {
                        if (!r.next()) {
                            try (PreparedStatement count = c.prepareStatement("SELECT COUNT(*) FROM trusted_ips WHERE uuid=? AND security_generation=?")) {
                                count.setString(1, uuid.toString()); count.setLong(2, generation);
                                try (ResultSet cr = count.executeQuery()) { cr.next(); if (cr.getLong(1) >= max) { c.rollback(); return false; } }
                            }
                        }
                    }
                }
                try (PreparedStatement p = c.prepareStatement("INSERT INTO trusted_ips(uuid,ip_hash,security_generation,created_at,last_seen_at) VALUES(?,?,?,?,?) ON CONFLICT(uuid,ip_hash) DO UPDATE SET security_generation=excluded.security_generation,last_seen_at=excluded.last_seen_at")) {
                    p.setString(1, uuid.toString()); p.setString(2, hash); p.setLong(3, generation); p.setLong(4, now); p.setLong(5, now);
                    boolean ok = p.executeUpdate() == 1; c.commit(); return ok;
                }
            } catch (Exception e) { try { c.rollback(); } catch (SQLException ignored) { } throw e; }
            finally { c.setAutoCommit(true); }
        });
    }

    public CompletableFuture<Set<String>> loadTrustedIps(UUID uuid) {
        return submit(c -> {
            Set<String> out = new HashSet<>();
            String sql = "SELECT t.ip_hash FROM trusted_ips t JOIN protected_accounts a ON a.uuid=t.uuid " +
                    "WHERE t.uuid=? AND a.status='ACTIVE' AND t.security_generation=a.security_generation";
            try (PreparedStatement p = c.prepareStatement(sql)) {
                p.setString(1, uuid.toString());
                try (ResultSet r = p.executeQuery()) { while (r.next()) out.add(r.getString(1)); }
            }
            return out;
        });
    }

    public CompletableFuture<ProtectedAccount> upsertAccount(UUID uuid, String username, Role role, String discordId, int maxDiscordAccounts) {
        return submit(c -> {
            c.setAutoCommit(false);
            try {
                Optional<ProtectedAccount> current = queryAccount(c, uuid);
                try (PreparedStatement count = c.prepareStatement(
                        "SELECT COUNT(*) FROM protected_accounts WHERE discord_id=? AND uuid<>? AND status<>'REMOVED'")) {
                    count.setString(1, discordId); count.setString(2, uuid.toString());
                    try (ResultSet r = count.executeQuery()) { r.next(); if (r.getLong(1) >= maxDiscordAccounts) throw new IllegalStateException("Discord User ID đã đạt giới hạn protected accounts"); }
                }
                long now = System.currentTimeMillis();
                long generation = current.map(ProtectedAccount::securityGeneration).orElse(1L);
                boolean principalChanged = current.isPresent() &&
                        (!Objects.equals(current.get().discordId(), discordId) || current.get().role() != role || current.get().status() != AccountStatus.ACTIVE);
                if (principalChanged) {
                    generation = safeIncrement(generation);
                    expirePendingForUpdate(c, uuid, now, "system:identity-changed");
                    deleteTrusted(c, uuid);
                    deactivateBan(c, uuid, now);
                }
                String sql = "INSERT INTO protected_accounts(uuid,username,role,discord_id,status,security_generation,created_at,updated_at) " +
                        "VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(uuid) DO UPDATE SET username=excluded.username,role=excluded.role,discord_id=excluded.discord_id,status='ACTIVE',security_generation=excluded.security_generation,updated_at=excluded.updated_at";
                try (PreparedStatement p = c.prepareStatement(sql)) {
                    p.setString(1, uuid.toString()); p.setString(2, username); p.setString(3, role.name()); p.setString(4, discordId);
                    p.setString(5, AccountStatus.ACTIVE.name()); p.setLong(6, generation);
                    p.setLong(7, current.map(ProtectedAccount::createdAt).orElse(now)); p.setLong(8, now); p.executeUpdate();
                }
                ProtectedAccount result = queryAccount(c, uuid).orElseThrow();
                c.commit();
                return result;
            } catch (Exception e) { try { c.rollback(); } catch (SQLException ignored) { } throw e; }
            finally { c.setAutoCommit(true); }
        });
    }

    public CompletableFuture<Boolean> removeAccount(UUID uuid) {
        return submit(c -> {
            c.setAutoCommit(false);
            try {
                Optional<ProtectedAccount> current = queryAccount(c, uuid);
                if (current.isEmpty()) { c.rollback(); return false; }
                long now = System.currentTimeMillis();
                try (PreparedStatement p = c.prepareStatement("UPDATE protected_accounts SET status='REMOVED',security_generation=?,updated_at=? WHERE uuid=?")) {
                    p.setLong(1, safeIncrement(current.get().securityGeneration())); p.setLong(2, now); p.setString(3, uuid.toString()); p.executeUpdate();
                }
                expirePendingForUpdate(c, uuid, now, "system:account-removed");
                deleteTrusted(c, uuid);
                deactivateBan(c, uuid, now);
                c.commit();
                return true;
            } catch (Exception e) { try { c.rollback(); } catch (SQLException ignored) { } throw e; }
            finally { c.setAutoCommit(true); }
        });
    }

    public CompletableFuture<Boolean> resetSecurity(UUID uuid) {
        return submit(c -> {
            c.setAutoCommit(false);
            try {
                Optional<ProtectedAccount> current = queryAccount(c, uuid);
                if (current.isEmpty() || current.get().status() == AccountStatus.REMOVED) { c.rollback(); return false; }
                long now = System.currentTimeMillis();
                long generation = safeIncrement(current.get().securityGeneration());
                try (PreparedStatement p = c.prepareStatement("UPDATE protected_accounts SET security_generation=?,updated_at=? WHERE uuid=?")) {
                    p.setLong(1, generation); p.setLong(2, now); p.setString(3, uuid.toString()); p.executeUpdate();
                }
                expirePendingForUpdate(c, uuid, now, "system:security-reset");
                deleteTrusted(c, uuid);
                deactivateBan(c, uuid, now);
                c.commit();
                return true;
            } catch (Exception e) { try { c.rollback(); } catch (SQLException ignored) { } throw e; }
            finally { c.setAutoCommit(true); }
        });
    }

    public CompletableFuture<Boolean> transitionStatus(UUID uuid, AccountStatus next) {
        return submit(c -> {
            c.setAutoCommit(false);
            try {
                Optional<ProtectedAccount> current = queryAccount(c, uuid);
                if (current.isEmpty() || current.get().status() == next) { c.rollback(); return false; }
                if (current.get().status() == AccountStatus.REMOVED) { c.rollback(); return false; }
                if (current.get().status() == AccountStatus.REVOKED && next != AccountStatus.REMOVED) { c.rollback(); return false; }
                long now = System.currentTimeMillis();
                boolean securityChanged = current.get().status() != next;
                long generation = securityChanged ? safeIncrement(current.get().securityGeneration()) : current.get().securityGeneration();
                try (PreparedStatement p = c.prepareStatement("UPDATE protected_accounts SET status=?,security_generation=?,updated_at=? WHERE uuid=?")) {
                    p.setString(1, next.name()); p.setLong(2, generation); p.setLong(3, now); p.setString(4, uuid.toString()); p.executeUpdate();
                }
                if (securityChanged) {
                    expirePendingForUpdate(c, uuid, now, "system:status-changed");
                    deleteTrusted(c, uuid);
                    if (next != AccountStatus.ACTIVE) deactivateBan(c, uuid, now);
                }
                c.commit(); return true;
            } catch (Exception e) { try { c.rollback(); } catch (SQLException ignored) { } throw e; }
            finally { c.setAutoCommit(true); }
        });
    }

    public enum TrustedLoginDecision {
        ACCOUNT_NOT_AUTHORIZABLE,
        TEMPORARY_SECURITY_BLOCK,
        NOT_TRUSTED,
        TRUSTED
    }

    




    public CompletableFuture<TrustedLoginDecision> authorizeTrustedLogin(UUID uuid, String ipHash, long now) {
        return submit(c -> {
            c.setAutoCommit(false);
            try {
                Optional<ProtectedAccount> account = queryAccount(c, uuid);
                if (account.isEmpty() || !account.get().active()) { c.rollback(); return TrustedLoginDecision.ACCOUNT_NOT_AUTHORIZABLE; }

                try (PreparedStatement ban = c.prepareStatement("SELECT active,expires_at FROM managed_bans WHERE uuid=? LIMIT 1")) {
                    ban.setString(1, uuid.toString());
                    try (ResultSet r = ban.executeQuery()) {
                        if (r.next()) {
                            boolean active = r.getInt(1) == 1;
                            long expiresAt = r.getLong(2);
                            if (active && expiresAt > now) {
                                c.rollback();
                                return TrustedLoginDecision.TEMPORARY_SECURITY_BLOCK;
                            }
                            if (active) deactivateBan(c, uuid, now);
                        }
                    }
                }

                String trustSql = "SELECT 1 FROM trusted_ips WHERE uuid=? AND ip_hash=? AND security_generation=? LIMIT 1";
                try (PreparedStatement p = c.prepareStatement(trustSql)) {
                    p.setString(1, uuid.toString()); p.setString(2, ipHash); p.setLong(3, account.get().securityGeneration());
                    try (ResultSet r = p.executeQuery()) {
                        if (!r.next()) { c.rollback(); return TrustedLoginDecision.NOT_TRUSTED; }
                    }
                }

                try (PreparedStatement p = c.prepareStatement("UPDATE protected_accounts SET last_seen_ip_hash=?,last_seen_at=?,updated_at=? WHERE uuid=? AND status='ACTIVE' AND security_generation=?")) {
                    p.setString(1, ipHash); p.setLong(2, now); p.setLong(3, now); p.setString(4, uuid.toString()); p.setLong(5, account.get().securityGeneration());
                    if (p.executeUpdate() != 1) { c.rollback(); return TrustedLoginDecision.ACCOUNT_NOT_AUTHORIZABLE; }
                }
                c.commit();
                return TrustedLoginDecision.TRUSTED;
            } catch (Exception e) { try { c.rollback(); } catch (SQLException ignored) { } throw e; }
            finally { c.setAutoCommit(true); }
        });
    }

    public CompletableFuture<Optional<VerificationSession>> findPendingSession(UUID uuid) {
        return submit(c -> queryPending(c, uuid, System.currentTimeMillis()));
    }

    private Optional<VerificationSession> queryPending(Connection c, UUID uuid, long now) throws SQLException {
        String sql = "SELECT " + SESSION_COLUMNS + " FROM verification_sessions WHERE uuid=? AND state='PENDING' AND expires_at>? ORDER BY created_at DESC LIMIT 1";
        try (PreparedStatement p = c.prepareStatement(sql)) {
            p.setString(1, uuid.toString()); p.setLong(2, now);
            try (ResultSet r = p.executeQuery()) { return r.next() ? Optional.of(session(r)) : Optional.empty(); }
        }
    }

    public CompletableFuture<Long> pendingCount() {
        return submit(c -> {
            try (PreparedStatement p = c.prepareStatement("SELECT COUNT(*) FROM verification_sessions WHERE state='PENDING' AND expires_at>?")) {
                p.setLong(1, System.currentTimeMillis()); try (ResultSet r = p.executeQuery()) { r.next(); return r.getLong(1); }
            }
        });
    }

    public CompletableFuture<Optional<VerificationSession>> createVerificationSession(UUID uuid, String discord, String ipHash, String tokenHash,
                                                                                       long created, long expires, int maxPending, long banExpiresAt) {
        return submit(c -> {
            c.setAutoCommit(false);
            try {
                long now = System.currentTimeMillis();
                expireExpiredSessions(c, now);
                Optional<ProtectedAccount> account = queryAccount(c, uuid);
                if (account.isEmpty() || !account.get().active()) { c.rollback(); return Optional.empty(); }
                Optional<VerificationSession> existing = queryPending(c, uuid, now);
                if (existing.isPresent()) {
                    VerificationSession pending = existing.get();
                    if (pending.accountGeneration() != account.get().securityGeneration() || !Objects.equals(pending.discordId(), account.get().discordId())) {
                        expirePendingForUpdate(c, uuid, now, "system:identity-mismatch");
                        existing = Optional.empty();
                    } else if (pending.ipHash().equals(ipHash)) {
                        upsertBan(c, uuid, Math.max(banExpiresAt, now + 1000), now);
                        c.commit(); return existing;
                    } else {
                        expirePendingForUpdate(c, uuid, now, "system:ip-changed");
                        existing = Optional.empty();
                    }
                }
                try (PreparedStatement count = c.prepareStatement("SELECT COUNT(*) FROM verification_sessions WHERE state='PENDING' AND expires_at>?")) {
                    count.setLong(1, now);
                    try (ResultSet r = count.executeQuery()) { r.next(); if (r.getLong(1) >= maxPending) { c.commit(); return Optional.empty(); } }
                }
                UUID id = UUID.randomUUID();
                String insert = "INSERT INTO verification_sessions(session_id,uuid,discord_id,ip_hash,token_hash,state,created_at,expires_at,account_generation,notification_count) VALUES(?,?,?,?,?,?,?,?,?,0)";
                try (PreparedStatement p = c.prepareStatement(insert)) {
                    p.setString(1, id.toString()); p.setString(2, uuid.toString()); p.setString(3, account.get().discordId()); p.setString(4, ipHash); p.setString(5, tokenHash);
                    p.setString(6, VerificationState.PENDING.name()); p.setLong(7, created); p.setLong(8, expires); p.setLong(9, account.get().securityGeneration()); p.executeUpdate();
                }
                upsertBan(c, uuid, Math.max(banExpiresAt, now + 1000), now);
                c.commit();
                return Optional.of(new VerificationSession(id, uuid, account.get().discordId(), ipHash, tokenHash, VerificationState.PENDING,
                        created, expires, null, null, account.get().securityGeneration(), 0, null));
            } catch (Exception e) { try { c.rollback(); } catch (SQLException ignored) { } throw e; }
            finally { c.setAutoCommit(true); }
        });
    }

    public CompletableFuture<Optional<VerificationSession>> claimNotification(UUID id, long now, long cooldownMs, int maxNotifications) {
        return submit(c -> {
            c.setAutoCommit(false);
            try {
                String sql = "UPDATE verification_sessions SET notification_count=notification_count+1,last_notification_at=? " +
                        "WHERE session_id=? AND state='PENDING' AND expires_at>? AND notification_count<? AND (last_notification_at IS NULL OR last_notification_at<=?) " +
                        "AND EXISTS (SELECT 1 FROM protected_accounts a WHERE a.uuid=verification_sessions.uuid AND a.status='ACTIVE' " +
                        "AND a.security_generation=verification_sessions.account_generation AND a.discord_id=verification_sessions.discord_id)";
                try (PreparedStatement p = c.prepareStatement(sql)) {
                    p.setLong(1, now); p.setString(2, id.toString()); p.setLong(3, now); p.setInt(4, maxNotifications); p.setLong(5, now - cooldownMs);
                    if (p.executeUpdate() != 1) { c.rollback(); return Optional.empty(); }
                }
                Optional<VerificationSession> out = querySession(c, id);
                c.commit(); return out;
            } catch (Exception e) { try { c.rollback(); } catch (SQLException ignored) { } throw e; }
            finally { c.setAutoCommit(true); }
        });
    }

    public CompletableFuture<Optional<VerificationSession>> findSession(UUID id) { return submit(c -> querySession(c, id)); }

    private Optional<VerificationSession> querySession(Connection c, UUID id) throws SQLException {
        try (PreparedStatement p = c.prepareStatement("SELECT " + SESSION_COLUMNS + " FROM verification_sessions WHERE session_id=?")) {
            p.setString(1, id.toString()); try (ResultSet r = p.executeQuery()) { return r.next() ? Optional.of(session(r)) : Optional.empty(); }
        }
    }

    public CompletableFuture<Optional<VerificationSession>> consumeSession(UUID id, VerificationState next, String actor) {
        if (next == VerificationState.PENDING || next == VerificationState.APPROVED) throw new IllegalArgumentException("Invalid consume state");
        return submit(c -> {
            c.setAutoCommit(false);
            try {
                long now = System.currentTimeMillis();
                try (PreparedStatement p = c.prepareStatement("UPDATE verification_sessions SET state=?,processed_at=?,processed_by=? WHERE session_id=? AND state='PENDING' AND expires_at>?")) {
                    p.setString(1, next.name()); p.setLong(2, now); p.setString(3, actor); p.setString(4, id.toString()); p.setLong(5, now);
                    if (p.executeUpdate() != 1) { c.rollback(); return Optional.empty(); }
                }
                Optional<VerificationSession> out = querySession(c, id);
                c.commit(); return out;
            } catch (Exception e) { try { c.rollback(); } catch (SQLException ignored) { } throw e; }
            finally { c.setAutoCommit(true); }
        });
    }

    public CompletableFuture<Optional<VerificationSession>> approveSession(UUID sessionId, String actor, long now, int maxTrustedIps) {
        return submit(c -> {
            c.setAutoCommit(false);
            try {
                VerificationSession session = querySession(c, sessionId).orElse(null);
                if (session == null || !session.pendingAndUnexpired(now)) { c.rollback(); return Optional.empty(); }
                ProtectedAccount account = queryAccount(c, session.uuid()).orElse(null);
                if (account == null || !account.active() || account.securityGeneration() != session.accountGeneration() || !Objects.equals(account.discordId(), session.discordId())) { c.rollback(); return Optional.empty(); }
                try (PreparedStatement p = c.prepareStatement("UPDATE verification_sessions SET state='APPROVED',processed_at=?,processed_by=? WHERE session_id=? AND state='PENDING' AND expires_at>? AND account_generation=?")) {
                    p.setLong(1, now); p.setString(2, actor); p.setString(3, sessionId.toString()); p.setLong(4, now); p.setLong(5, account.securityGeneration());
                    if (p.executeUpdate() != 1) { c.rollback(); return Optional.empty(); }
                }
                ensureTrustedIpSlot(c, session.uuid(), session.ipHash(), account.securityGeneration(), maxTrustedIps);
                try (PreparedStatement p = c.prepareStatement("INSERT INTO trusted_ips(uuid,ip_hash,security_generation,created_at,last_seen_at) VALUES(?,?,?,?,?) ON CONFLICT(uuid,ip_hash) DO UPDATE SET security_generation=excluded.security_generation,last_seen_at=excluded.last_seen_at")) {
                    p.setString(1, session.uuid().toString()); p.setString(2, session.ipHash()); p.setLong(3, account.securityGeneration()); p.setLong(4, now); p.setLong(5, now); p.executeUpdate();
                }
                try (PreparedStatement p = c.prepareStatement("UPDATE protected_accounts SET last_seen_ip_hash=?,last_seen_at=?,updated_at=? WHERE uuid=? AND status='ACTIVE' AND security_generation=?")) {
                    p.setString(1, session.ipHash()); p.setLong(2, now); p.setLong(3, now); p.setString(4, session.uuid().toString()); p.setLong(5, account.securityGeneration());
                    if (p.executeUpdate() != 1) { c.rollback(); return Optional.empty(); }
                }
                deactivateBan(c, session.uuid(), now);
                c.commit();
                return Optional.of(new VerificationSession(session.sessionId(), session.uuid(), session.discordId(), session.ipHash(), session.tokenHash(),
                        VerificationState.APPROVED, session.createdAt(), session.expiresAt(), now, actor, session.accountGeneration(), session.notificationCount(), session.lastNotificationAt()));
            } catch (Exception e) { try { c.rollback(); } catch (SQLException ignored) { } throw e; }
            finally { c.setAutoCommit(true); }
        });
    }

    private static void ensureTrustedIpSlot(Connection c, UUID uuid, String hash, long generation, int max) throws SQLException {
        if (max < 1) throw new IllegalArgumentException("max trusted IPs must be positive");
        try (PreparedStatement p = c.prepareStatement("SELECT 1 FROM trusted_ips WHERE uuid=? AND ip_hash=? AND security_generation=?")) {
            p.setString(1, uuid.toString()); p.setString(2, hash); p.setLong(3, generation);
            try (ResultSet r = p.executeQuery()) { if (r.next()) return; }
        }
        try (PreparedStatement p = c.prepareStatement("SELECT COUNT(*) FROM trusted_ips WHERE uuid=? AND security_generation=?")) {
            p.setString(1, uuid.toString()); p.setLong(2, generation);
            try (ResultSet r = p.executeQuery()) { r.next(); if (r.getLong(1) < max) return; }
        }
        try (PreparedStatement p = c.prepareStatement("DELETE FROM trusted_ips WHERE uuid=? AND ip_hash=(SELECT ip_hash FROM trusted_ips WHERE uuid=? AND security_generation=? ORDER BY last_seen_at ASC,created_at ASC LIMIT 1)")) {
            p.setString(1, uuid.toString()); p.setString(2, uuid.toString()); p.setLong(3, generation); p.executeUpdate();
        }
    }

    public CompletableFuture<Integer> expirePendingForUuid(UUID uuid, String reason) {
        return submit(c -> {
            long now = System.currentTimeMillis();
            try (PreparedStatement p = c.prepareStatement("UPDATE verification_sessions SET state='EXPIRED',processed_at=?,processed_by=? WHERE uuid=? AND state='PENDING'")) {
                p.setLong(1, now); p.setString(2, reason); p.setString(3, uuid.toString()); return p.executeUpdate();
            }
        });
    }

    public CompletableFuture<Integer> expireSessions() {
        return submit(c -> {
            long now = System.currentTimeMillis();
            try (PreparedStatement p = c.prepareStatement("UPDATE verification_sessions SET state='EXPIRED',processed_at=?,processed_by='system:expired' WHERE state='PENDING' AND expires_at<=?")) {
                p.setLong(1, now); p.setLong(2, now); return p.executeUpdate();
            }
        });
    }

    public CompletableFuture<Boolean> setBan(UUID uuid, String marker, long expires) {
        return submit(c -> {
            c.setAutoCommit(false);
            try {
                Optional<ProtectedAccount> account = queryAccount(c, uuid);
                if (account.isEmpty() || !account.get().active()) { c.rollback(); return false; }
                long now = System.currentTimeMillis();
                upsertBan(c, uuid, expires, now);
                c.commit();
                return true;
            } catch (Exception e) { try { c.rollback(); } catch (SQLException ignored) { } throw e; }
            finally { c.setAutoCommit(true); }
        });
    }

    public CompletableFuture<Optional<ManagedBan>> findBan(UUID uuid) {
        return submit(c -> {
            try (PreparedStatement p = c.prepareStatement("SELECT uuid,marker,expires_at,active,created_at,removed_at FROM managed_bans WHERE uuid=?")) {
                p.setString(1, uuid.toString());
                try (ResultSet r = p.executeQuery()) {
                    if (!r.next()) return Optional.empty();
                    return Optional.of(new ManagedBan(UUID.fromString(r.getString(1)), r.getString(2), r.getLong(3), r.getInt(4) == 1, r.getLong(5), (Long) r.getObject(6)));
                }
            }
        });
    }

    public CompletableFuture<Boolean> removeBan(UUID uuid) {
        return submit(c -> { return deactivateBan(c, uuid, System.currentTimeMillis()); });
    }

    private static boolean deactivateBan(Connection c, UUID uuid, long now) throws SQLException {
        try (PreparedStatement p = c.prepareStatement("UPDATE managed_bans SET active=0,removed_at=? WHERE uuid=? AND active=1")) {
            p.setLong(1, now); p.setString(2, uuid.toString()); return p.executeUpdate() == 1;
        }
    }

    private static void upsertBan(Connection c, UUID uuid, long expires, long now) throws SQLException {
        try (PreparedStatement p = c.prepareStatement("INSERT INTO managed_bans(uuid,marker,expires_at,active,created_at,removed_at) VALUES(?,?,?,?,?,NULL) ON CONFLICT(uuid) DO UPDATE SET expires_at=excluded.expires_at,active=1,created_at=excluded.created_at,removed_at=NULL,marker=excluded.marker")) {
            p.setString(1, uuid.toString()); p.setString(2, "AP-StaffGuard"); p.setLong(3, expires); p.setInt(4, 1); p.setLong(5, now); p.executeUpdate();
        }
    }

    public CompletableFuture<Void> cleanupExpiredBans() { return execute(c -> { long n = System.currentTimeMillis(); try (PreparedStatement p = c.prepareStatement("UPDATE managed_bans SET active=0,removed_at=? WHERE active=1 AND expires_at<=?")) { p.setLong(1,n); p.setLong(2,n); p.executeUpdate(); } }); }

    public CompletableFuture<Void> audit(SecurityEvent e) {
        return execute(c -> {
            String sql = "INSERT INTO audit_log(timestamp,uuid,role,event,result,reason,verification_id,ip_hash) VALUES(?,?,?,?,?,?,?,?)";
            try (PreparedStatement p = c.prepareStatement(sql)) {
                p.setLong(1, e.timestamp()); p.setString(2, e.uuid() == null ? null : e.uuid().toString()); p.setString(3, e.role() == null ? null : e.role().name());
                p.setString(4, e.event().name()); p.setString(5, e.result()); p.setString(6, e.reason()); p.setString(7, e.verificationId() == null ? null : e.verificationId().toString()); p.setString(8, e.ipHash()); p.executeUpdate();
            }
        });
    }

    public CompletableFuture<List<String>> logs(UUID uuid, int limit) {
        return submit(c -> {
            int bounded = Math.max(1, Math.min(limit, 100));
            List<String> out = new ArrayList<>();
            try (PreparedStatement p = c.prepareStatement("SELECT timestamp,event,result,reason,verification_id FROM audit_log WHERE uuid=? ORDER BY timestamp DESC,id DESC LIMIT ?")) {
                p.setString(1, uuid.toString()); p.setInt(2, bounded);
                try (ResultSet r = p.executeQuery()) {
                    while (r.next()) out.add(java.time.Instant.ofEpochMilli(r.getLong(1)) + " | " + r.getString(2) + " | " + r.getString(3) + " | " + r.getString(4) + (r.getString(5) == null ? "" : " | " + r.getString(5)));
                }
            }
            return out;
        });
    }

    public CompletableFuture<Integer> cleanupAudit(long retentionMs) {
        return submit(c -> {
            long cutoff = System.currentTimeMillis() - retentionMs;
            try (PreparedStatement p = c.prepareStatement("DELETE FROM audit_log WHERE timestamp<?")) { p.setLong(1, cutoff); return p.executeUpdate(); }
        });
    }

    private static void expirePendingForUpdate(Connection c, UUID uuid, long now, String reason) throws SQLException {
        try (PreparedStatement p = c.prepareStatement("UPDATE verification_sessions SET state='EXPIRED',processed_at=?,processed_by=? WHERE uuid=? AND state='PENDING'")) {
            p.setLong(1, now); p.setString(2, reason); p.setString(3, uuid.toString()); p.executeUpdate();
        }
    }

    private static void expireExpiredSessions(Connection c, long now) throws SQLException {
        try (PreparedStatement p = c.prepareStatement("UPDATE verification_sessions SET state='EXPIRED',processed_at=?,processed_by='system:expired' WHERE state='PENDING' AND expires_at<=?")) {
            p.setLong(1, now); p.setLong(2, now); p.executeUpdate();
        }
    }

    private static void deleteTrusted(Connection c, UUID uuid) throws SQLException {
        try (PreparedStatement p = c.prepareStatement("DELETE FROM trusted_ips WHERE uuid=?")) { p.setString(1, uuid.toString()); p.executeUpdate(); }
    }

    private static long safeIncrement(long generation) {
        if (generation == Long.MAX_VALUE) throw new IllegalStateException("Security generation exhausted");
        return generation + 1;
    }
}
