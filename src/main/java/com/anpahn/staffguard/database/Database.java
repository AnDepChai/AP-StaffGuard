package com.anpahn.staffguard.database;

import com.anpahn.staffguard.model.*;
import org.bukkit.plugin.java.JavaPlugin;

import java.io.File;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.sql.*;
import java.util.*;
import java.util.concurrent.*;

public final class Database implements AutoCloseable {
    private final JavaPlugin plugin;
    private final File file;
    private final ExecutorService executor;
    private volatile Connection connection;

    public Database(JavaPlugin plugin, File file) {
        this.plugin = plugin;
        this.file = file;
        this.executor = Executors.newSingleThreadExecutor(r -> {
            Thread t = new Thread(r, "AP-StaffGuard-DB");
            t.setDaemon(true);
            return t;
        });
    }

    public void start() throws SQLException {
        File parent = file.getParentFile();
        if (parent != null) parent.mkdirs();
        connection = DriverManager.getConnection("jdbc:sqlite:" + file.getAbsolutePath());
        try (Statement s = connection.createStatement()) {
            s.execute("PRAGMA foreign_keys=ON");
            s.execute("PRAGMA journal_mode=WAL");
            s.execute("PRAGMA busy_timeout=5000");
        }
        migrate();
    }

    public CompletableFuture<Void> startAsync() {
        return CompletableFuture.runAsync(() -> {
            try { start(); } catch (SQLException e) { throw new CompletionException(e); }
        }, executor);
    }

    private static List<String> splitSqlStatements(String sql) {
        List<String> statements = new ArrayList<>();
        StringBuilder current = new StringBuilder();
        boolean singleQuote = false;
        boolean doubleQuote = false;
        boolean lineComment = false;
        boolean blockComment = false;

        for (int i = 0; i < sql.length(); i++) {
            char ch = sql.charAt(i);
            char next = i + 1 < sql.length() ? sql.charAt(i + 1) : '\0';

            if (lineComment) {
                current.append(ch);
                if (ch == '\n' || ch == '\r') lineComment = false;
                continue;
            }
            if (blockComment) {
                current.append(ch);
                if (ch == '*' && next == '/') {
                    current.append(next);
                    i++;
                    blockComment = false;
                }
                continue;
            }
            if (!singleQuote && !doubleQuote && ch == '-' && next == '-') {
                current.append(ch).append(next);
                i++;
                lineComment = true;
                continue;
            }
            if (!singleQuote && !doubleQuote && ch == '/' && next == '*') {
                current.append(ch).append(next);
                i++;
                blockComment = true;
                continue;
            }
            if (ch == '\'' && !doubleQuote) {
                current.append(ch);
                if (singleQuote && next == '\'') {
                    current.append(next);
                    i++;
                } else {
                    singleQuote = !singleQuote;
                }
                continue;
            }
            if (ch == '"' && !singleQuote) {
                current.append(ch);
                if (doubleQuote && next == '"') {
                    current.append(next);
                    i++;
                } else {
                    doubleQuote = !doubleQuote;
                }
                continue;
            }
            if (ch == ';' && !singleQuote && !doubleQuote) {
                statements.add(current.toString());
                current.setLength(0);
            } else {
                current.append(ch);
            }
        }
        if (!current.isEmpty()) statements.add(current.toString());
        return statements;
    }

    private void migrate() throws SQLException {
        try (Statement s = connection.createStatement()) {
            s.execute("CREATE TABLE IF NOT EXISTS schema_version(version INTEGER PRIMARY KEY)");
            int version = 0;
            try (PreparedStatement q = connection.prepareStatement("SELECT version FROM schema_version ORDER BY version DESC LIMIT 1"); ResultSet rs = q.executeQuery()) {
                if (rs.next()) version = rs.getInt(1);
            }
            if (version < 1) {
                InputStream stream = plugin.getResource("migrations/001_initial.sql");
                if (stream == null) throw new SQLException("Missing database migration resource");
                String sql;
                try (stream) {
                    sql = new String(stream.readAllBytes(), StandardCharsets.UTF_8);
                } catch (java.io.IOException e) {
                    throw new SQLException("Failed to read database migration resource", e);
                }
                for (String statement : splitSqlStatements(sql)) {
                    if (!statement.isBlank()) s.execute(statement);
                }
                s.execute("INSERT INTO schema_version(version) VALUES(1)");
            }
        }
    }

    public <T> CompletableFuture<T> submit(SqlFunction<T> fn) {
        return CompletableFuture.supplyAsync(() -> {
            try {
                if (connection == null || connection.isClosed()) throw new SQLException("Database is not ready");
                return fn.apply(connection);
            } catch (Exception e) {
                throw new CompletionException(e);
            }
        }, executor);
    }

    public CompletableFuture<Void> execute(SqlConsumer fn) { return submit(c -> { fn.accept(c); return null; }); }
    @FunctionalInterface public interface SqlFunction<T> { T apply(Connection c) throws Exception; }
    @FunctionalInterface public interface SqlConsumer { void accept(Connection c) throws Exception; }

    public void close() {
        executor.shutdown();
        try {
            if (!executor.awaitTermination(5, TimeUnit.SECONDS)) {
                plugin.getLogger().warning("Database executor did not terminate within 5 seconds; pending DB tasks may be interrupted during shutdown.");
                executor.shutdownNow();
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            plugin.getLogger().warning("Interrupted while waiting for the database executor to terminate.");
            executor.shutdownNow();
        }
        try { if (connection != null) connection.close(); }
        catch (SQLException e) { plugin.getLogger().warning("Failed to close database: " + e.getMessage()); }
    }

    public CompletableFuture<List<ProtectedAccount>> loadAccounts() {
        return submit(c -> {
            List<ProtectedAccount> out = new ArrayList<>();
            String sql = "SELECT uuid,username,role,discord_id,status,last_seen_ip_hash,created_at,updated_at,last_seen_at FROM protected_accounts WHERE status<> 'REMOVED'";
            try (PreparedStatement ps = c.prepareStatement(sql); ResultSet rs = ps.executeQuery()) {
                while (rs.next()) out.add(account(rs));
            }
            return out;
        });
    }

    private static ProtectedAccount account(ResultSet r) throws SQLException {
        return new ProtectedAccount(UUID.fromString(r.getString(1)), r.getString(2), Role.valueOf(r.getString(3)), r.getString(4),
                AccountStatus.valueOf(r.getString(5)), r.getString(6), r.getLong(7), r.getLong(8), (Long) r.getObject(9));
    }

    public CompletableFuture<Optional<ProtectedAccount>> findAccount(UUID uuid) {
        return submit(c -> {
            try (PreparedStatement ps = c.prepareStatement("SELECT uuid,username,role,discord_id,status,last_seen_ip_hash,created_at,updated_at,last_seen_at FROM protected_accounts WHERE uuid=?")) {
                ps.setString(1, uuid.toString());
                try (ResultSet rs = ps.executeQuery()) { return rs.next() ? Optional.of(account(rs)) : Optional.empty(); }
            }
        });
    }

    public CompletableFuture<Set<String>> loadTrustedIps(UUID uuid) {
        return submit(c -> {
            Set<String> out = new HashSet<>();
            try (PreparedStatement ps = c.prepareStatement("SELECT ip_hash FROM trusted_ips WHERE uuid=?")) {
                ps.setString(1, uuid.toString());
                try (ResultSet rs = ps.executeQuery()) { while (rs.next()) out.add(rs.getString(1)); }
            }
            return out;
        });
    }

    public CompletableFuture<Long> countAccountsForDiscordExcept(String discordId, UUID excludedUuid) {
        return submit(c -> {
            try (PreparedStatement ps = c.prepareStatement("SELECT COUNT(*) FROM protected_accounts WHERE discord_id=? AND uuid<>? AND status<>'REMOVED'")) {
                ps.setString(1, discordId);
                ps.setString(2, excludedUuid.toString());
                try (ResultSet rs = ps.executeQuery()) { rs.next(); return rs.getLong(1); }
            }
        });
    }

    public CompletableFuture<Boolean> addTrustedIpHash(UUID uuid, String hash, long now, int max) {
        return submit(c -> {
            c.setAutoCommit(false);
            try {
                ensureTrustedIpSlot(c, uuid, hash, max);
                try (PreparedStatement q = c.prepareStatement(
                        "INSERT INTO trusted_ips(uuid,ip_hash,created_at,last_seen_at) VALUES(?,?,?,?) " +
                        "ON CONFLICT(uuid,ip_hash) DO UPDATE SET last_seen_at=excluded.last_seen_at")) {
                    q.setString(1, uuid.toString());
                    q.setString(2, hash);
                    q.setLong(3, now);
                    q.setLong(4, now);
                    q.executeUpdate();
                }
                c.commit();
                return true;
            } catch (Exception e) {
                c.rollback();
                throw e;
            } finally {
                c.setAutoCommit(true);
            }
        });
    }

    public CompletableFuture<Boolean> removeTrustedIp(UUID uuid, String hash) {
        return submit(c -> {
            try (PreparedStatement ps = c.prepareStatement("DELETE FROM trusted_ips WHERE uuid=? AND ip_hash=?")) {
                ps.setString(1, uuid.toString()); ps.setString(2, hash); return ps.executeUpdate() > 0;
            }
        });
    }

    public CompletableFuture<ProtectedAccount> upsertAccount(UUID uuid, String username, Role role, String discordId) {
        return submit(c -> {
            long now = System.currentTimeMillis(); c.setAutoCommit(false);
            try {
                String sql = "INSERT INTO protected_accounts(uuid,username,role,discord_id,status,created_at,updated_at) VALUES(?,?,?,?,?,?,?) " +
                        "ON CONFLICT(uuid) DO UPDATE SET username=excluded.username,role=excluded.role,discord_id=excluded.discord_id,status='ACTIVE',updated_at=excluded.updated_at";
                try (PreparedStatement ps = c.prepareStatement(sql)) {
                    ps.setString(1, uuid.toString()); ps.setString(2, username); ps.setString(3, role.name()); ps.setString(4, discordId);
                    ps.setString(5, AccountStatus.ACTIVE.name()); ps.setLong(6, now); ps.setLong(7, now); ps.executeUpdate();
                }
                c.commit(); return queryAccount(c, uuid).orElseThrow();
            } catch (Exception e) { c.rollback(); throw e; }
            finally { c.setAutoCommit(true); }
        });
    }

    private Optional<ProtectedAccount> queryAccount(Connection c, UUID uuid) throws SQLException {
        try (PreparedStatement ps = c.prepareStatement("SELECT uuid,username,role,discord_id,status,last_seen_ip_hash,created_at,updated_at,last_seen_at FROM protected_accounts WHERE uuid=?")) {
            ps.setString(1, uuid.toString()); try (ResultSet rs = ps.executeQuery()) { return rs.next() ? Optional.of(account(rs)) : Optional.empty(); }
        }
    }

    public CompletableFuture<Boolean> removeAccount(UUID uuid) {
        return submit(c -> {
            try (PreparedStatement ps = c.prepareStatement("UPDATE protected_accounts SET status='REMOVED',updated_at=? WHERE uuid=?")) {
                ps.setLong(1, System.currentTimeMillis()); ps.setString(2, uuid.toString()); return ps.executeUpdate() > 0;
            }
        });
    }

    public CompletableFuture<Void> updateLastSeen(UUID uuid, String ipHash) {
        return execute(c -> {
            try (PreparedStatement ps = c.prepareStatement("UPDATE protected_accounts SET last_seen_ip_hash=?,last_seen_at=?,updated_at=? WHERE uuid=? AND status='ACTIVE'")) {
                long n = System.currentTimeMillis(); ps.setString(1, ipHash); ps.setLong(2, n); ps.setLong(3, n); ps.setString(4, uuid.toString()); ps.executeUpdate();
            }
        });
    }

    public CompletableFuture<Optional<VerificationSession>> findPending(UUID uuid) {
        return submit(c -> {
            String sql = "SELECT session_id,uuid,discord_id,ip_hash,token_hash,state,created_at,expires_at,processed_at,processed_by FROM verification_sessions WHERE uuid=? AND state='PENDING' AND expires_at>? ORDER BY created_at DESC LIMIT 1";
            try (PreparedStatement ps = c.prepareStatement(sql)) {
                ps.setString(1, uuid.toString());
                ps.setLong(2, System.currentTimeMillis());
                try (ResultSet rs = ps.executeQuery()) { return rs.next() ? Optional.of(session(rs)) : Optional.empty(); }
            }
        });
    }

    public CompletableFuture<Integer> expirePendingForUuid(UUID uuid) {
        return submit(c -> {
            try (PreparedStatement ps = c.prepareStatement(
                    "UPDATE verification_sessions SET state='EXPIRED',processed_at=?,processed_by=? WHERE uuid=? AND state='PENDING'")) {
                long now = System.currentTimeMillis();
                ps.setLong(1, now);
                ps.setString(2, "system:ip-changed");
                ps.setString(3, uuid.toString());
                return ps.executeUpdate();
            }
        });
    }

    private static VerificationSession session(ResultSet r) throws SQLException {
        return new VerificationSession(UUID.fromString(r.getString(1)), UUID.fromString(r.getString(2)), r.getString(3), r.getString(4), r.getString(5), VerificationState.valueOf(r.getString(6)), r.getLong(7), r.getLong(8), (Long) r.getObject(9), r.getString(10));
    }

    public CompletableFuture<Long> pendingCount() { return submit(c -> { try (PreparedStatement ps = c.prepareStatement("SELECT COUNT(*) FROM verification_sessions WHERE state='PENDING' AND expires_at>?")) { ps.setLong(1, System.currentTimeMillis()); try (ResultSet rs=ps.executeQuery()){rs.next();return rs.getLong(1);} } }); }

    public CompletableFuture<Optional<VerificationSession>> createVerificationSession(
            UUID uuid, String discord, String ipHash, String tokenHash, long created, long expires, int maxPending) {
        return submit(c -> {
            c.setAutoCommit(false);
            try {
                long now = System.currentTimeMillis();

                try (PreparedStatement ps = c.prepareStatement(
                        "UPDATE verification_sessions SET state='EXPIRED',processed_at=?,processed_by=? WHERE state='PENDING' AND expires_at<=?")) {
                    ps.setLong(1, now);
                    ps.setString(2, "system:expired");
                    ps.setLong(3, now);
                    ps.executeUpdate();
                }

                Optional<VerificationSession> existing = Optional.empty();
                try (PreparedStatement ps = c.prepareStatement(
                        "SELECT session_id,uuid,discord_id,ip_hash,token_hash,state,created_at,expires_at,processed_at,processed_by " +
                        "FROM verification_sessions WHERE uuid=? AND state='PENDING' AND expires_at>? ORDER BY created_at DESC LIMIT 1")) {
                    ps.setString(1, uuid.toString());
                    ps.setLong(2, now);
                    try (ResultSet rs = ps.executeQuery()) {
                        if (rs.next()) existing = Optional.of(session(rs));
                    }
                }

                if (existing.isPresent()) {
                    VerificationSession pending = existing.get();
                    if (pending.ipHash().equals(ipHash)) {
                        c.commit();
                        return existing;
                    }
                    try (PreparedStatement ps = c.prepareStatement(
                            "UPDATE verification_sessions SET state='EXPIRED',processed_at=?,processed_by=? WHERE uuid=? AND state='PENDING'")) {
                        ps.setLong(1, now);
                        ps.setString(2, "system:ip-changed");
                        ps.setString(3, uuid.toString());
                        ps.executeUpdate();
                    }
                }

                try (PreparedStatement ps = c.prepareStatement(
                        "SELECT COUNT(*) FROM verification_sessions WHERE state='PENDING' AND expires_at>?")) {
                    ps.setLong(1, now);
                    try (ResultSet rs = ps.executeQuery()) {
                        rs.next();
                        if (rs.getLong(1) >= maxPending) {
                            c.commit();
                            return Optional.empty();
                        }
                    }
                }

                UUID id = UUID.randomUUID();
                try (PreparedStatement ps = c.prepareStatement(
                        "INSERT INTO verification_sessions(session_id,uuid,discord_id,ip_hash,token_hash,state,created_at,expires_at) VALUES(?,?,?,?,?,?,?,?)")) {
                    ps.setString(1, id.toString());
                    ps.setString(2, uuid.toString());
                    ps.setString(3, discord);
                    ps.setString(4, ipHash);
                    ps.setString(5, tokenHash);
                    ps.setString(6, VerificationState.PENDING.name());
                    ps.setLong(7, created);
                    ps.setLong(8, expires);
                    ps.executeUpdate();
                }

                VerificationSession createdSession = new VerificationSession(id, uuid, discord, ipHash, tokenHash,
                        VerificationState.PENDING, created, expires, null, null);
                c.commit();
                return Optional.of(createdSession);
            } catch (Exception ex) {
                c.rollback();
                throw ex;
            } finally {
                c.setAutoCommit(true);
            }
        });
    }

    public CompletableFuture<VerificationSession> createSession(UUID uuid, String discord, String ipHash, String tokenHash, long created, long expires) {
        return submit(c -> {
            UUID id=UUID.randomUUID(); String sql="INSERT INTO verification_sessions(session_id,uuid,discord_id,ip_hash,token_hash,state,created_at,expires_at) VALUES(?,?,?,?,?,?,?,?)";
            try(PreparedStatement ps=c.prepareStatement(sql)){ps.setString(1,id.toString());ps.setString(2,uuid.toString());ps.setString(3,discord);ps.setString(4,ipHash);ps.setString(5,tokenHash);ps.setString(6,VerificationState.PENDING.name());ps.setLong(7,created);ps.setLong(8,expires);ps.executeUpdate();}
            return new VerificationSession(id,uuid,discord,ipHash,tokenHash,VerificationState.PENDING,created,expires,null,null);
        });
    }

    public CompletableFuture<Optional<VerificationSession>> findSession(UUID id){return submit(c->{String sql="SELECT session_id,uuid,discord_id,ip_hash,token_hash,state,created_at,expires_at,processed_at,processed_by FROM verification_sessions WHERE session_id=?";try(PreparedStatement ps=c.prepareStatement(sql)){ps.setString(1,id.toString());try(ResultSet rs=ps.executeQuery()){return rs.next()?Optional.of(session(rs)):Optional.empty();}}});}

    public CompletableFuture<Optional<VerificationSession>> findPendingSession(UUID uuid){
        return submit(c->{
            String sql="SELECT session_id,uuid,discord_id,ip_hash,token_hash,state,created_at,expires_at,processed_at,processed_by " +
                    "FROM verification_sessions WHERE uuid=? AND state='PENDING' AND expires_at>? ORDER BY created_at DESC LIMIT 1";
            try(PreparedStatement ps=c.prepareStatement(sql)){
                ps.setString(1,uuid.toString());
                ps.setLong(2,System.currentTimeMillis());
                try(ResultSet rs=ps.executeQuery()){return rs.next()?Optional.of(session(rs)):Optional.empty();}
            }
        });
    }

    public CompletableFuture<Optional<VerificationSession>> consumeSession(UUID id, VerificationState next, String actor){
        return submit(c->{
            c.setAutoCommit(false);
            try {
                String sql="UPDATE verification_sessions SET state=?,processed_at=?,processed_by=? WHERE session_id=? AND state='PENDING' AND expires_at>?";
                try(PreparedStatement ps=c.prepareStatement(sql)){
                    long now = System.currentTimeMillis();
                    ps.setString(1,next.name()); ps.setLong(2,now); ps.setString(3,actor); ps.setString(4,id.toString()); ps.setLong(5,now);
                    if(ps.executeUpdate()!=1){c.rollback();return Optional.empty();}
                }
                Optional<VerificationSession> result=querySession(c,id);
                c.commit();
                return result;
            } catch(Exception e){ c.rollback(); throw e; } finally { c.setAutoCommit(true); }
        });
    }
    private Optional<VerificationSession> querySession(Connection c,UUID id)throws SQLException{try(PreparedStatement ps=c.prepareStatement("SELECT session_id,uuid,discord_id,ip_hash,token_hash,state,created_at,expires_at,processed_at,processed_by FROM verification_sessions WHERE session_id=?")){ps.setString(1,id.toString());try(ResultSet rs=ps.executeQuery()){return rs.next()?Optional.of(session(rs)):Optional.empty();}}}
    private static void ensureTrustedIpSlot(Connection c, UUID uuid, String hash, int max) throws SQLException {
        boolean exists;
        long count;
        try (PreparedStatement q = c.prepareStatement("SELECT 1 FROM trusted_ips WHERE uuid=? AND ip_hash=?")) {
            q.setString(1, uuid.toString());
            q.setString(2, hash);
            try (ResultSet r = q.executeQuery()) {
                exists = r.next();
            }
        }
        if (exists) return;

        try (PreparedStatement q = c.prepareStatement("SELECT COUNT(*) FROM trusted_ips WHERE uuid=?")) {
            q.setString(1, uuid.toString());
            try (ResultSet r = q.executeQuery()) {
                r.next();
                count = r.getLong(1);
            }
        }
        if (count < max) return;

        try (PreparedStatement q = c.prepareStatement(
                "DELETE FROM trusted_ips WHERE uuid=? AND ip_hash=(SELECT ip_hash FROM trusted_ips WHERE uuid=? ORDER BY last_seen_at ASC, created_at ASC LIMIT 1)")) {
            q.setString(1, uuid.toString());
            q.setString(2, uuid.toString());
            q.executeUpdate();
        }
    }

    public CompletableFuture<Optional<VerificationSession>> approveSession(UUID sessionId, String actor, long now, int maxTrustedIps) {
        return submit(c -> {
            c.setAutoCommit(false);
            try {
                VerificationSession session;
                try (PreparedStatement ps = c.prepareStatement(
                        "SELECT session_id,uuid,discord_id,ip_hash,token_hash,state,created_at,expires_at,processed_at,processed_by " +
                        "FROM verification_sessions WHERE session_id=?")) {
                    ps.setString(1, sessionId.toString());
                    try (ResultSet rs = ps.executeQuery()) {
                        if (!rs.next()) { c.rollback(); return Optional.empty(); }
                        session = session(rs);
                    }
                }
                if (!session.pendingAndUnexpired(now)) {
                    c.rollback();
                    return Optional.empty();
                }
                try (PreparedStatement ps = c.prepareStatement(
                        "UPDATE verification_sessions SET state='APPROVED',processed_at=?,processed_by=? " +
                        "WHERE session_id=? AND state='PENDING' AND expires_at>?")) {
                    ps.setLong(1, now); ps.setString(2, actor); ps.setString(3, sessionId.toString());
                    ps.setLong(4, now);
                    if (ps.executeUpdate() != 1) { c.rollback(); return Optional.empty(); }
                }
                ensureTrustedIpSlot(c, session.uuid(), session.ipHash(), maxTrustedIps);
                try (PreparedStatement ps = c.prepareStatement(
                        "INSERT INTO trusted_ips(uuid,ip_hash,created_at,last_seen_at) VALUES(?,?,?,?) " +
                        "ON CONFLICT(uuid,ip_hash) DO UPDATE SET last_seen_at=excluded.last_seen_at")) {
                    ps.setString(1, session.uuid().toString()); ps.setString(2, session.ipHash());
                    ps.setLong(3, now); ps.setLong(4, now); ps.executeUpdate();
                }
                try (PreparedStatement ps = c.prepareStatement(
                        "UPDATE protected_accounts SET last_seen_ip_hash=?,last_seen_at=?,updated_at=? WHERE uuid=? AND status='ACTIVE'")) {
                    ps.setString(1, session.ipHash()); ps.setLong(2, now); ps.setLong(3, now); ps.setString(4, session.uuid().toString());
                    if (ps.executeUpdate() != 1) { c.rollback(); return Optional.empty(); }
                }
                try (PreparedStatement ps = c.prepareStatement(
                        "UPDATE managed_bans SET active=0,removed_at=? WHERE uuid=? AND active=1 AND marker='AP-StaffGuard'")) {
                    ps.setLong(1, now); ps.setString(2, session.uuid().toString()); ps.executeUpdate();
                }
                c.commit();
                return Optional.of(new VerificationSession(session.sessionId(), session.uuid(), session.discordId(), session.ipHash(),
                        session.tokenHash(), VerificationState.APPROVED, session.createdAt(), session.expiresAt(), now, actor));
            } catch (Exception ex) {
                c.rollback();
                throw ex;
            } finally {
                c.setAutoCommit(true);
            }
        });
    }

    public CompletableFuture<Integer> expireSessions(){return submit(c->{try(PreparedStatement ps=c.prepareStatement("UPDATE verification_sessions SET state='EXPIRED',processed_at=? WHERE state='PENDING' AND expires_at<=?")){long n=System.currentTimeMillis();ps.setLong(1,n);ps.setLong(2,n);return ps.executeUpdate();}});}
    public CompletableFuture<Boolean> setBan(UUID uuid,String marker,long expires){return submit(c->{try(PreparedStatement ps=c.prepareStatement("INSERT INTO managed_bans(uuid,marker,expires_at,active,created_at) VALUES(?,?,?,?,?) ON CONFLICT(uuid) DO UPDATE SET marker=excluded.marker,expires_at=excluded.expires_at,active=1,created_at=excluded.created_at,removed_at=NULL")){ps.setString(1,uuid.toString());ps.setString(2,marker);ps.setLong(3,expires);ps.setInt(4,1);ps.setLong(5,System.currentTimeMillis());return ps.executeUpdate()==1;}});}
    public CompletableFuture<Optional<ManagedBan>> findBan(UUID uuid){return submit(c->{try(PreparedStatement ps=c.prepareStatement("SELECT uuid,marker,expires_at,active,created_at,removed_at FROM managed_bans WHERE uuid=?")){ps.setString(1,uuid.toString());try(ResultSet rs=ps.executeQuery()){if(!rs.next())return Optional.empty();return Optional.of(new ManagedBan(UUID.fromString(rs.getString(1)),rs.getString(2),rs.getLong(3),rs.getInt(4)==1,rs.getLong(5),(Long)rs.getObject(6)));}}});}
    public CompletableFuture<Boolean> removeBan(UUID uuid){return submit(c->{try(PreparedStatement ps=c.prepareStatement("UPDATE managed_bans SET active=0,removed_at=? WHERE uuid=? AND active=1")){ps.setLong(1,System.currentTimeMillis());ps.setString(2,uuid.toString());return ps.executeUpdate()==1;}});}
    public CompletableFuture<Void> audit(SecurityEvent e){return execute(c->{String sql="INSERT INTO audit_log(timestamp,uuid,role,event,result,reason,verification_id,ip_hash) VALUES(?,?,?,?,?,?,?,?)";try(PreparedStatement ps=c.prepareStatement(sql)){ps.setLong(1,e.timestamp());ps.setString(2,e.uuid()==null?null:e.uuid().toString());ps.setString(3,e.role()==null?null:e.role().name());ps.setString(4,e.event().name());ps.setString(5,e.result());ps.setString(6,e.reason());ps.setString(7,e.verificationId()==null?null:e.verificationId().toString());ps.setString(8,e.ipHash());ps.executeUpdate();}});}
    public CompletableFuture<List<String>> logs(UUID uuid,int limit){return submit(c->{List<String>out=new ArrayList<>();try(PreparedStatement ps=c.prepareStatement("SELECT timestamp,event,result,reason,verification_id FROM audit_log WHERE uuid=? ORDER BY timestamp DESC LIMIT ?")){ps.setString(1,uuid.toString());ps.setInt(2,Math.max(1,Math.min(limit,100)));try(ResultSet r=ps.executeQuery()){while(r.next())out.add(java.time.Instant.ofEpochMilli(r.getLong(1))+" | "+r.getString(2)+" | "+r.getString(3)+" | "+r.getString(4)+(r.getString(5)==null?"":" | "+r.getString(5)));}}return out;});}
    public CompletableFuture<Void> cleanupExpiredBans(){return execute(c->{try(PreparedStatement ps=c.prepareStatement("UPDATE managed_bans SET active=0,removed_at=? WHERE active=1 AND expires_at<=?")){long n=System.currentTimeMillis();ps.setLong(1,n);ps.setLong(2,n);ps.executeUpdate();}});}
}
