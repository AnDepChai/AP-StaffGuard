CREATE TABLE IF NOT EXISTS protected_accounts (
  uuid TEXT PRIMARY KEY,
  username TEXT NOT NULL,
  role TEXT NOT NULL CHECK(role IN ('OWNER','STAFF')),
  discord_id TEXT NOT NULL,
  status TEXT NOT NULL CHECK(status IN ('ACTIVE','LOCKED','REVOKED','REMOVED')),
  last_seen_ip_hash TEXT,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  last_seen_at INTEGER
);
CREATE INDEX IF NOT EXISTS idx_accounts_discord ON protected_accounts(discord_id);
CREATE INDEX IF NOT EXISTS idx_accounts_status ON protected_accounts(status);

CREATE TABLE IF NOT EXISTS trusted_ips (
  uuid TEXT NOT NULL,
  ip_hash TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  last_seen_at INTEGER NOT NULL,
  PRIMARY KEY(uuid, ip_hash),
  FOREIGN KEY(uuid) REFERENCES protected_accounts(uuid) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_trusted_ip_hash ON trusted_ips(ip_hash);

CREATE TABLE IF NOT EXISTS verification_sessions (
  session_id TEXT PRIMARY KEY,
  uuid TEXT NOT NULL,
  discord_id TEXT NOT NULL,
  ip_hash TEXT NOT NULL,
  token_hash TEXT NOT NULL,
  state TEXT NOT NULL CHECK(state IN ('PENDING','APPROVED','DENIED','EXPIRED','REVOKED')),
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  processed_at INTEGER,
  processed_by TEXT,
  FOREIGN KEY(uuid) REFERENCES protected_accounts(uuid) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_verification_uuid_state ON verification_sessions(uuid, state);
CREATE INDEX IF NOT EXISTS idx_verification_expires ON verification_sessions(expires_at);

CREATE TABLE IF NOT EXISTS managed_bans (
  uuid TEXT PRIMARY KEY,
  marker TEXT NOT NULL,
  expires_at INTEGER NOT NULL,
  active INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  removed_at INTEGER,
  FOREIGN KEY(uuid) REFERENCES protected_accounts(uuid) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_bans_expiry ON managed_bans(expires_at, active);

CREATE TABLE IF NOT EXISTS audit_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  timestamp INTEGER NOT NULL,
  uuid TEXT,
  role TEXT,
  event TEXT NOT NULL,
  result TEXT NOT NULL,
  reason TEXT NOT NULL,
  verification_id TEXT,
  ip_hash TEXT
);
CREATE INDEX IF NOT EXISTS idx_audit_uuid_time ON audit_log(uuid, timestamp DESC);

CREATE TABLE IF NOT EXISTS settings (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_one_pending_verification_per_uuid ON verification_sessions(uuid) WHERE state='PENDING';
