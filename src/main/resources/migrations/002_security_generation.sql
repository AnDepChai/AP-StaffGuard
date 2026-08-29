ALTER TABLE protected_accounts ADD COLUMN security_generation INTEGER NOT NULL DEFAULT 1 CHECK(security_generation > 0);
ALTER TABLE trusted_ips ADD COLUMN security_generation INTEGER NOT NULL DEFAULT 1 CHECK(security_generation > 0);
ALTER TABLE verification_sessions ADD COLUMN account_generation INTEGER NOT NULL DEFAULT 0;
ALTER TABLE verification_sessions ADD COLUMN notification_count INTEGER NOT NULL DEFAULT 0 CHECK(notification_count >= 0);
ALTER TABLE verification_sessions ADD COLUMN last_notification_at INTEGER;

UPDATE verification_sessions
SET state='EXPIRED', processed_at=CAST(strftime('%s','now') AS INTEGER)*1000, processed_by='migration:002'
WHERE state='PENDING';

CREATE INDEX IF NOT EXISTS idx_trusted_identity ON trusted_ips(uuid, security_generation);
CREATE INDEX IF NOT EXISTS idx_verification_pending_generation ON verification_sessions(uuid, account_generation, state, expires_at);
