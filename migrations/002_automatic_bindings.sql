-- Additive upgrade; preserves existing reservations, owners and credentials.
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS last_activity_at timestamptz;
CREATE TABLE IF NOT EXISTS automatic_bindings (
 owner_id text NOT NULL,
 binding_id text NOT NULL,
 session_id text NOT NULL REFERENCES sessions(id),
 request_hash text NOT NULL,
 authorization_expires_at timestamptz NOT NULL,
 PRIMARY KEY(owner_id,binding_id)
);
INSERT INTO schema_version VALUES(2) ON CONFLICT DO NOTHING;
