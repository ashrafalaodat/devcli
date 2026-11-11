-- Browser OAuth state and sessions contain encrypted tokens; cookies are hashed.
CREATE TABLE IF NOT EXISTS web_login_attempts (
 state_hash text PRIMARY KEY,
 cookie_hash text NOT NULL,
 payload_ciphertext bytea NOT NULL,
 expires_at timestamptz NOT NULL
);
CREATE TABLE IF NOT EXISTS web_sessions (
 id_hash text PRIMARY KEY,
 owner_id text NOT NULL,
 payload_ciphertext bytea NOT NULL,
 expires_at timestamptz NOT NULL,
 version bigint NOT NULL DEFAULT 1,
 refresh_id text,
 refresh_until timestamptz
);
CREATE INDEX IF NOT EXISTS web_sessions_owner ON web_sessions(owner_id);
INSERT INTO schema_version VALUES(4) ON CONFLICT DO NOTHING;
