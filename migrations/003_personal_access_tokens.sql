-- Browser-only clients receive one-time, session-scoped gateway credentials.
-- Store only SHA-256 digests; never store the token or generated kubeconfig.
CREATE TABLE IF NOT EXISTS personal_access_tokens (
 id text PRIMARY KEY,
 owner_id text NOT NULL,
 session_id text NOT NULL REFERENCES sessions(id),
 name text NOT NULL CHECK(length(name) BETWEEN 1 AND 100),
 token_digest bytea NOT NULL UNIQUE CHECK(octet_length(token_digest)=32),
 identity jsonb NOT NULL,
 created_at timestamptz NOT NULL DEFAULT now(),
 expires_at timestamptz NOT NULL,
 revoked_at timestamptz,
 last_used_at timestamptz,
 CHECK(expires_at>created_at)
);
CREATE INDEX IF NOT EXISTS personal_access_tokens_owner ON personal_access_tokens(owner_id,created_at DESC);
INSERT INTO schema_version VALUES(3) ON CONFLICT DO NOTHING;
