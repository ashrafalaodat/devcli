-- Reservation-only MVP. Never store plaintext Kubernetes credentials.
CREATE TABLE IF NOT EXISTS clusters (
 id text PRIMARY KEY,
 name text NOT NULL UNIQUE,
 labels jsonb NOT NULL DEFAULT '{}',
 kubeconfig_ciphertext bytea NOT NULL,
 maintenance boolean NOT NULL DEFAULT false,
 controller_session text,
 shareable boolean NOT NULL DEFAULT false,
 max_participants integer NOT NULL DEFAULT 2 CHECK(max_participants BETWEEN 2 AND 10)
);
CREATE TABLE IF NOT EXISTS sessions (
 id text PRIMARY KEY,
 owner_id text NOT NULL,
 identity jsonb NOT NULL,
 cluster_id text NOT NULL REFERENCES clusters(id),
 state text NOT NULL CHECK(state IN ('ACTIVE','RELEASED','EXPIRED')),
 created_at timestamptz NOT NULL DEFAULT now(),
 ended_at timestamptz,
 expires_at timestamptz,
 reason text NOT NULL,
 CHECK((state='ACTIVE' AND ended_at IS NULL) OR (state<>'ACTIVE' AND ended_at IS NOT NULL))
);
CREATE UNIQUE INDEX IF NOT EXISTS one_booking_per_user_per_cluster ON sessions(owner_id,cluster_id) WHERE state='ACTIVE';
CREATE TABLE IF NOT EXISTS booking_keys (
 owner_id text NOT NULL,
 key text NOT NULL,
 request_hash text NOT NULL,
 session_id text NOT NULL REFERENCES sessions(id),
 PRIMARY KEY(owner_id,key)
);
CREATE TABLE IF NOT EXISTS audit (
 id bigserial PRIMARY KEY,
 at timestamptz NOT NULL DEFAULT now(),
 actor text NOT NULL,
 action text NOT NULL,
 object_id text NOT NULL,
 detail text NOT NULL
);
CREATE TABLE IF NOT EXISTS schema_version(version integer PRIMARY KEY);
INSERT INTO schema_version VALUES(1) ON CONFLICT DO NOTHING;

-- Automatic client bindings remain pinned to one session across command retries.
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
-- A developer has one durable primary selection and an administrator-owned limit.
CREATE TABLE IF NOT EXISTS application_settings (
 singleton boolean PRIMARY KEY DEFAULT true CHECK(singleton),
 default_max_bookings integer NOT NULL DEFAULT 1 CHECK(default_max_bookings BETWEEN 1 AND 100)
);
INSERT INTO application_settings(singleton) VALUES(true) ON CONFLICT DO NOTHING;
CREATE TABLE IF NOT EXISTS developers (
 owner_id text PRIMARY KEY,
 identity jsonb NOT NULL,
 max_bookings_override integer CHECK(max_bookings_override BETWEEN 1 AND 100),
 primary_session_id text REFERENCES sessions(id),
 selection_version bigint NOT NULL DEFAULT 0,
 authorization_expires_at timestamptz,
 authorization_version bigint
);
-- Preserve reservations and identities. Existing holders above the default keep
-- their bookings but cannot add another until an administrator raises the limit.
INSERT INTO developers(owner_id,identity)
 SELECT DISTINCT ON (owner_id) owner_id,identity FROM sessions ORDER BY owner_id,created_at DESC,id DESC
 ON CONFLICT DO NOTHING;
UPDATE developers d SET primary_session_id=(
 SELECT s.id FROM sessions s WHERE s.owner_id=d.owner_id AND s.state='ACTIVE'
 AND (s.expires_at IS NULL OR s.expires_at>clock_timestamp()) ORDER BY s.created_at,s.id LIMIT 1
),selection_version=d.selection_version+1
WHERE d.primary_session_id IS NULL AND EXISTS(
 SELECT 1 FROM sessions s WHERE s.owner_id=d.owner_id AND s.state='ACTIVE'
 AND (s.expires_at IS NULL OR s.expires_at>clock_timestamp())
);
-- Never silently widen an old session-scoped credential into user-wide access.
ALTER TABLE personal_access_tokens ADD COLUMN IF NOT EXISTS scope text NOT NULL DEFAULT 'kubernetes:session';
ALTER TABLE personal_access_tokens ALTER COLUMN session_id DROP NOT NULL;
WITH retired AS (
 UPDATE personal_access_tokens SET revoked_at=clock_timestamp()
 WHERE scope<>'kubernetes:primary' AND revoked_at IS NULL RETURNING id,owner_id
) INSERT INTO audit(actor,action,object_id,detail)
 SELECT owner_id,'pat_retired',id,'legacy session credential retired; obtain a new developer gateway kubeconfig' FROM retired;
DROP TABLE IF EXISTS automatic_bindings;
INSERT INTO schema_version VALUES(5) ON CONFLICT DO NOTHING;
