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
