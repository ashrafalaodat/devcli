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

-- Booking lifetimes are derived from administrator policy and actual activity.
-- A separate baseline gives existing bookings a complete grace window without
-- inventing historical Kubernetes activity. Open executes this block again, so
-- the version guard is essential: restarting must never extend reservations.
ALTER TABLE application_settings ADD COLUMN IF NOT EXISTS inactivity_grace_seconds integer NOT NULL DEFAULT 14400
 CHECK(inactivity_grace_seconds BETWEEN 60 AND 604800);
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS idle_anchor_at timestamptz;
DO $$
DECLARE started_at timestamptz := clock_timestamp();
BEGIN
 IF NOT EXISTS(SELECT 1 FROM schema_version WHERE version=6) THEN
  UPDATE sessions SET idle_anchor_at=started_at,
   expires_at=started_at+make_interval(secs=>application_settings.inactivity_grace_seconds)
   FROM application_settings WHERE state='ACTIVE' AND singleton;
  IF NOT EXISTS(SELECT 1 FROM pg_constraint WHERE conrelid='sessions'::regclass AND conname='active_inactivity_deadline') THEN
   ALTER TABLE sessions ADD CONSTRAINT active_inactivity_deadline
    CHECK(state<>'ACTIVE' OR (expires_at IS NOT NULL AND idle_anchor_at IS NOT NULL));
  END IF;
  INSERT INTO audit(actor,action,object_id,detail)
   VALUES('system','inactivity_policy_upgrade','settings','existing active bookings received a full administrator inactivity grace window; historical activity and personal access tokens preserved');
  INSERT INTO schema_version VALUES(6);
 END IF;
END $$;
-- Keep original cluster identity for historical bookings while removing its
-- credentials and placement entry. Archived IDs cannot be reused; names can.
ALTER TABLE clusters ADD COLUMN IF NOT EXISTS deregistered_at timestamptz;
ALTER TABLE clusters ALTER COLUMN kubeconfig_ciphertext DROP NOT NULL;
ALTER TABLE clusters DROP CONSTRAINT IF EXISTS clusters_name_key;
CREATE UNIQUE INDEX IF NOT EXISTS live_cluster_names ON clusters(name) WHERE deregistered_at IS NULL;
DO $$
BEGIN
 IF NOT EXISTS(SELECT 1 FROM pg_constraint WHERE conrelid='clusters'::regclass AND conname='cluster_registration_credentials') THEN
  ALTER TABLE clusters ADD CONSTRAINT cluster_registration_credentials CHECK(
   (deregistered_at IS NULL AND kubeconfig_ciphertext IS NOT NULL) OR
   (deregistered_at IS NOT NULL AND kubeconfig_ciphertext IS NULL AND maintenance AND controller_session IS NULL AND NOT shareable)
  );
 END IF;
END $$;
INSERT INTO schema_version VALUES(7) ON CONFLICT DO NOTHING;
-- Existing credentials keep manual-only routing. Auto booking is an explicit,
-- editable server-side preference and never changes a token's own lifetime.
ALTER TABLE personal_access_tokens ADD COLUMN IF NOT EXISTS auto_booking_enabled boolean NOT NULL DEFAULT false;
ALTER TABLE personal_access_tokens ADD COLUMN IF NOT EXISTS auto_booking_selector jsonb NOT NULL DEFAULT '{}'
 CHECK(jsonb_typeof(auto_booking_selector)='object');
INSERT INTO schema_version VALUES(8) ON CONFLICT DO NOTHING;

-- Health monitoring is an explicit rollout choice. Migration never probes a
-- cluster, changes a reservation, or enables enforcement for existing installs.
ALTER TABLE application_settings ADD COLUMN IF NOT EXISTS health_mode text NOT NULL DEFAULT 'disabled'
 CHECK(health_mode IN ('disabled','observe','enforce'));
ALTER TABLE clusters ADD COLUMN IF NOT EXISTS configuration_generation bigint NOT NULL DEFAULT 1;
ALTER TABLE clusters ADD COLUMN IF NOT EXISTS health_profile text NOT NULL DEFAULT 'api-ready.v1'
 CHECK(health_profile IN ('api-ready.v1','discovery-only.v1'));
ALTER TABLE clusters ADD COLUMN IF NOT EXISTS health_policy_revision bigint NOT NULL DEFAULT 1;
CREATE TABLE IF NOT EXISTS cluster_health (
 cluster_id text PRIMARY KEY REFERENCES clusters(id),
 observed_state text NOT NULL DEFAULT 'UNKNOWN' CHECK(observed_state IN ('UNKNOWN','RECOVERING','PASSING','FAILING')),
 reason_code text NOT NULL DEFAULT 'not_checked',
 result jsonb NOT NULL DEFAULT '{}',
 observed_configuration_generation bigint NOT NULL DEFAULT 0,
 observed_policy_revision bigint NOT NULL DEFAULT 0,
 checked_at timestamptz,
 last_success_at timestamptz,
 consecutive_successes integer NOT NULL DEFAULT 0,
 next_check_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 probe_sequence bigint NOT NULL DEFAULT 0,
 lease_token text,
 lease_until timestamptz,
 started_at timestamptz,
 requested_at timestamptz,
 request_id text,
 CHECK((lease_token IS NULL)=(lease_until IS NULL))
);
CREATE INDEX IF NOT EXISTS cluster_health_due ON cluster_health(next_check_at,lease_until);
INSERT INTO cluster_health(cluster_id) SELECT id FROM clusters ON CONFLICT DO NOTHING;
CREATE OR REPLACE FUNCTION devctl_health_configuration_fence() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF OLD.kubeconfig_ciphertext IS DISTINCT FROM NEW.kubeconfig_ciphertext THEN
  NEW.configuration_generation := OLD.configuration_generation+1;
 END IF;
 IF OLD.health_profile IS DISTINCT FROM NEW.health_profile THEN
  NEW.health_policy_revision := OLD.health_policy_revision+1;
 END IF;
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS devctl_health_configuration_fence ON clusters;
CREATE TRIGGER devctl_health_configuration_fence BEFORE UPDATE ON clusters
 FOR EACH ROW EXECUTE FUNCTION devctl_health_configuration_fence();
CREATE OR REPLACE FUNCTION devctl_health_configuration_observe() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF TG_OP='INSERT' THEN
  INSERT INTO cluster_health(cluster_id) VALUES(NEW.id) ON CONFLICT DO NOTHING;
 ELSIF OLD.configuration_generation<>NEW.configuration_generation
    OR OLD.health_policy_revision<>NEW.health_policy_revision
    OR OLD.deregistered_at IS DISTINCT FROM NEW.deregistered_at THEN
  UPDATE cluster_health SET observed_state='UNKNOWN',reason_code='configuration_changed',result='{}',
   checked_at=NULL,consecutive_successes=0,next_check_at=clock_timestamp(),
   lease_token=NULL,lease_until=NULL,probe_sequence=probe_sequence+1
   WHERE cluster_id=NEW.id;
 END IF;
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS devctl_health_configuration_observe ON clusters;
CREATE TRIGGER devctl_health_configuration_observe AFTER INSERT OR UPDATE ON clusters
 FOR EACH ROW EXECUTE FUNCTION devctl_health_configuration_observe();
INSERT INTO schema_version VALUES(9) ON CONFLICT DO NOTHING;

-- Simple lifecycle hooks: audit-backed events and a durable outbox/run record.
CREATE TABLE IF NOT EXISTS webhooks (
 id text PRIMARY KEY, name text NOT NULL, url text NOT NULL, events text[] NOT NULL,
 selector jsonb NOT NULL DEFAULT '{}',cluster_id text NOT NULL DEFAULT '',
 blocking boolean NOT NULL DEFAULT false,enabled boolean NOT NULL DEFAULT false,
 idempotent boolean NOT NULL DEFAULT false,timeout_seconds integer NOT NULL DEFAULT 3600 CHECK(timeout_seconds BETWEEN 300 AND 86400),
 version bigint NOT NULL DEFAULT 1,secret_ciphertext bytea NOT NULL
);
CREATE TABLE IF NOT EXISTS webhook_deliveries (
 id text PRIMARY KEY,webhook_id text NOT NULL REFERENCES webhooks(id),event_id bigint NOT NULL REFERENCES audit(id),
 event_type text NOT NULL,cluster_id text NOT NULL DEFAULT '',blocking boolean NOT NULL,
 url text NOT NULL,secret_ciphertext bytea NOT NULL,body jsonb NOT NULL,
 state text NOT NULL DEFAULT 'PENDING' CHECK(state IN ('PENDING','AWAITING_CALLBACK','VERIFYING','SUCCEEDED','FAILED','TIMED_OUT','RESOLVED')),
 reason_code text NOT NULL DEFAULT '',attempts integer NOT NULL DEFAULT 0,http_status integer NOT NULL DEFAULT 0,
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),deadline timestamptz NOT NULL,
 next_attempt_at timestamptz NOT NULL DEFAULT clock_timestamp(),lease_token text,lease_until timestamptz,
 verify_after timestamptz,verify_sequence bigint NOT NULL DEFAULT 0,
 UNIQUE(webhook_id,event_id),CHECK((lease_token IS NULL)=(lease_until IS NULL))
);
CREATE INDEX IF NOT EXISTS webhook_due ON webhook_deliveries(next_attempt_at,lease_until) WHERE state='PENDING';
CREATE INDEX IF NOT EXISTS webhook_holds ON webhook_deliveries(cluster_id) WHERE blocking AND state NOT IN ('SUCCEEDED','RESOLVED');
INSERT INTO schema_version VALUES(10) ON CONFLICT DO NOTHING;
