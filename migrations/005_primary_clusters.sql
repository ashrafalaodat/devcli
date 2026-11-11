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
