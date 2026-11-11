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
