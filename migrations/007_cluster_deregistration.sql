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
