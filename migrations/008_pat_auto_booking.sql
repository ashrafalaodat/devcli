-- Existing credentials keep manual-only routing. Auto booking is an explicit,
-- editable server-side preference and never changes a token's own lifetime.
ALTER TABLE personal_access_tokens ADD COLUMN IF NOT EXISTS auto_booking_enabled boolean NOT NULL DEFAULT false;
ALTER TABLE personal_access_tokens ADD COLUMN IF NOT EXISTS auto_booking_selector jsonb NOT NULL DEFAULT '{}'
 CHECK(jsonb_typeof(auto_booking_selector)='object');
INSERT INTO schema_version VALUES(8) ON CONFLICT DO NOTHING;
