ALTER TABLE billing_report_exports
  ADD COLUMN IF NOT EXISTS next_attempt_at TIMESTAMPTZ;

ALTER TABLE billing_report_exports
  ADD COLUMN IF NOT EXISTS attempts INTEGER NOT NULL DEFAULT 0;

ALTER TABLE billing_report_exports
  ADD COLUMN IF NOT EXISTS max_attempts INTEGER NOT NULL DEFAULT 5;

ALTER TABLE billing_report_exports
  ADD COLUMN IF NOT EXISTS last_delivery_status TEXT;

ALTER TABLE billing_report_exports
  ALTER COLUMN attempts SET DEFAULT 0;

ALTER TABLE billing_report_exports
  ALTER COLUMN max_attempts SET DEFAULT 5;

UPDATE billing_report_exports
SET
  attempts = COALESCE(attempts, 0),
  max_attempts = CASE WHEN COALESCE(max_attempts, 0) < 1 THEN 5 ELSE max_attempts END,
  next_attempt_at = COALESCE(next_attempt_at, scheduled_for)
WHERE attempts IS NULL OR max_attempts IS NULL OR next_attempt_at IS NULL;

ALTER TABLE billing_report_exports
  DROP CONSTRAINT IF EXISTS billing_report_exports_max_attempts_check;

ALTER TABLE billing_report_exports
  ADD CONSTRAINT billing_report_exports_max_attempts_check
  CHECK (max_attempts >= 1);

CREATE INDEX IF NOT EXISTS idx_billing_report_exports_retry_window
  ON billing_report_exports(status, next_attempt_at, attempts, max_attempts, created_at);
