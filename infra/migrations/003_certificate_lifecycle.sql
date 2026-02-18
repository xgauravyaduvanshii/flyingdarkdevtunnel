-- Certificate lifecycle tracking columns

ALTER TABLE custom_domains
  ADD COLUMN IF NOT EXISTS tls_last_checked_at TIMESTAMPTZ;

ALTER TABLE custom_domains
  ADD COLUMN IF NOT EXISTS tls_not_after TIMESTAMPTZ;

ALTER TABLE custom_domains
  ADD COLUMN IF NOT EXISTS tls_last_error TEXT;
