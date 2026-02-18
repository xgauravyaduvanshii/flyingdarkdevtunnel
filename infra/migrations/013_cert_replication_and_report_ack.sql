CREATE TABLE IF NOT EXISTS cert_region_replicas (
  id UUID PRIMARY KEY,
  domain_id UUID NOT NULL REFERENCES custom_domains(id) ON DELETE CASCADE,
  domain TEXT NOT NULL,
  source_region TEXT NOT NULL,
  target_region TEXT NOT NULL,
  tls_mode TEXT NOT NULL CHECK (tls_mode IN ('termination', 'passthrough')),
  tls_status TEXT NOT NULL CHECK (tls_status IN ('issued', 'expiring', 'tls_error', 'passthrough_unverified', 'pending_route', 'pending_issue')),
  certificate_ref TEXT,
  tls_not_after TIMESTAMPTZ,
  renewal_due_at TIMESTAMPTZ,
  cert_last_event_at TIMESTAMPTZ,
  replication_state TEXT NOT NULL CHECK (replication_state IN ('source', 'replicated', 'stale')),
  lag_seconds INTEGER NOT NULL DEFAULT 0,
  synced_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE(domain_id, target_region)
);

CREATE INDEX IF NOT EXISTS idx_cert_region_replicas_target_state
  ON cert_region_replicas(target_region, replication_state, synced_at DESC);

CREATE INDEX IF NOT EXISTS idx_cert_region_replicas_domain
  ON cert_region_replicas(domain_id, source_region, target_region);

ALTER TABLE billing_report_exports
  ADD COLUMN IF NOT EXISTS delivery_ack_status TEXT NOT NULL DEFAULT 'not_required';

ALTER TABLE billing_report_exports
  ADD COLUMN IF NOT EXISTS delivery_ack_token_hash TEXT;

ALTER TABLE billing_report_exports
  ADD COLUMN IF NOT EXISTS delivery_ack_deadline TIMESTAMPTZ;

ALTER TABLE billing_report_exports
  ADD COLUMN IF NOT EXISTS delivery_ack_at TIMESTAMPTZ;

ALTER TABLE billing_report_exports
  ADD COLUMN IF NOT EXISTS delivery_ack_metadata JSONB;

ALTER TABLE billing_report_exports
  DROP CONSTRAINT IF EXISTS billing_report_exports_delivery_ack_status_check;

ALTER TABLE billing_report_exports
  ADD CONSTRAINT billing_report_exports_delivery_ack_status_check
  CHECK (delivery_ack_status IN ('not_required', 'pending', 'acknowledged', 'expired'));

CREATE INDEX IF NOT EXISTS idx_billing_report_exports_ack_status
  ON billing_report_exports(delivery_ack_status, delivery_ack_deadline, completed_at DESC);
