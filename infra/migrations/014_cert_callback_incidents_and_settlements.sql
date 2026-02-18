ALTER TABLE certificate_lifecycle_events
  ADD COLUMN IF NOT EXISTS callback_class TEXT;

ALTER TABLE certificate_lifecycle_events
  ADD COLUMN IF NOT EXISTS callback_action TEXT;

ALTER TABLE certificate_lifecycle_events
  ADD COLUMN IF NOT EXISTS callback_attempt INTEGER;

ALTER TABLE certificate_lifecycle_events
  ADD COLUMN IF NOT EXISTS callback_received_at TIMESTAMPTZ;

CREATE TABLE IF NOT EXISTS certificate_incidents (
  id UUID PRIMARY KEY,
  domain_id UUID REFERENCES custom_domains(id) ON DELETE SET NULL,
  domain TEXT NOT NULL,
  org_id UUID REFERENCES organizations(id) ON DELETE SET NULL,
  source TEXT,
  cluster_id TEXT,
  event_id UUID REFERENCES certificate_lifecycle_events(id) ON DELETE SET NULL,
  incident_type TEXT NOT NULL CHECK (incident_type IN ('issuance_failed', 'renewal_failed', 'certificate_expiring', 'tls_error')),
  tier INTEGER NOT NULL CHECK (tier IN (1, 2, 3)),
  status TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'acknowledged', 'resolved')),
  reason TEXT,
  context JSONB,
  acknowledged_by UUID REFERENCES users(id) ON DELETE SET NULL,
  acknowledged_at TIMESTAMPTZ,
  resolved_by UUID REFERENCES users(id) ON DELETE SET NULL,
  resolved_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_certificate_incidents_open_unique
  ON certificate_incidents(domain_id, incident_type)
  WHERE status = 'open';

CREATE INDEX IF NOT EXISTS idx_certificate_incidents_status_tier_created
  ON certificate_incidents(status, tier, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_certificate_incidents_org_created
  ON certificate_incidents(org_id, created_at DESC);

CREATE TABLE IF NOT EXISTS billing_settlement_receipts (
  id UUID PRIMARY KEY,
  provider TEXT NOT NULL CHECK (provider IN ('stripe', 'razorpay', 'paypal')),
  batch_id TEXT NOT NULL,
  period_start TIMESTAMPTZ,
  period_end TIMESTAMPTZ,
  total_events INTEGER NOT NULL DEFAULT 0,
  total_amount_cents BIGINT,
  currency TEXT,
  event_digest TEXT,
  payload_json JSONB,
  signature_valid BOOLEAN NOT NULL DEFAULT TRUE,
  reconciliation_status TEXT NOT NULL DEFAULT 'pending' CHECK (reconciliation_status IN ('pending', 'matched', 'delta', 'failed')),
  reconciliation_delta_events INTEGER,
  reconciliation_delta_amount_cents BIGINT,
  reconciled_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE(provider, batch_id)
);

CREATE INDEX IF NOT EXISTS idx_billing_settlement_receipts_status_created
  ON billing_settlement_receipts(reconciliation_status, created_at DESC);
