-- Finance operations events for cancel/refund and recovery workflows

CREATE TABLE IF NOT EXISTS billing_finance_events (
  id UUID PRIMARY KEY,
  org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  provider TEXT NOT NULL CHECK (provider IN ('stripe', 'razorpay', 'paypal')),
  event_type TEXT NOT NULL CHECK (event_type IN ('subscription_cancel', 'refund', 'payment_failed', 'payment_recovered')),
  status TEXT NOT NULL CHECK (status IN ('pending', 'processed', 'failed', 'mocked')),
  external_id TEXT,
  external_ref TEXT,
  amount_cents BIGINT,
  currency TEXT,
  reason TEXT,
  payload_json JSONB,
  result_json JSONB,
  error TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_billing_finance_events_org_created
  ON billing_finance_events(org_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_billing_finance_events_provider_status
  ON billing_finance_events(provider, status, created_at DESC);
