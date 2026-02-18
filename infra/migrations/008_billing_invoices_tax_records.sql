-- Invoice and tax ledgers for billing exports and finance reporting

CREATE TABLE IF NOT EXISTS billing_invoices (
  id UUID PRIMARY KEY,
  org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  provider TEXT NOT NULL CHECK (provider IN ('stripe', 'razorpay', 'paypal')),
  provider_invoice_id TEXT,
  provider_subscription_id TEXT,
  provider_payment_id TEXT,
  status TEXT NOT NULL CHECK (status IN ('draft', 'open', 'paid', 'past_due', 'void', 'uncollectible', 'failed', 'refunded')),
  currency TEXT,
  subtotal_cents BIGINT,
  tax_cents BIGINT,
  total_cents BIGINT,
  amount_due_cents BIGINT,
  amount_paid_cents BIGINT,
  invoice_url TEXT,
  period_start TIMESTAMPTZ,
  period_end TIMESTAMPTZ,
  issued_at TIMESTAMPTZ,
  due_at TIMESTAMPTZ,
  paid_at TIMESTAMPTZ,
  payload_json JSONB,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_billing_invoices_provider_invoice_id
  ON billing_invoices(provider, provider_invoice_id)
  WHERE provider_invoice_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_billing_invoices_org_created
  ON billing_invoices(org_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_billing_invoices_provider_status
  ON billing_invoices(provider, status, created_at DESC);

CREATE TABLE IF NOT EXISTS billing_tax_records (
  id UUID PRIMARY KEY,
  invoice_id UUID NOT NULL REFERENCES billing_invoices(id) ON DELETE CASCADE,
  org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  provider TEXT NOT NULL CHECK (provider IN ('stripe', 'razorpay', 'paypal')),
  tax_type TEXT NOT NULL,
  jurisdiction TEXT NOT NULL DEFAULT 'unknown',
  rate_bps INTEGER,
  amount_cents BIGINT NOT NULL,
  currency TEXT,
  payload_json JSONB,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE(invoice_id, tax_type, jurisdiction)
);

CREATE INDEX IF NOT EXISTS idx_billing_tax_records_org_created
  ON billing_tax_records(org_id, created_at DESC);
