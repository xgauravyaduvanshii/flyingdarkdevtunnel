import type { Pool } from "pg";

const statements = [
  `
  CREATE TABLE IF NOT EXISTS organizations (
    id UUID PRIMARY KEY,
    name TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  );
  `,
  `
  CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    authtoken_hash TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  );
  `,
  `
  CREATE TABLE IF NOT EXISTS memberships (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    role TEXT NOT NULL CHECK (role IN ('owner', 'admin', 'member')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(user_id, org_id)
  );
  `,
  `
  CREATE TABLE IF NOT EXISTS plans (
    id UUID PRIMARY KEY,
    code TEXT UNIQUE NOT NULL,
    name TEXT NOT NULL,
    max_tunnels INTEGER NOT NULL,
    max_concurrent_conns INTEGER NOT NULL,
    reserved_domains BOOLEAN NOT NULL,
    custom_domains BOOLEAN NOT NULL,
    ip_allowlist BOOLEAN NOT NULL,
    retention_hours INTEGER NOT NULL,
    stripe_price_id TEXT,
    razorpay_plan_id TEXT,
    paypal_plan_id TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  );
  `,
  `
  CREATE TABLE IF NOT EXISTS entitlements (
    id UUID PRIMARY KEY,
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    plan_id UUID NOT NULL REFERENCES plans(id),
    max_tunnels INTEGER NOT NULL,
    max_concurrent_conns INTEGER NOT NULL,
    reserved_domains BOOLEAN NOT NULL,
    custom_domains BOOLEAN NOT NULL,
    ip_allowlist BOOLEAN NOT NULL,
    retention_hours INTEGER NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(org_id)
  );
  `,
  `
  CREATE TABLE IF NOT EXISTS subscriptions (
    id UUID PRIMARY KEY,
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    billing_provider TEXT NOT NULL DEFAULT 'stripe' CHECK (billing_provider IN ('stripe', 'razorpay', 'paypal')),
    external_customer_id TEXT,
    stripe_customer_id TEXT,
    stripe_subscription_id TEXT,
    razorpay_subscription_id TEXT,
    paypal_subscription_id TEXT,
    status TEXT NOT NULL,
    plan_id UUID REFERENCES plans(id),
    current_period_end TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(org_id)
  );
  `,
  `
  ALTER TABLE plans ADD COLUMN IF NOT EXISTS razorpay_plan_id TEXT;
  `,
  `
  ALTER TABLE plans ADD COLUMN IF NOT EXISTS paypal_plan_id TEXT;
  `,
  `
  ALTER TABLE subscriptions
  ADD COLUMN IF NOT EXISTS billing_provider TEXT NOT NULL DEFAULT 'stripe';
  `,
  `
  ALTER TABLE subscriptions
  DROP CONSTRAINT IF EXISTS subscriptions_billing_provider_check;
  `,
  `
  ALTER TABLE subscriptions
  ADD CONSTRAINT subscriptions_billing_provider_check
  CHECK (billing_provider IN ('stripe', 'razorpay', 'paypal'));
  `,
  `
  ALTER TABLE subscriptions
  ADD COLUMN IF NOT EXISTS external_customer_id TEXT;
  `,
  `
  ALTER TABLE subscriptions
  ADD COLUMN IF NOT EXISTS razorpay_subscription_id TEXT;
  `,
  `
  ALTER TABLE subscriptions
  ADD COLUMN IF NOT EXISTS paypal_subscription_id TEXT;
  `,
  `
  CREATE UNIQUE INDEX IF NOT EXISTS idx_subscriptions_stripe_subscription_id
  ON subscriptions(stripe_subscription_id)
  WHERE stripe_subscription_id IS NOT NULL;
  `,
  `
  CREATE UNIQUE INDEX IF NOT EXISTS idx_subscriptions_razorpay_subscription_id
  ON subscriptions(razorpay_subscription_id)
  WHERE razorpay_subscription_id IS NOT NULL;
  `,
  `
  CREATE UNIQUE INDEX IF NOT EXISTS idx_subscriptions_paypal_subscription_id
  ON subscriptions(paypal_subscription_id)
  WHERE paypal_subscription_id IS NOT NULL;
  `,
  `
  CREATE TABLE IF NOT EXISTS billing_webhook_events (
    id UUID PRIMARY KEY,
    provider TEXT NOT NULL CHECK (provider IN ('stripe', 'razorpay', 'paypal')),
    event_id TEXT NOT NULL,
    provider_event_type TEXT,
    payload_hash TEXT NOT NULL,
    payload_json JSONB,
    status TEXT NOT NULL CHECK (status IN ('pending', 'processed', 'failed')),
    attempts INTEGER NOT NULL DEFAULT 1,
    replay_count INTEGER NOT NULL DEFAULT 0,
    received_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    processed_at TIMESTAMPTZ,
    last_error TEXT,
    UNIQUE(provider, event_id)
  );
  `,
  `
  ALTER TABLE billing_webhook_events
  ADD COLUMN IF NOT EXISTS provider_event_type TEXT;
  `,
  `
  ALTER TABLE billing_webhook_events
  ADD COLUMN IF NOT EXISTS payload_json JSONB;
  `,
  `
  ALTER TABLE billing_webhook_events
  ADD COLUMN IF NOT EXISTS replay_count INTEGER NOT NULL DEFAULT 0;
  `,
  `
  CREATE INDEX IF NOT EXISTS idx_billing_webhook_events_received_at
  ON billing_webhook_events(received_at DESC);
  `,
  `
  CREATE INDEX IF NOT EXISTS idx_billing_webhook_events_status
  ON billing_webhook_events(status);
  `,
  `
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
  `,
  `
  CREATE INDEX IF NOT EXISTS idx_billing_finance_events_org_created
  ON billing_finance_events(org_id, created_at DESC);
  `,
  `
  CREATE INDEX IF NOT EXISTS idx_billing_finance_events_provider_status
  ON billing_finance_events(provider, status, created_at DESC);
  `,
  `
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
  `,
  `
  CREATE UNIQUE INDEX IF NOT EXISTS idx_billing_invoices_provider_invoice_id
  ON billing_invoices(provider, provider_invoice_id)
  WHERE provider_invoice_id IS NOT NULL;
  `,
  `
  CREATE INDEX IF NOT EXISTS idx_billing_invoices_org_created
  ON billing_invoices(org_id, created_at DESC);
  `,
  `
  CREATE INDEX IF NOT EXISTS idx_billing_invoices_provider_status
  ON billing_invoices(provider, status, created_at DESC);
  `,
  `
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
  `,
  `
  CREATE INDEX IF NOT EXISTS idx_billing_tax_records_org_created
  ON billing_tax_records(org_id, created_at DESC);
  `,
  `
  CREATE TABLE IF NOT EXISTS tunnels (
    id UUID PRIMARY KEY,
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    protocol TEXT NOT NULL CHECK (protocol IN ('http', 'https', 'tcp')),
    local_addr TEXT NOT NULL,
    subdomain TEXT,
    public_url TEXT,
    status TEXT NOT NULL CHECK (status IN ('active', 'stopped', 'error')),
    inspect BOOLEAN NOT NULL DEFAULT TRUE,
    basic_auth_user TEXT,
    basic_auth_password TEXT,
    ip_allowlist TEXT[] DEFAULT '{}',
    region TEXT NOT NULL DEFAULT 'us',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  );
  `,
  `
  CREATE TABLE IF NOT EXISTS tunnel_sessions (
    id UUID PRIMARY KEY,
    tunnel_id UUID NOT NULL REFERENCES tunnels(id) ON DELETE CASCADE,
    connected_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    disconnected_at TIMESTAMPTZ,
    bytes_in BIGINT NOT NULL DEFAULT 0,
    bytes_out BIGINT NOT NULL DEFAULT 0,
    active BOOLEAN NOT NULL DEFAULT TRUE
  );
  `,
  `
  CREATE TABLE IF NOT EXISTS reserved_domains (
    id UUID PRIMARY KEY,
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    subdomain TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(subdomain)
  );
  `,
  `
  CREATE TABLE IF NOT EXISTS custom_domains (
    id UUID PRIMARY KEY,
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    domain TEXT NOT NULL,
    verified BOOLEAN NOT NULL DEFAULT FALSE,
    verification_token TEXT NOT NULL,
    tls_status TEXT NOT NULL DEFAULT 'pending',
    tls_mode TEXT NOT NULL DEFAULT 'termination',
    target_tunnel_id UUID REFERENCES tunnels(id) ON DELETE SET NULL,
    last_verified_at TIMESTAMPTZ,
    certificate_ref TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(domain)
  );
  `,
  `
  ALTER TABLE custom_domains ADD COLUMN IF NOT EXISTS tls_mode TEXT NOT NULL DEFAULT 'termination';
  `,
  `
  ALTER TABLE custom_domains
  ADD COLUMN IF NOT EXISTS target_tunnel_id UUID REFERENCES tunnels(id) ON DELETE SET NULL;
  `,
  `
  ALTER TABLE custom_domains ADD COLUMN IF NOT EXISTS last_verified_at TIMESTAMPTZ;
  `,
  `
  ALTER TABLE custom_domains ADD COLUMN IF NOT EXISTS certificate_ref TEXT;
  `,
  `
  ALTER TABLE custom_domains ADD COLUMN IF NOT EXISTS tls_last_checked_at TIMESTAMPTZ;
  `,
  `
  ALTER TABLE custom_domains ADD COLUMN IF NOT EXISTS tls_not_after TIMESTAMPTZ;
  `,
  `
  ALTER TABLE custom_domains ADD COLUMN IF NOT EXISTS tls_last_error TEXT;
  `,
  `
  CREATE INDEX IF NOT EXISTS idx_custom_domains_target_tunnel_id ON custom_domains(target_tunnel_id);
  `,
  `
  CREATE TABLE IF NOT EXISTS request_logs (
    id UUID PRIMARY KEY,
    tunnel_id UUID NOT NULL REFERENCES tunnels(id) ON DELETE CASCADE,
    method TEXT NOT NULL,
    path TEXT NOT NULL,
    status_code INTEGER,
    req_headers JSONB NOT NULL,
    res_headers JSONB,
    request_size BIGINT NOT NULL DEFAULT 0,
    response_size BIGINT NOT NULL DEFAULT 0,
    started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at TIMESTAMPTZ
  );
  `,
  `
  CREATE TABLE IF NOT EXISTS request_payload_refs (
    id UUID PRIMARY KEY,
    request_log_id UUID NOT NULL REFERENCES request_logs(id) ON DELETE CASCADE,
    req_body_ref TEXT,
    res_body_ref TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(request_log_id)
  );
  `,
  `
  CREATE TABLE IF NOT EXISTS replay_jobs (
    id UUID PRIMARY KEY,
    request_log_id UUID NOT NULL REFERENCES request_logs(id) ON DELETE CASCADE,
    status TEXT NOT NULL CHECK (status IN ('queued', 'running', 'completed', 'failed')),
    result JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  );
  `,
  `
  CREATE TABLE IF NOT EXISTS audit_logs (
    id UUID PRIMARY KEY,
    actor_user_id UUID,
    org_id UUID,
    action TEXT NOT NULL,
    entity_type TEXT NOT NULL,
    entity_id TEXT NOT NULL,
    metadata JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  );
  `,
  `
  CREATE TABLE IF NOT EXISTS usage_metrics_daily (
    id UUID PRIMARY KEY,
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    day DATE NOT NULL,
    requests_count BIGINT NOT NULL DEFAULT 0,
    bytes_in BIGINT NOT NULL DEFAULT 0,
    bytes_out BIGINT NOT NULL DEFAULT 0,
    active_minutes BIGINT NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(org_id, day)
  );
  `
];

const seedPlanStatements = [
  `
  INSERT INTO plans (id, code, name, max_tunnels, max_concurrent_conns, reserved_domains, custom_domains, ip_allowlist, retention_hours)
  VALUES
    ('11111111-1111-1111-1111-111111111111', 'free', 'Free', 3, 50, FALSE, FALSE, FALSE, 24),
    ('22222222-2222-2222-2222-222222222222', 'pro', 'Pro', 25, 500, TRUE, TRUE, TRUE, 168),
    ('33333333-3333-3333-3333-333333333333', 'team', 'Team', 100, 2000, TRUE, TRUE, TRUE, 720)
  ON CONFLICT (code) DO NOTHING;
  `
];

export async function runMigrations(pool: Pool): Promise<void> {
  for (const statement of statements) {
    await pool.query(statement);
  }
  for (const statement of seedPlanStatements) {
    await pool.query(statement);
  }
}
