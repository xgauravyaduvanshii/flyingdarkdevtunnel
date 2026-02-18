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
    role TEXT NOT NULL CHECK (role IN ('owner', 'admin', 'member', 'billing', 'viewer')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(user_id, org_id)
  );
  `,
  `
  ALTER TABLE memberships
  DROP CONSTRAINT IF EXISTS memberships_role_check;
  `,
  `
  ALTER TABLE memberships
  ADD CONSTRAINT memberships_role_check
  CHECK (role IN ('owner', 'admin', 'member', 'billing', 'viewer'));
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
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(domain)
  );
  `,
  `
  ALTER TABLE custom_domains ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW();
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
  ALTER TABLE custom_domains
  ADD COLUMN IF NOT EXISTS cert_failure_policy TEXT NOT NULL DEFAULT 'standard';
  `,
  `
  ALTER TABLE custom_domains
  ADD COLUMN IF NOT EXISTS cert_failure_count INTEGER NOT NULL DEFAULT 0;
  `,
  `
  ALTER TABLE custom_domains
  ADD COLUMN IF NOT EXISTS cert_retry_backoff_seconds INTEGER NOT NULL DEFAULT 0;
  `,
  `
  ALTER TABLE custom_domains
  ADD COLUMN IF NOT EXISTS cert_next_retry_at TIMESTAMPTZ;
  `,
  `
  ALTER TABLE custom_domains
  ADD COLUMN IF NOT EXISTS cert_last_event_type TEXT;
  `,
  `
  ALTER TABLE custom_domains
  ADD COLUMN IF NOT EXISTS cert_last_event_at TIMESTAMPTZ;
  `,
  `
  ALTER TABLE custom_domains
  ADD COLUMN IF NOT EXISTS cert_renewal_due_at TIMESTAMPTZ;
  `,
  `
  ALTER TABLE custom_domains
  DROP CONSTRAINT IF EXISTS custom_domains_cert_failure_policy_check;
  `,
  `
  ALTER TABLE custom_domains
  ADD CONSTRAINT custom_domains_cert_failure_policy_check
  CHECK (cert_failure_policy IN ('standard', 'strict', 'hold'));
  `,
  `
  CREATE INDEX IF NOT EXISTS idx_custom_domains_target_tunnel_id ON custom_domains(target_tunnel_id);
  `,
  `
  CREATE INDEX IF NOT EXISTS idx_custom_domains_retry_policy
  ON custom_domains(cert_next_retry_at, cert_failure_policy)
  WHERE cert_next_retry_at IS NOT NULL;
  `,
  `
  CREATE TABLE IF NOT EXISTS certificate_lifecycle_events (
    id UUID PRIMARY KEY,
    source TEXT NOT NULL DEFAULT 'cert_manager',
    source_event_id TEXT,
    domain_id UUID REFERENCES custom_domains(id) ON DELETE SET NULL,
    domain TEXT NOT NULL,
    event_type TEXT NOT NULL CHECK (event_type IN ('issuance_succeeded', 'issuance_failed', 'renewal_succeeded', 'renewal_failed', 'certificate_expiring')),
    status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'applied', 'failed')),
    certificate_ref TEXT,
    not_after TIMESTAMPTZ,
    renewal_due_at TIMESTAMPTZ,
    reason TEXT,
    payload_json JSONB,
    retry_count INTEGER NOT NULL DEFAULT 0,
    next_retry_at TIMESTAMPTZ,
    last_error TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    processed_at TIMESTAMPTZ
  );
  `,
  `
  DROP INDEX IF EXISTS idx_certificate_lifecycle_events_source_event_id;
  `,
  `
  CREATE UNIQUE INDEX IF NOT EXISTS idx_certificate_lifecycle_events_source_event_id
  ON certificate_lifecycle_events(source, source_event_id);
  `,
  `
  CREATE INDEX IF NOT EXISTS idx_certificate_lifecycle_events_status
  ON certificate_lifecycle_events(status, next_retry_at, created_at);
  `,
  `
  ALTER TABLE certificate_lifecycle_events
  ADD COLUMN IF NOT EXISTS cluster_id TEXT;
  `,
  `
  ALTER TABLE certificate_lifecycle_events
  ADD COLUMN IF NOT EXISTS provenance_subject TEXT;
  `,
  `
  ALTER TABLE certificate_lifecycle_events
  ADD COLUMN IF NOT EXISTS provenance_verified BOOLEAN NOT NULL DEFAULT FALSE;
  `,
  `
  CREATE INDEX IF NOT EXISTS idx_certificate_lifecycle_events_source_cluster_created
  ON certificate_lifecycle_events(source, cluster_id, created_at DESC);
  `,
  `
  CREATE TABLE IF NOT EXISTS cert_event_source_activity (
    source TEXT NOT NULL,
    cluster_id TEXT NOT NULL,
    last_event_id TEXT,
    last_event_type TEXT,
    last_status TEXT,
    events_total BIGINT NOT NULL DEFAULT 0,
    signature_failures BIGINT NOT NULL DEFAULT 0,
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (source, cluster_id)
  );
  `,
  `
  CREATE INDEX IF NOT EXISTS idx_cert_event_source_activity_last_seen
  ON cert_event_source_activity(last_seen_at DESC);
  `,
  `
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
  `,
  `
  CREATE INDEX IF NOT EXISTS idx_cert_region_replicas_target_state
  ON cert_region_replicas(target_region, replication_state, synced_at DESC);
  `,
  `
  CREATE INDEX IF NOT EXISTS idx_cert_region_replicas_domain
  ON cert_region_replicas(domain_id, source_region, target_region);
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
    prev_hash TEXT,
    entry_hash TEXT,
    immutable BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  );
  `,
  `
  ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS prev_hash TEXT;
  `,
  `
  ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS entry_hash TEXT;
  `,
  `
  ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS immutable BOOLEAN NOT NULL DEFAULT TRUE;
  `,
  `
  CREATE UNIQUE INDEX IF NOT EXISTS idx_audit_logs_entry_hash
  ON audit_logs(entry_hash)
  WHERE entry_hash IS NOT NULL;
  `,
  `
  CREATE INDEX IF NOT EXISTS idx_audit_logs_org_chain
  ON audit_logs(org_id, created_at, id);
  `,
  `
  CREATE TABLE IF NOT EXISTS auth_revoked_tokens (
    id UUID PRIMARY KEY,
    jti TEXT NOT NULL UNIQUE,
    token_type TEXT NOT NULL CHECK (token_type IN ('access', 'refresh', 'agent')),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    org_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
    expires_at TIMESTAMPTZ,
    reason TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  );
  `,
  `
  CREATE INDEX IF NOT EXISTS idx_auth_revoked_tokens_expires
  ON auth_revoked_tokens(expires_at);
  `,
  `
  CREATE TABLE IF NOT EXISTS secret_rotations (
    id UUID PRIMARY KEY,
    actor_user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    target_user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    org_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
    secret_type TEXT NOT NULL CHECK (secret_type IN ('authtoken', 'jwt')),
    reason TEXT,
    metadata JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  );
  `,
  `
  CREATE INDEX IF NOT EXISTS idx_secret_rotations_org_created
  ON secret_rotations(org_id, created_at DESC);
  `,
  `
  CREATE TABLE IF NOT EXISTS security_anomaly_events (
    id UUID PRIMARY KEY,
    category TEXT NOT NULL CHECK (category IN ('auth_failed', 'rate_limited', 'token_revoked', 'abuse_signal')),
    severity TEXT NOT NULL CHECK (severity IN ('low', 'medium', 'high')),
    ip TEXT,
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    org_id UUID REFERENCES organizations(id) ON DELETE SET NULL,
    route TEXT,
    details JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  );
  `,
  `
  CREATE INDEX IF NOT EXISTS idx_security_anomaly_events_created
  ON security_anomaly_events(created_at DESC);
  `,
  `
  CREATE TABLE IF NOT EXISTS sso_providers (
    id UUID PRIMARY KEY,
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    provider TEXT NOT NULL CHECK (provider IN ('saml', 'oidc')),
    enabled BOOLEAN NOT NULL DEFAULT FALSE,
    issuer TEXT,
    entrypoint TEXT,
    audience TEXT,
    certificate TEXT,
    metadata_json JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(org_id)
  );
  `,
  `
  CREATE TABLE IF NOT EXISTS org_role_templates (
    id UUID PRIMARY KEY,
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    template_key TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('owner', 'admin', 'member', 'billing', 'viewer')),
    description TEXT,
    metadata_json JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(org_id, template_key)
  );
  `,
  `
  CREATE INDEX IF NOT EXISTS idx_org_role_templates_org_key
  ON org_role_templates(org_id, template_key);
  `,
  `
  CREATE TABLE IF NOT EXISTS scim_provisioning_events (
    id UUID PRIMARY KEY,
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    actor_user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    external_id TEXT,
    email TEXT NOT NULL,
    template_key TEXT,
    requested_role TEXT CHECK (requested_role IN ('owner', 'admin', 'member', 'billing', 'viewer')),
    resolved_role TEXT CHECK (resolved_role IN ('owner', 'admin', 'member', 'billing', 'viewer')),
    action TEXT NOT NULL CHECK (action IN ('upsert', 'deactivate', 'delete')),
    status TEXT NOT NULL CHECK (status IN ('applied', 'skipped', 'failed')),
    details JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  );
  `,
  `
  CREATE INDEX IF NOT EXISTS idx_scim_provisioning_events_org_created
  ON scim_provisioning_events(org_id, created_at DESC);
  `,
  `
  ALTER TABLE certificate_lifecycle_events
  ADD COLUMN IF NOT EXISTS dlq_replay_count INTEGER NOT NULL DEFAULT 0;
  `,
  `
  ALTER TABLE certificate_lifecycle_events
  ADD COLUMN IF NOT EXISTS last_dlq_replayed_at TIMESTAMPTZ;
  `,
  `
  ALTER TABLE certificate_lifecycle_events
  ADD COLUMN IF NOT EXISTS callback_class TEXT;
  `,
  `
  ALTER TABLE certificate_lifecycle_events
  ADD COLUMN IF NOT EXISTS callback_action TEXT;
  `,
  `
  ALTER TABLE certificate_lifecycle_events
  ADD COLUMN IF NOT EXISTS callback_attempt INTEGER;
  `,
  `
  ALTER TABLE certificate_lifecycle_events
  ADD COLUMN IF NOT EXISTS callback_received_at TIMESTAMPTZ;
  `,
  `
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
  `,
  `
  CREATE UNIQUE INDEX IF NOT EXISTS idx_certificate_incidents_open_unique
  ON certificate_incidents(domain_id, incident_type)
  WHERE status = 'open';
  `,
  `
  CREATE INDEX IF NOT EXISTS idx_certificate_incidents_status_tier_created
  ON certificate_incidents(status, tier, created_at DESC);
  `,
  `
  CREATE INDEX IF NOT EXISTS idx_certificate_incidents_org_created
  ON certificate_incidents(org_id, created_at DESC);
  `,
  `
  CREATE TABLE IF NOT EXISTS billing_dunning_cases (
    id UUID PRIMARY KEY,
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    provider TEXT NOT NULL CHECK (provider IN ('stripe', 'razorpay', 'paypal')),
    subscription_ref TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'recovered', 'closed')),
    stage INTEGER NOT NULL DEFAULT 1,
    retry_count INTEGER NOT NULL DEFAULT 0,
    next_attempt_at TIMESTAMPTZ,
    last_attempt_at TIMESTAMPTZ,
    notification_count INTEGER NOT NULL DEFAULT 0,
    notification_channels TEXT[] NOT NULL DEFAULT ARRAY['webhook']::TEXT[],
    last_error TEXT,
    latest_event_id TEXT,
    latest_event_type TEXT,
    payload_json JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(org_id, provider, subscription_ref)
  );
  `,
  `
  ALTER TABLE billing_dunning_cases
  ADD COLUMN IF NOT EXISTS notification_channels TEXT[] NOT NULL DEFAULT ARRAY['webhook']::TEXT[];
  `,
  `
  ALTER TABLE billing_dunning_cases
  DROP CONSTRAINT IF EXISTS billing_dunning_cases_notification_channels_check;
  `,
  `
  ALTER TABLE billing_dunning_cases
  ADD CONSTRAINT billing_dunning_cases_notification_channels_check
  CHECK (
    notification_channels IS NOT NULL
    AND array_length(notification_channels, 1) >= 1
    AND notification_channels <@ ARRAY['webhook', 'email', 'slack']::TEXT[]
  );
  `,
  `
  CREATE INDEX IF NOT EXISTS idx_billing_dunning_cases_status_next_attempt
  ON billing_dunning_cases(status, next_attempt_at, updated_at);
  `,
  `
  CREATE TABLE IF NOT EXISTS billing_report_exports (
    id UUID PRIMARY KEY,
    org_id UUID REFERENCES organizations(id) ON DELETE SET NULL,
    dataset TEXT NOT NULL CHECK (dataset IN ('finance_events', 'invoices', 'dunning')),
    format TEXT NOT NULL CHECK (format IN ('csv')),
    status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'running', 'completed', 'failed')),
    destination TEXT NOT NULL DEFAULT 'inline' CHECK (destination IN ('inline', 'webhook', 's3', 'warehouse')),
    sink_url TEXT,
    scheduled_for TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    next_attempt_at TIMESTAMPTZ,
    attempts INTEGER NOT NULL DEFAULT 0,
    max_attempts INTEGER NOT NULL DEFAULT 5,
    last_delivery_status TEXT,
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    row_count INTEGER,
    content_text TEXT,
    content_hash TEXT,
    error TEXT,
    payload_json JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  );
  `,
  `
  ALTER TABLE billing_report_exports
  DROP CONSTRAINT IF EXISTS billing_report_exports_destination_check;
  `,
  `
  ALTER TABLE billing_report_exports
  ADD CONSTRAINT billing_report_exports_destination_check
  CHECK (destination IN ('inline', 'webhook', 's3', 'warehouse'));
  `,
  `
  ALTER TABLE billing_report_exports
  ADD COLUMN IF NOT EXISTS next_attempt_at TIMESTAMPTZ;
  `,
  `
  ALTER TABLE billing_report_exports
  ADD COLUMN IF NOT EXISTS attempts INTEGER NOT NULL DEFAULT 0;
  `,
  `
  ALTER TABLE billing_report_exports
  ADD COLUMN IF NOT EXISTS max_attempts INTEGER NOT NULL DEFAULT 5;
  `,
  `
  ALTER TABLE billing_report_exports
  ADD COLUMN IF NOT EXISTS last_delivery_status TEXT;
  `,
  `
  ALTER TABLE billing_report_exports
  ALTER COLUMN attempts SET DEFAULT 0;
  `,
  `
  ALTER TABLE billing_report_exports
  ALTER COLUMN max_attempts SET DEFAULT 5;
  `,
  `
  UPDATE billing_report_exports
  SET
    attempts = COALESCE(attempts, 0),
    max_attempts = CASE WHEN COALESCE(max_attempts, 0) < 1 THEN 5 ELSE max_attempts END,
    next_attempt_at = COALESCE(next_attempt_at, scheduled_for)
  WHERE attempts IS NULL OR max_attempts IS NULL OR next_attempt_at IS NULL;
  `,
  `
  ALTER TABLE billing_report_exports
  DROP CONSTRAINT IF EXISTS billing_report_exports_max_attempts_check;
  `,
  `
  ALTER TABLE billing_report_exports
  ADD CONSTRAINT billing_report_exports_max_attempts_check
  CHECK (max_attempts >= 1)
  NOT VALID;
  `,
  `
  ALTER TABLE billing_report_exports
  VALIDATE CONSTRAINT billing_report_exports_max_attempts_check;
  `,
  `
  CREATE INDEX IF NOT EXISTS idx_billing_report_exports_status_schedule
  ON billing_report_exports(status, scheduled_for, created_at);
  `,
  `
  CREATE INDEX IF NOT EXISTS idx_billing_report_exports_retry_window
  ON billing_report_exports(status, next_attempt_at, attempts, max_attempts, created_at);
  `,
  `
  ALTER TABLE billing_report_exports
  ADD COLUMN IF NOT EXISTS delivery_ack_status TEXT NOT NULL DEFAULT 'not_required';
  `,
  `
  ALTER TABLE billing_report_exports
  ADD COLUMN IF NOT EXISTS delivery_ack_token_hash TEXT;
  `,
  `
  ALTER TABLE billing_report_exports
  ADD COLUMN IF NOT EXISTS delivery_ack_deadline TIMESTAMPTZ;
  `,
  `
  ALTER TABLE billing_report_exports
  ADD COLUMN IF NOT EXISTS delivery_ack_at TIMESTAMPTZ;
  `,
  `
  ALTER TABLE billing_report_exports
  ADD COLUMN IF NOT EXISTS delivery_ack_metadata JSONB;
  `,
  `
  ALTER TABLE billing_report_exports
  DROP CONSTRAINT IF EXISTS billing_report_exports_delivery_ack_status_check;
  `,
  `
  ALTER TABLE billing_report_exports
  ADD CONSTRAINT billing_report_exports_delivery_ack_status_check
  CHECK (delivery_ack_status IN ('not_required', 'pending', 'acknowledged', 'expired'))
  NOT VALID;
  `,
  `
  ALTER TABLE billing_report_exports
  VALIDATE CONSTRAINT billing_report_exports_delivery_ack_status_check;
  `,
  `
  CREATE INDEX IF NOT EXISTS idx_billing_report_exports_ack_status
  ON billing_report_exports(delivery_ack_status, delivery_ack_deadline, completed_at DESC);
  `,
  `
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
  `,
  `
  CREATE INDEX IF NOT EXISTS idx_billing_settlement_receipts_status_created
  ON billing_settlement_receipts(reconciliation_status, created_at DESC);
  `,
  `
  CREATE TABLE IF NOT EXISTS relay_edges (
    id UUID PRIMARY KEY,
    edge_id TEXT NOT NULL UNIQUE,
    region TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'online' CHECK (status IN ('online', 'degraded', 'offline')),
    capacity INTEGER NOT NULL DEFAULT 0,
    in_flight INTEGER NOT NULL DEFAULT 0,
    rejected_overlimit BIGINT NOT NULL DEFAULT 0,
    metadata_json JSONB,
    last_heartbeat_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  );
  `,
  `
  CREATE INDEX IF NOT EXISTS idx_relay_edges_region_status_heartbeat
  ON relay_edges(region, status, last_heartbeat_at DESC);
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
