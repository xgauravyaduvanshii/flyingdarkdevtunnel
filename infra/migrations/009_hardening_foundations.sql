-- Hardening foundations:
-- - certificate lifecycle events + domain failure policy
-- - token revoke list + secret rotation ledger
-- - immutable audit hash chain fields
-- - enterprise SSO metadata
-- - billing dunning and report export queues
-- - expanded membership roles

ALTER TABLE memberships
  DROP CONSTRAINT IF EXISTS memberships_role_check;

ALTER TABLE memberships
  ADD CONSTRAINT memberships_role_check
  CHECK (role IN ('owner', 'admin', 'member', 'billing', 'viewer'));

ALTER TABLE custom_domains
  ADD COLUMN IF NOT EXISTS cert_failure_policy TEXT NOT NULL DEFAULT 'standard';

ALTER TABLE custom_domains
  ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW();

ALTER TABLE custom_domains
  ADD COLUMN IF NOT EXISTS cert_failure_count INTEGER NOT NULL DEFAULT 0;

ALTER TABLE custom_domains
  ADD COLUMN IF NOT EXISTS cert_retry_backoff_seconds INTEGER NOT NULL DEFAULT 0;

ALTER TABLE custom_domains
  ADD COLUMN IF NOT EXISTS cert_next_retry_at TIMESTAMPTZ;

ALTER TABLE custom_domains
  ADD COLUMN IF NOT EXISTS cert_last_event_type TEXT;

ALTER TABLE custom_domains
  ADD COLUMN IF NOT EXISTS cert_last_event_at TIMESTAMPTZ;

ALTER TABLE custom_domains
  ADD COLUMN IF NOT EXISTS cert_renewal_due_at TIMESTAMPTZ;

ALTER TABLE custom_domains
  DROP CONSTRAINT IF EXISTS custom_domains_cert_failure_policy_check;

ALTER TABLE custom_domains
  ADD CONSTRAINT custom_domains_cert_failure_policy_check
  CHECK (cert_failure_policy IN ('standard', 'strict', 'hold'));

CREATE INDEX IF NOT EXISTS idx_custom_domains_retry_policy
  ON custom_domains(cert_next_retry_at, cert_failure_policy)
  WHERE cert_next_retry_at IS NOT NULL;

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

DROP INDEX IF EXISTS idx_certificate_lifecycle_events_source_event_id;

CREATE UNIQUE INDEX IF NOT EXISTS idx_certificate_lifecycle_events_source_event_id
  ON certificate_lifecycle_events(source, source_event_id);

CREATE INDEX IF NOT EXISTS idx_certificate_lifecycle_events_status
  ON certificate_lifecycle_events(status, next_retry_at, created_at);

ALTER TABLE audit_logs
  ADD COLUMN IF NOT EXISTS prev_hash TEXT;

ALTER TABLE audit_logs
  ADD COLUMN IF NOT EXISTS entry_hash TEXT;

ALTER TABLE audit_logs
  ADD COLUMN IF NOT EXISTS immutable BOOLEAN NOT NULL DEFAULT TRUE;

CREATE UNIQUE INDEX IF NOT EXISTS idx_audit_logs_entry_hash
  ON audit_logs(entry_hash)
  WHERE entry_hash IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_audit_logs_org_chain
  ON audit_logs(org_id, created_at, id);

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

CREATE INDEX IF NOT EXISTS idx_auth_revoked_tokens_expires
  ON auth_revoked_tokens(expires_at);

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

CREATE INDEX IF NOT EXISTS idx_secret_rotations_org_created
  ON secret_rotations(org_id, created_at DESC);

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

CREATE INDEX IF NOT EXISTS idx_security_anomaly_events_created
  ON security_anomaly_events(created_at DESC);

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
  last_error TEXT,
  latest_event_id TEXT,
  latest_event_type TEXT,
  payload_json JSONB,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE(org_id, provider, subscription_ref)
);

CREATE INDEX IF NOT EXISTS idx_billing_dunning_cases_status_next_attempt
  ON billing_dunning_cases(status, next_attempt_at, updated_at);

CREATE TABLE IF NOT EXISTS billing_report_exports (
  id UUID PRIMARY KEY,
  org_id UUID REFERENCES organizations(id) ON DELETE SET NULL,
  dataset TEXT NOT NULL CHECK (dataset IN ('finance_events', 'invoices', 'dunning')),
  format TEXT NOT NULL CHECK (format IN ('csv')),
  status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'running', 'completed', 'failed')),
  destination TEXT NOT NULL DEFAULT 'inline' CHECK (destination IN ('inline', 'webhook')),
  sink_url TEXT,
  scheduled_for TIMESTAMPTZ NOT NULL DEFAULT NOW(),
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

CREATE INDEX IF NOT EXISTS idx_billing_report_exports_status_schedule
  ON billing_report_exports(status, scheduled_for, created_at);
