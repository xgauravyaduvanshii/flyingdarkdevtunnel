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
    stripe_customer_id TEXT,
    stripe_subscription_id TEXT,
    status TEXT NOT NULL,
    plan_id UUID REFERENCES plans(id),
    current_period_end TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(org_id)
  );
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
