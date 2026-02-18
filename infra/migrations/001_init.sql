-- Initial schema for flyingdarkdevtunnel.
-- Mirrors service-level startup migrations for auditability and manual DB operations.

CREATE TABLE IF NOT EXISTS organizations (
  id UUID PRIMARY KEY,
  name TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS users (
  id UUID PRIMARY KEY,
  email TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  authtoken_hash TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS memberships (
  id UUID PRIMARY KEY,
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  role TEXT NOT NULL CHECK (role IN ('owner', 'admin', 'member')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (user_id, org_id)
);

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
