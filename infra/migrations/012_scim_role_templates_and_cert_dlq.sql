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

CREATE INDEX IF NOT EXISTS idx_org_role_templates_org_key
  ON org_role_templates(org_id, template_key);

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

CREATE INDEX IF NOT EXISTS idx_scim_provisioning_events_org_created
  ON scim_provisioning_events(org_id, created_at DESC);

ALTER TABLE certificate_lifecycle_events
  ADD COLUMN IF NOT EXISTS dlq_replay_count INTEGER NOT NULL DEFAULT 0;

ALTER TABLE certificate_lifecycle_events
  ADD COLUMN IF NOT EXISTS last_dlq_replayed_at TIMESTAMPTZ;
