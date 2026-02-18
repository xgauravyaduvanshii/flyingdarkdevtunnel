-- Domain routing + TLS hardening updates

ALTER TABLE custom_domains
  ADD COLUMN IF NOT EXISTS tls_mode TEXT NOT NULL DEFAULT 'termination';

ALTER TABLE custom_domains
  ADD COLUMN IF NOT EXISTS target_tunnel_id UUID REFERENCES tunnels(id) ON DELETE SET NULL;

ALTER TABLE custom_domains
  ADD COLUMN IF NOT EXISTS last_verified_at TIMESTAMPTZ;

ALTER TABLE custom_domains
  ADD COLUMN IF NOT EXISTS certificate_ref TEXT;

CREATE INDEX IF NOT EXISTS idx_custom_domains_target_tunnel_id
  ON custom_domains(target_tunnel_id);
