-- Region heartbeat, certificate source provenance, dunning channels, report sinks.

ALTER TABLE certificate_lifecycle_events
  ADD COLUMN IF NOT EXISTS cluster_id TEXT;

ALTER TABLE certificate_lifecycle_events
  ADD COLUMN IF NOT EXISTS provenance_subject TEXT;

ALTER TABLE certificate_lifecycle_events
  ADD COLUMN IF NOT EXISTS provenance_verified BOOLEAN NOT NULL DEFAULT FALSE;

CREATE INDEX IF NOT EXISTS idx_certificate_lifecycle_events_source_cluster_created
  ON certificate_lifecycle_events(source, cluster_id, created_at DESC);

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

CREATE INDEX IF NOT EXISTS idx_cert_event_source_activity_last_seen
  ON cert_event_source_activity(last_seen_at DESC);

ALTER TABLE billing_dunning_cases
  ADD COLUMN IF NOT EXISTS notification_channels TEXT[] NOT NULL DEFAULT ARRAY['webhook']::TEXT[];

ALTER TABLE billing_dunning_cases
  DROP CONSTRAINT IF EXISTS billing_dunning_cases_notification_channels_check;

ALTER TABLE billing_dunning_cases
  ADD CONSTRAINT billing_dunning_cases_notification_channels_check
  CHECK (
    notification_channels IS NOT NULL
    AND array_length(notification_channels, 1) >= 1
    AND notification_channels <@ ARRAY['webhook', 'email', 'slack']::TEXT[]
  );

ALTER TABLE billing_report_exports
  DROP CONSTRAINT IF EXISTS billing_report_exports_destination_check;

ALTER TABLE billing_report_exports
  ADD CONSTRAINT billing_report_exports_destination_check
  CHECK (destination IN ('inline', 'webhook', 's3', 'warehouse'));

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

CREATE INDEX IF NOT EXISTS idx_relay_edges_region_status_heartbeat
  ON relay_edges(region, status, last_heartbeat_at DESC);
