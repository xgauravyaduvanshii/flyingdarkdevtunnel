-- Add payload and replay metadata for webhook replay automation

ALTER TABLE billing_webhook_events
  ADD COLUMN IF NOT EXISTS provider_event_type TEXT;

ALTER TABLE billing_webhook_events
  ADD COLUMN IF NOT EXISTS payload_json JSONB;

ALTER TABLE billing_webhook_events
  ADD COLUMN IF NOT EXISTS replay_count INTEGER NOT NULL DEFAULT 0;
