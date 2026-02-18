-- Billing webhook idempotency and replay-protection event store

CREATE TABLE IF NOT EXISTS billing_webhook_events (
  id UUID PRIMARY KEY,
  provider TEXT NOT NULL CHECK (provider IN ('stripe', 'razorpay', 'paypal')),
  event_id TEXT NOT NULL,
  payload_hash TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('pending', 'processed', 'failed')),
  attempts INTEGER NOT NULL DEFAULT 1,
  received_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  processed_at TIMESTAMPTZ,
  last_error TEXT,
  UNIQUE (provider, event_id)
);

CREATE INDEX IF NOT EXISTS idx_billing_webhook_events_received_at
ON billing_webhook_events(received_at DESC);

CREATE INDEX IF NOT EXISTS idx_billing_webhook_events_status
ON billing_webhook_events(status);
