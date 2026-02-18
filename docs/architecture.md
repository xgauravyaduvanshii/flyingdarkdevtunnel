# Architecture Overview

## Control Plane
- Service: `services/api`
- Responsibilities:
  - user/org auth and plan entitlements,
  - tunnel lifecycle APIs,
  - custom-domain management,
  - admin/audit and billing hooks (Stripe/Razorpay/PayPal),
  - subscription cancel/refund finance operations + finance-event ledger,
  - invoice/tax ledger APIs and CSV export surfaces,
  - agent token issuance.

## Data Plane
- Relay: `go/relay`
- Agent/CLI: `go/agent`
- Responsibilities:
  - persistent websocket control channel,
  - HTTP request forwarding,
  - raw TCP forwarding,
  - TLS termination and SNI-based passthrough routing,
  - edge auth/IP policy enforcement,
  - plan-bound per-tunnel concurrency backpressure (`429` on limit breach).

## Async Workers
- `services/worker-billing`: Stripe/Razorpay/PayPal subscription sync to entitlements.
- `services/worker-billing`: webhook event retention cleanup + failure health checks.
- `services/worker-billing`: provider-scoped alert webhook delivery for webhook failure spikes.
- `services/worker-billing`: billing SLO metrics endpoint + signed runbook replay triggers.
- `services/worker-inspector`: replay queue processing and retention cleanup.
- `services/worker-certificates`: custom-domain TLS probe loop and certificate lifecycle status sync.
- `services/worker-certificates`: expiry/tls-error warning pipeline with optional alert-webhook delivery + cooldown.

## Storage
- PostgreSQL: accounts, tunnels, domains, logs metadata, entitlements, billing webhook idempotency event store (`billing_webhook_events`), finance operation ledger (`billing_finance_events`), and invoice/tax ledgers (`billing_invoices`, `billing_tax_records`).
- Redis: ephemeral coordination and rate-limit support (reserved for current + future flows).
- S3-compatible object storage: payload references for inspection/replay bodies.

## UI Layer
- `apps/console-web`: user and admin surfaces.
- `apps/docs-site`: product/CLI docs.

## Deployment Model (current)
- Provider-agnostic Ubuntu VPS with Docker Compose.
- CI uses ephemeral PostgreSQL and Redis service containers.
