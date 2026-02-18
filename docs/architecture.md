# Architecture Overview

## Control Plane
- Service: `services/api`
- Responsibilities:
  - user/org auth and plan entitlements,
  - tunnel lifecycle APIs,
  - custom-domain management,
  - admin/audit and billing hooks (Stripe/Razorpay/PayPal),
  - agent token issuance.

## Data Plane
- Relay: `go/relay`
- Agent/CLI: `go/agent`
- Responsibilities:
  - persistent websocket control channel,
  - HTTP request forwarding,
  - raw TCP forwarding,
  - TLS termination and SNI-based passthrough routing,
  - edge auth/IP policy enforcement.

## Async Workers
- `services/worker-billing`: Stripe subscription sync to entitlements.
- `services/worker-inspector`: replay queue processing and retention cleanup.
- `services/worker-certificates`: custom-domain TLS probe loop and certificate lifecycle status sync.

## Storage
- PostgreSQL: accounts, tunnels, domains, logs metadata, entitlements.
- Redis: ephemeral coordination and rate-limit support (reserved for current + future flows).
- S3-compatible object storage: payload references for inspection/replay bodies.

## UI Layer
- `apps/console-web`: user and admin surfaces.
- `apps/docs-site`: product/CLI docs.

## Deployment Model (current)
- Provider-agnostic Ubuntu VPS with Docker Compose.
- CI uses ephemeral PostgreSQL and Redis service containers.
