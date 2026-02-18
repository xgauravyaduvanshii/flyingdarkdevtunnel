# Testing and CI

## Quality gates
- `pnpm lint`
- `pnpm typecheck`
- `pnpm test`
- `pnpm build`
- `go test ./...` and Go binary builds

## API integration tests
- Location: `services/api/src/integration/api.integration.test.ts`
- Covers:
  - register/login flow,
  - plan upgrade to paid tier,
  - tunnel creation with auth/IP policy,
  - custom-domain create/verify/route,
  - start tunnel and verify enriched agent token claims,
  - billing checkout provider fallbacks (`stripe`, `razorpay`, `paypal`) with mock URLs,
  - finance operations (`/billing/subscription/cancel`, `/billing/refund`) with mock fallback,
  - user and admin finance-event visibility APIs,
  - user/admin invoice listing + CSV export and tax-record export APIs,
  - billing webhook idempotency (`billing_webhook_events`) for duplicate Razorpay events,
  - admin billing-webhook visibility API for operations,
  - admin replay/reconcile billing webhook operations.

## End-to-end smoke test
- Script: `scripts/integration-smoke.sh`
- Starts:
  - API,
  - billing + inspector + certificate workers,
  - relay,
  - local upstream service,
  - agent HTTP/TCP sessions.
- Verifies:
  - HTTP tunnel routing with Basic Auth,
  - HTTPS termination path,
  - passthrough host-mode enforcement,
  - admin domain inventory visibility and TLS-mode mapping.

## Relay resilience and backpressure test
- Script: `scripts/relay-resilience.sh` (root alias: `pnpm test:resilience`)
- Scope:
  - baseline relay throughput on a delayed upstream,
  - backpressure validation (expects `429` when tunnel concurrency exceeds plan-bound limits),
  - reconnect-storm simulation (agent restart cycles while requests remain in-flight).
- Output:
  - JSON reports in `.data/resilience-logs/`:
    - `baseline.json`
    - `backpressure.json`
    - `storm.json`

## CI workflow
- File: `.github/workflows/ci.yml`
- Jobs:
  1. `quality`: lint, typecheck, unit tests, build, go test/build.
  2. `integration`: uses ephemeral Postgres/Redis service containers and runs API integration + smoke script.

## Monitoring validation
- Prometheus config:
  - `infra/monitoring/prometheus.yml`
  - `infra/monitoring/alert-rules.yml`
- Worker metrics endpoints:
  - billing: `worker-billing:9464/metrics`
  - certificates: `worker-certificates:9465/metrics`
