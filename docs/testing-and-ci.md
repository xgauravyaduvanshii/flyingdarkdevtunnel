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
  - billing webhook idempotency (`billing_webhook_events`) for duplicate Razorpay events,
  - admin billing-webhook visibility API for operations.

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

## CI workflow
- File: `.github/workflows/ci.yml`
- Jobs:
  1. `quality`: lint, typecheck, unit tests, build, go test/build.
  2. `integration`: uses ephemeral Postgres/Redis service containers and runs API integration + smoke script.
