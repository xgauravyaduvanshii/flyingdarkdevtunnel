# Project Plan and Live Status

## Mission
Build a production-ready, full-stack ngrok-like tunneling platform with secure HTTP/HTTPS/TCP tunnels, custom domain support, robust auth/policy controls, and CI-verified integration coverage.

## Current Phase
Phase 1 (MVP hardening + production readiness improvements)

## Completed
- Monorepo foundation with `pnpm` + Turbo workspaces.
- Fastify control-plane API with auth, tunnels, requests/replay, domains, billing, admin.
- Go relay + Go CLI agent with working end-to-end HTTP tunneling and TCP stream forwarding.
- Next.js console + admin UI with tunnel/domain/billing/inspection views.
- Billing worker + inspector worker + certificate lifecycle worker.
- Docker Compose local stack + Cloudflare helper + monitoring basics.
- Lint/typecheck/build/test pipelines.
- Initial CI workflow.

## Completed in this update
- Multi-provider billing integration:
  - Added provider-aware checkout for Stripe, Razorpay, and PayPal.
  - Added provider-specific webhook endpoints and plan-entitlement mapping.
  - Added DB support for provider plan IDs and subscription IDs.
  - Added worker-billing reconciliation for all three providers.
  - Added console billing provider selector and provider mock fallback UX.
  - Added API integration coverage for provider mock checkout flows.
- Custom-domain routing hardening APIs:
  - DNS verification flow (strict mode optional).
  - Domain-to-tunnel routing API.
  - TLS mode per domain (`termination` or `passthrough`).
- Agent token hardening:
  - Host list and TLS mode mapping claims.
  - Tunnel auth and IP policy claims for relay enforcement.
- Relay hardening:
  - TLS termination server (HTTPS).
  - Static cert support, autocert support, self-signed fallback.
  - TLS passthrough listener with SNI host extraction.
  - Host-mode enforcement (passthrough hosts blocked on HTTP termination path).
  - Basic auth and IP allowlist enforcement at relay edge.
- CI/integration upgrades:
  - API integration test coverage for paid-domain routing and enriched token claims.
  - End-to-end smoke script (API + relay + agent + workers + postgres + redis).
  - GitHub Actions integration job with ephemeral Postgres/Redis service containers.
- Certificate lifecycle visibility:
  - Added `worker-certificates` to probe custom-domain TLS and sync `tls_status`.
  - Added `tls_last_checked_at`, `tls_not_after`, `tls_last_error` schema tracking.
  - Added admin domain inventory API (`GET /v1/admin/domains`) and admin UI page.
  - Added console-domain expiry/error visibility.
  - Added smoke validation for admin domain visibility and TLS mode mapping.

## In Progress
- Certificate lifecycle automation depth:
  - Relay autocert path implemented.
  - Move from probe-based status to issuance-event/renewal-state integration for production ACME.
  - Add cert-expiry alerting and on-call runbooks.
- Payment production hardening:
  - Raw-body signature verification for all providers in production edge path.
  - Idempotency and replay-protection store for webhook events.

## Next (Implementation Queue)
1. Certificate lifecycle sync worker:
   - Integrate real issuance/renewal events from cert manager.
   - Add retry/backoff semantics and domain-level failure policy.
2. Payment hardening + finance ops:
   - Invoice/tax records, failed-payment recovery, and dunning workflows.
   - Refund/cancel flows with audit trails.
3. Multi-region edge foundations:
   - Region-aware relay registration and host assignment.
4. Enterprise controls:
   - Team/org RBAC expansion.
   - SSO and immutable audit controls.
5. Performance and resilience:
   - Load tests for relay concurrency and reconnect storms.
   - Backpressure and connection limit policy stress tests.
6. Security hardening:
   - Secret rotation workflows and token revoke list.
   - Enhanced abuse/rate limiting and anomaly detection.

## Definition of Done (for current hardening track)
- Domain verification + routing + TLS mode APIs are stable.
- Relay enforces auth/IP/host-mode policy correctly.
- CI runs integration tests against ephemeral Postgres/Redis containers.
- End-to-end smoke test passes in automation.

## Update Cadence
This file should be updated on every major implementation commit with:
- what shipped,
- what changed in scope,
- what remains.
