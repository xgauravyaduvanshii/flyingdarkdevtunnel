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
- Ops observability + paging baseline:
  - Added worker Prometheus endpoints:
    - billing worker: `:9464/metrics`
    - certificate worker: `:9465/metrics`
  - Added webhook latency SLO metrics (`fdt_billing_webhook_processing_latency_seconds_p95`) with provider-scoped failure/stale gauges.
  - Added certificate metrics for domain lifecycle state, event backlog, and runbook trigger counters.
  - Added Prometheus scrape + rule wiring (`infra/monitoring/prometheus.yml`, `infra/monitoring/alert-rules.yml`).
  - Added first responder runbook doc: `docs/runbooks/ops-oncall.md`.
- Certificate lifecycle hardening (event-driven):
  - Added certificate lifecycle event ingest API (`POST /v1/domains/cert-events`) with token auth.
  - Added `certificate_lifecycle_events` queue + worker apply/retry lifecycle with bounded backoff.
  - Added domain-level failure policy controls (`standard|strict|hold`) and retry state fields.
  - Added per-domain certificate event history endpoint (`GET /v1/domains/custom/:id/cert-events`).
  - Added admin/domain visibility for failure policy, retry windows, and event-derived state.
- Payment production hardening + finance ops queueing:
  - Added signed runbook replay endpoint (`POST /v1/billing/runbook/replay`) for provider/event-class replay automation.
  - Added worker-billing automatic runbook replay triggers on webhook failure spikes.
  - Added dunning lifecycle model (`billing_dunning_cases`) and APIs:
    - user: `GET /v1/billing/dunning`
    - admin: `GET /v1/admin/billing-dunning`
  - Added dunning orchestration loop in billing worker with staged retries and optional signed notification webhook.
  - Added scheduled finance report export queue (`billing_report_exports`) + admin APIs:
    - `POST /v1/admin/billing-reports/exports`
    - `GET /v1/admin/billing-reports/exports`
  - Added billing worker export processing with CSV packaging and optional external sink delivery.
- Multi-region edge foundations:
  - Added tunnel region selection (`ALLOWED_REGIONS`, tunnel `region` create/update/start paths).
  - Added region claim propagation into agent token and exchange payload.
  - Added relay region identity and region-aware edge assignment (`RELAY_REGION`, `RELAY_EDGE_POOL`).
  - Added CLI region flags for `http`/`tcp` and config-file `region` support.
- Performance and resilience hardening:
  - Added plan-bound per-tunnel concurrency claims (`maxConcurrentConns`) into agent tokens.
  - Added relay backpressure enforcement for HTTP and TCP concurrency (returns `429` / rejects excess streams).
  - Added resilience tooling:
    - `scripts/http-load.mjs` concurrent HTTP load runner,
    - `scripts/relay-resilience.sh` baseline/backpressure/reconnect-storm scenario runner.
- Enterprise controls + security baseline expansion:
  - Added team/org RBAC APIs (`/v1/admin/members*`) with owner safety checks.
  - Added SSO config scaffold APIs (`GET/PUT /v1/admin/sso`).
  - Added immutable audit hash-chain fields and integrity check API (`GET /v1/admin/audit/integrity`).
  - Added token revoke list (`auth_revoked_tokens`) with runtime enforcement in auth middleware.
  - Added token revoke API (`POST /v1/auth/token/revoke`) and anomaly logging.
  - Added authtoken rotation ledger (`secret_rotations`) with admin rotate endpoint.
  - Added security anomaly event store (`security_anomaly_events`) for auth failures/rate-limit signals.
- UI/admin expansion:
  - Added admin pages: members, SSO, dunning ops, report exports.
  - Extended billing UI with dunning visibility and domain UI with failure-policy controls.
- Test/CI coverage:
  - Added integration tests for RBAC+SSO+report-queue, token revoke + runbook replay + dunning, and cert-event ingest + domain policy controls.
  - Kept CI integration command compatible by building `@fdt/config` before API integration tests.
- Invoice/tax records and reporting exports:
  - Added invoice and tax ledgers (`billing_invoices`, `billing_tax_records`) plus migrations.
  - Added user invoice APIs (`/v1/billing/invoices`, `/v1/billing/invoices/export`).
  - Added admin invoice/tax ops APIs (`/v1/admin/billing-invoices`, `/v1/admin/billing-invoices/export`).
  - Added Stripe invoice-event persistence into invoice/tax ledgers.
  - Added billing/admin UI pages for invoice visibility and CSV exports.
  - Added integration coverage for invoice/tax listing + export behavior.
- Payment finance-ops hardening:
  - Added user billing APIs for subscription state, cancel, refund, and finance-event history.
  - Added provider-aware cancel/refund execution with safe mock fallbacks in local/dev.
  - Added persistent `billing_finance_events` ledger + migration for audit-grade finance ops history.
  - Added admin finance events visibility endpoint + admin console page.
  - Added integration coverage for cancel/refund + finance-event visibility paths.
- Certificate alerting hardening:
  - Added certificate expiry threshold controls to `worker-certificates`.
  - Added TLS error/expiry warning emission with per-domain cooldown logic.
  - Added optional certificate alert webhook routing for ops integrations.
- Billing replay automation + alert routing:
  - Added admin replay endpoint for individual failed webhook events.
  - Added admin reconcile endpoint for batch replay by provider.
  - Added payload-backed replay metadata (`provider_event_type`, `payload_json`, `replay_count`).
  - Added worker-based provider alert webhook routing with cooldown controls.
  - Added integration coverage for replay/reconcile admin operations.
- Billing operations tooling:
  - Added admin billing webhook events endpoint and filtered visibility (`/v1/admin/billing-webhooks`).
  - Added admin console billing ops page with summary stats and provider/status filters.
  - Added worker-billing retention cleanup for `billing_webhook_events`.
  - Added worker-billing health warnings for failed/stale webhook processing.
  - Added integration coverage for admin webhook ops endpoint.
- Billing webhook hardening:
  - Added raw-body signature verification path for Stripe and Razorpay.
  - Added webhook idempotency/replay store (`billing_webhook_events`).
  - Added duplicate-event handling that safely no-ops repeated deliveries.
  - Added webhook age enforcement via `BILLING_WEBHOOK_MAX_AGE_SECONDS`.
  - Added integration coverage for duplicate Razorpay webhook processing.
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
- Hardening closure in this cycle:
  - Added cert-event provenance controls (source+cluster HMAC validation, freshness checks, source activity ledger).
  - Added relay heartbeat registration API and region-aware edge assignment surfaced in tunnel start/agent exchange.
  - Added provider-specific dunning cadence and channels, plus finance export sinks (`webhook|s3|warehouse`).
  - Added nightly resilience CI workflow and relay-capacity alerting.
  - Added environment-aware renewal SLA escalation in `worker-certificates` with new warning/breach metrics and runbook routing.
  - Added Grafana auto-provisioning and dashboard for relay, billing, and certificate SLOs.
- Queue implementation batch (this update):
  - Added certificate lifecycle dead-letter tooling:
    - `GET /v1/admin/cert-events`
    - `POST /v1/admin/cert-events/:id/replay`
    - `POST /v1/admin/cert-events/replay`
  - Added cross-region certificate state summary endpoint:
    - `GET /v1/admin/domains/cert-region-summary`
  - Added billing export delivery guarantees:
    - retry scheduling (`attempts`, `max_attempts`, `next_attempt_at`, `last_delivery_status`)
    - stale-running reconciliation in billing worker
    - admin reconcile endpoint `POST /v1/admin/billing-reports/exports/reconcile`
  - Added weighted regional edge assignment and failover controls:
    - `RELAY_REGION_WEIGHTS`
    - `RELAY_FAILOVER_REGIONS`
  - Added adaptive auth abuse blocking:
    - `AUTH_ABUSE_BLOCK_THRESHOLD`
    - `AUTH_ABUSE_BLOCK_WINDOW_MINUTES`
    - login gate returns `429` for blocked high-risk IP windows.
  - Added admin UI pages/controls:
    - cert event operations (`apps/console-web/app/admin/cert-events/page.tsx`)
    - billing export reconcile + retry visibility enhancements.

## In Progress
- Certificate lifecycle automation depth:
  - Relay autocert path implemented.
  - Event-driven issuance/renewal status integration shipped with per-source/per-cluster provenance verification.
  - Renewal SLA escalation shipped with environment-aware incident routing (`dev|staging|prod`) and new alert classes.
  - DLQ replay and cert-region summary shipped; active-active cross-region replication remains.
- Payment production hardening:
  - Signed runbook replay automation and staged dunning orchestration shipped.
  - Dashboard SLO/paging baseline shipped via worker metrics + runbook scaffold (`docs/runbooks/billing-webhook-slo.md`).
  - Provider-specific dunning cadence and richer notification channels shipped (`webhook|email|slack`).
  - Export retry/reconciliation pipeline shipped; production retry tuning remains telemetry-driven.
- Observability operations:
  - Relay active/inflight/rejection metrics and alert rules are live.
  - Grafana auto-provisioned dashboard shipped (`infra/monitoring/grafana/dashboards/fdt-edge-billing-overview.json`).

## Next (Implementation Queue)
1. Certificate lifecycle sync worker:
   - Add multi-region cert-state replication for active-active relay topologies.
   - Add automated DLQ replay policies and incident escalation tiers.
2. Payment hardening + finance ops:
   - Tune provider retry/dunning policy by live payment telemetry and recovery outcomes.
   - Add sink delivery acknowledgement tracking and external reconciliation sinks.
3. Multi-region edge foundations:
   - Expand beyond US with region capacity planning and failover policy drills.
4. Enterprise controls:
   - SAML/OIDC IdP onboarding and enforcement flows.
   - SCIM-style org provisioning and advanced role templates.
5. Performance and resilience:
  - Continue tightening nightly resilience thresholds per environment baseline.
  - Add chaos experiments for relay/API/Redis dependency failures.
6. Security hardening:
   - Expand anomaly detection into adaptive abuse/rate-limit decisions across non-auth endpoints.
   - Add periodic secret-rotation automation and verification jobs.

## Definition of Done (for current hardening track)
- Domain verification + routing + TLS mode APIs are stable. `Complete`
- Relay enforces auth/IP/host-mode policy correctly. `Complete`
- CI runs integration tests against ephemeral Postgres/Redis containers. `Complete`
- End-to-end smoke test passes in automation. `Complete`

## Update Cadence
This file should be updated on every major implementation commit with:
- what shipped,
- what changed in scope,
- what remains.
