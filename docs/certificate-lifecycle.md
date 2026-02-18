# Certificate Lifecycle

## Scope
Tracks TLS health and cert metadata for verified custom domains in control-plane state.

Certificate state now supports two data paths:
1. event-driven lifecycle updates from cert manager/ACME integration,
2. probe-based fallback for drift detection.

Ingress endpoint:
- `POST /v1/domains/cert-events` (token-authenticated via `x-cert-event-token`)

Admin operations:
- `GET /v1/admin/cert-events` (queue/DLQ visibility)
- `POST /v1/admin/cert-events/:id/replay` (single-event replay)
- `POST /v1/admin/cert-events/replay` (bulk replay by status/source/cluster)
- `GET /v1/admin/domains/cert-region-summary` (cross-region lifecycle summary)

## Worker
- Service: `services/worker-certificates`
- Loop:
  1. Process pending `certificate_lifecycle_events` with retry/backoff semantics.
  2. Apply issuance/renewal outcomes to `custom_domains`.
  3. Optionally run TLS probe fallback on verified domains for drift visibility.
  4. Emit expiry/error alerts with cooldown control.
  5. Trigger signed runbook webhook events for alert-class states.
  6. Publish Prometheus metrics at `/metrics` (default `:9465`).

## Updated fields
- `tls_status`
- `certificate_ref`
- `tls_not_after`
- `tls_last_error`
- `tls_last_checked_at`
- `cert_failure_policy` (`standard|strict|hold`)
- `cert_failure_count`
- `cert_retry_backoff_seconds`
- `cert_next_retry_at`
- `cert_last_event_type`
- `cert_last_event_at`
- `cert_renewal_due_at`

## Status semantics
- `pending_issue`: domain verified; waiting for issuance/probe confirmation.
- `pending_route`: domain has no active tunnel route.
- `issued`: cert observed and expiry is more than 30 days away.
- `expiring`: cert observed with <=30 days remaining.
- `tls_error`: TLS probe failed for termination mode.
- `passthrough_unverified`: passthrough host (upstream-owned cert).

## Current limits
- Event ingest now supports per-source/per-cluster HMAC provenance validation (`CERT_EVENT_SOURCE_KEYS`) with timestamp freshness checks.
- Probes still run as fallback and process a bounded batch.
- Region summaries are API-level aggregates by routed tunnel region; active-active write-replication is not yet implemented.

## Alerts, metrics, and runbooks
- Prometheus metrics:
  - `fdt_cert_domains_total{status=...}`
  - `fdt_cert_events_pending_total`
  - `fdt_cert_events_failed_total`
  - `fdt_cert_domains_renewal_sla_warning_total`
  - `fdt_cert_domains_renewal_sla_breach_total`
  - `fdt_cert_renewal_sla_alerts_sent_total`
  - `fdt_cert_runbook_triggers_total`
  - `fdt_cert_runbook_trigger_failures_total`
- Alert rules:
  - `CertificateLifecycleRunbookFailures`
  - `CertificateTlsErrorsPresent`
  - `CertificateEventBacklogGrowing`
- Operational playbook:
  - `docs/runbooks/ops-oncall.md`

## Env
- `CERT_RUNBOOK_WEBHOOK_URL`
- `CERT_RUNBOOK_SIGNING_SECRET`
- `CERT_RUNBOOK_COOLDOWN_SECONDS`
- `CERT_DEPLOYMENT_ENV` (`dev|staging|prod`)
- `CERT_RENEWAL_SLA_WARNING_HOURS`
- `CERT_METRICS_PORT`

## Next hardening
- Add multi-region cert-state replication for active-active relay edges.
- Add automated DLQ replay policies with escalation classes.
