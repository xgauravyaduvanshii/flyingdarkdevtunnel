# On-Call Runbooks

This runbook maps Prometheus alert signals to immediate responder actions.

## Billing webhook latency
### Alert
- `BillingWebhookP95LatencyHigh`

### First checks
1. Inspect worker metrics: `curl -s http://worker-billing:9464/metrics | rg "fdt_billing_webhook_(processing_latency_seconds_p95|stale_pending|failed_events_1h)"`
2. Check API webhook ingestion errors in logs (`services/api`).
3. Check worker replay status in `billing_webhook_events` and `billing_finance_events`.

### Mitigation
1. Trigger replay runbook endpoint for impacted provider/event class.
2. Scale API/worker replicas if backlog is growing.
3. If provider outage confirmed, switch alert severity to ticket and keep replay loop active.

### Exit criteria
1. `fdt_billing_webhook_processing_latency_seconds_p95 <= fdt_billing_webhook_slo_seconds` for 15 minutes.
2. `fdt_billing_webhook_stale_pending == 0`.

## Billing stale pending events
### Alert
- `BillingWebhookStalePending`

### First checks
1. Query oldest pending rows:
   - `SELECT provider, event_id, received_at FROM billing_webhook_events WHERE status='pending' ORDER BY received_at ASC LIMIT 50;`
2. Confirm DB/Redis connectivity and webhook signature verification failures in API logs.

### Mitigation
1. Run admin reconcile endpoint for provider.
2. If signature errors spike, rotate provider secrets and redeploy.
3. Increase replay limit temporarily for controlled catch-up.

### Exit criteria
1. Pending queue older than 5 minutes is zero for 10 minutes.

## Billing failure burst
### Alert
- `BillingWebhookFailureBurst`

### First checks
1. Inspect recent failed payloads from `billing_webhook_events.last_error`.
2. Validate provider API health and credential validity.

### Mitigation
1. If provider auth issue, rotate key material and replay failures.
2. If schema mismatch, hotfix parser and replay failed class.

## Billing report export delivery failures
### Trigger
- Failed rows in `billing_report_exports` with destination `webhook|warehouse|s3`.

### First checks
1. Query failed exports:
   - `SELECT id, dataset, destination, attempts, max_attempts, next_attempt_at, error FROM billing_report_exports WHERE status='failed' ORDER BY updated_at DESC LIMIT 50;`
2. Confirm sink health (HTTP response status or object-store auth).

### Mitigation
1. Replay queue via admin API:
   - `POST /v1/admin/billing-reports/exports/reconcile`
2. If retries are exhausted too quickly, increase `max_attempts` for new jobs and tune `BILLING_REPORT_RETRY_SCHEDULE_SECONDS`.
3. For stale running jobs, verify worker liveness and `BILLING_REPORT_RUNNING_TIMEOUT_SECONDS`.

## Certificate runbook trigger failures
### Alert
- `CertificateLifecycleRunbookFailures`

### First checks
1. Check worker logs for `runbook alert delivery failed`.
2. Verify runbook endpoint health and signing secret alignment.

### Mitigation
1. Restore endpoint access or temporarily disable runbook webhook while preserving alert webhook.
2. Re-enable and validate with a controlled expiring-cert event.

## Certificate TLS errors
### Alert
- `CertificateTlsErrorsPresent`

### First checks
1. Inspect domains in `tls_error` from `custom_domains`.
2. Check last cert events for each domain (`/v1/domains/custom/:id/cert-events`).

### Mitigation
1. Route to fallback tunnel if applicable.
2. Force cert-manager renewal and verify DNS ownership records.
3. For persistent failures, set strict/hold policy based on blast radius.

## Certificate event backlog
### Alert
- `CertificateEventBacklogGrowing`

### First checks
1. Inspect pending queue depth in `certificate_lifecycle_events`.
2. Check worker loop health and DB performance.

### Mitigation
1. Increase worker throughput (`CERT_EVENT_BATCH_SIZE`) and reduce loop interval.
2. Clear poison events by marking failed after root-cause capture.

## Certificate renewal SLA breach
### Alert
- `CertificateRenewalSlaBreach`

### First checks
1. Inspect current breach count from metrics:
   - `fdt_cert_domains_renewal_sla_breach_total`
2. Query impacted domains:
   - `SELECT domain, tls_status, cert_renewal_due_at FROM custom_domains WHERE cert_renewal_due_at <= NOW() ORDER BY cert_renewal_due_at ASC LIMIT 50;`
3. Confirm recent lifecycle events:
   - `GET /v1/domains/custom/:id/cert-events`

### Mitigation
1. For production domains, trigger incident paging and force cert-manager renewal.
2. Temporarily shift affected hostname to fallback route if available.
3. If provenance/signature issues block updates, fix source keys and replay events.

## Certificate renewal SLA warning
### Alert
- `CertificateRenewalSlaWarning`

### First checks
1. Inspect warning count from metrics:
   - `fdt_cert_domains_renewal_sla_warning_total`
2. Review domains approaching due time and verify current issuance state.

### Mitigation
1. Preemptively trigger renewal for domains inside warning window.
2. Confirm cert-manager cluster health and queue depth before breach window.

## Relay overlimit burst
### Alert
- `RelayOverlimitRejectionsBurst`

### First checks
1. Inspect relay metrics:
   - `fdt_relay_inflight_http_requests`
   - `fdt_relay_active_tcp_streams`
   - `fdt_relay_http_overlimit_rejections_total`
   - `fdt_relay_tcp_overlimit_rejections_total`
2. Correlate with plan concurrency settings for impacted orgs.

### Mitigation
1. Scale relay capacity or rebalance to additional relay edges in the same region.
2. If abuse traffic is suspected, tighten allowlists/rate limits for impacted tunnels.

## Relay inflight high
### Alert
- `RelayInflightHigh`

### First checks
1. Check p95 upstream latency and agent connectivity health.
2. Validate whether reconnect storm tests or deployments are in progress.

### Mitigation
1. Increase relay concurrency budget temporarily and observe rejection counters.
2. Roll back recent edge change if inflight increase correlates with release start.
