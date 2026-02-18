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
