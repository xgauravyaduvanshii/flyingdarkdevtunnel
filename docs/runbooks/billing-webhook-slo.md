# Billing Webhook SLO Runbook

## SLO definition
- Source: `services/worker-billing` metrics endpoint (`/metrics`).
- Primary objective:
  - p95 processing latency `< BILLING_WEBHOOK_SLO_SECONDS`
  - low failed-event volume in rolling 1h/24h windows.

## Pager triggers
- `fdt_billing_webhook_slo_violations_1h{provider}>0` for 10 minutes.
- `fdt_billing_webhook_failed_events_1h{provider}` above warning threshold.
- `fdt_billing_webhook_stale_pending{provider}>0` sustained for 5+ minutes.

## Immediate response
1. Identify impacted provider (`stripe`, `razorpay`, `paypal`).
2. Inspect admin operations endpoints:
   - `GET /v1/admin/billing-webhooks`
   - `GET /v1/admin/billing-finance-events`
   - `GET /v1/admin/billing-dunning`
3. Check worker logs for signature or provider API failures.
4. For export sink backlog, inspect ACK state on:
   - `GET /v1/admin/billing-reports/exports`
   - `POST /v1/admin/billing-reports/exports/ack-reconcile`

## Replay automation path
- Worker auto-trigger uses signed endpoint:
  - `POST /v1/billing/runbook/replay`
  - headers: `x-fdt-runbook-timestamp`, `x-fdt-runbook-signature`
- If needed, run targeted admin replay:
  - `POST /v1/admin/billing-webhooks/:id/replay`
  - `POST /v1/admin/billing-webhooks/reconcile`

## Dunning and customer impact
- Validate dunning queue health:
  - stage progression and `next_attempt_at`
  - notification delivery status (`notification_count`, `last_error`)
- If backlog is growing, lower retry aggressiveness and prioritize provider recovery.
- If report exports remain `delivered_pending_ack`, run ACK reconcile and verify sink callback path:
  - `POST /v1/billing/reports/exports/:id/ack`

## Exit criteria
- SLO violations return to zero for one full hour.
- Failed/stale webhook counts return below thresholds.
- Replay backlog drained and affected subscriptions reconciled.
- Incident summary written with provider root cause and policy tuning actions.
