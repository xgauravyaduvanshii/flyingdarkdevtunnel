# Certificate Alert Runbook

## Trigger signals
- `services/worker-certificates` alert webhook (`CERT_ALERT_WEBHOOK_URL`).
- Alert classes:
  - `tls_error`
  - `certificate_expiring`
  - `issuance_failed`
  - `renewal_failed`
  - `renewal_sla_warning`
  - `renewal_sla_breach`

## Severity policy
- `SEV-2`: `renewal_failed` or repeated `issuance_failed` on production domains.
- `SEV-2`: `renewal_sla_breach` in production (`incidentRoute=page`).
- `SEV-3`: `certificate_expiring` with less than 14 days left.
- `SEV-3`: `renewal_sla_warning` (ticket route, pre-breach action required).
- `SEV-4`: transient `tls_error` with automatic recovery on next retry.

## Immediate triage
1. Identify domain and org from alert payload.
2. Query domain state:
   - `GET /v1/domains/custom`
   - `GET /v1/domains/custom/:id/cert-events`
3. Verify latest fields on `custom_domains`:
   - `tls_status`
   - `cert_failure_policy`
   - `cert_failure_count`
   - `cert_next_retry_at`
   - `cert_last_event_type`

## Decision matrix
- If DNS/ownership is invalid:
  - keep `cert_failure_policy=hold`,
  - notify customer to fix DNS validation.
- If ACME provider transient error:
  - set `cert_failure_policy=standard`,
  - allow worker retry/backoff.
- If high-risk production impact:
  - set `cert_failure_policy=strict`,
  - increase response priority and notify on-call.

## Operational actions
1. Update failure policy when needed:
   - `PATCH /v1/domains/custom/:id/failure-policy`
2. Ingest manual cert event if external cert manager has a definitive outcome:
   - `POST /v1/domains/cert-events`
   - include provenance headers (`x-cert-source`, `x-cert-cluster`, `x-cert-timestamp`, `x-cert-signature`) when strict validation is enabled.
3. Confirm recovery:
   - `tls_status=issued`
   - `cert_last_event_type` is success event
   - `tls_not_after` refreshed

## Exit criteria
- Domain returns to `issued` or accepted `passthrough_unverified`.
- No new failure events for 2 consecutive worker intervals.
- Incident timeline and root cause recorded in ops notes.
