# Certificate Lifecycle

## Scope
Tracks TLS health and cert metadata for verified custom domains in control-plane state.

## Worker
- Service: `services/worker-certificates`
- Loop:
  1. Fetch verified custom domains.
  2. If domain is unrouted: mark `pending_route`.
  3. If routed: probe TLS handshake on `:443`.
  4. Persist lifecycle fields on `custom_domains`.

## Updated fields
- `tls_status`
- `certificate_ref`
- `tls_not_after`
- `tls_last_error`
- `tls_last_checked_at`

## Status semantics
- `pending_issue`: domain verified; waiting for issuance/probe confirmation.
- `pending_route`: domain has no active tunnel route.
- `issued`: cert observed and expiry is more than 30 days away.
- `expiring`: cert observed with <=30 days remaining.
- `tls_error`: TLS probe failed for termination mode.
- `passthrough_unverified`: passthrough host (upstream-owned cert).

## Current limits
- Signal is probe-driven, not yet ACME-event-driven.
- Probes run on interval and process a bounded batch.
- Multi-region cert-state aggregation is not yet implemented.

## Next hardening
- Integrate cert-manager/ACME issuance events and renewal state.
- Add alerting on expiry/error thresholds.
- Add domain-level retry/backoff policies and failure suppression windows.
