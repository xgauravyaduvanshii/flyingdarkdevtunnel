# Security and TLS

## Edge security controls
- Relay validates host safety and host-to-tunnel mapping.
- Relay enforces tunnel-level Basic Auth when configured.
- Relay enforces IP allowlist/CIDR restrictions for inbound requests.
- Passthrough hosts are blocked from HTTP termination path (`426`).
- Relay enforces plan-bound concurrency limits from agent token claims and applies backpressure (`429`).
- Relay edge assignment supports weighted scheduling and configured regional failover.

## TLS modes
1. Termination
- Incoming TLS is terminated at relay HTTPS listener.
- Request is forwarded to agent over control/data frames.

2. Passthrough
- Relay extracts SNI from ClientHello and routes raw TCP stream to agent.
- Intended for end-to-end TLS where app terminates cert locally.

## Certificate strategies (relay)
1. Static certificate files (`RELAY_TLS_CERT_FILE`, `RELAY_TLS_KEY_FILE`).
2. ACME autocert (`RELAY_AUTOCERT_ENABLE=true`) with host policy allowlist.
3. Self-signed fallback for local/dev environments.

## Certificate lifecycle state (control-plane)
- `services/worker-certificates` now processes cert-manager/ACME lifecycle events and updates:
  - `certificate_lifecycle_events` queue -> `custom_domains` state sync.
- Probe fallback still runs on interval for drift detection and updates:
  - `tls_status`,
  - `certificate_ref`,
  - `tls_not_after`,
  - `tls_last_error`,
  - `tls_last_checked_at`.
- Current statuses in use: `pending_issue`, `pending_route`, `issued`, `expiring`, `tls_error`, `passthrough_unverified`.
- Passthrough domains remain explicit as `passthrough_unverified` because cert ownership is upstream.
- Cert event ingest endpoint:
  - `POST /v1/domains/cert-events` with `x-cert-event-token`.
- Domain-level retry controls:
  - `cert_failure_policy`, `cert_failure_count`, `cert_next_retry_at`.

## Domain verification
- Domain verification token is created by API.
- Strict mode (`DOMAIN_VERIFY_STRICT=true`) checks TXT record at `_fdt-verify.<domain>`.

## Next hardening items
- Renew/expiry SLO tuning by environment telemetry.
- Adaptive abuse response tuning with IP reputation feeds.

## Token and abuse hardening
- JWT access/refresh/agent tokens are issued with `jti`.
- Agent tokens include `maxConcurrentConns` for relay-side concurrency enforcement.
- Revocation list (`auth_revoked_tokens`) is enforced at auth middleware.
- Token revoke endpoint:
  - `POST /v1/auth/token/revoke`
- Security anomaly events (`security_anomaly_events`) track:
  - auth failures,
  - revoked-token activity,
  - rate-limit bursts,
  - abuse-signal escalations.
- Adaptive login gate:
  - repeated high-severity abuse signals from one IP trigger temporary login blocking (`429`).
