# Security and TLS

## Edge security controls
- Relay validates host safety and host-to-tunnel mapping.
- Relay enforces tunnel-level Basic Auth when configured.
- Relay enforces IP allowlist/CIDR restrictions for inbound requests.
- Passthrough hosts are blocked from HTTP termination path (`426`).

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
- Cert-source provenance validation and stricter cert-manager webhook trust boundaries.
- Renew/expiry SLO alerting and paging policy automation.
- Abuse/rate-limiting anomaly baselines and automated response tuning.

## Token and abuse hardening
- JWT access/refresh/agent tokens are issued with `jti`.
- Revocation list (`auth_revoked_tokens`) is enforced at auth middleware.
- Token revoke endpoint:
  - `POST /v1/auth/token/revoke`
- Security anomaly events (`security_anomaly_events`) track:
  - auth failures,
  - revoked-token activity,
  - rate-limit bursts.
