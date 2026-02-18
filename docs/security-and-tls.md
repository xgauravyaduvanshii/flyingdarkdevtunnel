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
- `services/worker-certificates` probes verified/routed domains on an interval and updates:
  - `tls_status`,
  - `certificate_ref`,
  - `tls_not_after`,
  - `tls_last_error`,
  - `tls_last_checked_at`.
- Current statuses in use: `pending_issue`, `pending_route`, `issued`, `expiring`, `tls_error`, `passthrough_unverified`.
- Passthrough domains remain explicit as `passthrough_unverified` because cert ownership is upstream.

## Domain verification
- Domain verification token is created by API.
- Strict mode (`DOMAIN_VERIFY_STRICT=true`) checks TXT record at `_fdt-verify.<domain>`.

## Next hardening items
- ACME issuance-event and renewal-state sync (replace probe-only signal as source of truth).
- Renew/expiry observability and alerting.
- Token revocation and stronger abuse controls.
