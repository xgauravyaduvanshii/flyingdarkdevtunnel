# Cloude Deployment Notes

This document tracks practical cloud deployment defaults for FlyingDarkDevTunnel.

## Baseline Topology

- DNS + edge records via Cloudflare.
- Relay edge exposed on HTTP/HTTPS/TCP ingress ports.
- API and workers behind private network boundaries.
- PostgreSQL + Redis + object storage for state and payload references.
- Prometheus + Grafana for platform health signals.

## Minimum Production Controls

- TLS everywhere required for public traffic.
- Secret rotation workflow enabled.
- Webhook signature verification enabled for all providers.
- Token revocation checks enabled in control and edge layers.
- Alert rules mapped to runbooks (`docs/runbooks/`).

## Deploy Order

1. Provision storage and databases.
2. Deploy API and migrations.
3. Deploy relay edge and heartbeat.
4. Deploy workers (billing, certs, inspector).
5. Deploy dashboards/alerts and run smoke checks.

## Release Gate

Do not promote if any of these fail:
- integration tests,
- relay/agent smoke path,
- billing webhook replay checks,
- certificate lifecycle health checks.

