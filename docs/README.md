# TunnelForge Docs

This folder contains implementation-focused documentation for engineers operating and extending the platform.

## Contents
- `docs/architecture.md`: system topology and data/control plane responsibilities.
- `docs/billing-providers.md`: Stripe/Razorpay/PayPal checkout and webhook mapping.
- `docs/certificate-lifecycle.md`: certificate state model, worker behavior, and hardening queue.
- `docs/security-and-tls.md`: TLS termination/passthrough, auth, and edge policy enforcement.
- `docs/testing-and-ci.md`: integration strategy, CI services, and smoke test flow.
- `docs/runbooks/certificate-alerts.md`: cert-event incident response and paging checklist.
- `docs/runbooks/billing-webhook-slo.md`: webhook latency SLO paging and runbook replay response.
- `docs/runbooks/ops-oncall.md`: alert-to-action runbooks for billing webhook and certificate lifecycle incidents.

## Living documentation
These docs are updated alongside code changes. The current implementation tracker is at `plan.md`.
