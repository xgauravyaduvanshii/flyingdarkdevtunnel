# FlyingDarkDevTunnel Docs

<p>
  <img alt="Docs Scope" src="https://img.shields.io/badge/Docs-Engineering%20Operations-0ea5e9" />
  <img alt="Coverage" src="https://img.shields.io/badge/Coverage-Architecture%20to%20Runbooks-22c55e" />
  <img alt="Status" src="https://img.shields.io/badge/Status-Live%20and%20Versioned-f97316" />
</p>

Implementation-focused documentation for engineers shipping, operating, and hardening the platform.

---

## Documentation Paths by Role

### Platform Engineer

1. `docs/architecture.md`
2. `docs/how-it-works.md`
3. `docs/security-and-tls.md`
4. `docs/certificate-lifecycle.md`
5. `docs/testing-and-ci.md`

### Billing/Finance Operations

1. `docs/billing-providers.md`
2. `docs/runbooks/billing-webhook-slo.md`
3. `docs/runbooks/ops-oncall.md`

### SRE / On-Call

1. `docs/runbooks/ops-oncall.md`
2. `docs/runbooks/certificate-alerts.md`
3. `docs/runbooks/chaos-drill.md`
4. `docs/runbooks/security-rotation.md`

---

## Core Documents

| File | Focus | When to Open It |
|---|---|---|
| `docs/architecture.md` | Control-plane/data-plane topology and boundaries | New contributors, major refactors |
| `docs/how-it-works.md` | End-to-end flow diagrams for tunnel, cert, and billing pipelines | Feature walkthroughs and onboarding |
| `docs/security-and-tls.md` | TLS modes, auth, edge policy rules | Security reviews, edge behavior changes |
| `docs/certificate-lifecycle.md` | Cert ingest, worker flows, incidents, replication | TLS automation and cert incidents |
| `docs/billing-providers.md` | Stripe/Razorpay/PayPal flows + admin ops | Payment changes and finance operations |
| `docs/testing-and-ci.md` | Quality gates, integration scope, CI workflow | Before merge/release validation |

---

## Runbooks

| File | Trigger Type | Outcome |
|---|---|---|
| `docs/runbooks/ops-oncall.md` | General platform alerts | Structured triage and escalation |
| `docs/runbooks/certificate-alerts.md` | TLS/cert failures or expiry pressure | Cert incident containment + recovery |
| `docs/runbooks/billing-webhook-slo.md` | Billing latency/failure SLO drift | Replay/reconcile and customer-impact reduction |
| `docs/runbooks/security-rotation.md` | Rotation hygiene/compliance checks | Secret rotation remediation workflow |
| `docs/runbooks/chaos-drill.md` | Reliability drills | Baseline resilience verification |

---

## Monitoring Assets

- Prometheus:
  - `infra/monitoring/prometheus.yml`
  - `infra/monitoring/alert-rules.yml`
- Grafana provisioning:
  - `infra/monitoring/grafana/provisioning/datasources/prometheus.yml`
  - `infra/monitoring/grafana/provisioning/dashboards/dashboards.yml`
- Dashboard JSON:
  - `infra/monitoring/grafana/dashboards/fdt-edge-billing-overview.json`

## Visual Assets

- `docs/assets/platform-banner.svg`
- `docs/assets/tunnel-flow.svg`

---

## Doc Maintenance Rules

- Update docs in the same PR/commit when behavior changes.
- Keep endpoint names and env keys exactly aligned with code.
- Record operational changes in runbooks, not only in code comments.
- Reflect major status changes in `plan.md`.

---

## Living Source of Truth

`plan.md` is the live implementation tracker for:
- shipped functionality,
- in-progress work,
- next queue priorities.

If a doc and code diverge, update the doc immediately in the next commit.

## Open-Source Community Files

Repository community/maintainer files are in the project root:

- `CONTRIBUTING.md`
- `CODE_OF_CONDUCT.md`
- `SECURITY.md`
- `SUPPORT.md`
- `GOVERNANCE.md`
- `MAINTAINERS.md`
- `CHANGELOG.md`
