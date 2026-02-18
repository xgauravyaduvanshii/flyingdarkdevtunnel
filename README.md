<div align="center">

![FlyingDarkDevTunnel Banner](docs/assets/platform-banner.svg)

# FlyingDarkDevTunnel

Open-source tunneling platform that turns localhost services into secure, policy-aware public endpoints.

<p>
  <a href="https://github.com/xgauravyaduvanshii/flyingdarkdevtunnel"><img alt="Open Source" src="https://img.shields.io/badge/Open%20Source-Yes-22c55e?logo=opensourceinitiative&logoColor=white"></a>
  <img alt="License" src="https://img.shields.io/badge/License-AGPL--3.0-0ea5e9?logo=gnu&logoColor=white">
  <img alt="Data Plane" src="https://img.shields.io/badge/Data%20Plane-Go-16a34a?logo=go&logoColor=white">
  <img alt="Control Plane" src="https://img.shields.io/badge/Control%20Plane-Fastify%20%2B%20PostgreSQL-f97316?logo=fastify&logoColor=white">
  <img alt="Frontend" src="https://img.shields.io/badge/Frontend-Next.js-111827?logo=nextdotjs&logoColor=white">
  <img alt="Monorepo" src="https://img.shields.io/badge/Monorepo-pnpm%20%2B%20Turbo-6366f1?logo=pnpm&logoColor=white">
  <img alt="Payments" src="https://img.shields.io/badge/Payments-Stripe%20%7C%20Razorpay%20%7C%20PayPal-eab308?logo=stripe&logoColor=white">
</p>
<p>
  <a href="docs/how-it-works.md">How It Works</a>
  ·
  <a href="docs/architecture.md">Architecture</a>
  ·
  <a href="docs/testing-and-ci.md">Testing and CI</a>
  ·
  <a href="docs/runbooks/ops-oncall.md">Runbooks</a>
  ·
  <a href="https://github.com/xgauravyaduvanshii">Owner: xgauravyaduvanshii</a>
  ·
  <a href="https://github.com/xgauravyaduvanshii/flyingdarkdevtunnel">Repository Home</a>
</p>

</div>

---

## Platform Story

FlyingDarkDevTunnel is built for teams that need more than a temporary tunnel URL.  
It combines data-plane speed, control-plane policy, payment operations, and production-grade runbook discipline in one monorepo.

This project is designed so that each critical behavior has:
- explicit ownership,
- deterministic retry/reconcile paths,
- and measurable operational signals.

> Build fast like a developer tool, run safe like production infrastructure.

![Platform Pillars](docs/assets/platform-pillars.svg)

---

## Why Teams Use It

- Ship webhook integrations without deploying staging environments for every branch.
- Expose demo and QA environments safely with auth/IP controls.
- Tunnel raw TCP services for SSH, DB diagnostics, and IoT flows.
- Manage billing entitlements and audit trails from the same platform model.
- Run with operational confidence using dashboards, alerts, and recovery runbooks.

This repository intentionally speaks to multiple personas who collaborate on one shared system model instead of disconnected tools.

![Persona and Use-Case Map](docs/assets/persona-usecases.svg)

---

## Capability Matrix

| Capability Group | Included |
|---|---|
| Tunnel Protocols | HTTP, HTTPS, raw TCP |
| URL Strategy | random URLs, reserved subdomains, custom domains |
| TLS Modes | edge termination and end-to-end passthrough |
| Access Controls | JWT auth, basic auth, CIDR allowlist, revocation lists |
| Inspection | request metadata capture, payload retention controls, replay API |
| Billing Providers | Stripe, Razorpay, PayPal |
| Admin Controls | user/org management, entitlement overrides, audit visibility |
| Reliability Features | retries, dead-letter workflows, replay/reconcile pipelines |
| Operations | Prometheus, Grafana, alert rules, incident runbooks |

![Feature and Plan Comparison](docs/assets/feature-plan-comparison.svg)
![Protocol Capability Grid](docs/assets/protocol-capability-grid.svg)

---

## Localhost to Internet Journey

![Local to Public Journey](docs/assets/local-to-public-journey.svg)
![Architecture Topology](docs/assets/architecture-topology.svg)
![Tunnel Flow](docs/assets/tunnel-flow.svg)
![Tunnel Sequence](docs/assets/tunnel-sequence.svg)
![Control Plane Lifecycle](docs/assets/control-plane-lifecycle.svg)

This request journey is built around strict checkpoints:
- identity and entitlement validation before edge registration,
- relay-side enforcement for host mode, auth, and network policy,
- stream forwarding between relay and agent,
- optional inspection and replay for debugging,
- metrics and audit artifacts for incident response.

![Inspection and Replay Cycle](docs/assets/inspection-replay-cycle.svg)

---

## CLI Experience

![CLI Command Landscape](docs/assets/cli-command-landscape.svg)

### Core commands

```bash
cd go

# login
go run ./agent login \
  --api http://localhost:4000 \
  --email xgauravyaduvanshii@gmail.com \
  --password yourpassword

# http tunnel
go run ./agent http \
  --api http://localhost:4000 \
  --relay ws://localhost:8081/control \
  --authtoken <authtoken> \
  --tunnel-id <tunnel-uuid> \
  --local http://localhost:3000 \
  --region us

# tcp tunnel
go run ./agent tcp \
  --api http://localhost:4000 \
  --relay ws://localhost:8081/control \
  --authtoken <authtoken> \
  --tunnel-id <tunnel-uuid> \
  --local 127.0.0.1:22 \
  --region us
```

For multi-tunnel configs:
- `ourdomain.yml.example`
- `go/ourdomain.example.yml`

---

## Monorepo Architecture

![Monorepo Map](docs/assets/monorepo-map.svg)

| Path | Role |
|---|---|
| `apps/` | User/admin console and docs surface |
| `services/` | API and workers (billing, inspector, certificates) |
| `go/` | Relay edge + agent CLI + shared proto contracts |
| `packages/` | Shared config, UI, SDK, lint/type presets |
| `infra/` | Docker, migrations, Cloudflare, monitoring |
| `docs/` | Design references, runbooks, operational guides |
| `scripts/` | Smoke tests, resilience drills, local bootstrap |

---

## Security and Trust Model

Security is not treated as an add-on; it is encoded in runtime decisions and async pipelines.

![Security Defense Layers](docs/assets/security-defense-layers.svg)
![Certificate Incident Timeline](docs/assets/cert-incident-timeline.svg)
![Edge Policy Flow](docs/assets/edge-policy-flow.svg)
![Threat to Response Map](docs/assets/threat-response-map.svg)

Implemented security controls include:
- hashed authtokens and short-lived signed agent tokens,
- token revoke-list checks in control and edge flows,
- relay-side basic auth and CIDR allowlist enforcement,
- signed provider callbacks for billing and certificate events,
- immutable audit integrity verification for sensitive admin actions.

See:
- `docs/security-and-tls.md`
- `docs/certificate-lifecycle.md`
- `docs/runbooks/certificate-alerts.md`

---

## Payments and Revenue Operations

Payment architecture is designed for correctness under retries, provider jitter, and delayed settlements.

![Payment Orchestration Layers](docs/assets/payment-orchestration-layers.svg)
![Billing Reconciliation Flow](docs/assets/billing-reconciliation-flow.svg)

Current behavior includes:
- real provider mode for Stripe with fallback mock checkout when keys are absent,
- Razorpay and PayPal provider orchestration hooks,
- signed webhook ingestion and replay-safe processing,
- dunning state tracking and finance export packaging workflows.

See:
- `docs/billing-providers.md`
- `docs/runbooks/billing-webhook-slo.md`
- `services/worker-billing/`

---

## Reliability and On-Call Operations

![Release and Operations Loop](docs/assets/release-ops-loop.svg)
![Roadmap Flight Path](docs/assets/roadmap-flightpath.svg)
![Observability Command Center](docs/assets/observability-command-center.svg)

Reliability foundation:
- Prometheus and alert rules under `infra/monitoring/`,
- Grafana provisioning and dashboard JSON committed in-repo,
- integration smoke plus resilience scripts in `scripts/`,
- runbook-first incident handling for certificate, payment, and security classes.

---

## Deployment Blueprint

![Deployment Blueprint](docs/assets/deployment-blueprint.svg)
![Custom Domain Lifecycle Map](docs/assets/domain-lifecycle-map.svg)

The platform can run as a managed SaaS stack on Ubuntu VPS with Docker Compose:
- edge relay for ingress and policy gates,
- API and workers for control + async workflows,
- PostgreSQL/Redis/object storage for persistence layers,
- monitoring and alerting for on-call visibility.

---

## Quick Start

### Prerequisites

- Node.js `20+`
- pnpm `10+`
- Go `1.18+`
- Docker + Docker Compose plugin

### Install and run

```bash
pnpm install
pnpm dev:infra
```

Core local endpoints:
- API: `http://localhost:4000`
- Console: `http://localhost:3000`
- Docs: `http://localhost:3001`
- Relay HTTP: `http://localhost:8080`
- Relay HTTPS: `https://localhost:8443`
- Grafana: `http://localhost:3100`
- Prometheus: `http://localhost:9090`

---

## Quality Gates

```bash
pnpm lint
pnpm typecheck
pnpm test
pnpm build

cd go
go test ./...
go build -o bin/relay ./relay
go build -o bin/fdt ./agent
```

Integration tests (API):

```bash
DATABASE_URL=postgres://postgres:postgres@127.0.0.1:55432/fdt \
REDIS_URL=redis://127.0.0.1:6379 \
pnpm --filter @fdt/api test:integration
```

![CI and Release Gates](docs/assets/ci-release-gates.svg)

Release quality philosophy:
- code quality checks prevent drift in shared contracts and policies,
- integration gates validate behavior across API, workers, and relay surfaces,
- resilience checks validate recovery workflows before customer-impacting changes ship.

---

## Documentation

- docs hub: `docs/README.md`
- architecture deep dive: `docs/architecture.md`
- flow diagrams: `docs/how-it-works.md`
- security and TLS: `docs/security-and-tls.md`
- billing providers: `docs/billing-providers.md`
- certificate lifecycle: `docs/certificate-lifecycle.md`
- testing and CI: `docs/testing-and-ci.md`
- live execution tracker: `plan.md`

---

## Open Source

![Contribution Workflow](docs/assets/contribution-workflow.svg)

Community and governance files:
- `CONTRIBUTING.md`
- `CODE_OF_CONDUCT.md`
- `SECURITY.md`
- `SUPPORT.md`
- `GOVERNANCE.md`
- `MAINTAINERS.md`
- `CHANGELOG.md`
- `.github/ISSUE_TEMPLATE/`
- `.github/PULL_REQUEST_TEMPLATE.md`
- `.github/dependabot.yml`

---

## Maintainer Links

- Owner profile: `https://github.com/xgauravyaduvanshii`
- Repository: `https://github.com/xgauravyaduvanshii/flyingdarkdevtunnel`

---

## License

Licensed under the **GNU Affero General Public License v3.0**.  
See `LICENSE` for full text.
