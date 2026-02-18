<div align="center">

![FlyingDarkDevTunnel Banner](docs/assets/platform-banner.svg)

# FlyingDarkDevTunnel

Open-source, full-stack tunneling platform inspired by ngrok.

<p>
  <a href="https://github.com"><img alt="Open Source" src="https://img.shields.io/badge/Open%20Source-Yes-22c55e?logo=opensourceinitiative&logoColor=white"></a>
  <img alt="License" src="https://img.shields.io/badge/License-AGPL--3.0-0ea5e9?logo=gnu&logoColor=white">
  <img alt="Data Plane" src="https://img.shields.io/badge/Data%20Plane-Go-16a34a?logo=go&logoColor=white">
  <img alt="Control Plane" src="https://img.shields.io/badge/Control%20Plane-Fastify%20%2B%20PostgreSQL-f97316?logo=fastify&logoColor=white">
  <img alt="Frontend" src="https://img.shields.io/badge/Frontend-Next.js-111827?logo=nextdotjs&logoColor=white">
  <img alt="Monorepo" src="https://img.shields.io/badge/Monorepo-pnpm%20%2B%20Turbo-6366f1?logo=pnpm&logoColor=white">
  <img alt="Payments" src="https://img.shields.io/badge/Payments-Stripe%20%7C%20Razorpay%20%7C%20PayPal-eab308?logo=stripe&logoColor=white">
</p>

</div>

---

## What This Project Does

FlyingDarkDevTunnel lets you expose local services to the Internet using secure, policy-aware tunnels.

It is designed for:
- webhook testing and callback development,
- public demo links for local apps,
- temporary secure developer access,
- TCP forwarding use cases (SSH/database/IoT),
- team-managed dev/test edge access with auditability.

---

## Product Capabilities

| Capability Group | Included |
|---|---|
| Tunnel Types | HTTP, HTTPS, raw TCP |
| URL Strategy | random URLs, reserved subdomains, custom domains |
| TLS Modes | termination and passthrough |
| Security Controls | basic auth, IP allowlist, token security, signed callbacks |
| Observability | request inspection, replay, metrics, logs, dashboards |
| Billing | Stripe/Razorpay/PayPal checkout, webhooks, dunning, finance exports |
| Admin | user/org controls, role templates, SCIM-like provisioning, audit chain |
| Resilience | retry/reconcile workflows, backpressure, integration + chaos testing |

---

## Architecture

### High-level topology

```mermaid
flowchart LR
  Internet[Public Internet] --> Relay[Go Relay Edge]
  Relay --> Agent[Go Agent CLI / Daemon]
  Agent --> Local[Local Service]

  Console[Next.js Console/Admin] --> API[Fastify Control Plane API]
  API --> Postgres[(PostgreSQL)]
  API --> Redis[(Redis)]
  API --> S3[(S3/MinIO)]

  WorkerBilling[worker-billing] --> API
  WorkerInspector[worker-inspector] --> API
  WorkerCert[worker-certificates] --> API
```

### Request flow (HTTP tunnel)

![Tunnel Flow](docs/assets/tunnel-flow.svg)

```mermaid
sequenceDiagram
  participant U as End User
  participant R as Relay
  participant A as Agent
  participant L as Local App

  U->>R: HTTPS request to public hostname
  R->>R: Policy checks (auth/IP/host mode/concurrency)
  R->>A: Forward over active control/data session
  A->>L: Send request to local target
  L-->>A: Response
  A-->>R: Return response stream
  R-->>U: Final response
```

### Control-plane tunnel lifecycle

```mermaid
flowchart TD
  Login[User Login] --> CreateTunnel[Create Tunnel via API]
  CreateTunnel --> StartTunnel[Start Tunnel]
  StartTunnel --> TokenIssue[API issues short-lived agent token]
  TokenIssue --> AgentConnect[Agent connects to Relay control socket]
  AgentConnect --> Active[Traffic becomes routable]
  Active --> Inspect[Request inspection + replay optional]
  Active --> Stop[Stop/Delete tunnel]
```

---

## Monorepo Structure

```txt
flyingdarkdevtunnel/
  apps/
    console-web/                 # user + admin web console
    docs-site/                   # docs frontend
  services/
    api/                         # control plane API
    worker-billing/              # billing sync/dunning/report pipeline
    worker-inspector/            # request inspection/replay retention
    worker-certificates/         # cert lifecycle + replication state
  go/
    relay/                       # edge relay ingress
    agent/                       # CLI/local tunnel client
    proto/                       # shared protocol contracts
  packages/
    ui/ config/ sdk/ eslint-config/ tsconfig/
  infra/
    docker/ cloudflare/ monitoring/ migrations/
  docs/
    runbooks/ assets/            # implementation + operations docs
  scripts/
    integration-smoke.sh relay-resilience.sh chaos-drill.sh
```

---

## Quick Start

### Prerequisites

- Node.js `20+`
- pnpm `10+`
- Go `1.18+`
- Docker + Docker Compose plugin

### Install

```bash
pnpm install
```

### Start full local stack

```bash
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

## Local CLI Usage

```bash
cd go

# Login
go run ./agent login \
  --api http://localhost:4000 \
  --email you@example.com \
  --password yourpassword

# Start HTTP tunnel
go run ./agent http \
  --api http://localhost:4000 \
  --relay ws://localhost:8081/control \
  --authtoken <authtoken> \
  --tunnel-id <tunnel-uuid> \
  --local http://localhost:3000 \
  --region us
```

For multi-tunnel config mode:
- `ourdomain.yml.example`
- `go/ourdomain.example.yml`

---

## How We Built It

This platform is intentionally split into clear responsibility layers:

1. **Data plane in Go**  
   High-throughput relay and agent control/data paths with low overhead and predictable runtime behavior.

2. **Control plane in TypeScript/Fastify**  
   Fast product iteration for auth, billing, admin, API contracts, and policy orchestration.

3. **Workers for async domains**  
   Billing reconciliation, request replay/retention, and certificate lifecycle run in isolated loops.

4. **Monorepo for consistency**  
   Shared config schemas, lint/type rules, CI workflows, and deployment definitions stay in sync.

5. **Ops-first hardening model**  
   Metrics, alerting, runbooks, replay/reconcile tooling, and chaos workflows are treated as core product features.

---

## Security Model

Security-critical behaviors included today:

- hashed secrets/tokens and JWT-based auth flows,
- token revocation list enforcement,
- relay-side policy enforcement (basic auth, CIDR allowlist, host-mode guards),
- signed webhook/callback ingestion (billing + certificate events + runbook triggers),
- audit-chain integrity controls for admin events,
- anomaly event capture and adaptive abuse controls,
- replay/reconcile tooling for billing/cert failure recovery.

See:
- `docs/security-and-tls.md`
- `docs/certificate-lifecycle.md`
- `docs/runbooks/`

---

## Observability and Reliability

- Prometheus and alert rules: `infra/monitoring/prometheus.yml`, `infra/monitoring/alert-rules.yml`
- Grafana provisioning and dashboard JSON in `infra/monitoring/grafana/`
- Resilience scripts:
  - `scripts/relay-resilience.sh`
  - `scripts/chaos-drill.sh`
- Integration smoke:
  - `scripts/integration-smoke.sh`

---

## Development Quality Gates

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

---

## Open Source and Community

This repository is now configured as an open-source project with full community files:

- License: `LICENSE` (GNU AGPL-3.0)
- Contributing guide: `CONTRIBUTING.md`
- Code of conduct: `CODE_OF_CONDUCT.md`
- Security policy: `SECURITY.md`
- Support channels: `SUPPORT.md`
- Changelog: `CHANGELOG.md`
- Issue templates: `.github/ISSUE_TEMPLATE/`
- PR template: `.github/PULL_REQUEST_TEMPLATE.md`
- Dependabot config: `.github/dependabot.yml`

---

## Documentation Map

- Docs hub: `docs/README.md`
- How it works (deep flow diagrams): `docs/how-it-works.md`
- Architecture: `docs/architecture.md`
- Billing: `docs/billing-providers.md`
- Certificate lifecycle: `docs/certificate-lifecycle.md`
- Testing/CI: `docs/testing-and-ci.md`
- Live plan/progress: `plan.md`

---

## License

Licensed under the **GNU Affero General Public License v3.0**.  
See `LICENSE` for full text.
