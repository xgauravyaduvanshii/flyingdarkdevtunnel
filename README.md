<div align="center">

# FlyingDarkDevTunnel

Production-oriented, full-stack tunneling platform inspired by ngrok, built as a modern monorepo with a Go data plane and TypeScript control plane.

<p>
  <img alt="Phase" src="https://img.shields.io/badge/Phase-MVP%20Hardening-0ea5e9" />
  <img alt="Data Plane" src="https://img.shields.io/badge/Data%20Plane-Go-22c55e" />
  <img alt="Control Plane" src="https://img.shields.io/badge/Control%20Plane-Fastify%20%2B%20Postgres-f97316" />
  <img alt="Monorepo" src="https://img.shields.io/badge/Monorepo-pnpm%20%2B%20Turbo-6366f1" />
  <img alt="Billing" src="https://img.shields.io/badge/Billing-Stripe%20%7C%20Razorpay%20%7C%20PayPal-eab308" />
  <img alt="License" src="https://img.shields.io/badge/License-Private-64748b" />
</p>

</div>

---

## Table of Contents

1. [What This Project Is](#what-this-project-is)
2. [Feature Overview](#feature-overview)
3. [Architecture at a Glance](#architecture-at-a-glance)
4. [Monorepo Structure](#monorepo-structure)
5. [Quick Start](#quick-start)
6. [Environment and Secrets](#environment-and-secrets)
7. [Developer Workflows](#developer-workflows)
8. [API and Product Surface](#api-and-product-surface)
9. [Security Model](#security-model)
10. [Observability and Operations](#observability-and-operations)
11. [Testing and Quality Gates](#testing-and-quality-gates)
12. [Documentation Map](#documentation-map)
13. [Live Status and Roadmap](#live-status-and-roadmap)

---

## What This Project Is

FlyingDarkDevTunnel exposes local services to the public Internet through secure temporary or persistent tunnels.

It supports:
- `HTTP` and `HTTPS` tunnels for webhook/dev app flows
- raw `TCP` tunnels for SSH, databases, and service ports
- policy enforcement at the edge (auth, IP allowlists, host mode)
- request inspection and replay workflows
- SaaS-grade billing, entitlement gates, and admin operations
- role-based team controls and auditability

This repository includes both:
- product-facing layers (API, web console, admin panel, billing flows), and
- network-facing layers (relay, agent, edge policies, tunnel forwarding).

---

## Feature Overview

| Area | Implemented |
|---|---|
| Tunneling | HTTP/HTTPS/TCP tunnels, region-aware assignment, relay concurrency/backpressure |
| Domains + TLS | Custom domain verify/route, termination + passthrough modes, cert lifecycle ingestion |
| Auth + Access | JWT auth, agent token exchange, basic auth + IP allowlist enforcement |
| Billing | Stripe/Razorpay/PayPal checkout + webhook processing + dunning + invoice/tax records |
| Finance Ops | Finance event ledger, exports, ACK workflows, signed settlement receipt reconciliation |
| Inspector | Request logging, payload refs, replay queue orchestration |
| Admin Ops | Users, tunnels, domains, billing, cert events/incidents, audit integrity checks |
| Enterprise Foundations | Team RBAC, role templates, SCIM-like provisioning events, SSO scaffold |
| Reliability + Ops | Prometheus/Grafana, alert rules, runbooks, resilience/chaos scripts, CI integration |

---

## Architecture at a Glance

```txt
               Public Internet
                       |
             +-------------------+
             |    Go Relay Edge  |
             |  HTTP/HTTPS/TCP   |
             +-------------------+
                 | control/data
                 v
         +-----------------------+
         | Go Agent CLI/Daemon   |
         | on developer machine  |
         +-----------------------+
                 | local forward
                 v
            Local services

 Control Plane (SaaS):
 +-------------------------------+
 | Fastify API                   |
 | - auth, tunnels, domains      |
 | - billing, admin, audit       |
 +-------------------------------+
      | Postgres | Redis | S3
      v          v       v
   state      ephemeral  payload refs

 Async workers:
 - worker-billing
 - worker-inspector
 - worker-certificates
```

---

## Monorepo Structure

```txt
flyingdarkdevtunnel/
  apps/
    console-web/         # Next.js user + admin web console
    docs-site/           # product/docs frontend
  services/
    api/                 # Fastify control plane
    worker-billing/      # billing sync, dunning, exports
    worker-inspector/    # inspection retention + replay orchestration
    worker-certificates/ # cert lifecycle + replication snapshots
  go/
    relay/               # edge ingress and forwarding
    agent/               # CLI and local tunnel client
    proto/               # shared protocol contracts
  packages/
    config/              # shared env schema
    sdk/                 # TS SDK
    ui/                  # shared UI components/tokens
  infra/
    docker/              # compose stacks
    cloudflare/          # DNS automation scripts
    monitoring/          # Prometheus/Grafana configs
    migrations/          # SQL migration files
  scripts/
    integration-smoke.sh
    relay-resilience.sh
    chaos-drill.sh
  plan.md                # live implementation tracker
```

---

## Quick Start

### 1) Prerequisites

- Node.js `20+`
- pnpm `10+`
- Go `1.18+`
- Docker Engine + Compose plugin

### 2) Install dependencies

```bash
pnpm install
```

### 3) Start infrastructure

```bash
pnpm dev:infra
```

This brings up Postgres, Redis, MinIO, API, relay, console, docs, and workers using:
- `infra/docker/docker-compose.dev.yml`

### 4) Local URLs

- API: `http://localhost:4000`
- Console: `http://localhost:3000`
- Docs site: `http://localhost:3001`
- Relay HTTP edge: `http://localhost:8080`
- Relay HTTPS edge: `https://localhost:8443`
- Grafana: `http://localhost:3100`
- Prometheus: `http://localhost:9090`

### 5) Minimal manual run (service-by-service)

```bash
# API
cd services/api
cp .env.example .env
pnpm dev

# Relay
cd go
RELAY_AGENT_JWT_SECRET=<match API AGENT_JWT_SECRET> go run ./relay

# Console
cd apps/console-web
pnpm dev
```

---

## Environment and Secrets

Primary API env file:
- `services/api/.env.example`

Important key groups:

| Category | Variables |
|---|---|
| Core | `DATABASE_URL`, `REDIS_URL`, `JWT_SECRET`, `JWT_REFRESH_SECRET`, `AGENT_JWT_SECRET` |
| Domain/TLS | `BASE_DOMAIN`, `DOMAIN_VERIFY_STRICT`, `CERT_EVENT_*` |
| Billing Providers | `STRIPE_*`, `RAZORPAY_*`, `PAYPAL_*` |
| Billing Security | `BILLING_WEBHOOK_MAX_AGE_SECONDS`, `BILLING_RUNBOOK_*`, `BILLING_SETTLEMENT_*` |
| Relay Coordination | `RELAY_HEARTBEAT_*`, `ALLOWED_REGIONS`, `RELAY_REGION_WEIGHTS`, `RELAY_FAILOVER_REGIONS` |
| Object Storage | `S3_ENDPOINT`, `S3_ACCESS_KEY`, `S3_SECRET_KEY`, `S3_BUCKET` |
| DNS | `CLOUDFLARE_API_TOKEN`, `CLOUDFLARE_ZONE_ID` |

Use strong random values for all signing/JWT/token secrets in non-dev environments.

---

## Developer Workflows

### Root commands

```bash
pnpm dev
pnpm lint
pnpm typecheck
pnpm test
pnpm build
```

### Go service checks

```bash
cd go
go test ./...
go build -o bin/relay ./relay
go build -o bin/fdt ./agent
```

### Integration smoke and resilience

```bash
DATABASE_URL=postgres://postgres:postgres@127.0.0.1:55432/fdt \
REDIS_URL=redis://127.0.0.1:6379 \
bash scripts/integration-smoke.sh

DATABASE_URL=postgres://postgres:postgres@127.0.0.1:55432/fdt \
REDIS_URL=redis://127.0.0.1:6379 \
bash scripts/relay-resilience.sh

DATABASE_URL=postgres://postgres:postgres@127.0.0.1:55432/fdt \
REDIS_URL=redis://127.0.0.1:6379 \
bash scripts/chaos-drill.sh
```

---

## API and Product Surface

### Public control-plane areas

- `/v1/auth`:
  - register/login/refresh/revoke
- `/v1/tunnels`:
  - create/start/stop/update/delete tunnel sessions
- `/v1/requests`:
  - inspection and replay operations
- `/v1/domains`:
  - custom domain create/verify/route/failure-policy
  - cert event ingest + per-domain cert event listing
- `/v1/billing`:
  - checkout/cancel/refund/finance/dunning/invoices
  - webhook endpoints for Stripe/Razorpay/PayPal

### Admin operations

- `/v1/admin/users`, `/v1/admin/tunnels`, `/v1/admin/domains`
- billing operations:
  - webhook replay/reconcile
  - finance events, dunning, invoices, exports
  - settlement receipt list/reconcile
- certificate operations:
  - cert events replay controls
  - cert incidents list/ack/resolve
  - cert region and replication visibility
- team operations:
  - memberships, role templates, SCIM-like provisioning
- security and audit:
  - secret rotation health
  - audit integrity checks

---

## Security Model

Built-in hardening patterns include:

- authtoken hashing and JWT session controls
- token revocation list enforcement
- relay-side basic auth and CIDR allowlist checks
- host-mode policy enforcement for TLS termination/passthrough
- signed webhook and signed runbook/settlement endpoints
- cert event provenance validation (`source+cluster+timestamp+HMAC`)
- immutable audit chain integrity checking
- abuse/rate-limit anomaly event capture

Operational recommendation:
- keep dev tunnels short-lived,
- scope allowlists tightly,
- rotate all secrets on schedule,
- monitor replay/backlog and cert incident queues.

---

## Observability and Operations

### Metrics stack

- Prometheus config: `infra/monitoring/prometheus.yml`
- Alert rules: `infra/monitoring/alert-rules.yml`
- Grafana dashboards:
  - `infra/monitoring/grafana/dashboards/fdt-edge-billing-overview.json`

### Worker metrics endpoints

- Billing worker: `:9464/metrics`
- Certificate worker: `:9465/metrics`

### Runbooks

- `docs/runbooks/ops-oncall.md`
- `docs/runbooks/certificate-alerts.md`
- `docs/runbooks/billing-webhook-slo.md`
- `docs/runbooks/security-rotation.md`
- `docs/runbooks/chaos-drill.md`

---

## Testing and Quality Gates

CI and local validation include:

- lint + typecheck for TypeScript workspaces
- API unit/integration tests
- Go tests/builds
- end-to-end smoke script
- relay resilience/backpressure script
- nightly chaos drill workflow
- weekly secret-rotation verification workflow

Main integration suite:
- `services/api/src/integration/api.integration.test.ts`

---

## Documentation Map

- Main engineering docs: `docs/README.md`
- Architecture: `docs/architecture.md`
- Billing: `docs/billing-providers.md`
- Certificate lifecycle: `docs/certificate-lifecycle.md`
- TLS/security: `docs/security-and-tls.md`
- Testing/CI: `docs/testing-and-ci.md`
- Live roadmap/progress: `plan.md`

---

## Live Status and Roadmap

Current hardening track is focused on:

- certificate lifecycle depth and active-active readiness
- payment reliability and finance reconciliation depth
- enterprise controls expansion and policy hardening
- resilience and anomaly-driven operations

For continuously updated implementation progress, see:
- `plan.md`
