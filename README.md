# flyingdarkdevtunnel

Full-stack ngrok-like tunneling platform in a `pnpm` monorepo.

Implemented stack:
- Control plane API: Fastify + PostgreSQL + JWT + Stripe webhook support
- Data plane: Go relay + Go agent CLI with HTTP tunnel forwarding and TCP stream multiplexing
- Product UI: Next.js user/admin console + docs site
- Workers: billing sync + inspection retention/replay queue processor + certificate lifecycle sync
- Infra: Docker Compose (Postgres/Redis/MinIO/services), Cloudflare DNS script, Prometheus config

## Monorepo layout

- `apps/console-web`: user/admin console (onboarding, tunnels, inspect, domains, billing, admin pages)
- `apps/docs-site`: docs and examples
- `services/api`: control plane API (`/v1/auth`, `/v1/tunnels`, `/v1/requests`, `/v1/domains`, `/v1/billing`, `/v1/admin`, `/v1/agent`)
- `services/worker-billing`: Stripe subscription -> entitlement sync loop
- `services/worker-inspector`: replay queue + retention cleanup loop
- `services/worker-certificates`: custom-domain TLS probe and lifecycle status sync loop
- `go/relay`: edge relay (public HTTP + control websocket + TCP listeners)
- `go/agent`: CLI (`login`, `http`, `tcp`, `start`, `tunnels ls`, `inspect`)
- `go/proto`: shared control/data frame types
- `packages/config`: shared Zod env/type schemas
- `packages/sdk`: TS API client + protocol types
- `packages/ui`: shared UI primitives
- `infra/docker`: local/dev compose stack
- `infra/cloudflare`: DNS automation script for wildcard CNAME provisioning

## Prerequisites

- Node.js 20+
- pnpm 10+
- Go 1.18+
- Docker + Docker Compose plugin

Install dependencies:

```bash
pnpm install
```

## Local run (recommended)

1. Start infra:

```bash
docker compose -f infra/docker/docker-compose.dev.yml up -d postgres redis minio
```

2. Start API (from repo root):

```bash
cd services/api
cp .env.example .env
# For local docker postgres mapped to host 55432:
# DATABASE_URL=postgres://postgres:postgres@localhost:55432/fdt
pnpm dev
```

3. Start relay:

```bash
cd go
RELAY_AGENT_JWT_SECRET=<same-as-AGENT_JWT_SECRET> go run ./relay
```

4. Start console:

```bash
cd apps/console-web
cp .env.example .env
pnpm dev
```

5. Use CLI:

```bash
cd go
go run ./agent login --api http://localhost:4000 --email you@example.com --password yourpassword --authtoken <authtoken>
go run ./agent http --api http://localhost:4000 --relay ws://localhost:8081/control --tunnel-id <tunnel-uuid> --local http://localhost:3000 --authtoken <authtoken>
```

## Quality checks

```bash
pnpm lint
pnpm typecheck
pnpm build
pnpm test
cd go && go test ./... && go build -o bin/relay ./relay && go build -o bin/fdt ./agent
```

## Integration validation

```bash
# requires postgres + redis
DATABASE_URL=postgres://postgres:postgres@127.0.0.1:5432/fdt \
REDIS_URL=redis://127.0.0.1:6379 \
bash scripts/integration-smoke.sh
```

## Example multi-tunnel config

See `ourdomain.yml.example` or `go/ourdomain.example.yml`.

## Planning and technical docs

- Live implementation plan: `plan.md`
- Engineering docs: `docs/`
