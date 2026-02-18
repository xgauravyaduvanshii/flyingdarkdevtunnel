# Agent Guide

This file is a quick operator guide for AI agents and engineering contributors in this repository.

## Mission

Build and operate a production-minded tunneling platform:
- reliable data plane (`go/relay`, `go/agent`),
- policy-aware control plane (`services/api`),
- async reliability loops (billing, certificates, inspector workers),
- docs and runbooks as first-class artifacts.

## Fast Start

```bash
pnpm install
pnpm dev:infra
```

Core endpoints:
- API: `http://localhost:4000`
- Console: `http://localhost:3000`
- Relay: `http://localhost:8080` / `https://localhost:8443`

## Non-Negotiables

- Keep `plan.md` updated when status changes.
- Keep docs in sync with behavior.
- Prefer deterministic retries/reconcile over silent failures.
- Enforce security controls on both API and relay paths.
- Commit in small, reviewable units.

## Validation Checklist

```bash
pnpm lint
pnpm typecheck
pnpm test
cd go && go test ./...
```

