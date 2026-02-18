# Contributing to FlyingDarkDevTunnel

Thank you for helping improve this project.

This guide explains how to contribute code, docs, tests, and operational improvements in a way that keeps the platform stable and secure.

---

## Table of Contents

1. [Ways to Contribute](#ways-to-contribute)
2. [Development Setup](#development-setup)
3. [Branch and Commit Rules](#branch-and-commit-rules)
4. [Quality Gates](#quality-gates)
5. [Pull Request Process](#pull-request-process)
6. [Security-Sensitive Changes](#security-sensitive-changes)
7. [Documentation Requirements](#documentation-requirements)

---

## Ways to Contribute

- Fix bugs.
- Add or improve features.
- Improve documentation and diagrams.
- Add tests, benchmarks, and resilience checks.
- Improve CI/CD and developer experience.
- Improve runbooks and operational tooling.

---

## Development Setup

### Prerequisites

- Node.js `20+`
- pnpm `10+`
- Go `1.18+`
- Docker + Docker Compose plugin

### Install

```bash
pnpm install
```

### Start local environment

```bash
pnpm dev:infra
```

---

## Branch and Commit Rules

- Create a feature branch from `master`.
- Keep changes scoped and atomic.
- Use clear commit messages. Conventional style is recommended:
  - `feat: ...`
  - `fix: ...`
  - `docs: ...`
  - `refactor: ...`
  - `test: ...`
  - `chore: ...`

Examples:
- `feat: add relay certificate failover policy controls`
- `fix: prevent duplicate webhook replay on stale pending events`

---

## Quality Gates

Before opening a PR, run:

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

For API integration changes, run:

```bash
DATABASE_URL=postgres://postgres:postgres@127.0.0.1:55432/fdt \
REDIS_URL=redis://127.0.0.1:6379 \
pnpm --filter @fdt/api test:integration
```

For relay/performance behavior changes, also run:

```bash
bash scripts/relay-resilience.sh
```

---

## Pull Request Process

1. Open a PR with a clear title and summary.
2. Explain:
   - problem,
   - approach,
   - risks/tradeoffs,
   - testing evidence.
3. Link related issue(s).
4. Keep PR scope focused.
5. Update docs when behavior changes.
6. Add migration notes if schema/env/API changes.

Use the PR template in `.github/PULL_REQUEST_TEMPLATE.md`.

---

## Security-Sensitive Changes

Changes in these areas require extra review and test proof:

- authentication/session/token flows,
- relay request enforcement logic (auth/IP/host mode/rate/backpressure),
- billing webhook signature validation and replay behavior,
- certificate ingest and provenance checks,
- secrets handling, encryption/hashing, or audit integrity.

If you find a vulnerability, do **not** open a public issue.
Follow `SECURITY.md` for private disclosure instructions.

---

## Documentation Requirements

If your PR changes behavior, update relevant docs:

- `README.md` for project-level behavior,
- `docs/` for technical/ops detail,
- `docs/runbooks/` for alert/incident response changes,
- `plan.md` for major implementation milestones.

---

Thanks again for contributing.
