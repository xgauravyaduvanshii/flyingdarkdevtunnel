# Codex Working Notes

Repository-specific notes for Codex-style contributors.

## Preferred Workflow

1. Read impacted files first.
2. Make focused changes.
3. Run relevant tests/checks.
4. Update docs if behavior changed.
5. Commit and push.

## Project Focus Areas

- `go/relay`: edge policy, routing, tunnel session behavior.
- `go/agent`: CLI ergonomics, reconnect/resilience flows.
- `services/api`: auth, tunnels, domains, billing/admin endpoints.
- `services/worker-*`: retries, replay safety, reconciliation loops.
- `docs/` + `plan.md`: source of truth for operation and roadmap status.

## Change Quality Rules

- Keep security posture explicit (auth, IP controls, TLS modes).
- Prefer backward-compatible API changes.
- Use clear commit messages with scope.
- Avoid hidden side effects; make failure states observable.

