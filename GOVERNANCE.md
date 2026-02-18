# Governance

## Project Model

FlyingDarkDevTunnel uses a maintainer-led governance model.

- Maintainers review and merge contributions.
- Major architectural/security changes require explicit maintainer approval.
- Operational safety and security correctness take precedence over feature speed.

## Decision Process

1. Problem statement in issue/discussion.
2. Proposal with tradeoffs.
3. Maintainer review and decision.
4. Implementation with tests/docs.
5. Post-merge validation and follow-up.

## Maintainer Responsibilities

- protect reliability/security baselines,
- review and triage issues/PRs,
- keep docs and runbooks current,
- coordinate releases and incident follow-ups.

## Escalation Areas

These areas require stricter review:
- auth/session/token paths,
- relay enforcement and traffic policy,
- billing signatures and reconciliation logic,
- cert lifecycle/provenance ingestion,
- schema migrations touching core entities.

## Community Conduct

All participation follows `CODE_OF_CONDUCT.md`.
