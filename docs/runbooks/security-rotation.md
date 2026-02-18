# Security Rotation Runbook

## Scope
- Weekly secret-rotation posture verification for org user authtokens.
- Runtime scan and admin response for stale rotation drift.

## Automation
- GitHub workflow: `.github/workflows/security-rotation-weekly.yml`
- Command:
  - `pnpm --filter @fdt/api verify:secret-rotations`
- Inputs:
  - `SECRET_ROTATION_MAX_AGE_DAYS` (default `90`)
  - `SECRET_ROTATION_ENFORCE` (`true` fails workflow when stale orgs exist)

## Runtime checks
1. Admin posture snapshot:
   - `GET /v1/admin/secrets/rotation-health?maxAgeDays=90`
2. Record anomaly + audit scan:
   - `POST /v1/admin/secrets/rotation/scan`
3. Rotate target authtoken when needed:
   - `POST /v1/admin/secrets/rotate/authtoken`

## Triage policy
- `SEV-3`: stale rotation ratio > 20% in any paid org.
- `SEV-2`: stale rotation ratio > 50% in production org with active tunnels.

## Exit criteria
- Workflow passes without stale org violations (or approved exception documented).
- High-risk stale users rotated and confirmed by `rotation-health` API.
- Audit log entries exist for scan/rotation actions.
