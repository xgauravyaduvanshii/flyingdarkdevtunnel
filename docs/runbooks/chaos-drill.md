# Chaos Drill Runbook

## Scope
- Nightly resilience drill for API + relay + agent with optional Redis restart fault.
- Validates behavior under restart storms and transient dependency disruption.

## Automation
- GitHub workflow: `.github/workflows/chaos-nightly.yml`
- Script:
  - `bash scripts/chaos-drill.sh`
  - root alias: `pnpm test:chaos`

## What the drill does
1. Builds API and Go binaries.
2. Starts API, relay, and delayed local upstream.
3. Registers user/tunnel and launches CLI agent.
4. Starts concurrent HTTP load.
5. Restarts relay and API during active load.
6. Optionally restarts Redis (`CHAOS_REDIS_FAULT=true`).
7. Fails if success/failure ratios exceed configured bounds.

## Outputs
- Directory: `.data/chaos-logs/`
- Key artifacts:
  - `chaos-report.json`
  - `api.log`
  - `relay.log`
  - `agent.log`
  - `upstream.log`

## Exit criteria
- Drill exits zero and report stays within configured min-success/max-failure thresholds.
- No unrecovered tunnel outage after restart sequence.
- Follow-up incident ticket opened if thresholds fail.
