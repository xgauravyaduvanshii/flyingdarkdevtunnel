#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

API_PORT="${API_PORT:-4400}"
RELAY_HTTP_PORT="${RELAY_HTTP_PORT:-8088}"
RELAY_HTTPS_PORT="${RELAY_HTTPS_PORT:-8443}"
RELAY_CONTROL_PORT="${RELAY_CONTROL_PORT:-8089}"
RELAY_TLS_PASSTHROUGH_PORT="${RELAY_TLS_PASSTHROUGH_PORT:-9443}"
LOCAL_HTTP_PORT="${LOCAL_HTTP_PORT:-3905}"

DATABASE_URL="${DATABASE_URL:-postgres://postgres:postgres@127.0.0.1:5432/fdt}"
REDIS_URL="${REDIS_URL:-redis://127.0.0.1:6379}"
BASE_DOMAIN="${BASE_DOMAIN:-tunnel.yourdomain.com}"
JWT_SECRET="${JWT_SECRET:-12345678901234567890123456789012}"
JWT_REFRESH_SECRET="${JWT_REFRESH_SECRET:-12345678901234567890123456789012}"
AGENT_JWT_SECRET="${AGENT_JWT_SECRET:-12345678901234567890123456789012}"

LOG_DIR="${ROOT_DIR}/.data/integration-logs"
mkdir -p "${LOG_DIR}"

PIDS=()
cleanup() {
  for pid in "${PIDS[@]:-}"; do
    if kill -0 "$pid" >/dev/null 2>&1; then
      kill "$pid" >/dev/null 2>&1 || true
    fi
  done
}
trap cleanup EXIT

wait_for_http() {
  local url="$1"
  for _ in $(seq 1 60); do
    if curl -sf "$url" >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  echo "Timed out waiting for $url" >&2
  return 1
}

json_get() {
  local key="$1"
  node -e "const fs=require('fs');const v=JSON.parse(fs.readFileSync(0,'utf8'));const p='${key}'.split('.');let cur=v;for(const part of p){cur=cur?.[part];}if(cur===undefined){process.exit(2);}if(typeof cur==='object'){process.stdout.write(JSON.stringify(cur));}else{process.stdout.write(String(cur));}"
}

echo "[integration] building api/workers"
cd "$ROOT_DIR"
pnpm --filter @fdt/api build >/dev/null
pnpm --filter @fdt/worker-billing build >/dev/null
pnpm --filter @fdt/worker-inspector build >/dev/null
pnpm --filter @fdt/worker-certificates build >/dev/null


echo "[integration] starting api"
(
  cd "$ROOT_DIR/services/api"
  NODE_ENV=test \
  API_PORT="$API_PORT" \
  DATABASE_URL="$DATABASE_URL" \
  REDIS_URL="$REDIS_URL" \
  JWT_SECRET="$JWT_SECRET" \
  JWT_REFRESH_SECRET="$JWT_REFRESH_SECRET" \
  AGENT_JWT_SECRET="$AGENT_JWT_SECRET" \
  BASE_DOMAIN="$BASE_DOMAIN" \
  DOMAIN_VERIFY_STRICT=false \
  node dist/index.js >"$LOG_DIR/api.log" 2>&1
) &
PIDS+=("$!")


echo "[integration] starting workers"
(
  cd "$ROOT_DIR/services/worker-billing"
  DATABASE_URL="$DATABASE_URL" node dist/index.js >"$LOG_DIR/worker-billing.log" 2>&1
) &
PIDS+=("$!")

(
  cd "$ROOT_DIR/services/worker-inspector"
  DATABASE_URL="$DATABASE_URL" node dist/index.js >"$LOG_DIR/worker-inspector.log" 2>&1
) &
PIDS+=("$!")

(
  cd "$ROOT_DIR/services/worker-certificates"
  DATABASE_URL="$DATABASE_URL" CERT_WORKER_INTERVAL_SECONDS=15 TLS_PROBE_TIMEOUT_SECONDS=4 \
    node dist/index.js >"$LOG_DIR/worker-certificates.log" 2>&1
) &
PIDS+=("$!")


echo "[integration] starting relay"
(
  cd "$ROOT_DIR/go"
  RELAY_HTTP_PORT="$RELAY_HTTP_PORT" \
  RELAY_HTTPS_PORT="$RELAY_HTTPS_PORT" \
  RELAY_CONTROL_PORT="$RELAY_CONTROL_PORT" \
  RELAY_TLS_PASSTHROUGH_PORT="$RELAY_TLS_PASSTHROUGH_PORT" \
  RELAY_BASE_DOMAIN="$BASE_DOMAIN" \
  RELAY_AGENT_JWT_SECRET="$AGENT_JWT_SECRET" \
  RELAY_TLS_ENABLE=true \
  RELAY_AUTOCERT_ENABLE=false \
  go run ./relay >"$LOG_DIR/relay.log" 2>&1
) &
PIDS+=("$!")


echo "[integration] starting local upstream service"
(
  cd "$ROOT_DIR"
  python3 -m http.server "$LOCAL_HTTP_PORT" >"$LOG_DIR/local-http.log" 2>&1
) &
PIDS+=("$!")

wait_for_http "http://127.0.0.1:${API_PORT}/healthz"
wait_for_http "http://127.0.0.1:${RELAY_HTTP_PORT}/healthz"

API_BASE="http://127.0.0.1:${API_PORT}"

EMAIL="integration-smoke-$(date +%s)@example.com"
PASSWORD="passw0rd123"


echo "[integration] register user"
REGISTER_RESP="$(curl -sS -X POST "$API_BASE/v1/auth/register" -H 'content-type: application/json' -d "{\"email\":\"$EMAIL\",\"password\":\"$PASSWORD\",\"orgName\":\"Integration Smoke\"}")"
ACCESS_TOKEN="$(printf '%s' "$REGISTER_RESP" | json_get accessToken)"
AUTHTOKEN="$(printf '%s' "$REGISTER_RESP" | json_get authtoken)"

USERS_RESP="$(curl -sS "$API_BASE/v1/admin/users" -H "authorization: Bearer $ACCESS_TOKEN")"
USER_ID="$(printf '%s' "$USERS_RESP" | node -e "const fs=require('fs');const v=JSON.parse(fs.readFileSync(0,'utf8'));const target='${EMAIL}';const u=v.users.find(x=>x.email===target);if(!u){process.exit(2)};process.stdout.write(u.id)")"

curl -sS -X PATCH "$API_BASE/v1/admin/users/$USER_ID/plan" \
  -H "authorization: Bearer $ACCESS_TOKEN" \
  -H 'content-type: application/json' \
  -d '{"planCode":"pro"}' >/dev/null


echo "[integration] create and configure http tunnel"
HTTP_TUNNEL_RESP="$(curl -sS -X POST "$API_BASE/v1/tunnels" -H "authorization: Bearer $ACCESS_TOKEN" -H 'content-type: application/json' -d "{\"name\":\"http-smoke\",\"protocol\":\"http\",\"localAddr\":\"http://127.0.0.1:${LOCAL_HTTP_PORT}\",\"inspect\":true,\"basicAuthUser\":\"smoke\",\"basicAuthPassword\":\"secret\",\"ipAllowlist\":[\"127.0.0.1/32\"]}")"
HTTP_TUNNEL_ID="$(printf '%s' "$HTTP_TUNNEL_RESP" | json_get id)"
CUSTOM_DOMAIN="app-smoke-$(date +%s).example.com"

DOMAIN_RESP="$(curl -sS -X POST "$API_BASE/v1/domains/custom" -H "authorization: Bearer $ACCESS_TOKEN" -H 'content-type: application/json' -d "{\"domain\":\"$CUSTOM_DOMAIN\",\"tlsMode\":\"termination\"}")"
DOMAIN_ID="$(printf '%s' "$DOMAIN_RESP" | json_get id)"

curl -sS -X POST "$API_BASE/v1/domains/custom/$DOMAIN_ID/verify" -H "authorization: Bearer $ACCESS_TOKEN" -H 'content-type: application/json' -d '{}' >/dev/null
curl -sS -X POST "$API_BASE/v1/domains/custom/$DOMAIN_ID/route" -H "authorization: Bearer $ACCESS_TOKEN" -H 'content-type: application/json' -d "{\"tunnelId\":\"$HTTP_TUNNEL_ID\",\"tlsMode\":\"termination\"}" >/dev/null

START_HTTP_RESP="$(curl -sS -X POST "$API_BASE/v1/tunnels/$HTTP_TUNNEL_ID/start" -H "authorization: Bearer $ACCESS_TOKEN" -H 'content-type: application/json' -d '{}')"
if ! printf '%s' "$START_HTTP_RESP" | json_get agentToken >/dev/null; then
  echo "failed to start http tunnel" >&2
  exit 1
fi


echo "[integration] start http agent"
(
  cd "$ROOT_DIR/go"
  go run ./agent http \
    --api "$API_BASE" \
    --relay "ws://127.0.0.1:${RELAY_CONTROL_PORT}/control" \
    --tunnel-id "$HTTP_TUNNEL_ID" \
    --local "http://127.0.0.1:${LOCAL_HTTP_PORT}" \
    --authtoken "$AUTHTOKEN" >"$LOG_DIR/agent-http.log" 2>&1
) &
PIDS+=("$!")

sleep 3

HTTP_CODE_NO_AUTH="$(curl -s -o /dev/null -w '%{http_code}' -H "Host: $CUSTOM_DOMAIN" "http://127.0.0.1:${RELAY_HTTP_PORT}/")"
if [ "$HTTP_CODE_NO_AUTH" != "401" ]; then
  echo "expected 401 without basic auth, got $HTTP_CODE_NO_AUTH" >&2
  exit 1
fi

curl -sf -u smoke:secret -H "Host: $CUSTOM_DOMAIN" "http://127.0.0.1:${RELAY_HTTP_PORT}/" >/dev/null
curl -skf -u smoke:secret -H "Host: $CUSTOM_DOMAIN" "https://127.0.0.1:${RELAY_HTTPS_PORT}/" >/dev/null


echo "[integration] configure passthrough host on tcp tunnel"
TCP_TUNNEL_RESP="$(curl -sS -X POST "$API_BASE/v1/tunnels" -H "authorization: Bearer $ACCESS_TOKEN" -H 'content-type: application/json' -d "{\"name\":\"tcp-smoke\",\"protocol\":\"tcp\",\"localAddr\":\"127.0.0.1:${LOCAL_HTTP_PORT}\",\"inspect\":false}")"
TCP_TUNNEL_ID="$(printf '%s' "$TCP_TUNNEL_RESP" | json_get id)"
PASS_DOMAIN="pass-smoke-$(date +%s).example.com"
PASS_DOMAIN_RESP="$(curl -sS -X POST "$API_BASE/v1/domains/custom" -H "authorization: Bearer $ACCESS_TOKEN" -H 'content-type: application/json' -d "{\"domain\":\"$PASS_DOMAIN\",\"tlsMode\":\"passthrough\"}")"
PASS_DOMAIN_ID="$(printf '%s' "$PASS_DOMAIN_RESP" | json_get id)"

curl -sS -X POST "$API_BASE/v1/domains/custom/$PASS_DOMAIN_ID/verify" -H "authorization: Bearer $ACCESS_TOKEN" -H 'content-type: application/json' -d '{}' >/dev/null
curl -sS -X POST "$API_BASE/v1/domains/custom/$PASS_DOMAIN_ID/route" -H "authorization: Bearer $ACCESS_TOKEN" -H 'content-type: application/json' -d "{\"tunnelId\":\"$TCP_TUNNEL_ID\",\"tlsMode\":\"passthrough\"}" >/dev/null
curl -sS -X POST "$API_BASE/v1/tunnels/$TCP_TUNNEL_ID/start" -H "authorization: Bearer $ACCESS_TOKEN" -H 'content-type: application/json' -d '{}' >/dev/null

(
  cd "$ROOT_DIR/go"
  go run ./agent tcp \
    --api "$API_BASE" \
    --relay "ws://127.0.0.1:${RELAY_CONTROL_PORT}/control" \
    --tunnel-id "$TCP_TUNNEL_ID" \
    --local "127.0.0.1:${LOCAL_HTTP_PORT}" \
    --authtoken "$AUTHTOKEN" >"$LOG_DIR/agent-tcp.log" 2>&1
) &
PIDS+=("$!")

sleep 3

HTTP_CODE_PASS="$(curl -s -o /dev/null -w '%{http_code}' -u smoke:secret -H "Host: $PASS_DOMAIN" "http://127.0.0.1:${RELAY_HTTP_PORT}/")"
if [ "$HTTP_CODE_PASS" != "426" ]; then
  echo "expected 426 for passthrough host on HTTP endpoint, got $HTTP_CODE_PASS" >&2
  exit 1
fi

echo "[integration] verify admin domain visibility"
ADMIN_DOMAINS_RESP="$(curl -sS "$API_BASE/v1/admin/domains" -H "authorization: Bearer $ACCESS_TOKEN")"
printf '%s' "$ADMIN_DOMAINS_RESP" | CUSTOM_DOMAIN="$CUSTOM_DOMAIN" PASS_DOMAIN="$PASS_DOMAIN" node -e "
const fs = require('fs');
const body = JSON.parse(fs.readFileSync(0, 'utf8'));
if (!Array.isArray(body.domains)) process.exit(2);
const expected = [
  { domain: process.env.CUSTOM_DOMAIN, mode: 'termination' },
  { domain: process.env.PASS_DOMAIN, mode: 'passthrough' },
];
for (const item of expected) {
  const row = body.domains.find((d) => d.domain === item.domain);
  if (!row) process.exit(3);
  if (row.tls_mode !== item.mode) process.exit(4);
}
"

echo "[integration] smoke test passed"
