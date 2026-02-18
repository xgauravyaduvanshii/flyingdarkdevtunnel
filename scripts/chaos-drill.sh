#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

API_PORT="${API_PORT:-4600}"
RELAY_HTTP_PORT="${RELAY_HTTP_PORT:-8288}"
RELAY_CONTROL_PORT="${RELAY_CONTROL_PORT:-8289}"
LOCAL_HTTP_PORT="${LOCAL_HTTP_PORT:-3920}"

DATABASE_URL="${DATABASE_URL:-postgres://postgres:postgres@127.0.0.1:5432/fdt}"
REDIS_URL="${REDIS_URL:-redis://127.0.0.1:6379}"
BASE_DOMAIN="${BASE_DOMAIN:-tunnel.yourdomain.com}"
JWT_SECRET="${JWT_SECRET:-12345678901234567890123456789012}"
JWT_REFRESH_SECRET="${JWT_REFRESH_SECRET:-12345678901234567890123456789012}"
AGENT_JWT_SECRET="${AGENT_JWT_SECRET:-12345678901234567890123456789012}"

CHAOS_REQUESTS="${CHAOS_REQUESTS:-1200}"
CHAOS_CONCURRENCY="${CHAOS_CONCURRENCY:-80}"
CHAOS_MIN_SUCCESS_RATE="${CHAOS_MIN_SUCCESS_RATE:-0.15}"
CHAOS_MAX_FAILURE_RATE="${CHAOS_MAX_FAILURE_RATE:-0.95}"
CHAOS_RELAY_RESTART_DELAY_SECONDS="${CHAOS_RELAY_RESTART_DELAY_SECONDS:-2}"
CHAOS_API_RESTART_DELAY_SECONDS="${CHAOS_API_RESTART_DELAY_SECONDS:-2}"
CHAOS_REDIS_FAULT="${CHAOS_REDIS_FAULT:-false}"

LOG_DIR="${ROOT_DIR}/.data/chaos-logs"
mkdir -p "${LOG_DIR}"

PIDS=()
API_PID=""
RELAY_PID=""
AGENT_PID=""

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
  for _ in $(seq 1 80); do
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

start_api() {
  (
    cd "${ROOT_DIR}/services/api"
    NODE_ENV=test \
    API_PORT="${API_PORT}" \
    DATABASE_URL="${DATABASE_URL}" \
    REDIS_URL="${REDIS_URL}" \
    JWT_SECRET="${JWT_SECRET}" \
    JWT_REFRESH_SECRET="${JWT_REFRESH_SECRET}" \
    AGENT_JWT_SECRET="${AGENT_JWT_SECRET}" \
    BASE_DOMAIN="${BASE_DOMAIN}" \
    DOMAIN_VERIFY_STRICT=false \
    node dist/index.js >"${LOG_DIR}/api.log" 2>&1
  ) &
  API_PID="$!"
  PIDS+=("${API_PID}")
}

start_relay() {
  (
    cd "${ROOT_DIR}/go"
    RELAY_HTTP_PORT="${RELAY_HTTP_PORT}" \
    RELAY_CONTROL_PORT="${RELAY_CONTROL_PORT}" \
    RELAY_BASE_DOMAIN="${BASE_DOMAIN}" \
    RELAY_AGENT_JWT_SECRET="${AGENT_JWT_SECRET}" \
    RELAY_TLS_ENABLE=false \
    ./bin/relay >"${LOG_DIR}/relay.log" 2>&1
  ) &
  RELAY_PID="$!"
  PIDS+=("${RELAY_PID}")
}

restart_process() {
  local pid="$1"
  local delay="$2"
  local start_fn="$3"
  if kill -0 "$pid" >/dev/null 2>&1; then
    kill "$pid" >/dev/null 2>&1 || true
    wait "$pid" 2>/dev/null || true
  fi
  sleep "$delay"
  "$start_fn"
}

echo "[chaos] building api and go binaries"
cd "${ROOT_DIR}"
pnpm --filter @fdt/api build >/dev/null
cd "${ROOT_DIR}/go"
go build -o bin/relay ./relay
go build -o bin/fdt ./agent

echo "[chaos] starting API + relay + upstream"
start_api
start_relay

(
  UPSTREAM_DELAY_MS=150 LOCAL_HTTP_PORT="${LOCAL_HTTP_PORT}" node -e '
    const http = require("http");
    const delay = Number(process.env.UPSTREAM_DELAY_MS || 150);
    const port = Number(process.env.LOCAL_HTTP_PORT || 3920);
    const server = http.createServer((req, res) => {
      setTimeout(() => {
        res.statusCode = 200;
        res.setHeader("content-type", "application/json");
        res.end(JSON.stringify({ ok: true, path: req.url, delay }));
      }, delay);
    });
    server.listen(port, "127.0.0.1", () => console.log("upstream ready", port));
  ' >"${LOG_DIR}/upstream.log" 2>&1
) &
PIDS+=("$!")

wait_for_http "http://127.0.0.1:${API_PORT}/healthz"
wait_for_http "http://127.0.0.1:${RELAY_HTTP_PORT}/healthz"

API_BASE="http://127.0.0.1:${API_PORT}"
EMAIL="chaos-$(date +%s)@example.com"
PASSWORD="passw0rd123"

REGISTER_RESP="$(curl -sS -X POST "${API_BASE}/v1/auth/register" -H 'content-type: application/json' -d "{\"email\":\"${EMAIL}\",\"password\":\"${PASSWORD}\",\"orgName\":\"Chaos Org\"}")"
ACCESS_TOKEN="$(printf '%s' "${REGISTER_RESP}" | json_get accessToken)"
AUTHTOKEN="$(printf '%s' "${REGISTER_RESP}" | json_get authtoken)"

TUNNEL_RESP="$(curl -sS -X POST "${API_BASE}/v1/tunnels" -H "authorization: Bearer ${ACCESS_TOKEN}" -H 'content-type: application/json' -d "{\"name\":\"chaos-http\",\"protocol\":\"http\",\"localAddr\":\"http://127.0.0.1:${LOCAL_HTTP_PORT}\",\"inspect\":false}")"
TUNNEL_ID="$(printf '%s' "${TUNNEL_RESP}" | json_get id)"
SUBDOMAIN="$(printf '%s' "${TUNNEL_RESP}" | json_get subdomain)"
curl -sS -X POST "${API_BASE}/v1/tunnels/${TUNNEL_ID}/start" -H "authorization: Bearer ${ACCESS_TOKEN}" -H 'content-type: application/json' -d '{}' >/dev/null

(
  cd "${ROOT_DIR}/go"
  ./bin/fdt http \
    --api "${API_BASE}" \
    --relay "ws://127.0.0.1:${RELAY_CONTROL_PORT}/control" \
    --tunnel-id "${TUNNEL_ID}" \
    --local "http://127.0.0.1:${LOCAL_HTTP_PORT}" \
    --authtoken "${AUTHTOKEN}" >"${LOG_DIR}/agent.log" 2>&1
) &
AGENT_PID="$!"
PIDS+=("${AGENT_PID}")

sleep 3

TARGET_URL="http://127.0.0.1:${RELAY_HTTP_PORT}/chaos"
HOST_HEADER="${SUBDOMAIN}.${BASE_DOMAIN}"

echo "[chaos] running load while injecting failures"
TARGET_URL="${TARGET_URL}" \
HOST_HEADER="${HOST_HEADER}" \
REQUESTS="${CHAOS_REQUESTS}" \
CONCURRENCY="${CHAOS_CONCURRENCY}" \
MAX_FAILURE_RATE="${CHAOS_MAX_FAILURE_RATE}" \
MIN_SUCCESS_RATE="${CHAOS_MIN_SUCCESS_RATE}" \
node "${ROOT_DIR}/scripts/http-load.mjs" >"${LOG_DIR}/chaos-report.json" &
LOAD_PID="$!"

sleep 2
echo "[chaos] restarting relay process"
restart_process "${RELAY_PID}" "${CHAOS_RELAY_RESTART_DELAY_SECONDS}" start_relay
wait_for_http "http://127.0.0.1:${RELAY_HTTP_PORT}/healthz"

sleep 2
echo "[chaos] restarting api process"
restart_process "${API_PID}" "${CHAOS_API_RESTART_DELAY_SECONDS}" start_api
wait_for_http "http://127.0.0.1:${API_PORT}/healthz"

if [[ "${CHAOS_REDIS_FAULT}" == "true" ]]; then
  if command -v docker >/dev/null 2>&1 && docker ps --format '{{.Names}}' | grep -q '^fdt-redis$'; then
    echo "[chaos] restarting redis container fdt-redis"
    docker restart fdt-redis >/dev/null
  else
    echo "[chaos] redis fault requested but fdt-redis container not found; skipping"
  fi
fi

wait "${LOAD_PID}"
cat "${LOG_DIR}/chaos-report.json"

echo "[chaos] drill passed"
