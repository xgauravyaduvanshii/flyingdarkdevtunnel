#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

API_PORT="${API_PORT:-4500}"
RELAY_HTTP_PORT="${RELAY_HTTP_PORT:-8188}"
RELAY_HTTPS_PORT="${RELAY_HTTPS_PORT:-8543}"
RELAY_CONTROL_PORT="${RELAY_CONTROL_PORT:-8189}"
LOCAL_HTTP_PORT="${LOCAL_HTTP_PORT:-3910}"
UPSTREAM_DELAY_MS="${UPSTREAM_DELAY_MS:-120}"

DATABASE_URL="${DATABASE_URL:-postgres://postgres:postgres@127.0.0.1:5432/fdt}"
REDIS_URL="${REDIS_URL:-redis://127.0.0.1:6379}"
BASE_DOMAIN="${BASE_DOMAIN:-tunnel.yourdomain.com}"
JWT_SECRET="${JWT_SECRET:-12345678901234567890123456789012}"
JWT_REFRESH_SECRET="${JWT_REFRESH_SECRET:-12345678901234567890123456789012}"
AGENT_JWT_SECRET="${AGENT_JWT_SECRET:-12345678901234567890123456789012}"

BASELINE_REQUESTS="${BASELINE_REQUESTS:-120}"
BASELINE_CONCURRENCY="${BASELINE_CONCURRENCY:-20}"
BASELINE_MAX_FAILURE_RATE="${BASELINE_MAX_FAILURE_RATE:-0.05}"
BASELINE_MAX_P95_MS="${BASELINE_MAX_P95_MS:-5000}"

BACKPRESSURE_REQUESTS="${BACKPRESSURE_REQUESTS:-600}"
BACKPRESSURE_CONCURRENCY="${BACKPRESSURE_CONCURRENCY:-160}"

STORM_REQUESTS="${STORM_REQUESTS:-320}"
STORM_CONCURRENCY="${STORM_CONCURRENCY:-25}"
STORM_RECONNECT_CYCLES="${STORM_RECONNECT_CYCLES:-10}"
STORM_RECONNECT_INTERVAL_SECONDS="${STORM_RECONNECT_INTERVAL_SECONDS:-0.7}"
STORM_MAX_FAILURE_RATE="${STORM_MAX_FAILURE_RATE:-0.99}"
STORM_MIN_SUCCESS_RATE="${STORM_MIN_SUCCESS_RATE:-0.01}"

LOG_DIR="${ROOT_DIR}/.data/resilience-logs"
mkdir -p "${LOG_DIR}"

PIDS=()
AGENT_PID=""

cleanup() {
  if [[ -n "${AGENT_PID}" ]] && kill -0 "${AGENT_PID}" >/dev/null 2>&1; then
    kill "${AGENT_PID}" >/dev/null 2>&1 || true
  fi
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

start_agent() {
  (
    cd "${ROOT_DIR}/go"
    ./bin/fdt http \
      --api "http://127.0.0.1:${API_PORT}" \
      --relay "ws://127.0.0.1:${RELAY_CONTROL_PORT}/control" \
      --tunnel-id "${TUNNEL_ID}" \
      --local "http://127.0.0.1:${LOCAL_HTTP_PORT}" \
      --authtoken "${AUTHTOKEN}" >"${LOG_DIR}/agent.log" 2>&1
  ) &
  AGENT_PID="$!"
  PIDS+=("${AGENT_PID}")
  sleep 2
}

restart_agent() {
  if [[ -n "${AGENT_PID}" ]] && kill -0 "${AGENT_PID}" >/dev/null 2>&1; then
    kill "${AGENT_PID}" >/dev/null 2>&1 || true
    wait "${AGENT_PID}" 2>/dev/null || true
  fi
  start_agent
}

echo "[resilience] building API and Go binaries"
cd "${ROOT_DIR}"
pnpm --filter @fdt/api build >/dev/null
cd "${ROOT_DIR}/go"
go build -o bin/relay ./relay
go build -o bin/fdt ./agent

echo "[resilience] starting API"
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
PIDS+=("$!")

echo "[resilience] starting relay"
(
  cd "${ROOT_DIR}/go"
  RELAY_HTTP_PORT="${RELAY_HTTP_PORT}" \
  RELAY_HTTPS_PORT="${RELAY_HTTPS_PORT}" \
  RELAY_CONTROL_PORT="${RELAY_CONTROL_PORT}" \
  RELAY_BASE_DOMAIN="${BASE_DOMAIN}" \
  RELAY_AGENT_JWT_SECRET="${AGENT_JWT_SECRET}" \
  RELAY_TLS_ENABLE=true \
  RELAY_AUTOCERT_ENABLE=false \
  ./bin/relay >"${LOG_DIR}/relay.log" 2>&1
) &
PIDS+=("$!")

echo "[resilience] starting delayed local upstream"
(
  UPSTREAM_DELAY_MS="${UPSTREAM_DELAY_MS}" LOCAL_HTTP_PORT="${LOCAL_HTTP_PORT}" node -e '
    const http = require("http");
    const delay = Number(process.env.UPSTREAM_DELAY_MS || 200);
    const port = Number(process.env.LOCAL_HTTP_PORT || 3910);
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
EMAIL="resilience-$(date +%s)@example.com"
PASSWORD="passw0rd123"

echo "[resilience] registering test user and tunnel"
REGISTER_RESP="$(curl -sS -X POST "${API_BASE}/v1/auth/register" -H 'content-type: application/json' -d "{\"email\":\"${EMAIL}\",\"password\":\"${PASSWORD}\",\"orgName\":\"Resilience Org\"}")"
ACCESS_TOKEN="$(printf '%s' "${REGISTER_RESP}" | json_get accessToken)"
AUTHTOKEN="$(printf '%s' "${REGISTER_RESP}" | json_get authtoken)"

TUNNEL_RESP="$(curl -sS -X POST "${API_BASE}/v1/tunnels" -H "authorization: Bearer ${ACCESS_TOKEN}" -H 'content-type: application/json' -d "{\"name\":\"resilience-http\",\"protocol\":\"http\",\"localAddr\":\"http://127.0.0.1:${LOCAL_HTTP_PORT}\",\"inspect\":false}")"
TUNNEL_ID="$(printf '%s' "${TUNNEL_RESP}" | json_get id)"
SUBDOMAIN="$(printf '%s' "${TUNNEL_RESP}" | json_get subdomain)"

START_RESP="$(curl -sS -X POST "${API_BASE}/v1/tunnels/${TUNNEL_ID}/start" -H "authorization: Bearer ${ACCESS_TOKEN}" -H 'content-type: application/json' -d '{}')"
if ! printf '%s' "${START_RESP}" | json_get agentToken >/dev/null; then
  echo "failed to start tunnel" >&2
  exit 1
fi

HOST_HEADER="${SUBDOMAIN}.${BASE_DOMAIN}"
TARGET_URL="http://127.0.0.1:${RELAY_HTTP_PORT}/load-test"

echo "[resilience] starting agent"
start_agent

echo "[resilience] baseline load phase"
TARGET_URL="${TARGET_URL}" \
HOST_HEADER="${HOST_HEADER}" \
REQUESTS="${BASELINE_REQUESTS}" \
CONCURRENCY="${BASELINE_CONCURRENCY}" \
MAX_FAILURE_RATE="${BASELINE_MAX_FAILURE_RATE}" \
MIN_SUCCESS_RATE="0.95" \
MAX_P95_MS="${BASELINE_MAX_P95_MS}" \
node "${ROOT_DIR}/scripts/http-load.mjs" | tee "${LOG_DIR}/baseline.json"

echo "[resilience] backpressure phase (expect relay 429 under concurrency pressure)"
TARGET_URL="${TARGET_URL}" \
HOST_HEADER="${HOST_HEADER}" \
REQUESTS="${BACKPRESSURE_REQUESTS}" \
CONCURRENCY="${BACKPRESSURE_CONCURRENCY}" \
MAX_FAILURE_RATE="0.98" \
MIN_SUCCESS_RATE="0.01" \
REQUIRE_STATUS="429:1" \
node "${ROOT_DIR}/scripts/http-load.mjs" | tee "${LOG_DIR}/backpressure.json"

echo "[resilience] reconnect storm phase"
TARGET_URL="${TARGET_URL}" \
HOST_HEADER="${HOST_HEADER}" \
REQUESTS="${STORM_REQUESTS}" \
CONCURRENCY="${STORM_CONCURRENCY}" \
MAX_FAILURE_RATE="${STORM_MAX_FAILURE_RATE}" \
MIN_SUCCESS_RATE="${STORM_MIN_SUCCESS_RATE}" \
node "${ROOT_DIR}/scripts/http-load.mjs" >"${LOG_DIR}/storm.json" &
STORM_LOAD_PID="$!"

for _ in $(seq 1 "${STORM_RECONNECT_CYCLES}"); do
  restart_agent
  sleep "${STORM_RECONNECT_INTERVAL_SECONDS}"
done

wait "${STORM_LOAD_PID}"
cat "${LOG_DIR}/storm.json"

echo "[resilience] relay resilience test passed"
