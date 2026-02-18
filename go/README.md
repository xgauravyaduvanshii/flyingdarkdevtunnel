# Go Data Plane and CLI

<p>
  <img alt="Language" src="https://img.shields.io/badge/Language-Go-0ea5e9" />
  <img alt="Modules" src="https://img.shields.io/badge/Modules-relay%20%7C%20agent%20%7C%20proto-22c55e" />
  <img alt="Role" src="https://img.shields.io/badge/Role-Edge%20Ingress%20%2B%20Client-f97316" />
</p>

This folder contains:
- `relay`: public edge service for HTTP/HTTPS/TCP ingress and forwarding
- `agent`: local CLI/client that connects to relay control plane and forwards traffic to local targets
- `proto`: shared protocol contracts used by relay and agent

---

## Directory Layout

```txt
go/
  relay/                  # edge ingress listeners + control channel
  agent/                  # fdt CLI (login/http/tcp/start/inspect)
  proto/                  # shared message and frame definitions
  ourdomain.example.yml   # multi-tunnel config example
  bin/                    # optional local build output
```

---

## Relay Service

### Run relay locally

```bash
cd go
go run ./relay
```

### Build relay binary

```bash
cd go
go build -o bin/relay ./relay
./bin/relay
```

### Relay environment variables

| Variable | Default | Purpose |
|---|---|---|
| `RELAY_BASE_DOMAIN` | `tunnel.yourdomain.com` | Base wildcard domain used for generated host routing |
| `RELAY_REGION` | `us` | Region identity for edge selection and routing claims |
| `RELAY_EDGE_POOL` | `us=us-edge-1\|us-edge-2\|us-edge-3` | Region to edge-id mapping for assignment |
| `RELAY_AGENT_JWT_SECRET` | required | Must match API `AGENT_JWT_SECRET` |
| `RELAY_HTTP_PORT` | `8080` | Public HTTP listener |
| `RELAY_HTTPS_PORT` | `8443` | Public HTTPS listener (termination path) |
| `RELAY_CONTROL_PORT` | `8081` | Agent control websocket listener |
| `RELAY_TLS_PASSTHROUGH_PORT` | `9443` | TLS passthrough listener |
| `RELAY_TCP_START_PORT` | `7000` | Start of raw TCP ingress range |
| `RELAY_TCP_END_PORT` | `7099` | End of raw TCP ingress range |
| `RELAY_TLS_ENABLE` | `true` | Enable TLS termination listener |
| `RELAY_TLS_CERT_FILE` | empty | Static cert path (optional) |
| `RELAY_TLS_KEY_FILE` | empty | Static key path (optional) |
| `RELAY_AUTOCERT_ENABLE` | `false` | ACME autocert enable toggle |
| `RELAY_AUTOCERT_CACHE_DIR` | `.data/autocert` | ACME cert cache directory |
| `RELAY_AUTOCERT_EMAIL` | empty | ACME account email |
| `RELAY_AUTOCERT_ALLOW_ANY` | `false` | If false, use explicit host allowlist |
| `RELAY_ALLOWED_TLS_HOSTS` | empty | Comma-separated autocert host allowlist |
| `RELAY_DEFAULT_MAX_CONCURRENT_CONNS` | `100` | Fallback per-tunnel connection cap |
| `RELAY_ID` | auto | Relay edge identifier |
| `RELAY_HEARTBEAT_API_URL` | empty | API base URL for heartbeat registration |
| `RELAY_HEARTBEAT_TOKEN` | empty | Shared relay heartbeat bearer token |
| `RELAY_HEARTBEAT_INTERVAL_SECONDS` | `15` | Heartbeat interval |

---

## Agent CLI

### Run CLI help

```bash
cd go
go run ./agent --help
```

### Build CLI binary

```bash
cd go
go build -o bin/fdt ./agent
./bin/fdt --help
```

### Main commands

| Command | Purpose |
|---|---|
| `fdt login` | authenticate and store local credentials |
| `fdt http` | start HTTP/HTTPS tunnel session |
| `fdt tcp` | start TCP tunnel session |
| `fdt start --config ourdomain.yml` | start named tunnels from config file |
| `fdt tunnels ls` | list tunnels from API |
| `fdt inspect --tunnel-id <id>` | fetch request logs for a tunnel |

### Command examples

```bash
# 1) login and save local auth context
go run ./agent login \
  --api http://localhost:4000 \
  --email xgauravyaduvanshii@gmail.com \
  --password yourpassword

# 2) run HTTP tunnel session
go run ./agent http \
  --api http://localhost:4000 \
  --relay ws://localhost:8081/control \
  --authtoken <authtoken> \
  --tunnel-id <http_tunnel_uuid> \
  --local http://localhost:3000 \
  --region us

# 3) run TCP tunnel session
go run ./agent tcp \
  --api http://localhost:4000 \
  --relay ws://localhost:8081/control \
  --authtoken <authtoken> \
  --tunnel-id <tcp_tunnel_uuid> \
  --local 127.0.0.1:22 \
  --region us
```

---

## Multi-Tunnel Config Mode

Use config-based startup with:
- `go/ourdomain.example.yml`

Minimal shape:

```yaml
authtoken: your_authtoken
apiBaseUrl: http://localhost:4000
relayControlUrl: ws://localhost:8081/control
tunnels:
  - name: web
    protocol: http
    tunnelId: 11111111-1111-1111-1111-111111111111
    localAddr: http://localhost:3000
    region: us
  - name: ssh
    protocol: tcp
    tunnelId: 22222222-2222-2222-2222-222222222222
    localAddr: 127.0.0.1:22
    region: us
```

Start it:

```bash
cd go
go run ./agent start --config ourdomain.example.yml
```

---

## Relay and Agent Integration Checklist

Before debugging traffic path issues, verify:

1. API `AGENT_JWT_SECRET` equals relay `RELAY_AGENT_JWT_SECRET`.
2. Relay control port is reachable from agent (`ws://.../control`).
3. Tunnel exists and is started in control plane (`POST /v1/tunnels/:id/start` path).
4. Host/region claims in token match relay routing expectations.
5. For TLS termination, relay certificate mode is configured correctly.

---

## Common Troubleshooting

| Symptom | Likely Cause | Fix |
|---|---|---|
| Agent cannot connect to control websocket | wrong relay URL/port | verify `--relay` and relay `RELAY_CONTROL_PORT` |
| `401`/token errors on agent exchange | secret mismatch or expired token | rotate token and re-check JWT secret alignment |
| Public host returns `429` | concurrency cap reached | reduce load or raise entitlements/limits |
| TLS handshake failures | invalid static cert or host mismatch | verify cert files, host mapping, or autocert allowlist |
| Tunnel starts but no local traffic | wrong `localAddr` target | verify local service is reachable from agent host |

---

## Developer Notes

- Keep relay and agent changes protocol-compatible with `go/proto`.
- When changing edge behavior, also update:
  - integration smoke scripts,
  - resilience scripts,
  - docs in `docs/security-and-tls.md` and `docs/testing-and-ci.md`.
- For new config fields, update `go/ourdomain.example.yml` and root docs.
