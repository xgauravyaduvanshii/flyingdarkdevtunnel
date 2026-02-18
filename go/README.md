# Go Services

## Relay

Run relay service:

```bash
cd go
go run ./relay
```

Env vars:
- `RELAY_HTTP_PORT` (default `8080`)
- `RELAY_HTTPS_PORT` (default `8443`)
- `RELAY_CONTROL_PORT` (default `8081`)
- `RELAY_TLS_PASSTHROUGH_PORT` (default `9443`)
- `RELAY_BASE_DOMAIN` (default `tunnel.yourdomain.com`)
- `RELAY_AGENT_JWT_SECRET` (must match API `AGENT_JWT_SECRET`)
- `RELAY_TLS_ENABLE` (`true` or `false`)
- `RELAY_TLS_CERT_FILE` + `RELAY_TLS_KEY_FILE` (optional static cert/key)
- `RELAY_AUTOCERT_ENABLE` (enable ACME/autocert)
- `RELAY_AUTOCERT_CACHE_DIR` (default `.data/autocert`)
- `RELAY_ALLOWED_TLS_HOSTS` (comma-separated host allowlist for autocert)
- `RELAY_TCP_START_PORT` / `RELAY_TCP_END_PORT`

## Agent CLI

```bash
cd go
go run ./agent --help
```

Commands:
- `fdt login --api ... --email ... --password ... --authtoken ...`
- `fdt http --tunnel-id ... --local http://localhost:3000`
- `fdt tcp --tunnel-id ... --local 127.0.0.1:22`
- `fdt start --config ourdomain.yml`
- `fdt tunnels ls`
- `fdt inspect --tunnel-id ...`
