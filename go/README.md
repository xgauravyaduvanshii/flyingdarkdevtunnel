# Go Services

## Relay

Run relay service:

```bash
cd go
go run ./relay
```

Env vars:
- `RELAY_HTTP_PORT` (default `8080`)
- `RELAY_CONTROL_PORT` (default `8081`)
- `RELAY_BASE_DOMAIN` (default `tunnel.yourdomain.com`)
- `RELAY_AGENT_JWT_SECRET` (must match API `AGENT_JWT_SECRET`)
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
