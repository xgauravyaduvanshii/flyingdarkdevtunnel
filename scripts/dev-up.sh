#!/usr/bin/env bash
set -euo pipefail

pnpm install

docker compose -f infra/docker/docker-compose.dev.yml up -d postgres redis minio

pnpm dev
