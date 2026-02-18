#!/usr/bin/env bash
set -euo pipefail

if ! command -v curl >/dev/null 2>&1; then
  sudo apt-get update
  sudo apt-get install -y curl
fi

if ! command -v pnpm >/dev/null 2>&1; then
  npm install -g pnpm
fi

if ! command -v go >/dev/null 2>&1; then
  echo "Installing Go..."
  sudo apt-get update
  sudo apt-get install -y golang-go
fi

if ! command -v docker >/dev/null 2>&1; then
  echo "Installing Docker..."
  sudo apt-get update
  sudo apt-get install -y docker-ce docker-ce-cli docker-buildx-plugin docker-compose-plugin || \
    sudo apt-get install -y docker.io docker-compose-plugin
  sudo usermod -aG docker "$USER" || true
fi

echo "Bootstrap complete."
