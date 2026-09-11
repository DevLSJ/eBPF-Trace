#!/usr/bin/env bash
# Executed on EC2 from a verified release directory.
set -euo pipefail
cd "$(dirname "$0")/.."
test -s .env
docker compose -p ebpf-trace-app -f docker-compose.yml -f docker-compose.tunnel.yml config --quiet
docker compose -p ebpf-trace-app -f docker-compose.yml -f docker-compose.tunnel.yml up -d --wait --wait-timeout 120
docker compose -p ebpf-trace-app -f docker-compose.yml -f docker-compose.tunnel.yml exec -T nginx nginx -s reload
curl --fail --silent --show-error --max-time 10 http://127.0.0.1/health
