#!/usr/bin/env bash
# 로컬 개발 전체 기동 (docs/08 Phase 1). 인프라(docker) + engine + gateway + web.
set -euo pipefail
cd "$(dirname "$0")/.."

echo "▶ 인프라(postgres/redis) 기동…"
docker compose -f infra/docker-compose.yml up -d

echo "▶ postgres 대기…"
for i in $(seq 1 30); do
  if [ "$(docker inspect --format '{{.State.Health.Status}}' scw-postgres 2>/dev/null)" = "healthy" ]; then break; fi
  sleep 1
done

echo "▶ 마이그레이션…"
pnpm --filter @scw/gateway migrate

echo "▶ shared-types 빌드…"
pnpm --filter @scw/shared-types build

pids=()
cleanup() { echo; echo "▶ 종료…"; for p in "${pids[@]}"; do kill "$p" 2>/dev/null || true; done; }
trap cleanup EXIT INT TERM

echo "▶ engine(:8000) 기동…"
( cd apps/engine && uv run uvicorn app.main:app --reload --port "${ENGINE_PORT:-8000}" ) & pids+=($!)
echo "▶ gateway(:4000) 기동…"
pnpm --filter @scw/gateway dev & pids+=($!)
echo "▶ web(:3000) 기동…"
pnpm --filter @scw/web dev & pids+=($!)

echo "✓ http://localhost:3000 (web) · :4000 (gateway) · :8000 (engine)"
wait
