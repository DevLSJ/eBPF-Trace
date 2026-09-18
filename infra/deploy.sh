#!/usr/bin/env bash
# Executed on EC2 from a verified release directory.
set -euo pipefail
cd "$(dirname "$0")/.."
test -s .env
compose=(docker compose -p ebpf-trace-app -f docker-compose.yml -f docker-compose.tunnel.yml)
if grep -Eq '^HTTPS_ENABLED=true\r?$' .env; then
  compose+=(-f docker-compose.https.yml)
fi
"${compose[@]}" config --quiet
"${compose[@]}" up -d --no-build --wait --wait-timeout 120
"${compose[@]}" exec -T --interactive=false nginx nginx -s reload
curl --fail --silent --show-error --max-time 10 http://127.0.0.1/health
if grep -Eq '^HTTPS_ENABLED=true\r?$' .env; then
  public_host=$("${compose[@]}" exec -T --interactive=false https printenv PUBLIC_HOST)
  curl --fail --silent --show-error --retry 12 --retry-all-errors --retry-delay 5 --max-time 10 "https://$public_host/health"
fi
if grep -Eq '^OPS_TEST_ACCOUNT_MODE=true\r?$' .env; then
  "${compose[@]}" exec -T --interactive=false backend python -m infra.operators \
    --username admin --name '공개 테스트 관리자' --role admin --test-account
fi
