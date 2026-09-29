#!/usr/bin/env bash
# EC2 에서 검증된 릴리스 디렉터리 안에서 실행된다 (CI deploy job 또는 수동).
# 1) 기존 eBPF-Trace 스택(compose 프로젝트 ebpf-trace-app, 80/443)을 내리고
# 2) SupplyGuard 스택을 올린 뒤 3) /health 로 확인한다. 볼륨은 지우지 않는다.
set -euo pipefail
cd "$(dirname "$0")/.."
test -s .env

compose=(docker compose -p supplyguard --project-directory . -f deploy/docker-compose.yml)
if grep -Eq '^HTTPS_ENABLED=true\r?$' .env; then
  compose+=(-f deploy/docker-compose.https.yml)
fi
"${compose[@]}" config --quiet

# 이전 프로젝트가 같은 포트를 쓰고 있으면 교체한다 (컨테이너만 정리, 볼륨·이미지는 유지)
old=$(docker ps -aq --filter label=com.docker.compose.project=ebpf-trace-app)
if [[ -n "$old" ]]; then
  echo "stopping legacy ebpf-trace-app containers"
  docker stop $old >/dev/null
  docker rm $old >/dev/null
fi

"${compose[@]}" up -d --no-build --remove-orphans --wait --wait-timeout 180
"${compose[@]}" exec -T --interactive=false nginx nginx -s reload

curl --fail --silent --show-error --max-time 10 "http://127.0.0.1:${HTTP_PORT:-80}/health"
echo
if grep -Eq '^HTTPS_ENABLED=true\r?$' .env; then
  public_host=$("${compose[@]}" exec -T --interactive=false https printenv PUBLIC_HOST)
  curl --fail --silent --show-error --retry 12 --retry-all-errors --retry-delay 5 --max-time 10 "https://$public_host/health"
  echo
fi
"${compose[@]}" ps
