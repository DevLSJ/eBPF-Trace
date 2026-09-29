#!/usr/bin/env bash
# 운영 스택 compose 래퍼. 저장소 어디서 불러도 루트를 프로젝트 디렉터리로 잡고
# 루트 .env 를 읽는다. HTTPS_ENABLED=true 면 Caddy(443) 파일을 덧붙인다.
#   deploy/compose.sh ps
#   deploy/compose.sh logs -f backend
#   deploy/compose.sh up -d --build        # 로컬 이미지 빌드 포함
set -euo pipefail
cd "$(dirname "$0")/.."
compose=(docker compose -p supplyguard --project-directory . -f deploy/docker-compose.yml)
if [[ -s .env ]] && grep -Eq '^HTTPS_ENABLED=true\r?$' .env; then
  compose+=(-f deploy/docker-compose.https.yml)
fi
exec "${compose[@]}" "$@"
