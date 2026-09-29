#!/usr/bin/env bash
# 정상 트래픽만 만드는 기준 컨테이너 (1단계 문서의 victim). 대시보드에 '정상' 이벤트가 흐르는지 확인용.
set -euo pipefail
docker rm -f victim >/dev/null 2>&1 || true
docker run -d --name victim --rm busybox \
  sh -c 'while true; do cat /dev/null; wget -q -O- http://example.com >/dev/null 2>&1; sleep 2; done'
echo "victim started: exec(cat, wget) · open(/dev/null) · connect(example.com:80)"
echo "주의: 기본 정책 no-shell-download 는 wget 실행을 kill 대상으로 본다 — 정책 dry-run 으로 두고 보거나 victim 을 예외 컨테이너로 두세요."
