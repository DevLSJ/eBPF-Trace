# 데모 컨테이너

EC2(가젯 소스)에서 탐지·격리를 눈으로 확인하는 스크립트. 로컬 macOS 에서는 `EVENT_SOURCE=mock` 이
같은 시나리오를 대신 재생하므로 이 스크립트는 필요 없다.

| 스크립트 | 컨테이너 | 하는 일 |
| --- | --- | --- |
| `run-victim.sh` | `victim` | 2초마다 `cat`·`wget example.com` — 정상 이벤트 기준선 |
| `run-attacker.sh` | `pkg-reqeusts` | 시나리오 1→2→3 (`curl\|sh` → `/etc/shadow` → `203.0.113.7:4444`) 한 번 실행. `LOOP=1` 이면 10초마다 반복 |
| `cleanup.sh` | | 위 컨테이너 제거 |

기본 정책(`backend/policies/default.yaml`)과 `ENFORCE_KILL=true` 면 attacker 는 시나리오 1 에서
`no-shell-download`/`pipe-to-shell` 에 걸려 종료된다. 세 시나리오를 모두 보고 싶으면 대시보드 정책 화면에서
해당 정책을 dry-run 으로 바꾸거나 `.env` 의 `ENFORCE_KILL=false` 로 전역 dry-run 을 켠다.

목적지 `203.0.113.0/24` 는 문서용 TEST-NET-3 대역이라 실제 연결은 일어나지 않는다(타임아웃).
