# SupplyGuard — eBPF 기반 오픈소스 공급망 공격 런타임 탐지 플랫폼

캡스톤디자인 프로젝트. 정적 분석(SCA)이 놓치는 **런타임 악성 행위**를 커널 단에서 잡는다.
오픈소스 패키지가 Docker 컨테이너에서 실행되는 순간 `execve`·`openat`·`connect` 를
[Inspektor Gadget](https://inspektor-gadget.io) 가젯(eBPF)으로 가로채, YAML 정책과 비교해
위반이면 알림하고 컨테이너를 **강제 종료(격리)** 한다. 결과는 WebSocket 으로 React 대시보드에 실시간 스트리밍된다.

```
커널 syscall → IG 가젯(eBPF) → Go ingestion → 규칙 평가 → (위반) Docker kill + 알림
                                                   └→ Redis 버퍼 → WebSocket → React 대시보드
                                                   └→ PostgreSQL 감사 로그
```

| 구성 | 스택 | 위치 |
| --- | --- | --- |
| 백엔드 | Go 1.26 · Inspektor Gadget v0.56.1 (Go 패키지, 가젯 3종 in-process) · gorilla/websocket · pgx · go-redis | `backend/` |
| 프론트엔드 | React 18 · TypeScript · Vite 7 · Tailwind 4 · React Flow · Recharts | `frontend/` |
| 배포 | Docker Compose (nginx · backend · frontend · PostgreSQL 17 · Redis 7 · 선택 Caddy HTTPS) · GitHub Actions → Docker Hub → EC2 | `deploy/` · `.github/workflows/` |
| 문서 | 개발 계획 · 단계별 문서 · 진행 현황 | `docs/` |
| 목업 | 정적 HTML 대시보드 — 내장 시뮬레이션 또는 실제 백엔드에 붙여서 화면·흐름 검토 (UI 설계는 여기서 먼저 확정해 React 에 이식) | `mock/` |

## 빠른 시작 (로컬, 커널 없이)

macOS/Windows 에서는 eBPF 를 못 돌리므로 `EVENT_SOURCE=mock` 이 데모 시나리오(정상 컨테이너 `web-api`·`worker` + 타이포스쿼팅 패키지
`pkg-reqeusts` 가 20초마다 공격 3종)를 재생한다. 대시보드 피드는 `/ws/events` 로 실시간 갱신된다.

```bash
make dev        # 백엔드(mock, :8000) + Vite(:5173) 를 함께 띄운다 → http://127.0.0.1:5173
```

따로 띄우려면 `make backend` / `make frontend`. 백엔드는 `ALLOWED_ORIGINS` 에 Vite 와 목업 출처가 들어간 채로 뜨므로
목업(`mock/`)의 "실제 백엔드" 모드도 바로 붙는다 (`make mock` → http://127.0.0.1:8766).

전체 스택을 컨테이너로 보려면 (nginx 경유, 저장소는 실제 Postgres·Redis):

```bash
cp .env.example .env            # POSTGRES_PASSWORD 채우고 EVENT_SOURCE=mock, HTTP_PORT 조정
make stack-up                   # docker compose … -f deploy/docker-compose.yml -f deploy/docker-compose.mock.yml up -d --build --wait
make stack-down
```

개발용 Postgres·Redis 만 필요하면 `docker compose -f deploy/docker-compose.dev.yml up -d`
(127.0.0.1:25432 / 127.0.0.1:26379). `make test` 가 백엔드 vet·race 테스트와 프론트 lint·build 를 돈다.

## 설치 샌드박스 — 패키지를 감시 컨테이너에서 설치

개발자 PC 에 오픈소스 패키지를 바로 깔지 않고, SupplyGuard 가 커널에서 감시하는 일회용 컨테이너 안에서 설치한다.
설치 스크립트가 외부 스크립트를 실행(`no-shell-download`)하거나 자격 증명 파일을 읽거나(`sandbox-secrets`)
레지스트리·GitHub 밖으로 접속(`sandbox-egress`·`reverse-shell-ports`)하면 설치가 끝나기 전에 격리된다.

```bash
make sandbox-up                            # 가젯 소스 백엔드를 :8000 에 띄운다 (WATCH_CONTAINERS=sg-install-* 로 범위 제한)
tools/sg-install pip requests              # 정상 패키지 → 위반 없음
tools/sg-install pip ./deploy/demo/reqeusts   # 타이포스쿼팅 데모(무해 시뮬) → 격리 + 위반 목록
make sandbox-down
```

`WATCH_CONTAINERS=sg-install-*` 이므로 개발 PC 의 다른 컨테이너(minikube 등)는 평가·격리 대상이 아니다.
목적지 도메인 표시·규칙(`allowHosts`/`denyHosts`)은 `trace_dns` 가젯으로 동작하며, macOS Docker Desktop 과 리눅스 양쪽에서 확인됐다.
(도메인을 확인 못 한 연결은 fail-open 이라 정상 다운로드를 죽이지 않는다.)

## 운영 배포 (EC2, 실제 eBPF)

Ubuntu 22.04/24.04 + Docker 가 있는 단일 호스트. 백엔드 컨테이너가 `privileged` · `pid: host` · `/:/host:ro` ·
`/var/run/docker.sock` 으로 떠서 가젯을 직접 로드하고 Docker Engine API 로 kill 한다. 자기 스택은
`IGNORE_CONTAINERS=supplyguard-*` 로 관찰에서 빠진다.

```bash
cp .env.example .env    # POSTGRES_*, ADMIN_TOKEN, ALLOWED_ORIGINS(실제 접속 주소), DOCKERHUB_USERNAME, IMAGE_TAG
deploy/compose.sh pull && deploy/deploy.sh      # 기존 ebpf-trace-app 컨테이너를 내리고 supplyguard 를 올린다
deploy/compose.sh logs -f backend
```

CI/CD(`.github/workflows/ci-cd.yml`): PR/푸시마다 `go vet`·`go test -race`·정적 빌드·`npm run lint/build`·compose 검증 →
`main` 이면 Docker Hub 에 `supplyguard-backend/frontend:<sha>` 푸시 → self-hosted runner 가 EC2 로 SSH 해
`deploy/deploy.sh` 실행. 필요한 시크릿: `DOCKERHUB_USERNAME` · `DOCKERHUB_TOKEN` · `EC2_HOST` · `EC2_USER` · `EC2_SSH_KEY` · `EC2_KNOWN_HOSTS`.
EC2 에는 `/home/ubuntu/supplyguard/.env` 가 미리 있어야 한다.

데모 컨테이너(`deploy/demo/`): `run-victim.sh`(정상 기준선) · `run-attacker.sh`(시나리오 1→2→3) · `cleanup.sh`.

## 정책

`backend/policies/default.yaml` 이 DB 가 비었을 때 한 번 시드된다. 이후는 대시보드 정책 화면(폼 ↔ YAML, dry-run, 저장 후 적용,
전체 YAML 교체)에서 바꾼다. 쓰기 API 는 `ADMIN_TOKEN`(Bearer) 이 필요하고, 전역 `ENFORCE_KILL=false` 면 kill 정책도 알림만 보낸다.

| 규칙 | kind | action | 잡는 것 |
| --- | --- | --- | --- |
| `sensitive-files` | open | kill | `/etc/shadow`, `/root/.ssh/`, `/home/*/.ssh/*`, `/root/.aws/`, `/var/run/secrets/` |
| `no-shell-download` | exec | kill | `wget`·`curl`·`nc`·`ncat` 실행 |
| `pipe-to-shell` | exec | kill | `\| sh`, `\| bash`, `base64 -d` 인자 |
| `reverse-shell-ports` | connect | kill | 4444·1337·31337 포트 |
| `egress-allowlist` | connect | alert | 사설 대역도 아니고 80·443·53 도 아닌 아웃바운드 |
| `sandbox-egress` | connect | kill | (sg-install-* 만) 패키지 레지스트리·GitHub 외 도메인 |
| `sandbox-secrets` | open | kill | (sg-install-* 만) `~/.ssh`·`~/.aws`·`.npmrc`·`.pypirc` 등 |

## API

| 메서드 | 경로 | 비고 |
| --- | --- | --- |
| GET | `/health` | postgres·redis 핑 포함 |
| GET | `/api/info` · `/api/stats` · `/api/events/recent?limit=` | |
| GET | `/api/policies` · `/api/policies/export` (YAML) | |
| POST / PUT / DELETE | `/api/policies` · `/api/policies/{id}` | 토큰 필요 · PUT 은 YAML 전체 교체 |
| GET | `/api/audit?kind&action&rule&container&since&until&before&limit` | 최신순, `id` 커서 |
| OPTIONS | (모든 경로) | `ALLOWED_ORIGINS` 에 있는 Origin 에만 CORS 허용 (Vite dev·목업이 REST 를 직접 부를 때) |
| WS | `/ws/events` | `{type:"verdict"|"stats", data}` — 위반은 전부, 정상은 초당 `NORMAL_EVENT_RATE` 개 |

## 검증

```bash
cd backend && go vet ./... && GOOS=linux go vet ./... && go test -race ./...
cd frontend && npm run lint && npm run build
```

eBPF 가젯 실행 검증은 커널이 있는 EC2/VM 에서만 한다 — `docs/01-1단계-환경구축.md` 체크리스트.

## 문서

- `docs/00-개발-계획.md` — 무엇을 왜 만드는가, 아키텍처, 로드맵, 데모 시나리오
- `docs/01~03` — 환경 구축 · 백엔드 · 프론트 단계별 설계
- `docs/04-진행-현황.md` — 현재 상태와 남은 일 (새 세션은 여기서 시작)
- `mock/README.md` — 목업 사용법
