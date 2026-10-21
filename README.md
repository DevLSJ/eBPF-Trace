# SupplyGuard — eBPF 기반 오픈소스 공급망 공격 런타임 탐지 플랫폼

캡스톤디자인 프로젝트. 정적 분석(SCA)이 놓치는 **런타임 악성 행위**를 커널 단에서 잡는다.
오픈소스 패키지를 설치하거나 컨테이너에서 실행하는 순간 `execve`·`openat`·`connect` 를
[Inspektor Gadget](https://inspektor-gadget.io) 가젯(eBPF)으로 가로채, YAML 정책과 비교해
위반이면 증거를 남기고 컨테이너를 **강제 종료(격리)** 한다. 결과는 WebSocket 으로 React 대시보드에 실시간 스트리밍된다.

```
커널 syscall → IG 가젯(eBPF) → Go ingestion(컨테이너 발견 auto) → 규칙 평가
   → (위반) 증거 수집(≤0.7초) → Docker kill + 웹훅/Slack 알림
   → Redis 버퍼 → WebSocket → React 대시보드 · PostgreSQL 감사 로그
REST · WS 앞: 로그인(쿠키 세션 · 역할 · OTP) — CLI 는 Bearer ADMIN_TOKEN, sg-install 은 SANDBOX_TOKEN
공급망 검사: GuardDog · OSV-Scanner 검사기 컨테이너 / AI 도우미: 로컬 Ollama(선택)
```

| 구성 | 스택 | 위치 |
| --- | --- | --- |
| 백엔드 | Go 1.26 · Inspektor Gadget v0.56.1 (Go 패키지, in-process) · pgx · go-redis · bcrypt · TOTP(RFC 6238) | `backend/` |
| 프론트엔드 | React 18 · TypeScript · Vite 7 · Tailwind 4 · React Flow · Recharts · qrcode | `frontend/` |
| 배포 | Docker Compose (nginx · backend · frontend · PostgreSQL 17 · Redis 7 · 선택 Caddy HTTPS · 선택 Ollama) · GitHub Actions → Docker Hub → EC2 | `deploy/` · `.github/workflows/` |
| 목업 | 정적 HTML 대시보드 — 화면 · 흐름을 먼저 확정하는 곳(React 가 기준) | `mock/` |
| 문서 | 개발 계획 · 결정 · 아키텍처 · API 계약 · 진행 기록 | Claude Docs (아래 「문서」) |

화면: 대시보드(판정 대기 · eBPF 수집 종합) · 설치 검사 · 공급망 검사 · 이벤트 · 토폴로지 · 정책 · 감사 로그 · 설정(서버 · 계정 · 라이선스 · 인증 감사),
우측 하단 도우미(대응 가이드 · AI 도우미).

## 빠른 시작 (로컬, 커널 없이)

macOS/Windows 에서는 eBPF 를 못 돌리므로 `EVENT_SOURCE=mock` 이 데모 시나리오(정상 컨테이너 + 타이포스쿼팅 패키지 `pkg-reqeusts`)를 재생한다.

```bash
make dev        # 백엔드(mock, :8000) + Vite(:5173) → http://127.0.0.1:5173
```

- 로그인은 켜져 있다. 개발용 관리자 계정은 `admin` / Makefile `DEV_ADMIN_PW`(개발 전용 값), OTP 는 꺼져 있다(`DEV_AUTH`). 첫 로그인에서 비밀번호 변경 → 라이선스(숫자 16자리) 순서
- 목업: `make mock` → http://127.0.0.1:8766 (`?source=sim&as=admin` 로 로그인 건너뜀)

전체 스택을 컨테이너로 보려면 (nginx 경유, 실제 Postgres·Redis):

```bash
cp .env.example .env            # POSTGRES_PASSWORD · ADMIN_INITIAL_PASSWORD 채우고 EVENT_SOURCE=mock
make stack-up
make stack-down
```

## 설치 샌드박스 — 패키지를 감시 컨테이너에서 설치

개발자 PC 에 오픈소스 패키지를 바로 깔지 않고, SupplyGuard 가 커널에서 감시하는 일회용 컨테이너 안에서 설치한다.
설치 스크립트가 외부 스크립트를 실행하거나 자격 증명 파일을 읽거나 레지스트리·GitHub 밖으로 접속(도메인 조회 없는 IP 직접 연결 포함)하면
설치가 끝나기 전에 격리된다.

```bash
make sandbox-up                               # 가젯 백엔드 :8000 (WATCH_CONTAINERS=sg-install-*)
tools/sg-install pip requests                 # 정상 → [OK] 위반 없음 (종료 코드 0)
tools/sg-install pip ./deploy/demo/reqeusts   # 타이포스쿼팅 데모(무해 시뮬) → 격리 + 위반 목록 (종료 코드 2)
make sandbox-down
```

종료 코드: 0 통과 · 1 설치 실패 · 2 위반 · 3 차단 목록이라 거부 · 4 결과 확인 불가(통과로 보지 않음) · 69 연결 실패 · 77 토큰 거부.
데모 공격 시나리오(`deploy/demo/README.md`): `SCENARIO=all|shell|revshell|direct-ip|domain|udp bash deploy/demo/run-attacker.sh`.

## 운영 배포 (EC2 · VM, 실제 eBPF)

Ubuntu 22.04/24.04 + Docker 가 있는 단일 호스트. 백엔드 컨테이너가 `privileged` · `pid: host` · `/:/host:ro` ·
`/var/run/docker.sock` 으로 떠서 가젯을 직접 로드하고 Docker Engine API 로 kill 한다. 자기 스택은 `IGNORE_CONTAINERS=supplyguard-*` 로 빠진다.

```bash
cp .env.example .env    # POSTGRES_* · AUTH_SECRET_KEY(openssl rand -hex 32) · ADMIN_INITIAL_PASSWORD · ADMIN_TOKEN · SANDBOX_TOKEN · ALLOWED_ORIGINS(실제 접속 주소)
deploy/compose.sh pull && deploy/deploy.sh      # 백업 → 반영 → 확인 → 실패 시 복구
deploy/compose.sh logs -f backend
```

- AI 도우미를 켜려면 `.env` 에 `OLLAMA_URL=http://ollama:11434` 를 넣고 compose 를 `--profile ai` 로 띄운 뒤 모델을 한 번 받는다(`ollama pull qwen2.5:3b`, 메모리 4GB)
- 알림: `NOTIFY_WEBHOOK_URL` · `NOTIFY_SLACK_URL` · `PUBLIC_URL`
- 컨테이너 발견 `CONTAINER_DISCOVERY=auto`(fanotify 먼저, 안 되면 docker-events — 시작 직후 약 0.1초는 놓칠 수 있음)

CI/CD(`.github/workflows/ci-cd.yml`): PR/푸시마다 `go vet`·`go test -race`·정적 빌드·`npm run lint/build`·React e2e(Playwright)·compose 검증 →
`main` 이면 Docker Hub 푸시 → self-hosted runner 가 EC2 에서 `deploy/deploy.sh` 실행.
필요한 시크릿: `DOCKERHUB_USERNAME` · `DOCKERHUB_TOKEN` · `EC2_HOST` · `EC2_USER` · `EC2_SSH_KEY` · `EC2_KNOWN_HOSTS`.

## 정책

`backend/policies/default.yaml` 이 DB 가 비었을 때 한 번 시드된다. 이후는 대시보드 정책 화면(쉬운 설정 ↔ YAML, 저장 전 확인)에서 바꾼다.
버전이 올라 기본 정책에 새 규칙이 생기면 정책 화면 「새 기본 규칙 있음」 안내로 골라 추가한다(덮어쓰지 않음).
전역 `ENFORCE_KILL=false` 면 kill 정책도 알림만 보낸다.

| 규칙 | kind | action | 잡는 것 |
| --- | --- | --- | --- |
| `sensitive-files` | open | kill | `/etc/shadow`, `/root/.ssh/`, `/home/*/.ssh/*`, `/root/.aws/`, `/var/run/secrets/` |
| `no-shell-download` | exec | kill | `wget`·`curl`·`nc`·`ncat` 실행 |
| `pipe-to-shell` | exec | kill | `\| sh`, `\| bash`, `base64 -d` 인자 |
| `reverse-shell-ports` | connect | kill | 4444·1337·31337 포트 |
| `egress-allowlist` | connect | alert | 사설 대역도 아니고 80·443·53 도 아닌 아웃바운드 |
| `runtime-direct-ip` | connect | alert | 도메인 조회 없이 공인 IP 로 바로 나가는 연결(`directIp`) |
| `sandbox-egress` | connect | kill | (sg-install-* 만) 레지스트리·GitHub 외 도메인 + IP 직접 연결 |
| `sandbox-secrets` | open | kill | (sg-install-* 만) `~/.ssh`·`~/.aws`·`.npmrc`·`.pypirc` 등 |

## API

`/health` 를 뺀 모든 경로는 **로그인 세션**(쿠키) 뒤에 있다. 쓰기는 관리자 역할 — 조회자는 읽기 · 미리보기 · 챗봇만.
CLI · 자동화는 `Authorization: Bearer $ADMIN_TOKEN`(관리자, 처리자 「cli」), sg-install 보고는 `SANDBOX_TOKEN`.
전체 계약은 Claude Docs 「API 계약」 탭.

| 묶음 | 경로 |
| --- | --- |
| 상태 | `GET /health` · `/api/info` · `/api/stats` · `/api/summary?range=` |
| 이벤트 · 감사 | `GET /api/events/recent` · `/api/audit` · `/api/evidence?container=` · `WS /ws/events` |
| 정책 | `GET/POST/PUT /api/policies` · `DELETE /api/policies/{id}` · `GET /api/policies/export` · `/api/policies/defaults` · `POST /api/policies/preview` |
| 판정 흐름 | 설치 세션 `/api/installs*` · 건 `/api/cases*`(판정 미리보기 `POST …/{id}/preview`) · 제안 `/api/proposals*`(적용 · 버림 `{reason?}`) · 차단 목록 `/api/blocklist*` · 변경 이력 `/api/changes` |
| 공급망 검사 | `POST /api/scans`(패키지 · GitHub 주소(tree · commit · tag · 하위 경로) · 파일) · `GET /api/scans*` · `POST /api/scans/{id}/block` |
| 인증 · 계정 | `/api/auth/{login,me,password,license,otp/enroll,otp/enroll/confirm,otp,logout}` · `GET/PUT /api/license` · `/api/users*` · `GET /api/auth/audit` |
| 알림 · AI | `POST /api/notify/test` · `POST /api/chat`(SSE) |

## 검증

```bash
cd backend && go vet ./... && GOOS=linux go vet ./... && go test -race ./...
cd frontend && npm run lint && npm run build && npx playwright test
```

eBPF 가젯 실행 검증은 커널이 있는 EC2/VM 에서만 한다.

## 문서

- [SupplyGuard 개발 문서](https://claude.ai/code/artifact/5fc4e674-2b54-4bb2-9cd6-a03cae190285) — 개요 · 결정 · 아키텍처 · 정책 · API 계약 · 진행 기록 · 남은 일 (새 세션은 여기서 시작)
- `mock/README.md` — 목업 사용법 · 결정 기록
- `deploy/demo/README.md` — 데모 공격 시나리오
