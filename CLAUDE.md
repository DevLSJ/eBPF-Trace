# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## 현재 상태와 우선순위

**로컬 개발 + sg-vm 실서버(2026-10-20).** 개인 캡스톤 프로젝트 SupplyGuard — eBPF(Inspektor Gadget)로 오픈소스 패키지의 런타임 악성 행위를 커널 단에서 잡아 격리한다. 1인, Jira 없음, 사내 표준 미적용. 원격 저장소 없음(GitHub는 나중, 만들 때 **공개** `github.com/devlsj/ebpf-supplychain-guard`).

두 시나리오는 **동등**하다 [2026-10-15 확정]:
- **설치 샌드박스** — `tools/sg-install pip|npm|cargo <패키지>`가 감시 컨테이너(`sg-install-*`)에서 설치하고, 위반이면 설치가 끝나기 전에 격리
- **런타임 감시** — 배포된 컨테이너를 같은 엔진으로 상시 관찰

기능(10/20 기준): 설치 검사 · 런타임 감시 · 공급망 검사(GuardDog + OSV) · eBPF 수집 종합 · 도우미(대응 가이드 · AI) · 로그인/라이선스/OTP · 외부 알림(웹훅 · Slack) · kill 직전 증거 보존.

작업 우선순위 [2026-10-20 확정]:
1. 커밋 — `3becc47` 이후 변경 전부(Tier 1은 커밋 분리)
2. 목업을 React에 맞춤 — 재시도 동작 · 패키지 묶기 · README 낡은 문장
3. GitHub — 공개 전 이력 점검(예: 첫 커밋의 실제 공인 IP), 원격 생성 뒤 CI 첫 실행 확인
4. EC2 첫 배포

마감: 미확정(아래 TBD).

## 아키텍처 [2026-09-29 확정 · 2026-10-20 갱신]

```
커널 syscall → IG 가젯(exec·open·connect, + trace_dns) → Go ingestion(컨테이너 발견 auto)
  → 규칙 평가(YAML) → (위반) 증거 수집(≤0.7초) → Docker API kill + 웹훅/Slack 알림
  → Redis 버퍼 → WebSocket → React 대시보드
  → PostgreSQL 감사 로그 · 건 · 제안 · 차단 목록 · 계정
REST · WS 앞: 로그인 관문(쿠키 세션, CLI 는 Bearer ADMIN_TOKEN, sg-install 은 SANDBOX_TOKEN)
공급망 검사: 백엔드 → 검사기 컨테이너(GuardDog · OSV-Scanner)
AI 도우미: 백엔드 → Ollama qwen2.5:3b(선택, 읽기 전용 조회 → 사실 문장 → 답, 판정 상태 · 링크는 서버가 붙임)
```

- **백엔드**: Go 1.26 · Inspektor Gadget v0.56.1을 Go 패키지로 프로세스 안에서 실행(Cgo 없음). 가젯 데이터 오퍼레이터는 `operators.GetDataOperators()` 전체를 쓰고 LocalManager만 직접 만든 컬렉션으로 교체한다 — 일부만 넣으면 trace_dns가 CO-RE 오류로 안 뜬다
- **컨테이너 발견**: `CONTAINER_DISCOVERY=auto`(기본) — fanotify(runc 훅)를 먼저 시도하고 안 되면(Docker Desktop) docker-events. docker-events는 컨테이너 시작 직후 약 0.1초 안의 동작을 놓친다(sg-vm 실측)
- **프론트**: React 18 · TS · Vite 7 · Tailwind 4 · React Flow · Recharts · qrcode(로컬 번들)
- **저장**: PostgreSQL 17 · Redis 7(이벤트 버퍼)
- **배포**: Docker Compose(nginx 80 → backend :8000 · frontend :80 · PG · Redis · 선택 Caddy · 선택 `ollama`(`--profile ai`, 4GB)) · 레지스트리 Docker Hub · EC2 단일 호스트(기존 `ebpf-trace-app` 대체)
- **격리 책임**: IG는 탐지만, kill은 백엔드가 Docker API로
- **도메인 미확인 연결은 fail-open** — 단, trace_dns가 켜져 있는데 도메인 조회 없이 공인 IP로 붙으면 규칙의 `directIp`로 판정
- **커밋하지 않는 것**: `.env` · 키 · `claude-portable/`(개인 작업 틀) · `.claude/worktrees/`

### 구조

```
backend/   cmd/{server,healthcheck} · internal/{api,auth,chat,config,dockerapi,enforcer,evidence,ingestion,model,notify,osv,pipeline,review,rules,scan,sginstall,stats,store,summary,ws} · policies/default.yaml
frontend/  src/{components/{shell,list},features/{dashboard,installs,scans,events,topology,policies,audit,settings},hooks,lib} · e2e/
mock/      정적 목업(index.html + shared/ + tests/) — 결정 확인용
deploy/    compose(기본 · dev · mock · https) · Dockerfile · nginx · deploy.sh · demo/
tools/     sg-install
```

### 명령 (루트에서)

| 명령 | 내용 |
|---|---|
| `make dev` | 백엔드(mock 이벤트, :8000, 로그인 켜짐 · OTP만 끔 · 개발용 관리자 비밀번호는 Makefile `DEV_AUTH`) + Vite(:5173) |
| `make mock` | 목업 :8766 (**8765는 참고 제품 목업 — 끄지 않는다**). 병렬 회귀는 8767 · 8768 |
| `make test` | 백엔드 vet · race 테스트 + 프론트 lint · build |
| `cd frontend && npx playwright test` | React e2e(가짜 백엔드, CI 에도 있음) |
| `make stack-up` / `stack-down` | 전체 스택 컨테이너(mock 소스, `.env` 에 `ADMIN_INITIAL_PASSWORD` 필요) |
| `make sandbox-up` / `sandbox-down` | 실제 가젯 백엔드, `WATCH_CONTAINERS=sg-install-*`, 실행마다 `AUTH_SECRET_KEY` 새로 생성 · OTP 켬 |
| `cd backend && GOOS=linux go vet ./...` | 리눅스 전용 코드 검사 |

**주의**: 맥에서 실제 가젯 소스 + `ENFORCE_KILL`을 쓸 때는 반드시 `WATCH_CONTAINERS=sg-install-*`. 범위 없이 돌려 minikube 컨테이너가 두 번 죽은 적이 있다.

### 서버

- **`sg-vm`** — UTM Ubuntu 22.04 arm64(커널 5.15), 키 인증. docker는 sudo 없이, sudo는 비밀번호 필요 → 사용자가 자기 터미널에서 직접. 작업 경로 `~/sg/` 안에서만
  - 전체 스택 상시 실행: `~/sg/stack`, compose 프로젝트 `supplyguard`, http://192.168.64.2. 로그인 켜짐(10/20) · 발견 auto → fanotify · `ENFORCE_KILL=true` · 전체 감시 · `ollama` 프로필 켬
  - 반영: 소스를 tar 로 옮겨 VM 에서 빌드(`docker compose … build`) → 이전 이미지에 롤백 태그 → `up -d` → health 확인 → 실패 시 롤백 태그로 복구. 롤백 태그 · `.env` 백업 위치는 메모리
  - `.env` · `~/sg/.tokens` 는 600, 값은 출력하지 않는다
- **`sg-ec2`** — 운영 EC2(Ubuntu 22.04, t3.medium). 별칭 등록 보류 [2026-10-15] — 배포 단계에서 키 파일을 정해 추가. 경로 `/home/ubuntu/supplyguard*` 안에서만. 메모리가 작아 `ollama` 프로필은 끄고 운영
- 반영은 `deploy/deploy.sh`의 백업 → 반영 → 확인 → 실패 시 복구만

### 목업 (`mock/`) [2026-10-15 확정 · 2026-10-20 갱신]

**React가 기준이고, 목업은 결정 확인용이다.** 화면 변경은 목업에서 먼저 보여 주고 확정한 뒤 React에 반영한다. 둘이 다르면 어느 쪽이 맞는지 묻는다. 목업을 재구성하지 않는다. 테마는 지금 것을 유지하고, 기능을 우선한다(다크 모드 보류).

- 데이터 소스 2종: 내장 시뮬레이션 / 실제 백엔드(`?source=live&api=…`, 쿠키 로그인 — 목업 · 백엔드를 같은 호스트 이름 127.0.0.1 로). 빈 서버 `?fresh=1`, 로그인 건너뛰기 `?as=admin|viewer`, 첫 로그인부터 `?auth=fresh`
- **결정 기록**: 10/15 1차 · 10/16 · 10/20 도우미(`guide-1020.cjs`) · 10/20 2차(로그인 · 대화상자 · 알림 센터 · 목록 · 셸 · 새 기본 규칙 · 증거, `feedback-1020b.cjs`) · 10/20 결정 반영(토큰 칸 삭제 · 설정 화면 · 라이선스 칩 · 30초 재시도 · 비밀번호 5자, `feedback-1020c.cjs`) — 상세는 `mock/README.md` 반영 기록
- API 계약: Claude Docs 「API 계약」 탭
- Playwright: `frontend/node_modules/playwright`(목업 회귀는 `PLAYWRIGHT=` 로 빌려 쓴다)
- 회귀: 목업 10묶음(feedback-1015 · goals-1015 · decisions-1016 · policy-1016 · overview-1016 · scan-1016 · guide-1020 · feedback-1020b · feedback-1020c · align-1021) + React `frontend/e2e`. 판정 N/N + 콘솔 오류 0. live 검사는 `API=` 백엔드가 떠 있을 때만(로그인은 `mock/tests/live-login.cjs`)
- 스크린샷은 `mock/screenshots/`(gitignore)

## 도메인 규칙

- 판정: `allow` · `alert` · `kill`. 전역 `ENFORCE_KILL=false`면 kill 정책도 알림만
- 정책은 `backend/policies/default.yaml`(기본 8개)이 빈 DB에 한 번 시드, 이후 대시보드 정책 화면에서 바꾼다. 기존 서버에 새 기본 규칙은 정책 화면 「새 기본 규칙 있음」 안내로 추가(덮어쓰지 않고 빈 값만 채움)
- connect 규칙 `directIp: allow|alert|kill` — trace_dns 가 켜져 있을 때 도메인 조회 없는 공인 IP 연결. `directIp` 만 있고 `allowHosts` 가 없는 규칙은 IP 직접 연결 전용
- kill 직전 증거(로그 · 파일 변경 · 프로세스)를 0.7초 안에서 모은다. 넘으면 기다리지 않고 kill
- 자기 스택은 `IGNORE_CONTAINERS=supplyguard-*`로 관찰 제외
- **인증**: `/health` 를 뺀 모든 화면 · API · WebSocket 은 로그인 뒤. 쓰기는 관리자 역할(조회자는 읽기 · 미리보기 · 챗봇만). `ADMIN_TOKEN` 은 CLI · 자동화용 Bearer(처리자 「cli」). `SANDBOX_TOKEN` 은 sg-install 보고만(mock 은 비어도 허용). 비밀번호 5자 이상 · 아이디와 다름, 5번 틀리면 5분 잠금. `AUTH_SECRET_KEY` 는 가젯 모드에서 필수(32자 이상)
- 감사 처리자는 로그인 계정의 표시 이름. 적용 · 버림 · 차단 해제의 사유는 변경 이력에 남는다
- 데모 패키지 `deploy/demo/reqeusts`는 무해 시뮬(TEST-NET 주소 · 예약 도메인만). 실제 악성 코드를 넣지 않는다

## 개발 프로세스

### 커밋 · 머지 [2026-10-15 확정]

- 원격이 생기기 전: **그날 작업 마무리 때 커밋**(main). 커밋 전에 묻는다. `git add -A` 금지 — 내 파일만 골라 담는다. Tier 1 변경은 커밋을 나눈다
- GitHub가 생긴 뒤: 기능 브랜치 → PR(CI 통과) → 사용자 메시지에 **「머지 승인」**이 있을 때만 셀프 머지

### Tier

| Tier | 대상 |
|---|---|
| **1** — 한 줄씩 설명 가능, 커밋 분리 | `enforcer`(kill · 증거 훅) · `rules` 매칭(`directIp` 포함) · 관찰 범위(`WATCH_`/`IGNORE_CONTAINERS` · 컨테이너 발견 방식) · **인증**(`auth` — 로그인 · 세션 · 역할 · CSRF · 잠금 · `AUTH_SECRET_KEY` · 라이선스) · CORS · 가젯 로딩(privileged · `pid: host` · docker.sock) · `deploy.sh` |
| **2** — 설계 + 테스트 | `pipeline` · `resolver`(DNS 캐시) · `ingestion` · `store` · `ws` · `review` · `scan` · `notify` · `evidence` · `chat` · `summary` · API 계약 · `sg-install` |
| **3** — 실행해 보고 확인 | 화면 · 목업 · 스타일 · 설정 |

### 매 세션

1. 계획 승인 → 구현. 계획과 실측이 다르면 멈추고 정정 보고
2. 결함은 원인 실측 후 설계. 수정 전 코드에서 새 테스트 실패를 먼저 보인다
3. 자가 검증: `make test` + React e2e + 바뀐 화면 회귀 N/N + 콘솔 오류 0. 가젯 동작은 `sg-vm`에서만 실측
4. 화면 질문은 앱을 띄워 열어 준 뒤 한다

### 문서

기획 · 설계 · 진행 현황은 **Claude Docs 「SupplyGuard 개발 문서」**(https://claude.ai/code/artifact/5fc4e674-2b54-4bb2-9cd6-a03cae190285)에 둔다 [2026-10-15]. 결정이 바뀌면 이 문서를 고친다(하위 에이전트 `doc-sync`). `docs/`는 `.gitignore`(옛 로컬 사본, 9/29 기준).

## 미확정 (TBD)

- 발표 · 마감 날짜 → 범위 줄이는 순서
- `sg-ec2` 키 파일 경로(배포 단계에서)
- `claude-portable/` gitignore 여부
- 인증 감사 보관 기간
- GuardDog 위험 점수 임계 5 검증(10/18 보류)
- 768px 미만 화면 폭(960px 보장, 768px 은 대시보드 · 이벤트까지 맞춤)
