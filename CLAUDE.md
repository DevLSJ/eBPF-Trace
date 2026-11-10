# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## 현재 상태와 우선순위

**로컬 개발 + sg-vm 실서버 + sg-ec2(2026-11-05).** 개인 캡스톤 프로젝트 SupplyGuard — eBPF(Inspektor Gadget)로 오픈소스 패키지의 런타임 악성 행위를 커널 단에서 잡아 격리한다. 1인, Jira 없음, 사내 표준 미적용. 원격 저장소는 공개 GitHub `github.com/DevLSJ/eBPF-Trace`(11/05 이력 치환 뒤 force push로 덮어씀, gh 활성 계정 DevLSJ — 발표 뒤 Lee-SungJae로 되돌릴지 다시 묻는다).

두 시나리오는 **동등**하다 [2026-10-15 확정]:
- **설치 샌드박스** — `tools/sg-install pip|npm|cargo <패키지>`가 감시 컨테이너(`sg-install-*`)에서 설치하고, 위반이면 설치가 끝나기 전에 격리
- **런타임 감시** — 배포된 컨테이너를 같은 엔진으로 상시 관찰

기능(10/30 기준): 설치 검사 · 런타임 감시(DNS 질의 규칙 포함) · 공급망 검사(GuardDog + OSV) · eBPF 수집 종합 · 시연 패널 · 격리 타임라인 · 상태 신호등 · 건 보고서 · 도우미(대응 가이드 · AI) · 로그인/라이선스/OTP · 외부 알림(웹훅 · Slack) · kill 직전 증거 보존 · 다크 모드 · 768px 미만.

**마감 2026-11-13(발표)** [2026-10-30 확정]. 범위를 줄일 때는 오탐률 하네스 → 보고서 · 신호등 → 디자인 토큰 → DNS 조건 일부 순서로 뺀다.

작업 우선순위 [2026-11-02 라운드 계획 승인 — 11일에 맞춘 축소안 · 2026-11-05 갱신]:
1. ✅ 11/02 작업 커밋(C1~C10) · 공급망 검사 판정 3단계 + 오탐률 하네스 `tools/sg-bench`(11/03)
2. ✅ 종합 판정 — `sg-install` 세션 시작 때 같은 패키지 정적 검사 자동 시작, 설치 화면 한 건에 런타임 + 정적(11/04)
3. ✅ 연쇄 규칙 `kind: sequence` — 기본 `chain-download-secrets`(kill · dryRun, 11/04)
4. ✅ 평가 라운드(11/04) — 실제 악성 594 · 정상 600 정적 측정, sg-vm 런타임 반복 측정, ML 비교(운영은 규칙), 「평가」 화면 · `GET /api/evaluation`. 결과는 `bench/reports/` · README 「실측 결과」
5. ✅ UI 라운드(11/04) — 공통 부품 · 스크롤 없는 페이지 · 길게 눌러 옮기기 · 코드 창 · 파일 트리 · 채팅 · 대시보드 재배치 · 시연 전용 페이지 `/demo`(대시보드 시연 카드 제거) · 표 쪽 번호. 개발용 로그인 admin/admin(`AUTH_DEV_MODE`, 11/05)
6. ✅ sg-vm 반영 · 실측(11/05, 052894d) — 시연 benign 통과 · chain 1단계 격리 · all 격리 · 증거 즉시 조회 · 1920 한 화면. `DEMO_ENABLED=true` 켬
7. EC2 — ✅ 11/05 첫 반영(`/home/ubuntu/supplyguard/current`, sg-vm 과 같은 이미지) · 시연 3종 · 공급망 검사 실측 통과. 남은 것: 보안 그룹 HTTP 80 · 인스턴스 t4g.small(지금 micro)
8. ✅ GitHub 공개(11/05) — `DevLSJ/eBPF-Trace` 를 덮어씀(옛 main 은 태그 `archive/ebpf-trace-main`, 옛 미커밋은 브랜치 `archive/ebpf-trace`). CI 는 테스트 · 이미지 빌드만 — 옛 EC2 secrets · self-hosted 러너 · deploy 작업은 11/05 정리(공개 저장소의 남의 PR 이 sg-vm 에서 돌지 않게)
8-1. ✅/진행 11/09 라운드(브랜치 `feat/round-1109`, PR 전 — 로컬 :5173 이 이 브랜치): Claude 챗봇(opus-5-5 · Ollama 예비) · 설치 검사 「사용 방법」 · 시연 3줄/묶음/흐름 그림 · 평가 쉬운 이름 · 토폴로지 접기/읽히는 맞춤 · chain 시연 시작 1초 대기 · `make dev` = 실제 가젯 로컬 스택 · 정책 변경 이력/되돌리기 백엔드 · 흰 배경 + 규격 토큰 + Pretendard · 공통 목록 부품 · 정책 화면 분리 · 다른 목록 화면 정리. 두 서버(sg-vm · sg-ec2)는 main 쪽 판으로 되돌려 둠. 11/09 저녁: 화면 「—」 없애기 · 평가 화면 접는 목록 · 참고 제품 UI 문서 대조 30항목(해/달 단추 · 제목 21 · 오류 고정 문장 · 토스트 5/9초 · 이름표 · 없는 주소 화면 · 로그인 표시 개선 · 대시보드 최종 갱신). **개발 · 시연은 관리자(admin) 계정 기준** — 조회자 화면 동작은 바꾸지 않는다(11/09 사용자)
9. 리허설(11/11) · 최종 녹화(11/12) · 발표(11/13). **발표 뒤**: 판정 규칙 조정 실험 · 위반 · 분 집계 · 인증 감사 보관 기간(30일) · 커널 7.0 이벤트 유실

## 아키텍처 [2026-09-29 확정 · 2026-10-20 갱신]

```
커널 syscall → IG 가젯(exec·open·connect, + trace_dns 질의 · 응답) → Go ingestion(컨테이너 발견 auto)
  → 규칙 평가(YAML) → (위반) 증거 수집(≤0.7초) → Docker API kill + 웹훅/Slack 알림
  → Redis 버퍼 → WebSocket → React 대시보드
  → PostgreSQL 감사 로그 · 건 · 제안 · 차단 목록 · 계정
REST · WS 앞: 로그인 관문(쿠키 세션, CLI 는 Bearer ADMIN_TOKEN, sg-install 은 SANDBOX_TOKEN)
공급망 검사: 백엔드 → 검사기 컨테이너(GuardDog · OSV-Scanner)
시연(DEMO_ENABLED=true): 백엔드 → Docker API 로 sg-install-demo-* 컨테이너(mock 소스는 모의 재생)
AI 도우미: 백엔드 → Claude API claude-opus-5-5(기본, `ANTHROPIC_API_KEY` · 공식 Go SDK · effort low · 서버 쪽 대체) · Ollama qwen2.5:3b(예비, 또는 `CHAT_PROVIDER=ollama` 로 단독 — 서버 밖으로 안 보냄) [2026-11-09]. 읽기 전용 조회 → 사실 문장 → 답, 판정 상태 · 링크는 서버가 붙임. 보내는 범위는 설정 → 서버 「AI 도우미」
```

- **백엔드**: Go 1.26 · Inspektor Gadget v0.56.1을 Go 패키지로 프로세스 안에서 실행(Cgo 없음). 가젯 데이터 오퍼레이터는 `operators.GetDataOperators()` 전체를 쓰고 LocalManager만 직접 만든 컬렉션으로 교체한다 — 일부만 넣으면 trace_dns가 CO-RE 오류로 안 뜬다
- **컨테이너 발견**: `CONTAINER_DISCOVERY=auto`(기본) — fanotify(runc 훅)를 먼저 시도하고 안 되면(Docker Desktop) docker-events. docker-events는 컨테이너 시작 순간의 동작을 놓친다(11/03 sg-vm · sg-ec2 실측: 시작 0초 0/10, 0.05초부터 10/10)
- **프론트**: React 18 · TS · Vite 7 · Tailwind 4 · React Flow · qrcode(로컬 번들). 차트는 직접 그린 SVG(차트 라이브러리 없음 — 26b0225 에서 Recharts 제거, 11/04 「SVG 유지」 확정)
- **저장**: PostgreSQL 17 · Redis 7(이벤트 버퍼). 정상 이벤트는 하나씩 저장하지 않고 분 단위 개수만(`collected_minutes`, 11/10 부터 같은 1분 안 같은 (컨테이너 · 종류 · 프로세스 · 대상) 반복은 1건 — `stats` · 상한 5만 키/분, 판정 · 실시간 흐름 · 「초당 N건」은 모든 이벤트 그대로), 감사 로그는 위반만. 증거만 7일 정리(11/02 sg-vm 실측: 이벤트 12.7만 건 뒤 DB 8.9MB)
- **배포**: Docker Compose(nginx 80 → backend :8000 · frontend :80 · PG · Redis · 선택 Caddy · 선택 `ollama`(`--profile ai`, 4GB)) · 레지스트리 Docker Hub(`sg-ec2` 는 SSH 로 이미지 전송) · EC2 단일 호스트(`sg-ec2`, 11/03 새 계정)
- **격리 책임**: IG는 탐지만, kill은 백엔드가 Docker API로
- **도메인 미확인 연결은 fail-open** — 단, trace_dns가 켜져 있는데 도메인 조회 없이 공인 IP로 붙으면 규칙의 `directIp`로 판정
- **커밋하지 않는 것**: `.env` · 키 · `claude-portable/`(개인 작업 틀) · `.claude/worktrees/`

### 구조

```
backend/   cmd/{server,healthcheck} · internal/{api,auth,chat,config,dockerapi,enforcer,evidence,ingestion,model,notify,osv,pipeline,review,rules,scan,sginstall,stats,store,summary,ws} · policies/default.yaml
frontend/  src/{components/{shell,list},features/{dashboard,installs,scans,events,topology,policies,audit,settings},hooks,lib} · e2e/
mock/      옛 정적 목업(index.html + shared/ + tests/) — 11/05 부터 기록용(고치지 않음)
deploy/    compose(기본 · dev · mock · https) · Dockerfile · nginx · deploy.sh · demo/
tools/     sg-install
```

### 명령 (루트에서)

| 명령 | 내용 |
|---|---|
| `make setup` | 새 PC · 새 clone 에서 처음 한 번 — 도구 확인 · Go 모듈 · `npm ci` · Playwright chromium(11/06). `make dev` · `make test` 는 `node_modules` 가 없으면 `npm ci` 부터 |
| `make dev` | [11/09 「5173 메인만 활용」] Docker Desktop 안 실제 가젯 백엔드(127.0.0.1:8000) + 개발 DB(Postgres 25433 · Redis 26380 — 다른 로컬 프로젝트와 겹치지 않게) + Vite(:5173), 구성은 `deploy/docker-compose.dev.yml`. 로그인 `admin`/`admin`(비밀번호 변경 단계 없음, `AUTH_DEV_MODE` + `LOCAL_DEV=true` — `LOCAL_DEV` 는 서버 `.env` 에 넣지 않음) · 평가판 라이선스는 DB 에 한 번 등록 · OTP 켬(첫 로그인에 QR 등록). 감시 = 전체, 격리 = `sg-install-*` · 시연 · `supplyguard.enforce=true` 라벨만. `.env.local`(gitignore · 600)에 없는 `AUTH_SECRET_KEY` · `ADMIN_TOKEN` · `SANDBOX_TOKEN` 을 한 번 만듦(`AUTH_SECRET_KEY` 가 바뀌면 OTP 등록을 못 읽음), `ANTHROPIC_API_KEY` 가 있으면 AI 도우미는 Claude. 「사용 방법」 주소 `SG_INSTALL_API`. 한계: Docker Desktop 은 fanotify 가 없어 docker-events — 시작 직후 약 0.1초 동작은 놓칠 수 있음. 백엔드 코드를 고치면 다시 `make dev` · 로그 `make dev-logs` · 내림 `make dev-down`(DB 볼륨은 남김) |
| `make dev-mock` | 예전 `make dev` — Docker 없이 빠른 화면 개발. 백엔드(mock 소스, go run :8000, 메모리 저장, OTP 끔 · `admin`/`admin` 으로 바로 대시보드 — Makefile `DEV_AUTH`) + Vite(:5173). 공급망 검사는 Docker Desktop 이 켜져 있어야 하고 작업 폴더는 `.scan-work`(검사기에 bind, 11/06) |
| `make mock` | 옛 목업 :8766 — 11/05 부터 개발 · 검증에 쓰지 않음(기록 열람용). **8765는 참고 제품 목업 — 끄지 않는다** |
| `make test` | 백엔드 vet · race 테스트 + 프론트 lint · build |
| `cd frontend && npx playwright test` | React e2e(가짜 백엔드, CI 에도 있음) |
| `make stack-up` / `stack-down` | 전체 스택 컨테이너(mock 소스, `.env` 에 `ADMIN_INITIAL_PASSWORD` 필요) |
| `make sandbox-up` / `sandbox-down` | 실제 가젯 백엔드, `WATCH_CONTAINERS=sg-install-*`, 실행마다 `AUTH_SECRET_KEY` 새로 생성 · OTP 켬 — `make dev` 와 달리 감시도 `sg-install-*` 만 · 메모리 저장 · 개발 로그인 없음, 같은 :8000 이라 함께 띄우지 않음 |
| `make vm-open` / `vm-close` | sg-vm 화면을 http://localhost:8080 으로(SSH 터널, `VM_PORT=` 로 바꿈). UTM VM 이 켜져 있어야 함. 로그인 Origin 은 같은 호스트로 통과 — `ALLOWED_ORIGINS` 안 바꿈(11/05 실측) |
| `cd backend && GOOS=linux go vet ./...` | 리눅스 전용 코드 검사 |
| `ADMIN_TOKEN=… tools/sg-bench [-a API] [-l 목록] [-o 결과]` | 공급망 검사 오탐률 하네스 — 인기 패키지 20개 + 취약 버전을 실제 백엔드로 검사, 인기 패키지가 「악성」이면 실패. sg-vm 에서는 `-t ~/sg/.tokens` |

**주의**: 맥에서 실제 가젯 소스 + `ENFORCE_KILL`을 쓸 때는 격리 범위를 반드시 좁힌다 — 11/06 부터 격리는 `sg-install-*` · 시연 · `supplyguard.enforce=true` 라벨(`ENFORCE_CONTAINERS`)만이라 make dev 는 전체를 감시해도 다른 컨테이너를 죽이지 않는다(그 밖은 `enforceSkip: "label"` 로 보류). 11/06 이전 코드로 돌릴 때는 `WATCH_CONTAINERS=sg-install-*` — 범위 없이 돌려 minikube 컨테이너가 두 번 죽은 적이 있다.

### 서버

- **`sg-vm`** — UTM Ubuntu 22.04 arm64(커널 5.15), 키 인증. docker는 sudo 없이, sudo는 비밀번호 필요 → 사용자가 자기 터미널에서 직접. 작업 경로 `~/sg/` 안에서만
  - 전체 스택 상시 실행: `~/sg/stack`, compose 프로젝트 `supplyguard`, 이 Mac 의 UTM VM(`bridge100`, http://192.168.64.2 — 이 Mac 에서만 열림, 화면은 `make vm-open` 의 http://localhost:8080 으로 연다 [2026-11-05]). 로그인 켜짐(10/20) · 발견 auto → fanotify · `ENFORCE_KILL=true` · 전체 감시 · `ollama` 프로필 켬
  - 반영: 소스를 tar 로 옮겨 VM 에서 빌드(`docker compose … build`) → 이전 이미지에 롤백 태그 → `up -d` → health 확인 → 실패 시 롤백 태그로 복구. 롤백 태그 · `.env` 백업 위치는 메모리
  - `.env` · `~/sg/.tokens` 는 600, 값은 출력하지 않는다
- **`sg-ec2`** — 시험 · 시연용 EC2 [2026-11-03]. **새 AWS 계정**(기존 계정 · `ebpf-trace-app` 과 무관) · 스톡홀름 리전 · t4g.small(arm64, 2GB) · **Ubuntu 22.04**(커널 6.8) · 8GB gp3 · 파일 시스템 없음 · 고정 주소는 탄력적 IP. 별칭 `sg-ec2`(전용 키, 주소는 `~/.ssh/config` 에만). 경로 `/home/ubuntu/supplyguard*` 안에서만. `ollama` 프로필은 끈다
  - **sudo 는 Claude 가 직접 실행한다**(이 서버만, 전역 규칙의 예외 — Docker 설치 · 설정 · 스왑 · 패키지 업데이트). 새 계정의 AWS 콘솔 · CLI 권한은 Claude 에게 없어 콘솔 설정은 사용자에게 요청
  - 이미지는 Mac 에서 arm64 로 빌드해 `docker save | ssh sg-ec2 docker load` 로 옮긴다(EC2 에서 빌드하지 않는다 · Docker Hub 안 씀). Docker 는 overlay2 저장 · 로그 10MB×3 · journald 100MB, cargo 이미지는 상주시키지 않는다
  - **Ubuntu 26.04(커널 7.0)는 쓰지 않는다** — IG v0.56.1 가젯 이벤트가 발견 방식과 상관없이 약 절반 빠졌다(11/03 실측: 26.04 fanotify 14/40 · 22.04 fanotify 40/40 · docker-events 는 컨테이너 시작 순간 동작만 놓쳐 30/40)
- 반영은 `deploy/deploy.sh`의 백업 → 반영 → 확인 → 실패 시 복구만

### 화면 개발 [2026-11-05 사용자 결정 — 목업 단계 · 목업 테스트 없앰]

**로컬 서버(React · 백엔드) 위주로 개발하고 테스트한다.** 화면 변경은 `make dev`(:5173 · admin/admin · 첫 로그인에 OTP 등록 · 실제 가젯 백엔드 [11/09])에서 바로 만들어 띄워 보여 주고 확정한다. Docker 없이 화면만 볼 때는 `make dev-mock`(같은 :5173 · OTP 없음). 검증은 `make test` + React e2e(`frontend/e2e`), 새 회귀 테스트도 React e2e 로만 쓴다. 개인 규칙의 「목업 먼저(mockup-first)」는 이 저장소에서 쓰지 않는다.

디자인 [2026-11-10 새벽 — 사용자 「x.com 페이지를 참고하여 ui를 깔끔하게」, 범위 = 배치까지 · 주 버튼 파랑 유지 + 알약 · 어두운 화면 = 참고 사이트 남색(Dim)]: **지금 값**(아래 11/09 값보다 우선) — 바탕 하나 `#FFFFFF`(회색 바탕 없앰) · 글자 `#0F1419` · 흐림 `#536471` · 구분 선 `#EFF3F4` · 입력 테두리 `#CFD9DE` · 줄 hover `#F7F9F9` · 카드 · 패널 그림자 없음 + 1px 선(떠 있는 면만 옅은 그림자) · 버튼 알약 9999px(주 = 파랑 `#1769E8`, 보조 = 투명 + 선 + 본문 글자) · 표 머리 바탕 없음 + 아래 선 · 작은 위험 글자는 `--danger-text` · 어두운(Dim) 바탕 `#15202B` · 한 단 위 `#1E2732` · 선 `#38444D` · 글자 `#F7F9F9` · 흐림 `#8B98A5` · 주 버튼 `#1B70EE`. 셸 배치: 평평한 사이드바(아이콘 24 · 글자 16/500 · 지금 화면 700 · 알약 hover · 계정은 맨 아래 · 1280 이상 글자 / 768~1279 아이콘만 / 768 미만 서랍) · 본문 단 맨 위 고정 제목 줄(53 · 반투명 + blur 12 · 오른쪽 상태 묶음) · 본문 단 가운데 + 좌우 1px 세로선, 셸 값은 `components/shell.css`. 지킴 시험 `e2e/x-tokens-1109.spec.ts` · `x-shell-1109.spec.ts`. [이전 11/09 저녁 기록 — 같은 날 아침의 「참고 홈페이지 구조값(미색)」을 사용자가 되돌림]: 공통 토큰(값은 `frontend/src/index.css`)은 **11/05 흰 배경 판 + 대비 수정** — 바탕 `#F6F7FB` · 카드 흰색 · 강조 · 주 버튼 파랑 `#1769E8`(보조 = 파란 외곽선) · 흐림 글자 `#5F6675`(11/05 `#7A8090` 은 4.5:1 미달) · 위험 채움 버튼 `#B52D49` · 반경 8(버튼 6) · 넓고 옅은 카드 그림자 · 표 머리 42 · 행 48 · 상태 배지 27 · 12.5/**700 · 테두리 = 글자색(currentColor)**(어두운 배지 「설치 전 거부」만 바탕색 — 11/09 예외) · 쪽 넘김 「총 N건 · p/P 페이지」 + 「N개씩」 · 빈 상태 아이콘 없음 · 격리 배지 위험 톤 · 작은 외곽선 단추 `sg-btn sg-btn-sm sg-btn-secondary`. **규격 토큰**(참고 제품 답변 권고, 11/09): 움직임 `--dur-fast/base/slow` 120 · 180 · 450ms · 곡선 `--ease-enter/move/color` · 포커스 링 하나(2px 주색 · 바깥 offset 2) · 글자 5단 `--fs-xs…xl` 12 · 13.5 · 14 · 16 · 21(표 · 입력 13.5, 화면 제목 21/700) · 스켈레톤 반짝임은 바탕보다 한 단계 진하게. **글꼴**: Pretendard Variable 한글 서브셋을 저장소 안 `frontend/src/assets/fonts/`(SIL OFL 라이선스 파일 함께)에 두고 `@font-face` — 외부 요청 없음(11/09 사용자가 글꼴 파일 제공, 「웹폰트 · 내려받지 않음」 규칙을 바꿈). 움직임: 시트는 열릴 때만 밀려 들어오고(뒤 어둡게 120ms 먼저) 닫힘은 바로 · 열린 채 다른 줄은 내용만 교체 · 큰 창은 뒤 어둡게만 · 팝오버 120ms 하나 · 카운트업은 값이 바뀔 때만 · 표 hover · 선택 · 탭 밑줄은 즉시 · 동작 줄이기 존중. 값만 옮기고 참고 제품의 이름 · 로고 · 아이콘 · 문구 · 코드 문장은 넣지 않는다(공개 저장소 — 주석 · 시험 · 커밋에도 「참고 제품」으로). 종류 색(실행 · 파일 · 통신 · 조회) · 코드 창 · 차트 모양은 이 제품 고유. 빨강은 위험에만. 외부 CSS · 로고 금지. 다크 모드(`supplyguard.theme`, 11/09 저녁 — **해/달 단추 하나** `components/ThemeToggle.tsx` 를 셸 머리 · 로그인 화면 오른쪽 위에, 처음은 PC 설정 · 누르면 기억 · 450ms 전환 · 계정 메뉴 테마 칸 없음) · 768px 미만(서랍 사이드바 · 1열, 단 종합 숫자 칸은 2열) 포함. 회귀 `frontend/e2e/theme-white-1109.spec.ts` · `tokens-1109.spec.ts` · `table-kit-1109.spec.ts`.

목록 · 표 · 문구 [2026-11-09 — 참고 제품 화면 설계 · 답변 · 문구 양식을 SupplyGuard 규격으로]: 목록 화면 = 제목 + 설명 한 줄(11/09 밤: 오른쪽 끝 = 화면 주 버튼 — 공통 `components/ScreenHead.tsx` + `<PageActions>`, 머리 줄은 제목 + 상태 표시만, 768 미만은 버튼이 설명 아래) → 거르기 줄(검색 Enter · 「○○ 전체」 필터) → 표 도구줄(총 N건 · 새로고침 · 칸 고르기 · 내보내기 = 보이는 칸) → 표 → 쪽 넘김. 행 클릭 = 오른쪽 상세 시트(탭). 공통 부품 `useTableKit`(칸 보이기 · 폭 · 순서 = localStorage `supplyguard.grid.<표>.v1`) · `useListQuery` · `TableToolbar` · `Select` · `SearchField` · `FilterBar` · `Sheet`(탭 · 부제 · 배지 · 초점 가둠) · `Modal size="xl"`(2단 · 미저장 확인) · `ConfirmDialog`(영향 · 막는 사유 · 확인 체크) · `ActionButton reason`(aria-disabled + 사유) · 칸 도우미 `TwoLine` · `TimeText`. **주소에는 링크용 값(id · proposal · tab · view · node)만, 필터 · 검색 · 쪽 · 정렬은 화면 상태**(10/21 결정 유지 — 11/09 재확인). 칸: 현황 표는 상태 맨 앞 · 기록류는 시각 먼저 · 기록류 시각은 초까지 고정폭 / 현황 `MM-DD HH:mm` + 툴팁 / 등록일 날짜만 · 상대 시각 없음 · 빈 값은 빈 칸(11/09 저녁 — 「—」 안 씀) · 폭 표준 시각 160(기록류 초까지 `COL_W.log` 192) · 사용자 110 · 상태 120 · ID 120 · 숫자 80 · 행을 흐리게 하지 않음. 문구: 문장 「~합니다」 격식체 · 개조식 명사형 · 라벨 명사구 · 화면 설명 한 줄 20~50자 「[대상]을 [동작]하고 [동작]합니다.」는 `frontend/src/lib/screenCopy.ts` 한 곳(시험으로 지킴) · 알림 「~했습니다.」/「~하지 못했습니다.」 + 할 일 · 확인 창 「~할까요?」 · 꺼진 단추 사유는 마침표 없음 · 동작 태그 색은 끝말로(`lib/actionTone.ts`) · 기호 `›` ` · ` 「」 `→` `…` · 천 단위 쉼표 · 용어 「적용 컨테이너」. 11/09 저녁(참고 제품 UI 문서 대조): 칸 · 단추 이름은 `lib/fieldNames.ts` 한 곳(정책 · 처리자 · 패키지 관리자 · 필터 해제 「조건 지우기」 하나) · 시각은 어디서나 `YYYY-MM-DD HH:mm:ss`(`fmtDateTime` = 표 칸과 같음) · 오류는 상태 코드를 화면에 내지 않고 서버 문장만, 연결 실패는 「서버에 연결하지 못했습니다. 네트워크를 확인한 뒤 다시 시도하세요.」, 알림은 「~하지 못했습니다. {서버 문장}」(괄호에 넣지 않음) · 토스트 단추 있으면 9초 · 없으면 5초 · 위험은 role=alert · 설정 이름(DEMO_ENABLED · NOTIFY_* 등)은 화면 글자에 내지 않고 툴팁 · 보조 글로만 · 없는 주소는 「화면을 찾을 수 없습니다」 · 확인 창 제목 「~할까요?」 + 영향 범위. 지킴 시험 `e2e/ui-{a,b,c,d,integ}-1109.spec.ts`. 평가 화면(11/09 저녁, 참고 그림 원리) = 위 큰 숫자 3칸(정적 악성 탐지율 · 정상 패키지 오판율 · 런타임 공격 탐지율) + 접는 목록 8줄(▶ · 값 · 막대 · 상태 칩, 처음 모두 접힘 · 여러 줄 · 「모두 펼치기 · 모두 접기」), ③ 판정 4칸 목표 탐지율 ≥ 92% · 오판율 ≤ 2%(사용자 지정, 측정값은 그대로), 지킴 시험 `e2e/eval-accordion-1109.spec.ts`. **화면에 「—」(U+2014) 금지**(11/09 저녁 사용자 — 페이지 · 탭 · 시트 · 창 · 알림 · 툴팁 · placeholder · aria-label · 챗봇 답 · 서버가 만드는 화면 문구, 주석 · 로그 · CLI 출력 · 시험 이름 · 사용자 데이터 제외): 결과 · 상태 문장은 「[상태어] 짧은 설명」(예 「[통과] 위반 사항 없음」) · 제목 · 라벨은 괄호 부연 「로그(마지막 200줄)」 · 설명 문장은 쉼표 · 괄호로 잇거나 나눔 · 공급망 검사 엔진 줄은 이름 · 판만. 지킴 시험 `frontend/e2e/no-dash-1109.spec.ts` · 백엔드 `internal/api/screen_text_test.go`(문자열 상수, 로그 · 시작 오류 제외) · 챗봇은 답 후처리. 사이드바 묶음(11/09 밤): **연동**(연동 `/integration` = 흐름 그림 + 시나리오 마법사, 카드는 한 줄 설명 + 예 하나 · 환경 점검 `/integration/env` = 수집 준비 + 연결 테스트 · 감시 중 컨테이너 `/integration/watch` — 행 클릭 = 상세 시트 정보 · 위반 이력 · 최근 이벤트, 11/10 · 읽기 전용 `GET /api/integration/containers/{id}`(Docker inspect, 환경 변수는 읽지 않음)) · **정책** — 묶음 머리로 접고 펴기, 지금 화면 묶음은 늘 펼침, 나머지는 localStorage `supplyguard.nav.open.v1`(처음 접힘). 정책은 사이드바 하위 메뉴 **정책 · 차단 목록 · 변경 이력** 세 페이지, 정책 상세 탭 **편집 · 차단 이력 · 변경 이력**(되돌리기, 편집 탭 아래 요약 띠는 없음 — 11/09 밤 사용자, 요약은 저장 전 확인 · 목록 설명 칸에), 「정책 생성」 = 2단 창(오른쪽 적용 컨테이너 카드 — 규칙 `containers`, 「지정」 0개면 저장 막음).

- `mock/`(정적 목업 · `mock/tests/*.cjs`)은 지난 결정의 기록으로만 남긴다 — 고치지 않고 회귀도 돌리지 않는다. 지난 결정 기록 원문은 `mock/README.md` 반영 기록
- 지난 결정(목업 시절): 10/15 1차 · 10/16 · 10/20 도우미(`guide-1020.cjs`) · 10/20 2차(로그인 · 대화상자 · 알림 센터 · 목록 · 셸 · 새 기본 규칙 · 증거, `feedback-1020b.cjs`) · 10/20 결정 반영(토큰 칸 삭제 · 설정 화면 · 라이선스 칩 · 30초 재시도 · 비밀번호 5자, `feedback-1020c.cjs`) · 10/30(DNS 규칙 · 시연 · 타임라인 · 신호등 · 보고서 · 디자인 토큰 · 다크 · 768px, `dns-1030` · `demo-1030` · `theme-1030`, 11/02 React 맞춤) · 11/05 슬라이드 패널(상세는 본문 위에 겹쳐 오른쪽에서 — 공급망 · 설치 70% · 그 밖 720 · 뒤 어둡게 · 「n / m ‹ ›」 · ↑↓ · 주제별 블록, `sheet-1105`) — 상세는 `mock/README.md` 반영 기록
- API 계약: Claude Docs 「API 계약」 탭
- 스크린샷은 `frontend/test-results/screens/`(e2e `SHOTS`)

## 도메인 규칙

- 연쇄 규칙(`kind: sequence`, 11/04) — 같은 컨테이너에서 `windowSeconds`(1~60) 안에 `steps`(2~5, 각 단계는 exec · open · connect · dns 조건) 가 순서대로 일어나면 판정. 처리 순서 기준 · 사이 이벤트 허용 · 판정은 이벤트 1건에 1개(더 강한 쪽, 동률이면 단일 규칙 — 진 연쇄는 `sequence` 주석). 미리보기 · 자동 예외 불가(감사 로그에 앞 단계가 없음). 기본 `chain-download-secrets`(kill, **dryRun — 발표까지 유지**). 기본 `no-shell-download` 가 1단계에서 먼저 격리하므로 시연은 그 규칙을 dryRun 으로 두고 한다
- 정책 변경 기록(11/09): 변경(`changes`)에 `ruleIds` · 변경 전/후(`before` · `after` = {정책id: 규칙}) · `revertOf` — 정책 저장 · 삭제 · YAML 교체(바뀐 정책만) · 제안 적용 · 되돌리기 · 도메인 차단 해제(→ `blocklist-hosts`)가 남긴다. 정책별 이력 `GET /api/changes?rule=&kind=&offset=&limit=`(offset 없으면 예전처럼 배열), 되돌리기 `POST /api/policies/{id}/revert {changeId, reason}`(관리자 · 사유 필수 · 시스템 규칙 · 새로 만든 기록 · 같은 값은 409), 정책 목록에 `updatedAt` · `updatedBy`. 11/09 이전 옛 기록은 정책 id 가 없어 정책별 이력에 나오지 않는다. 정책별 차단 이력은 `GET /api/audit?rule=`(완전 일치)
- 판정: `allow` · `alert` · `kill`. 전역 `ENFORCE_KILL=false`면 kill 정책도 알림만
- 정책은 `backend/policies/default.yaml`(기본 11개 — 11/04 연쇄 규칙 추가)이 빈 DB에 한 번 시드, 이후 대시보드 정책 화면에서 바꾼다. 기존 서버에 새 기본 규칙은 정책 화면 「새 기본 규칙 있음」 안내로 추가(덮어쓰지 않고 빈 값만 채움)
- connect 규칙 `directIp: allow|alert|kill` — trace_dns 가 켜져 있을 때 도메인 조회 없는 공인 IP 연결. `directIp` 만 있고 `allowHosts` 가 없는 규칙은 IP 직접 연결 전용
- dns 규칙(`kind: dns`, 10/30) — 질의만 판정. `denyHosts` → `allowHosts` 통과 → `denyQtypes` → `maxLabelLength` → `maxNameLength` → 허용 목록 밖(점 없는 이름 · `*.arpa` · `*.local` · `*.internal` 제외) 순서. 기본 `runtime-dns-exfil`(alert) · `sandbox-dns`(kill — 11/03 sg-vm 실측 뒤 dryRun 해제: 정상 설치 27건 새 오탐 0). `blocklist-hosts` 는 dns 질의에 적용하지 않는다
- 시연(`DEMO_ENABLED=true`, 운영은 끈다) — 관리자 세션만 `POST /api/demo/run`, 동시 1개 · 90초 · 변경 이력. 서버 종료 때 진행 중인 시연 컨테이너를 지우고 끝낸다
- kill 직전 증거(로그 · 파일 변경 · 프로세스)를 0.7초 안에서 모은다. 넘으면 기다리지 않고 kill
- 자기 스택은 `IGNORE_CONTAINERS=supplyguard-*`로 관찰 제외
- 라벨 연동(11/06, `pipeline/scope.go`): 감시 = `WATCH_CONTAINERS` 비면 전체, 아니면 이름 패턴 OR 라벨 `supplyguard.watch=true`. **격리 = 라벨 `supplyguard.enforce=true` · `supplyguard.sandbox`(sg-install) · `supplyguard.demo`(시연) 또는 `ENFORCE_CONTAINERS`(기본 `sg-install-*`)만** — 그 밖의 kill 은 보류(`dryRun` + `enforceSkip: "label"`). 라벨은 Docker inspect 로 컨테이너당 한 번(종료 때 잊음), 조회 실패면 이름 규칙만. 연동 화면 `GET /api/integration` · 연결 테스트 `POST /api/integration/test`(관리자 세션 · 시험 컨테이너 `sg-probe-*` busybox · 감시 라벨만 · 동시 1개 · 45초)
- **인증**: `/health` 를 뺀 모든 화면 · API · WebSocket 은 로그인 뒤. 쓰기는 관리자 역할(조회자는 읽기 · 미리보기 · 챗봇만). `ADMIN_TOKEN` 은 CLI · 자동화용 Bearer(처리자 「cli」). `SANDBOX_TOKEN` 은 sg-install 보고만(mock 은 비어도 허용). 비밀번호 5자 이상 · 아이디와 다름, 5번 틀리면 5분 잠금. `AUTH_SECRET_KEY` 는 가젯 모드에서 필수(32자 이상)
- 감사 처리자는 로그인 계정의 표시 이름. 적용 · 버림 · 차단 해제의 사유는 변경 이력에 남는다
- 데모 패키지 `deploy/demo/reqeusts`는 무해 시뮬(TEST-NET 주소 · 예약 도메인만). 실제 악성 코드를 넣지 않는다
- 공급망 검사 판정(11/03, `scan/verdict.go`): **악성** = GuardDog 점수 ≥ 5 **그리고** 설치 시점 규칙(`threat-setup-*` · `npm-preinstall-script` · `network-exfil*` · `dns-exfil` · `reverse-shell` · `download-exec` · `self-propagation`) 1개 이상 · **취약** = 알려진 취약점 · **주의** = 점수 ≥ 5 인데 런타임 휴리스틱 규칙만 · 그 외 정상. 우선순위 악성 > 취약 > 주의 > 정상. 테스트 코드 탐지는 어디에도 넣지 않는다. `threat-process-hooks` 는 정상 setup.py 에도 흔해 설치 시점 규칙에서 뺐다

## 개발 프로세스

### 커밋 · 머지 [2026-10-15 확정]

- [2026-11-05 GitHub 공개 뒤] 기능 브랜치 → PR(CI 통과) → 사용자 메시지에 **「머지 승인」**이 있을 때만 셀프 머지. main 에 바로 커밋 · push 하지 않는다. `git add -A` 금지 — 내 파일만 골라 담는다. Tier 1 변경은 커밋을 나눈다

### Tier

| Tier | 대상 |
|---|---|
| **1** — 한 줄씩 설명 가능, 커밋 분리 | `enforcer`(kill · 증거 훅) · `rules` 매칭(`directIp` · `kind: dns` 포함) · 시연 API(`demo` — 컨테이너 기동) · 관찰 범위(`WATCH_`/`IGNORE_CONTAINERS` · 컨테이너 발견 방식) · **인증**(`auth` — 로그인 · 세션 · 역할 · CSRF · 잠금 · `AUTH_SECRET_KEY` · 라이선스) · CORS · 가젯 로딩(privileged · `pid: host` · docker.sock) · `deploy.sh` |
| **2** — 설계 + 테스트 | `pipeline` · `resolver`(DNS 캐시) · `ingestion` · `store` · `ws` · `review` · `scan` · `notify` · `evidence` · `chat` · `summary` · API 계약 · `sg-install` |
| **3** — 실행해 보고 확인 | 화면 · 스타일 · 설정 |

### 매 세션

1. 계획 승인 → 구현. 계획과 실측이 다르면 멈추고 정정 보고
2. 결함은 원인 실측 후 설계. 수정 전 코드에서 새 테스트 실패를 먼저 보인다
3. 자가 검증: `make test` + React e2e(바뀐 화면은 e2e 로 지킨다) + 콘솔 오류 0. 목업 회귀는 돌리지 않는다 [11/05]. 가젯 동작은 `make dev`(Docker Desktop · docker-events — 시작 직후 약 0.1초를 놓칠 수 있음) 또는 `sg-vm`(fanotify)에서 실측 [11/09]
4. 화면 질문은 앱을 띄워 열어 준 뒤 한다

### 문서

기획 · 설계 · 진행 현황은 **Claude Docs 「SupplyGuard 개발 문서」**(https://claude.ai/code/artifact/5fc4e674-2b54-4bb2-9cd6-a03cae190285)에 둔다 [2026-10-15]. 결정이 바뀌면 이 문서를 고친다(하위 에이전트 `doc-sync`). 단 10/30 부터 이 문서가 지금 계정에서 읽히지 않아(공유 확인 필요) 결정은 `mock/README.md` 반영 기록과 이 파일에 남긴다. `docs/`는 `.gitignore`(옛 로컬 사본 · 10/30 공통 계약 `docs/contract-1030.md`).

## 미확정 (TBD)

- ~~`sg-ec2` 키 파일 경로~~ → 11/03 전용 키 · 별칭 등록(서버 항목)
- 커널 7.0(Ubuntu 26.04) 가젯 이벤트 유실 원인 · `CONTAINER_DISCOVERY=auto` 보완(fanotify 누락 시 경고 + docker-events 보충) — 발표 뒤 재검토 [2026-11-03]
- `claude-portable/` gitignore 여부
- ~~GuardDog 위험 점수 임계~~ → 11/03 판정 3단계로 확정(도메인 규칙). 임계 5 는 그대로, 「악성」은 설치 시점 규칙이 걸릴 때만
- 위반 기록 · 분 단위 집계 보관 기간(인증 감사 30일 구현 때 함께)
