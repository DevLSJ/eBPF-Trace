# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## 현재 상태와 우선순위

**로컬 개발 단계(2026-10-15).** 개인 캡스톤 프로젝트 SupplyGuard — eBPF(Inspektor Gadget)로 오픈소스 패키지의 런타임 악성 행위를 커널 단에서 잡아 격리한다. 1인, Jira 없음, 사내 표준 미적용. 원격 저장소 없음(GitHub는 나중, 만들 때 **공개** `github.com/devlsj/ebpf-supplychain-guard`).

두 시나리오는 **동등**하다 [2026-10-15 확정]:
- **설치 샌드박스** — `tools/sg-install pip|npm|cargo <패키지>`가 감시 컨테이너(`sg-install-*`)에서 설치하고, 위반이면 설치가 끝나기 전에 격리
- **런타임 감시** — 배포된 컨테이너를 같은 엔진으로 상시 관찰

작업 우선순위 [2026-10-15 확정]:
1. 틀 정리 — 이 파일 · 문서를 Claude Docs로 이전 · `docs/` 추적 해제
2. **「설치 검사」 화면** — 목업 시안 → 확정 → 세션 API + React
3. 회귀 테스트 — React E2E(기존 5화면) + 목업 `.cjs`
4. 실측 · 배포 — `sg-vm` 공격 시나리오 재확인 → GitHub(공개 전 이력 점검) → EC2 첫 배포

마감: 미확정(아래 TBD).

## 아키텍처 [2026-09-29 실측 확정]

```
커널 syscall → IG 가젯(exec·open·connect, + trace_dns) → Go ingestion(docker-events 컨테이너 발견)
  → 규칙 평가(YAML) → (위반) Docker API kill + 알림
  → Redis 버퍼 → WebSocket → React 대시보드
  → PostgreSQL 감사 로그
```

- **백엔드**: Go 1.26 · Inspektor Gadget v0.56.1을 Go 패키지로 프로세스 안에서 실행(Cgo 없음). 가젯 데이터 오퍼레이터는 `operators.GetDataOperators()` 전체를 쓰고 LocalManager만 docker-events 컬렉션으로 교체한다 — 일부만 넣으면 trace_dns가 CO-RE 오류로 안 뜬다
- **프론트**: React 18 · TS · Vite 7 · Tailwind 4 · React Flow · Recharts
- **저장**: PostgreSQL 17(정책 · 감사) · Redis 7(이벤트 버퍼)
- **배포**: Docker Compose(nginx 80 → backend :8000 · frontend :80 · PG · Redis · 선택 Caddy) · 레지스트리 Docker Hub · EC2 단일 호스트(기존 `ebpf-trace-app` 대체)
- **격리 책임**: IG는 탐지만, kill은 백엔드가 Docker API로
- **도메인 미확인 연결은 fail-open**(정상 다운로드를 죽이지 않는다)
- **커밋하지 않는 것**: `.env` · 키 · `claude-portable/`(개인 작업 틀)

### 구조

```
backend/   cmd/{server,healthcheck} · internal/{api,config,dockerapi,enforcer,ingestion,model,pipeline,rules,stats,store,ws} · policies/default.yaml
frontend/  src/{components,features/{dashboard,events,topology,policies,audit},hooks,lib}
mock/      정적 목업(index.html + shared/) — 결정 확인용
deploy/    compose(기본 · dev · mock · https) · Dockerfile · nginx · deploy.sh · demo/
tools/     sg-install
```

### 명령 (루트에서)

| 명령 | 내용 |
|---|---|
| `make dev` | 백엔드(mock 이벤트, :8000) + Vite(:5173) |
| `make mock` | 목업 :8766 (**8765는 참고 제품 목업 — 끄지 않는다**) |
| `make test` | 백엔드 vet · race 테스트 + 프론트 lint · build |
| `make stack-up` / `stack-down` | 전체 스택 컨테이너(mock 소스) |
| `make sandbox-up` / `sandbox-down` | 실제 가젯 백엔드, `WATCH_CONTAINERS=sg-install-*` |
| `cd backend && GOOS=linux go vet ./...` | 리눅스 전용 코드 검사 |

**주의**: 맥에서 실제 가젯 소스 + `ENFORCE_KILL`을 쓸 때는 반드시 `WATCH_CONTAINERS=sg-install-*`. 범위 없이 돌려 minikube 컨테이너가 두 번 죽은 적이 있다.

### 서버

- **`sg-vm`** — UTM Ubuntu 22.04 arm64(커널 5.15), 키 인증. docker는 sudo 없이, sudo는 비밀번호 필요 → 사용자가 `!`로 직접. 작업 경로 `~/sg/` 안에서만
- **`sg-ec2`** — 운영 EC2(Ubuntu 22.04, t3.medium). 별칭 등록 보류 [2026-10-15] — 배포 단계에서 키 파일을 정해 추가. 경로 `/home/ubuntu/supplyguard*` 안에서만
- 이미지 옮기기: `docker save local/supplyguard-backend:dev | gzip | ssh sg-vm 'gunzip | docker load'`
- 반영은 `deploy/deploy.sh`의 백업 → 반영 → 확인 → 실패 시 복구만

### 목업 (`mock/`) [2026-10-15 확정]

**React가 기준이고, 목업은 결정 확인용이다.** 화면 변경은 목업에서 먼저 보여 주고 확정한 뒤 React에 반영한다. 둘이 다르면 어느 쪽이 맞는지 묻는다. 목업을 재구성하지 않는다. 테마는 지금 것을 유지하고, 기능을 우선한다(다크 모드 보류).

- 데이터 소스 2종: 내장 시뮬레이션 / 실제 백엔드(`?source=live&api=…`). 빈 서버 `?fresh=1`
- **결정 기록**: 2026-10-15 1차 반영 — 사이드바 시나리오 묶음 · 단계 칩 삭제 · 「설치 검사」 화면(세션 표 + 시트, 확인함) · 대시보드 조치 필요 · 이벤트 기본 위반만 · 감사 로그 페이지 고정 · 정책 첫 항목 선택 · 토스트 묶음 8초 — 회귀 `mock/tests/feedback-1015.cjs`(상세는 `mock/README.md` 반영 기록)
- **설치 세션 API 계약 초안**: `mock/shared/app.js` api 위 주석. CLI 보고는 `SANDBOX_TOKEN`, 끝 보고가 없으면 컨테이너 종료 10분 뒤 「결과 미확인」 [2026-10-15 확정]
- Playwright: `~/Documents/캡스톤/eBPF-project/frontend/node_modules/playwright` 를 `PLAYWRIGHT=` 로 빌려 쓴다(이 저장소에 아직 없음)
- 회귀: 목업 `mock/tests/feedback-MMDD.cjs` + React `frontend/e2e`(Playwright, CI 포함). 판정 N/N + 콘솔 오류 0
- 스크린샷은 `mock/screenshots/`(gitignore)

## 도메인 규칙

- 판정: `allow` · `alert` · `kill`. 전역 `ENFORCE_KILL=false`면 kill 정책도 알림만
- 정책은 `backend/policies/default.yaml`이 빈 DB에 한 번 시드, 이후 대시보드 정책 화면에서 바꾼다
- 자기 스택은 `IGNORE_CONTAINERS=supplyguard-*`로 관찰 제외
- 쓰기 API는 `ADMIN_TOKEN`(Bearer) 필요. 예외는 `EVENT_SOURCE=mock`뿐
- 데모 패키지 `deploy/demo/reqeusts`는 무해 시뮬(TEST-NET 주소만). 실제 악성 코드를 넣지 않는다

## 개발 프로세스

### 커밋 · 머지 [2026-10-15 확정]

- 원격이 생기기 전: **그날 작업 마무리 때 커밋 하나**(main). 커밋 전에 묻는다. `git add -A` 금지 — 내 파일만 골라 담는다
- GitHub가 생긴 뒤: 기능 브랜치 → PR(CI 통과) → 사용자 메시지에 **「머지 승인」**이 있을 때만 셀프 머지

### Tier

| Tier | 대상 |
|---|---|
| **1** — 한 줄씩 설명 가능, 커밋 분리 | `enforcer`(kill) · `rules` 매칭 · 관찰 범위(`WATCH_`/`IGNORE_CONTAINERS`) · 쓰기 API 인증 · CORS · 가젯 로딩(privileged · `pid: host` · docker.sock) · `deploy.sh` |
| **2** — 설계 + 테스트 | `pipeline` · `resolver`(DNS 캐시) · `ingestion` · `store` · `ws` · API 계약 · `sg-install` |
| **3** — 실행해 보고 확인 | 화면 · 목업 · 스타일 · 설정 |

### 매 세션

1. 계획 승인 → 구현. 계획과 실측이 다르면 멈추고 정정 보고
2. 결함은 원인 실측 후 설계. 수정 전 코드에서 새 테스트 실패를 먼저 보인다
3. 자가 검증: `make test` + 바뀐 화면 회귀 N/N + 콘솔 오류 0. 가젯 동작은 `sg-vm`에서만 실측
4. 화면 질문은 앱을 띄워 열어 준 뒤 한다

### 문서

기획 · 설계 · 진행 현황은 **Claude Docs 「SupplyGuard 개발 문서」**(https://claude.ai/code/artifact/5fc4e674-2b54-4bb2-9cd6-a03cae190285)에 둔다 [2026-10-15]. 결정이 바뀌면 이 문서를 고친다(하위 에이전트 `doc-sync`). `docs/`는 `.gitignore`(옛 로컬 사본, 9/29 기준).

## 미확정 (TBD)

- 발표 · 마감 날짜 → 범위 줄이는 순서(2026-10-15 기준 미정)
- `sg-ec2` 키 파일 경로(배포 단계에서)
- 「설치 검사」 세션 API 모양(목업 확정 때)
- `claude-portable/` gitignore 여부
