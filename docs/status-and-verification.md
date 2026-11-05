# eBPF Trace — 진행 상황 · 검증 기록 · 남은 작업

> 이 문서는 기존 `tasks.md` · `verification-2026-09-11/16/17/17-context/17-upgrade.md` ·
> `research-2026-09-15.md` · `response-design-2026-09-17.md`의 핵심을 통합한 요약본이다.
> 기준: 웹/API 배포 커밋 `bde12ed`, 사건 대응·차단 게이트 구현은 미배포.

## 1. 현재 상태 요약

| 상태 | 범위 | 결과 |
|---|---|---|
| 완료 | 5일 PCAP·정답 결합 | 52.43 GB, 15,226,375개 피처 구간 중 12,250,475개(80.46%) 매칭 |
| 완료 | 문맥 피처·성능 최적화 | 25개 공유 피처, 증분 집계·해시 재개·학습 표본 상한 |
| 완료 | 모델 비교 | HGB 25개 시험 F1 90.98%, FPR 0.26% (단, 시험 공격 4/14종) |
| 완료 | 백엔드·DB·프론트 | v2 완전성 검증, 5일 매칭 현황·모델 선택·유형별 재현율·보고서 다운로드 |
| 완료 | 시나리오·검토 | 실행 ID로 DB 그래프/이벤트 연결, 모의/실시간 분리, 관리자 정탐·오탐 검토 |
| 완료 | 웹/API 배포 | main `bde12ed`; CI 테스트·이미지 빌드·EC2 배포 성공, 운영 화면 10개 캡처 |
| 구현·미배포 | 사건 대응·차단 게이트 | risk_gate·autoresponse·개인계정·2인승인·nftables 에이전트·목업 3종 (커밋/배포 안 함) |
| 구현·미커밋 | 초보자 친화 UX (Part A) | 용어 쉬운말·상태 신호등·온보딩·메뉴 그룹화·시나리오/이벤트 요약·사건 대응 초보자화·반응형 마감 (2026-09-27, e2e 30/30, 표시 레이어만) |
| 구현·미커밋 | UI 리뉴얼 (앱 셸·알림·안내) | 고정 셸(본문만 스크롤)·사용 흐름 레일·사용 안내·알림 센터 드로어·토스트·사이드바 접기/모바일 서랍·스켈레톤·화면 전환 (2026-09-28, 2-B절) |
| 구현·미커밋 | 실시간 검사 + 글자 넘침 정리 | 내 와이파이·랜선 트래픽을 수집 → 1차 규칙 → 2차 AI → 대응에 통과시키는 `#live` 화면과 방어선 점검(API `/api/live/*`), 정적 목업 `/live` 동일 구현, 본문 글자가 상자를 벗어나는 결함 자동 검출·수정 (2026-09-28, 2-C절) |
| 대기 | VM Collector v2 갱신 | 기존 스키마 1 유지. runner sudo start/stop 권한 설정 후 배포 job 재실행 필요 |
| 후속 | 모델 운영 승인 | 시험 누락 10종·Bot 강화, 신규 공격 실행·독립 환경 검증 |
| 후속 | 운영 확장 | HTTPS, 알림 실제 전달, Terraform 기존 자원 정합 |

운영은 규칙 기반이며 실험 모델은 배포하지 않는다. 원본 `label/`·`pcap/`·생성 피처·모델은 Git/Docker 제외.

## 2. 게이트 검증 결과 (2026-09-23 Phase 1)

- **ruff 통과 · pytest 113 통과(5 skip) · Vite 빌드 통과 · Playwright E2E 20/20 통과 · 목업 36/36 화면 렌더 확인.**
- 백엔드: `risk_gate.py`(4신호+강제정지3종), `autoresponse.py`(자동 경로 7단계), 신규 API 3종, 마이그레이션 `b7d3e9f1a2c4`.
- 프론트: 홈을 `Workspace.tsx`로 전환(기본 `#overview`), 게이트 UI(점수 바·근거·자동 판단 배너), 자동 경로 스위치·자산 옵트인.
- 목업 3종(`mock/`): v1-trace(자체 스타일) · v2a-legacy · v2b-jira. 공용 화면·데이터, 테마만 교체. TEST-NET 주소만.
- 테스트 10개 추가: 게이트 단위 6 + 통합 4.

## 2-A. 초보자 친화 UX 개선 — Part A (2026-09-27, 미커밋)

네트워크를 모르는 처음 사용자도 화면만으로 상황을 이해하도록 프론트엔드를 개선했다.
**표시 레이어만 변경**했고 내부 값·API·enum·option value·버튼 문구·2인 승인 로직은 불변이다.
검증: 매 단계 `npm run build` + 브라우저 Playwright e2e 통과. e2e는 초기 20개 → **최종 30개**(desktop 15 + mobile 15), 기존 기대치 변경은 1줄(오류 메시지 한글화)뿐이고 나머지는 추가.

| 단계 | 내용 | 핵심 산출물 |
|---|---|---|
| 0 | 용어 인벤토리 | 어려운 용어·영어 코드·빈 값 처리 목록화, 검증 베이스라인 |
| 1 | 용어 쉬운 말로 | `src/labels.ts`(57개 용어 사전), `Term.tsx`. 심각도→긴급/높음/보통/낮음, SYN_FLOOD→연결 폭주(SYN Flood) 등. 툴팁 병기 |
| 2 | 상태 신호등 | `StatusBanner.tsx` 정상/주의/문제 3색+아이콘+원인+행동 버튼. 빈 값 `—` 구분. 백엔드 영문 오류 4종 프론트 한글 매핑(`translateError`) |
| 3 | 온보딩·메뉴 그룹화 | `OnboardingCard.tsx`(1회 노출·localStorage 기억). 메뉴를 모니터링/위협 대응/실습·분석/설정으로 그룹화(접기 가능). breadcrumb·eyebrow 한글화 |
| 4 | 흐름을 이야기처럼 | 시나리오 진행 표시줄(progressbar)·단계별 설명·실측 결과 요약. 이벤트 상세 동적 한 문장 요약 + raw features `<details>` 접기(DOM 유지로 e2e 무회귀) |
| 5 | 사건 대응 초보자화 | 상태별 "다음 할 일" 안내, 게이트 근거 쉬운 문장(신호 4개 = 백엔드 `risk_gate.py` WEIGHTS 키와 일치), TTL/CIDR/nftables 툴팁, 결과 피드백 15종. **로직·버튼·API 무변경, operations.spec.ts 무수정 통과** |
| 6 | 반응형·접근성 마감 | 한글 고정폭 폰트 fallback(`--font-mono`), WCAG AA 대비 미달 27곳→0곳, 전역 `:focus-visible`, 백엔드 문자열 표시 매핑(`humanizeCodes`, 이중 병기 스킵), 태블릿 18조합 overflow 0 |

원칙: 영어 코드(SYN_FLOOD, CRITICAL, P1, lab, rules_only 등)가 사용자 텍스트로 노출되는 곳 0건(grep 근거). 백엔드가 만든 문자열은 표시 시점 매핑만 하고 원문 불변.
남은 것(Part B, 원격 인프라): VM Collector v2 → EC2 배포 → 알림 검증 → ML 검증 → Terraform → HTTPS → 릴리즈. 아래 5절과 동일.

## 2-B. UI 리뉴얼 — 앱 셸·알림·안내 (2026-09-28, 미커밋)

Part A의 용어·신호등·온보딩 위에, **처음 사용자가 화면만 보고 흐름을 따라갈 수 있도록** 프론트엔드 셸을 다시 짰다.
참고한 것은 `~/Documents/Loguard/mockup`의 **기능 트릭**(페이지 고정·본문만 스크롤·휠 관성·토스트·사이드바 접기·배지)뿐이고, 디자인 토큰은 eBPF Trace 자체 스타일(남색 사이드바·파란 강조·청록 포인트·둥근 카드)을 유지했다.
내부 값·API·enum·2인 승인 로직은 불변이며, 기존 e2e 셀렉터·문구는 그대로 통과한다.

| 영역 | 내용 | 파일 |
|---|---|---|
| 고정 셸 | `html/body overflow:hidden`, 사이드바·상단바는 제자리, **본문(main)만 안쪽 스크롤**(스크롤바 숨김·휠 관성, 안쪽 스크롤 영역·모달 우선, 움직임 줄이기 존중). 표는 패널 안에서만 스크롤(sticky 헤더) | `styles.css`, `hooks/useSmoothScroll.ts` |
| 사용 흐름 레일 | 상단바 가운데 **관찰 › 체험 › 검토 › 대응 › 분석** 5단계. 현재 화면이 강조되고 누르면 이동 | `Workspace.tsx`, `GuideDialog.tsx`(GUIDE_STEPS) |
| 사용 안내 | 물음표 버튼 또는 `?` 키로 여는 5단계 안내 대화상자(각 단계에서 화면으로 바로 이동) | `components/GuideDialog.tsx` |
| 알림 센터 | 상단 종 아이콘 + 읽지 않은 수 배지(새 알림 시 튀는 애니메이션) → 오른쪽 드로어. 새 탐지 이벤트(실제/모의 구분)·실시간 연결·수집기·서버 상태 변화가 쌓임. 전체/탐지/시스템 필터, 모두 읽음, 기록 열기(이벤트 상세) | `store/notifyStore.ts`, `hooks/useNotifications.ts`, `components/NotificationDrawer.tsx` |
| 토스트 | 오른쪽 아래, 자동 소멸, 행동 버튼 1개. 긴급·높음 **실제** 탐지(3초 병합), 연결 끊김/복구, 수집기 연결/해제, 시나리오 실행 종료에만 사용(모의 이벤트는 드로어에만) | `components/ToastHost.tsx`, `ScenarioPanel.tsx` |
| 사이드바 | 접기/펼치기(브라우저 기억 `ebpf.sidebar.collapsed`, 아이콘만+툴팁), '탐지 이벤트' 메뉴에 읽지 않은 탐지 배지, 활성 항목 청록 바. 모바일(≤768px)은 메뉴 버튼으로 여는 서랍 + 배경 | `styles.css`, `Workspace.tsx` |
| 대시보드 | 상태 신호등을 제목 바로 아래로, 탐지 건수 카운트업, 카드 hover 상승, LIVE 점 맥동, 불러오는 중 스켈레톤, 화면 전환 페이드 | `Workspace.tsx`, `EventTable.tsx`, `ui.css` |
| 사건 대응 | 상단 탭을 알약형으로, 진행 단계 스테퍼(도달 단계 파란 원·진행 중 링 맥동), '다음 할 일' 카드 강조, 행동 결과 피드백을 **화면 위 가운데 스낵바**로(8초 뒤 자동 소멸, 닫기 버튼) | `ui.css`, `OperationsWorkspace.tsx`(자동 소멸 타이머 1줄) |
| 가독성 | 사용자 문구 최소 11px(기존 8~10px 다수), 버튼 높이 ≥34px, 포커스 링 전역 통일, `prefers-reduced-motion`에서 모든 애니메이션 해제 | `styles.css`, `features.css`, `ui.css` |

검증: `npm run build` 통과 · Playwright e2e **32/32 통과 (desktop 16 + mobile 16, 2.9분)** (기존 30개 + 신규 1개×2 프로젝트: 고정 뷰포트·알림 센터·안내 대화상자·사이드바 접기/모바일 서랍·연결 끊김/복구 토스트).
정적 목업 `mock/`(3버전)도 같은 구조로 갱신했다: 상단바(경로·사용 흐름 레일·연결 상태·알림 종·안내)·알림 센터 드로어·스낵바·안내 대화상자·사이드바 여정 그룹/접기/모바일 서랍·스켈레톤·화면 전환을 공용 엔진(`shared/app.js`)에 넣고, 화면을 14개(대시보드·탐지 이벤트·시스템 상태·대응 관제·사건·대응·알림·시나리오·데이터 분석·설정·자산·모델)로 늘렸다. v1 테마는 React `styles.css` 토큰과 동일. Playwright로 3버전 × 14화면 + 상호작용(드로어·데모 알림·안내·이벤트 상세·스낵바·접기·모바일 서랍) 렌더 42/42, 콘솔 오류 0, 모바일 가로 넘침 0 확인.
로컬 환경 참고: 복사된 `node_modules`·`.venv`의 네이티브 바이너리에 macOS 격리 속성이 붙어 `npm run build`가 실패하던 상태였다(`xattr -dr com.apple.quarantine`, 실행 비트·`.bin` 심볼릭 링크 복구로 해결. 저장소 파일 변경 아님).

## 2-C. 실시간 검사 · 방어선 점검 · 글자 넘침 정리 (2026-09-28, 미커밋)

**목표**: 대시보드를 내 컴퓨터의 와이파이·랜선에 직접 붙여 실제 트래픽이 1차 방어선(규칙) → 2차 방어선(AI) → 대응까지 실제로 통과하는지 확인할 수 있게 하고, 같은 화면을 정적 목업에도 넣는다. 동시에 목업·프론트에서 글자가 상자 밖으로 튀어나오는 결함을 찾아 없앤다.

| 영역 | 내용 | 파일 |
|---|---|---|
| 백엔드 | `LiveInspector`: 호스트 인터페이스 목록(종류·주소·활성), 검사 실행(5~300초, 동시 1개), 매초 관측을 수집기와 **같은 `process_flow` 경로**(규칙 → 모델 → 사건 묶기 → 자동 경로)에 투입, 단계별 집계(수집·규칙·모델·대응), 대시보드 WebSocket 방송(`capture` 표식). 패킷 검사는 scapy + 수집기 `FeatureCalculator` 재사용(25개 항목·양방향 문맥), 카운터 검사는 psutil(권한 불필요, 출발지 `0.0.0.0`) | `backend/services/live_inspection.py`, `backend/api/live.py`(`/api/live/*`, 관리자 토큰), `backend/core/schemas.py`(`InspectionRequest`), `backend/main.py` |
| DB 영속 · 명세 | 검사 행 `live_inspections`(임계값·엔진 스냅샷, 단계 집계 `totals`, 이벤트·사건 id)와 매초 관측 창 `live_inspection_windows`를 **실행 중에 기록**(마이그레이션 `f3a1c8d2e6b4`, PostgreSQL은 JSONB). 기동 시 `running` 잔여 행은 `interrupted`로, 창 행은 `ops_retention.py` 보존 기간 뒤 정리. 웹앱의 `검사 기록` 선택은 DB에서 읽는다. API·테이블·로컬 도커 절차 명세 작성 | `backend/db/models.py`, `backend/db/migrations/versions/f3a1c8d2e6b4_live_inspections.py`, `infra/ops_retention.py`, `docs/api-live-inspection.md` |
| 방어선 점검 | `POST /api/live/check`: 저장된 임계값에서 표본 5개를 만들어 규칙 엔진 판정, 같은 표본으로 모델 점수, 두 출발지 표본으로 차단 안전 점검(자동/승인 경로) — 저장 없음. 모델 없음·Redis 없음은 이유와 함께 `skipped` | 같은 파일 |
| React | `#live` "내 네트워크 검사": 처음 안내 4단계 카드 → 토큰 → 인터페이스 카드(와이파이/유선/가상/루프백) → 방식·시간 → 4단계 파이프라인 카드(진행 중 맥동·정상·건너뜀·실패) + 진행률 + 요약 문장 + 그래프 + 탐지표(이벤트 상세·사건 링크) → 방어선 점검 판정표. 모니터링 그룹 메뉴·안내 문구 반영 | `frontend/src/components/LiveInspectionPanel.tsx`, `live.css`, `Workspace.tsx`, `api/client.ts`, `types/index.ts`, `GuideDialog.tsx` |
| 목업 | `/live` 화면 3버전 동일(15초 카운터 검사 시뮬레이션: 7~9초 급증 → 탐지 3건·사건 1건 → 탐지 기록·알림 센터·토스트 연결, 방어선 점검 판정표) | `mock/shared/screens.js`, `data.js`, `trace.css`, `mock/README.md` |
| 글자 넘침 | Playwright 스캐너(`text-spill.cjs`, 세션 스크래치패드)가 모든 텍스트 노드의 실제 그리기 영역을 가장 가까운 상자(테두리·배경·셀·클리핑)와 비교해 **spill(상자 밖)·clipped(잘림)·viewport(화면 밖)·잘못된 문자열(undefined·NaN)** 을 표시 | — |

글자 넘침 검사 결과(React 4폭 1440·1024·768·390 × 13화면 + 상세·드로어·안내·실시간 검사 / 목업 3버전 × 3폭 × 15화면 + 상호작용):

| 대상 | 발견 | 조치 |
|---|---|---|
| React (기존 화면) | 0건 | — |
| React `#live` 390px | 패널 머리글·점검표 2건 잘림 | 머리글 줄바꿈·표 상자 안 스크롤 → 0건 |
| 목업 사건 받은편지함 390px | 헤더 액션이 제목을 한 글자씩 세로로 밀어냄 | `.page-header` 줄바꿈 |
| 목업 데이터 분석 390px | KPI 큰 숫자(12,000,000)가 카드 밖으로 | 좁은 화면 KPI 20px·줄바꿈 허용 |
| 목업 시스템/사건 390px | KPI 부제가 `…`으로 잘림 | 2줄까지 표시 |
| 목업 안내·이벤트 상세 모달 390px | 모달이 화면보다 넓어 버튼이 밖으로 | 모달 폭을 뷰포트 안으로(그리드 트랙 `minmax(0,1fr)`) |
| 목업 (재검사) | 0건 | — |

검증: `ruff` 통과 · Python SQLite **119 passed / 5 skipped**, **Docker PostgreSQL(`TEST_DATABASE_URL`) 123 passed / 1 skipped**(신규 7개: 인터페이스 목록·권한, 카운터 검사 → 규칙 → 사건 → WebSocket, 동시 실행 409·중지, 패킷 누적 → 25개 항목 → SYN Flood, 방어선 점검, DB 기록·재시작 복구, 마이그레이션 왕복) · `vite build` 통과 · Playwright e2e **34/34 (desktop 17 + mobile 17)**(신규: 토큰 → 루프백 인터페이스 → 5초 카운터 검사 → 4단계 채움 → 방어선 점검 판정표 → 대시보드 그래프 반영 → 새로고침 후 DB 기록 재조회).
**로컬 실기동 확인(2026-09-28)**: Docker Desktop의 `docker-compose.dev.yml`(PostgreSQL 17 · Redis 7) + `alembic upgrade head` + 백엔드 8000 + Vite 5173. Wi-Fi(en0)·유선 LAN(en5)에서 10초 카운터 검사를 각각 실행해 `live_inspections` 2행·`live_inspection_windows` 20행이 저장되고(`en5` 300패킷·최고 73pps), 웹앱 `검사 기록`에서 같은 값을 다시 읽는 것을 확인했다.
**한계**: 이 Mac에는 scapy가 없고 `/dev/bpf*`가 root 전용이라 패킷 검사는 실제 인터페이스로 끝까지 돌려보지 못했다(누적기 → 관측 항목 → 규칙 경로만 단위 테스트). 실제 확인은 `pip install scapy` 후 sudo 실행 또는 ChmodBPF 설치가 필요하다. 2차 AI는 검증된 모델과 Redis가 있을 때만 실시간 경로에 적용되며(운영과 동일), 로컬 SQLite 환경에서는 "건너뜀"과 그 이유가 표시된다.

## 2-D. 대시보드 한 화면 고정 · 시연 페이지 스크롤 (2026-09-28, 미커밋)

사용자 지적 두 가지를 고쳤다.

| 문제 | 원인 | 조치 |
|---|---|---|
| 공급망 안내 시연(`#supply`) 페이지가 아래로 내려가지 않음 | 2-B의 고정 셸(`html/body overflow:hidden`) 도입 후, 셸 밖에서 렌더링되는 시연 화면에는 스크롤 컨테이너가 없었다 | `.trust-app`을 `height:100dvh; overflow-y:auto`의 자체 스크롤 컨테이너로. 상단 고정 헤더·"기능 둘러보기" 앵커 이동 그대로 동작 |
| 첫 화면(대시보드)이 스크롤로 내려감 | 대시보드 본문이 한 화면보다 길어 `main`이 스크롤됐다 | 데스크톱(≥1024×900)에서는 `main.fixed-view`가 스크롤되지 않고, 제목·상태 배너·온보딩·지표·그래프를 압축해 제자리에 두며 **탐지 이벤트 표만 패널 안에서 스크롤**(고정 머리글). 그래프 3열(트래픽·AI 점수·시스템), 시나리오 배너는 숨김. 낮은 창·태블릿·모바일은 기존 본문 스크롤로 되돌아감 |

정적 목업 3버전도 같은 규칙(`.page[data-view="overview"]` + 표 `fill`)을 적용했다.

| 화면 | React 본문 넘침 / 표 높이 | 목업 v1 본문 넘침 / 표 높이 |
|---|---|---|
| 1440×1000 (온보딩 표시) | 0 / 166px | 0 / 149px |
| 1470×956 MacBook Air | 0 / 129px | 0 / 101px |
| 1280×800 (임계 미만) | 본문 스크롤로 복귀 | 본문 스크롤로 복귀 |

검증: e2e 셸 테스트를 "데스크톱 대시보드는 본문이 스크롤되지 않고 표만 스크롤, 긴 화면(탐지 이벤트)은 본문 스크롤"로 바꾸고, 시연 페이지 스크롤 테스트 1개를 추가했다.

## 3. CIC-IDS2017 검증 (2026-09-17 Context v2)

정답 매칭률:

| 요일 | 피처 구간 | 매칭 | 매칭률 |
|---|---:|---:|---:|
| 월 | 2,898,867 | 2,345,037 | 80.89% |
| 화 | 2,675,578 | 2,166,408 | 80.97% |
| 수 | 3,694,503 | 2,847,052 | 77.06% |
| 목 | 2,599,785 | 2,170,602 | 83.49% |
| 금 | 3,357,642 | 2,721,376 | 81.05% |

모델 비교 (동일 분리 기준):

| 모델 | 보정 F1 | 시험 F1 | 시험 FPR |
|---|---:|---:|---:|
| IF 6개 | 30.42% | 0.00% | 2.99% |
| IF 9개 | 60.47% | 0.00% | 4.19% |
| IF 25개 | 61.93% | 0.00% | 4.06% |
| IF 25개 / 표본 확대 | 64.64% | 0.00% | 3.95% |
| **HGB 25개 (보정 기준 선택)** | **96.28%** | **90.98%** | **0.26%** |

- **시험 F1 90.98%는 4개 공격 유형(FTP/SSH-Patator·Web Brute Force·Bot)에 한정**된 개발 실험 결과.
- 시험에 없는 유형: DDoS, PortScan, DoS 4종, Heartbleed, Infiltration, Web SQLi/XSS (10종).
- Bot 재현율 51.45%로 절반가량 미탐. 혼동 행렬: TP 5,007 / FN 70 / FP 923 / TN 354,657.
- 신규 공격 실행·별도 환경 검증 필요. **운영은 규칙 기반 유지.**

## 4. 코드 검증 이력

- 실 PostgreSQL·Redis 포함 로컬 테스트 통과. GitHub CI: Python 69개, 브라우저 16개, Ruff·TypeScript·Vite·eBPF 컴파일 통과 (게이트 구현 후 Python 118개·브라우저 20개로 확대).
- 배포: `bde12ed`를 main 푸시, CI 테스트·이미지 빌드·EC2 웹/API 배포 성공. EC2 `/home/ubuntu/ebpf-current`가 이 릴리즈를 가리킴.
- 두 번째 배포 시도는 새 이미지 설치 후 남은 디스크 787 MiB < 최소 900 MiB로 사전 검사 중단. 오래된 `2eae69b` 이미지 정리로 ~1.2 GiB 확보. 운영 데이터 미삭제.

## 5. 남은 작업 (SRS 기준)

| 상태 | 항목 | 이유 |
|---|---|---|
| ⬜ | F-M12 무재학습 적응 | Could 등급, 재학습 없이 2주 후 FPR 유지 검증 필요 |
| 🔶 | NF-P08 전체 파이프라인 처리량, NF-S01 capability 축소, NF-M02 Terraform import | Linux VM·EC2에서 실측 필요 |
| ❌ | NF-P03 원격 P95 (관측 798ms) | 한국↔호주 물리 거리 |
| 대기 | VM Collector v2 갱신 | runner sudo start/stop 권한 설정 대기 |
| 후속 | 독립 ML 검증·LIVE Shadow 7일 | 시험 누락 10종·Bot 포함 신규 실행 필요 |
| 후속 | HTTPS·프록시, 실제 Slack/SMTP 전달, 서비스 probe 배포 | 운영 활성화 전제 조건 |

Phase 2(자체 캡처 벤치마크)·LIVE Shadow 시작·부스 시연 버튼은 미완 — 단독 진행 불가.

## 6. 인프라·접속 재개 조건

- **VM 접근**: `ssh ubuntu@192.168.64.2` 비밀번호 로그인 성공 확인(2026-09-15). 커널 `5.15.0-191-generic`, XDP program 연결 확인. runner·Collector·터널 systemd active.
- **EC2**: `ubuntu@203.0.113.10` 키 접속 정상, runner online. 루트 여유 정리로 608 MB → ~1.6 GB 확보.
- **Terraform**: `ec2:DescribeInstances` 권한 없음. OIDC 역할·S3 state bucket 미완. 20 GB 설정은 신규 자원 정의(기존 루트 증설 아님).
- **CIC 데이터**: 로컬 Mac `ml/data/cic-ids2017/`에 원본 `.pcap`과 `GeneratedLabelledFlows.zip` 레이블 CSV 준비. `MachineLearningCSV`만으로는 부족.

## 7. 코드 검토 발견 항목 (정합화 필요)

- **모델 검증 상태 강제**: `ml.validate`는 `validated` 기록하나 `DetectionEngine`이 메타데이터를 읽지 않아 검증 실패 모델도 로드 시도 가능.
- **Redis 장애 알림**: `collector/cache.py`가 3회 실패 후 로그만, F-D04 관리자 알림 미구현.
- **CI 검증 범위**: 기본 `pytest -q`에 실 DB/Redis 환경 변수 없어 해당 테스트 skip.
