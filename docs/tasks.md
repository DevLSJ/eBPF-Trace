# eBPF 기반 이상 트래픽 탐지 및 대응 시스템 — Task 목록

## 2026-09-17 현재 상태

이 섹션이 아래 과거 기록과 초기 Phase 체크리스트보다 우선한다. 상세 근거: [9월 17일 검증](verification-2026-09-17.md).

| 상태 | 범위 | 결과 |
|---|---|---|
| 완료 | 제공 TrafficLabelling 연동 | Thursday/Friday CSV 5개, 543,252개 피처 정답 매칭; 시간 불확실성·빈 행·오류·충돌 기록 |
| 완료 | 실제 ML 실험 | 시간순 평가 161,667행, F1 2.82%·FPR 1.51%; 목표 미달 및 표본 편향으로 운영 미승인 |
| 완료 | 백엔드 | 캡처+레이블 API, 모델 평가/운영 상태 API, 양쪽 IP 검색, 보고서 정합성 검사 |
| 완료 | 프론트엔드 | 분석 전용 화면·타임라인·정답 분포·혼동 행렬·JSON·모바일 메뉴·IP 검색 |
| 완료 | 검증 | 실 PostgreSQL/Redis 포함 Python 49개, 브라우저 12개, TypeScript/Vite/Ruff |
| 완료 | 운영 배포 | `da3f62d` main 푸시·CI/CD 성공, 실제 화면 4개 캡처 및 운영 API 확인 |
| 완료 | README 정리 | 상단 스택 아이콘·기능 소개·데이터 근거·운영 가이드 분리 |
| 후속 | 모델 개선 | 초 단위 정답 정합 확보, 단기 공격 표본 복구, 별도 검증 데이터로 재평가 |
| 후속 | 운영 확장 | HTTPS, Slack 실제 알림, Terraform 기존 자원 정합, VM Collector 코드 갱신은 별도 범위 |

운영은 규칙 기반이며, 이번 실험 모델은 배포하지 않는다. 원본 `label/`, `pcap/`, 생성 피처·모델은 Git/Docker에서 제외한다.

---


> 작성 기준일: 2026-09-09
> 전략: 의존성 기반 순서 / 독립 테스트 가능 / 점진적 통합 / 단계별 체크포인트
> 상태: [ ] 미시작 / [-] 진행 중 / [x] 완료

> **2026-09-15 과거 기록: EC2 정리 및 VM SSH 접속 확인 완료.** 루트 여유는 608 MB에서 약 1.6 GB로 증가했다. Collector 연결·새 트래픽 수신, VM의 Collector/터널/runner 서비스 실행 및 XDP 연결을 확인했다. 재배포와 CIC 데이터 준비는 남아 있다. 아래 기존 체크리스트는 구현·검증 기록과 불일치하므로 완료율로 해석하지 않는다. 현재 진행상황은 [다음 작업 재개 메모](#다음-작업-재개-메모)의 최신 기록을 따른다.

## 2026-09-16 개발 상태

이 표는 9월 16일 기준 기록이다. 현재 상태는 위 9월 17일 섹션을 따른다. 상세 근거는 [9월 16일 검증](verification-2026-09-16.md)에 기록한다.

| 상태 | 범위 | 근거 / 남은 조건 |
|---|---|---|
| 완료 | PCAP 변환 | Thursday/Friday 총 19,319,899 패킷, 5,957,427 피처 행; SHA-256 기록 |
| 완료 | 레이블 결합 CLI | CSV/폴더/ZIP, 시간대 명시, 양방향 5-tuple, 충돌·미매칭 제외; fixture 검증 |
| 완료 | 학습/모델 보호 | 시간 경계 10초 제거, 장기 플로우 제외, 메타데이터·해시·버전 검증 |
| 대기 | 실제 CIC ML 평가 | GeneratedLabelledFlows 정답 CSV 필요. 규칙 판정을 정답으로 대체하지 않음 |
| 완료 | 피처 계산 최적화 | 출발지 윈도우 증분 계산, 기존 계산과 회귀 비교; 금요일 합계 일치 |
| 완료 | Port Scan 요구사항 | 엔트로피가 낮아도 고유 포트 ≥20이면 탐지; F-M03 정합화 |
| 완료 | 홈페이지 | 이벤트 상세, 유형 필터, 페이지 내보내기, PCAP 선택, 관리자 설정, 오프라인 복구 |
| 완료 | 자동 검사 보강 | 실 DB/Redis·브라우저 E2E; EC2 외부 이미지 빌드, 배포 공간 사전 검사 |
| 확인 | VM runner/Collector | 사용자 VM 기동 후 GitHub online/idle, 운영 Collector 연결 true |
| 미완료 | 최종 외부 검증 | 실 레이블 모델 성능, Slack 실제 발송, Terraform import/plan·SG, HTTPS |

VM Collector 코드는 별도 운영 업데이트가 필요하다. EC2 웹/API 배포가 VM 수집기 소스까지 바꾸지는 않는다. 9월 11일 커널/격리망/장애복구 수치를 이번 재측정으로 간주하지 않는다. `v1.0.0`은 아직 발행하지 않는다.

접속 커맨드 (중요)
> Linux Ubuntu Server ifconig : 192.168.64.2
> ssh ubuntu@192.168.64.2
> EC2 Server ip : 52.62.165.10
> ssh -i "don forget.pem" ubuntu@52.62.165.10
---

## Phase 0. 프로젝트 기반 설정 (체크포인트 A)

> 이후 모든 Phase의 전제 조건. 여기서 롤백 시 폴더/설정 초기화.

- [v] 0-1. 프로젝트 디렉토리 구조 생성
  - `ebpf-agent/`, `collector/`, `backend/`, `frontend/`, `infra/`, `ml/`, `docs/`
- [v] 0-2. GitHub 레포지토리 초기화 및 `.gitignore` 설정
  - `.env`, `*.pkl`, `terraform.tfvars`, `__pycache__/` 등 제외
- [v] 0-3. 공통 `.env.example` 파일 작성
  - 전체 환경 변수 키 목록 정의 (값 없이 키만)
- [v] 0-4. Linux VM 개발 환경 구성
  - 커널 버전 확인 (`uname -r` ≥ 5.15)
  - clang, llvm, linux-headers, BCC, bpftrace 설치
  - `sysctl` 커널 파라미터 적용 (BPF JIT, perf_event_paranoid)
- [ ] 0-5. 백엔드 Python 가상환경 구성
  - Python 3.14+, `venv` 생성, `requirements.txt` 초안 작성
- [ ] 0-6. 프론트엔드 Node 환경 구성
  - Node.js 24 LTS, Vite + React + TypeScript 프로젝트 생성
- [ ] 0-7. 개발용 Docker Compose 구성 (`docker-compose.dev.yml`)
  - PostgreSQL 17, Redis 7 로컬 컨테이너 기동 확인

---

## Phase 1. eBPF/XDP 커널 에이전트 (체크포인트 B)

> Phase 0 완료 후 시작. 독립 검증: bpftool, bpftrace로 맵/이벤트 확인.

- [ ] 1-1. XDP 스켈레톤 작성 (`ebpf-agent/xdp_agent.c`)
  - Ethernet → IPv4 → TCP/UDP 헤더 파싱
  - `XDP_PASS` 반환 (패킷 통과만, 기능 없음)
  - `clang -O2 -target bpf` 컴파일 확인
- [ ] 1-2. BPF 맵 정의
  - `BPF_MAP_TYPE_LRU_HASH`: `flow_stats_map` (max 65536)
  - `BPF_MAP_TYPE_RINGBUF`: `events` (4MB)
  - `BPF_MAP_TYPE_ARRAY`: `config_map` (임계값 저장용)
- [ ] 1-3. 플로우 집계 로직 구현
  - `flow_key` 구성 (src_ip, dst_ip, src_port, dst_port, proto)
  - `pkt_cnt`, `byte_cnt` 증가
  - `first_seen_ns`, `last_seen_ns` 타임스탬프 기록
- [ ] 1-4. SYN 패킷 카운트 구현
  - TCP 헤더 파싱 → SYN 플래그 확인 → `syn_cnt` 증가
- [ ] 1-5. Port Scan 추적 구현
  - `dst_ports[16]` 배열에 최근 접근 포트 기록
  - `port_cnt` (고유 포트 수) 관리
- [ ] 1-6. ring_buffer 이벤트 발행 구현
  - 100ms 주기로 `flow_event` 구조체 발행
  - `bpf_ringbuf_reserve` → `bpf_ringbuf_submit` 패턴
- [ ] 1-7. XDP 프로그램 로드 및 동작 검증
  - BCC Python으로 로드 (`ip link set dev eth0 xdp obj ...`)
  - `bpftool map dump` 로 플로우 집계 확인
  - `bpftrace`로 ring_buffer 이벤트 수신 확인
- [ ] 1-8. 에이전트 종료 시 BPF 맵 정리 확인
  - 프로세스 종료 후 `/sys/fs/bpf` 잔여 맵 없음 검증

---

## Phase 2. Collector (데이터 수집 API) (체크포인트 C)

> Phase 1 완료 후 시작. 독립 검증: Redis CLI로 캐시 데이터 확인.

- [ ] 2-1. BCC Python ring_buffer 이벤트 리더 구현
  - `BPF["events"].open_ring_buffer(callback)` 패턴
  - `ring_buffer_poll(timeout=100)` 메인 루프
- [ ] 2-2. 피처 계산 모듈 구현 (`collector/features.py`)
  - `pkt_rate`, `byte_rate`, `syn_ratio`, `flow_duration`, `avg_pkt_size` 계산
  - `port_entropy` 계산 (Shannon entropy)
- [ ] 2-3. Redis 슬라이딩 윈도우 캐시 구현 (`collector/cache.py`)
  - Sorted Set ZADD / ZRANGEBYSCORE / ZREMRANGEBYSCORE 패턴
  - TTL 60초 적용
  - Redis 연결 끊김 시 재연결 로직 (3회, 1초 간격)
- [ ] 2-4. WebSocket 클라이언트 구현 (`collector/ws_client.py`)
  - FastAPI 백엔드로 피처 JSON 전송
  - 연결 끊김 시 지수 백오프 재연결 (최대 5회)
- [ ] 2-5. Collector 메인 프로세스 통합 (`collector/main.py`)
  - ring_buffer 리더 → 피처 계산 → Redis 캐시 → WebSocket 전송 연결
- [ ] 2-6. Collector 독립 테스트
  - Redis 모킹으로 피처 계산 단위 테스트
  - 실제 Redis에 슬라이딩 윈도우 데이터 적재 확인
  - FastAPI 없이 WebSocket 서버 모킹으로 전송 확인

---

## Phase 3. ML 분석 엔진 (체크포인트 D)

> Phase 0 완료 후 독립 진행 가능. Phase 4와 통합 전 독립 검증.

- [ ] 3-1. CIC-IDS-2017 데이터셋 다운로드 및 탐색
  - 정상/공격 트래픽 분포 확인
  - 사용할 피처 6개 컬럼 매핑 확인
- [ ] 3-2. 데이터 전처리 스크립트 작성 (`ml/preprocess.py`)
  - 결측값 제거, 무한대 클리핑
  - 정상 트래픽 필터링
  - StandardScaler 학습 및 `scaler.pkl` 저장
- [ ] 3-3. Isolation Forest 학습 스크립트 작성 (`ml/train_model.py`)
  - `n_estimators=100`, `contamination=0.05`, `random_state=42`
  - 학습 후 `isolation_forest.pkl` 저장
  - `model_version.json` 생성 (학습 일시, 성능 지표)
- [ ] 3-4. 모델 검증 스크립트 작성 (`ml/validate.py`)
  - CIC-IDS-2017 레이블 기준 Precision / Recall / F1 / FPR 계산
  - 목표: F1 ≥ 0.80, FPR ≤ 0.05 통과 여부 출력
- [ ] 3-5. Rule-based 탐지 엔진 구현 (`ml/rule_engine.py`)
  - SYN Flood 탐지 (syn_ratio, pkt_rate 임계값)
  - Port Scan 탐지 (port_entropy, port_cnt 임계값)
  - Traffic Spike, Large Flow 탐지
  - 임계값은 환경 변수에서 읽도록 구현
- [ ] 3-6. 심각도 분류기 구현 (`ml/engine.py`)
  - Rule-based 결과 + anomaly_score 앙상블
  - Critical / High / Medium / Low 분류 반환
- [ ] 3-7. ML 엔진 단위 테스트 (`ml/tests/`)
  - 각 Rule-based 임계값 경계 케이스 테스트
  - 모델 로드 실패 시 Rule-based 폴백 동작 확인
  - anomaly_score 범위 (-1.0 ~ 0.0) 검증

---

## Phase 4. FastAPI 백엔드 (체크포인트 E)

> Phase 3 완료 후 시작. 독립 검증: httpx로 API 응답 확인.

- [ ] 4-1. FastAPI 프로젝트 구조 생성 (`backend/`)
  - 디렉토리: `api/`, `websocket/`, `ml/`, `db/`, `services/`, `core/`
  - `pydantic-settings` 기반 환경 변수 설정 (`core/config.py`)
- [ ] 4-2. DB 모델 및 연결 설정
  - SQLAlchemy 비동기 엔진 설정 (`asyncpg`)
  - `detection_events`, `system_metrics` ORM 모델 정의
  - Alembic 마이그레이션 초기화 및 초기 마이그레이션 생성
- [ ] 4-3. CRUD 함수 구현 (`db/crud.py`)
  - `create_event()`, `get_events()` (페이지네이션), `get_event_by_id()`
  - `create_metric()`, `get_latest_metric()`
- [ ] 4-4. REST API 라우터 구현
  - `GET /api/events` (필터, 페이지네이션)
  - `GET /api/events/{id}`
  - `GET /api/metrics`, `GET /api/metrics/history`
  - `GET/PUT /api/config/thresholds`
  - `GET /health`
- [ ] 4-5. 표준 에러 응답 핸들러 구현
  - 400 / 422 / 404 / 500 JSON 에러 포맷 통일
  - FastAPI `exception_handler` 등록
- [ ] 4-6. WebSocket 연결 관리자 구현 (`websocket/manager.py`)
  - `ConnectionManager` 클래스 (연결 풀, broadcast, dead 연결 정리)
- [ ] 4-7. Collector 수신 WebSocket 핸들러 구현 (`websocket/collector.py`)
  - Collector로부터 피처 JSON 수신
  - ML 엔진 호출 → 이상 탐지 시 DB 저장 + 프론트엔드 broadcast
- [ ] 4-8. ML 엔진 FastAPI 통합
  - `startup` 이벤트에서 모델 로드
  - 모델 파일 없을 시 Rule-based 폴백 경고 로그
- [ ] 4-9. Slack Webhook 알림 서비스 구현 (`services/alert.py`)
  - Critical 이벤트 발생 시 httpx 비동기 POST
  - 실패 시 로그 기록 (재시도 없음)
- [ ] 4-10. psutil 메트릭 수집 태스크 구현 (`services/metrics_collector.py`)
  - 10초 간격 `asyncio` 백그라운드 태스크
  - CPU / 메모리 수집 → DB 저장
- [ ] 4-11. 백엔드 단위 및 통합 테스트 (`backend/tests/`)
  - API 응답 형식 / 페이지네이션 / 에러 케이스 테스트
  - DB 연동 통합 테스트 (테스트용 DB 사용)
  - ML 엔진 모킹으로 탐지 흐름 테스트

---

## Phase 5. 프론트엔드 대시보드 (체크포인트 F)

> Phase 4 완료 후 시작. 독립 검증: Mock 데이터로 UI 컴포넌트 확인.

- [ ] 5-1. TypeScript 타입 정의 (`src/types/index.ts`)
  - `DetectionEvent`, `SystemMetric`, `FlowInfo`, `Severity` 타입
- [ ] 5-2. REST API 클라이언트 구현 (`src/api/client.ts`)
  - axios 기반, 에러 응답 파싱
- [ ] 5-3. WebSocket 훅 구현 (`src/hooks/useWebSocket.ts`)
  - 연결 / 연결 끊김 / 재연결 상태 관리
  - 지수 백오프 재연결 (MAX_RETRY=5)
- [ ] 5-4. Zustand 전역 상태 스토어 구성 (`src/store/eventStore.ts`)
  - 이벤트 목록, 메트릭 최신값, WebSocket 연결 상태 관리
- [ ] 5-5. ConnectionStatus 컴포넌트 구현
  - connected / reconnecting / disconnected 상태 색상 표시
- [ ] 5-6. SeverityBadge 컴포넌트 구현
  - Critical(빨강) / High(주황) / Medium(노랑) / Low(파랑) 배지
- [ ] 5-7. TrafficChart 컴포넌트 구현 (Recharts)
  - 실시간 pps/bps 시계열 차트 (최근 5분)
  - 1초 갱신 주기
- [ ] 5-8. AnomalyScoreChart 컴포넌트 구현 (Recharts)
  - anomaly_score 시계열 차트
  - 임계값(-0.1) 기준선 표시
- [ ] 5-9. EventTable 컴포넌트 구현
  - 탐지 이벤트 목록 테이블
  - 심각도 / 시간 기준 필터링 (`src/hooks/useEventFilter.ts`)
- [ ] 5-10. MetricsPanel 컴포넌트 구현
  - CPU / 메모리 게이지 (psutil 데이터)
- [ ] 5-11. 대시보드 레이아웃 통합 (`src/App.tsx`)
  - 4개 컴포넌트 단일 화면 배치
  - WebSocket 수신 이벤트 → 스토어 업데이트 → 컴포넌트 반영
- [ ] 5-12. 프론트엔드 빌드 확인
  - `npm run build` 오류 없음 확인
  - Mock 데이터로 전체 UI 동작 확인

---

## Phase 6. 인프라 구성 (체크포인트 G)

> Phase 0 완료 후 독립 진행 가능. EC2 배포 전 Terraform으로 환경 먼저 구성.

- [ ] 6-1. Terraform 프로젝트 구조 생성 (`infra/`)
  - `main.tf`, `variables.tf`, `outputs.tf`, `terraform.tfvars.example`
  - `terraform.tfvars` → `.gitignore` 등록 확인
- [ ] 6-2. AWS VPC / 서브넷 / IGW / 라우팅 테이블 정의
- [ ] 6-3. Security Group 정의
  - SSH(22): 관리자 IP만 허용
  - HTTP(80) / HTTPS(443): 전체 허용
  - PostgreSQL(5432) / Redis(6379): 외부 차단
- [ ] 6-4. EC2 인스턴스 정의
  - AMI: Ubuntu 22.04 LTS
  - 인스턴스 타입: `t3.medium`
  - `user_data` 스크립트: Docker / Docker Compose 자동 설치
- [ ] 6-5. `terraform init` / `plan` / `apply` 실행 및 EC2 생성 확인
  - `outputs.tf`에서 EC2 퍼블릭 IP 출력 확인
- [ ] 6-6. EC2 운영용 Docker Compose 작성 (`docker-compose.yml`)
  - nginx, backend, frontend, postgres, redis 서비스 정의
  - `restart: unless-stopped` 전체 적용
  - PostgreSQL / Redis 외부 포트 바인딩 제거
- [ ] 6-7. Nginx 리버스 프록시 설정 (`nginx/nginx.conf`)
  - `/api/*` → FastAPI, `/ws/*` → WebSocket, `/*` → React
- [ ] 6-8. EC2에 Docker Compose 배포 및 전체 서비스 기동 확인
  - `docker compose up -d` 후 `/health` 응답 확인

---

## Phase 7. 통합 연동 및 E2E 검증 (체크포인트 H)

> Phase 1~6 모두 완료 후 시작. 전체 파이프라인 연결 검증.

- [ ] 7-1. Collector ↔ FastAPI WebSocket 연동 확인
  - Linux VM Collector → EC2 FastAPI WebSocket 연결 확인
  - 피처 JSON 수신 로그 확인
- [ ] 7-2. 탐지 이벤트 전체 파이프라인 검증
  - hping3 SYN Flood 발생 → 탐지 이벤트 PostgreSQL 저장 확인
  - nmap Port Scan 발생 → 탐지 이벤트 생성 확인
- [ ] 7-3. 실시간 대시보드 WebSocket 브로드캐스트 확인
  - 탐지 이벤트 발생 → 프론트엔드 즉시 반영 확인 (≤ 1초)
- [ ] 7-4. Slack Webhook 알림 확인
  - Critical 이벤트 발생 → Slack 채널 수신 확인 (≤ 1분)
- [ ] 7-5. 오류 복구 시나리오 검증
  - Redis 컨테이너 강제 종료 → Rule-based 탐지 계속 동작 확인
  - FastAPI 컨테이너 재시작 → 자동 복구 및 Collector 재연결 확인
  - PostgreSQL 컨테이너 재시작 → 데이터 유실 없음 확인
- [ ] 7-6. eBPF 오버헤드 측정
  - psutil로 eBPF 적용 전/후 CPU 사용률 측정
  - 증가분 ≤ 5% 확인 및 결과 기록
- [ ] 7-7. API 성능 테스트
  - 동시 접속 10명 기준 P95 응답 시간 ≤ 200ms 확인

---

## Phase 8. CI/CD 파이프라인 구성 (체크포인트 I)

> Phase 6 완료 후 시작. 자동화 배포 구성.

- [ ] 8-1. GitHub Actions self-hosted runner Linux VM에 설치 및 등록
- [ ] 8-2. GitHub Secrets 등록
  - `DOCKERHUB_USER`, `DOCKERHUB_TOKEN`
  - `EC2_HOST`, `EC2_KEY` (SSH 접속용)
  - `SLACK_WEBHOOK_URL`, `POSTGRES_PASSWORD` 등
- [ ] 8-3. 백엔드 Dockerfile 작성 (`backend/Dockerfile`)
  - 멀티스테이지 빌드, 불필요한 파일 제외
- [ ] 8-4. 프론트엔드 Dockerfile 작성 (`frontend/Dockerfile`)
  - `npm run build` → Nginx static 서빙
- [ ] 8-5. GitHub Actions 워크플로우 작성 (`.github/workflows/deploy.yml`)
  - 단계: 테스트 → Docker 빌드/푸시 → EC2 배포
  - main 브랜치 푸시 시 자동 실행
- [ ] 8-6. Terraform 프로비저닝 워크플로우 작성 (`.github/workflows/infra.yml`)
  - `workflow_dispatch` 수동 트리거
  - `terraform plan` 출력 → `apply`
- [ ] 8-7. CI/CD 파이프라인 동작 확인
  - 코드 푸시 → 테스트 통과 → 이미지 빌드 → EC2 자동 배포 확인

---

## Phase 9. 성능 검증 및 최종 마무리 (체크포인트 J)

> Phase 7~8 완료 후 시작. 졸업작품 제출 전 최종 검증.

- [ ] 9-1. CIC-IDS-2017 기반 모델 성능 최종 측정
  - Precision / Recall / F1-Score / FPR 결과 기록
  - 목표 미달 시 contamination 재조정 후 재학습
- [ ] 9-2. 시연 시나리오 리허설 실행
  - SYN Flood 시나리오 → 탐지 시간 측정 (목표 ≤ 3초)
  - Port Scan 시나리오 → 탐지 시간 측정 (목표 ≤ 5초)
  - 대시보드 시각화 및 Slack 알림 동작 확인
- [ ] 9-3. 보안 점검
  - `.env` Git 미포함 확인
  - EC2 Security Group 규칙 검토
  - PostgreSQL 외부 접근 차단 확인
- [ ] 9-4. 문서 최종 정리
  - `README.md` 작성 (실행 방법, 구조 설명)
  - `docs/` 내 requirements.md / design.md / tasks.md 최신화
- [ ] 9-5. 최종 태그 및 릴리즈
  - `git tag v1.0.0` 및 GitHub Release 생성

---

## 의존성 요약

```
Phase 0 (기반)
  ├── Phase 1 (eBPF 에이전트)
  │     └── Phase 2 (Collector)
  │           └── Phase 7 (통합 E2E)
  ├── Phase 3 (ML 엔진) ────────────┐
  │                                  ├── Phase 4 (백엔드)
  │                                  │     └── Phase 5 (프론트엔드)
  │                                  │           └── Phase 7 (통합 E2E)
  └── Phase 6 (인프라) ─────────────┘
        └── Phase 8 (CI/CD)
              └── Phase 9 (검증 및 마무리)
```

## 병렬 진행 가능 조합

| 병렬 그룹 | 진행 가능 Phase |
|---|---|
| A 그룹 | Phase 1 + Phase 3 + Phase 6 (Phase 0 완료 후 동시 진행 가능) |
| B 그룹 | Phase 4 + Phase 5 (Phase 3 완료 후 일부 병렬 가능) |
| C 그룹 | Phase 7 + Phase 8 (각 선행 Phase 완료 후 병렬 가능) |

---

## 다음 작업 재개 메모

### 2026-09-15 VM 비밀번호 인증 및 서비스 확인

사용자가 제공한 비밀번호로 `ssh ubuntu@192.168.64.2` 대화형 로그인에 성공했다. 이전 `BatchMode=yes` 접속은 비밀번호 입력을 허용하지 않았고 기본 SSH 개인키도 없어 인증 단계에서 실패했다. 현재 관리용 SSH 접속 차단 조건은 해소됐다. 비밀번호는 파일·진행 문서·Git에 저장하지 않았다.

- Ubuntu 22.04.5 LTS, ARM64, 커널 `5.15.0-191-generic`, 인터페이스 `enp0s1`, IPv4 `192.168.64.2` 확인.
- `ebpf-collector.service`: `active/running`, `ExecMainStatus=0`, `NRestarts=0`.
- `ebpf-tunnel.service`: `active/running`, `ExecMainStatus=0`, `NRestarts=0`.
- GitHub Actions runner systemd 서비스: `loaded/active/running`. GitHub 측 online 상태는 별도 조회하지 않았다.
- `ip -details link show dev enp0s1`: 인터페이스 UP, XDP program ID 16 연결 확인.
- 읽기 점검만 수행하고 SSH 세션을 종료했다. 서비스 재시작이나 SSH 설정 변경은 하지 않았다.

남은 작업은 빌드 공간 검토 후 재배포 및 CIC 원본/레이블 준비다. 아래 인증 거부 기록은 이번 비밀번호 로그인 전의 상태로 보존한다.

### 2026-09-15 후속 작업: 디스크 정리 및 VM 기동 후 확인

사용자가 VM을 기동하고 EC2의 불필요한 파일 삭제를 지시하여 해당 정리 작업을 수행했다. 아래 최초 재점검 기록의 Collector 미연결/608 MB 상태는 정리 전의 역사적 결과다.

- **공간:** EC2 루트 여유 **608 MB → 약 1.6 GB**(최종 1,689,878,528 bytes), 사용률 **92% → 77%**.
- **삭제:** 실행 컨테이너가 참조하지 않는 실패한 SHA `1430899db3d9048fb7e216afcb697c3ff0ae4969`의 backend/frontend 이미지 2개, 24시간 이상 미사용 빌드 캐시(Docker 보고 726.1 MB), APT 다운로드/캐시(약 208 MiB), 비활성 Snap revision 3개 및 단독 참조로 남은 오래된 Snap 다운로드 캐시 1개.
- **보존:** 동일 ID의 컨테이너 9개, 사용 중인 이미지 6개, 볼륨 6개, 소스/릴리즈 파일, 비밀 설정, 현재 활성 Snap 버전. 기존 PostgreSQL 16/Redis도 사용 중인 컨테이너이므로 제거하지 않았다.
- **정리 후 상태:** DB/Redis 정상, `rules_only`, `collector_connected=true`. EC2 내부 dashboard WS에서 `traffic` 프레임 수신; 메시지 timestamp와 수신 시각 차이 **150 ms**. 이는 단일 수신 표본이며 SYN 탐지 시간 또는 성능 P95 측정이 아니다.
- **VM SSH:** `192.168.64.2:22`는 응답하지만 `Permission denied (publickey,password)`로 인증 실패. 이 로컬 계정의 기본 SSH 개인키 파일은 없고, VM 내부 systemd/runner 조회는 미실행이다. Collector가 자동으로 연결된 사실과 관리용 SSH 인증 문제를 구분한다.
- **남은 한계:** 재배포·빌드 재시도는 하지 않았다. 확보된 1.6 GB만으로 다음 이미지 빌드 성공을 보장하지 않는다. 정리 후 Docker는 사용하지 않는 이미지/컨테이너/볼륨의 회수 가능 공간을 모두 0으로 보고했다. 추가 용량이 필요하면 EBS 증설 또는 별도 빌드 환경을 검토한다.

**CIC 데이터 배치 안내:** 로컬 Mac의 `/Users/ineb_lsj/Documents/캡스톤/eBPF-project/ml/data/cic-ids2017/`에 원본 `.pcap`과 `GeneratedLabelledFlows.zip`의 레이블 `.csv`를 넣는다. 압축을 풀었다면 폴더째 넣어도 되고 이름·하위 디렉터리를 유지한다. `.zip` 상태로 보관해도 된다. `MachineLearningCSV`만으로는 부족하다. 현재는 원본 보관 위치이며 PCAP 변환·레이블 결합기 구현은 다음 ML 작업이다.

다음 재개 조건: VM 관리용 SSH 인증 수단 확인, 빌드 공간 검토, CIC 원본/레이블 준비. 이번에는 디스크 정리와 상태 확인·문서화만 수행했으며 구현 코드·배포 버전은 변경하지 않았다.

### 2026-09-15 재점검 및 중단 사유

README를 먼저 읽고 `context.md`, 이 문서, `verification-2026-09-11.md`, `requirements.md`, `github-actions-setup.md`, `design.md` 전체를 검토했다. 커널·Collector·ML·백엔드·프론트 상태 관리·배포/Terraform 코드를 대조하고 공식 자료에 근거한 [조사 보고서](research-2026-09-15.md)를 작성했다. HEAD는 `1430899`이며 작업 시작 전부터 존재하던 README/context/tasks/verification 수정은 보존했다.

| 항목 | 이번 확인 결과 | 판단 |
|---|---|---|
| EC2 SSH | `ubuntu@52.62.165.10` 접속 성공 | EC2 접속 자체는 정상 |
| EC2 루트 | 총 6.8 GB, 사용 6.1 GB, 여유 **608 MB**, 사용률 92% | 이전 이미지 unpack 실패 후 용량 부족 미해결; 재빌드 보류 |
| EC2 컨테이너 | 앱 5개, 개발 DB/Redis 2개, 기존 DB/Redis 2개 실행 중 | 현재 서비스 유지 |
| 백엔드 health | DB/Redis `ok`, `rules_only`, `collector_connected=false` | 서비스 응답과 실제 수집 정상 여부를 구분 |
| Ubuntu VM | SSH 22번 접속 시간 초과 | VM 전원·실제 IP·네트워크·SSH 상태 확인 필요; 원인은 미확정 |
| CIC 원본 | 현재 프로젝트의 `ml/data/cic-ids2017/` 안 파일 0개 | 학습/실제 성능 검증 진행 불가 |
| 로컬 모델 | `ml/models/` 없음 | 운영 모델 품질을 검증한 상태가 아님 |
| Python 테스트 | **28 passed, 2 skipped**, 2개 deprecation warning | 실 PostgreSQL/Redis는 이번에 검증하지 않음 |
| Ruff / 프론트 빌드 | 모두 통과; Node 24.21.0 | Vite의 500 kB 초과 청크 경고 있음 |

VM 접속은 최초 샌드박스 제한을 제거한 승인 실행에서도 시간 초과됐다. 로컬 WebSocket 테스트의 최초 포트 바인딩 실패는 승인 후 재실행으로 해소됐다. 두 오류를 애플리케이션 결함으로 기록하지 않는다. 이번에는 서버 쓰기·재시작·공간 정리·배포·Slack 전송·AWS 변경을 수행하지 않았다. 사용자 지시의 중단 조건에 따라 다음 구현은 보류한다.

### 재개에 필요한 보충 사항

1. **VM 접근 복구:** Ubuntu VM 전원 및 현재 IP를 확인하고 Mac에서 `ssh ubuntu@192.168.64.2`가 되는 상태를 확보한다. IP가 변경됐다면 실제 주소를 반영한다. 아직 VM 내부 서비스 상태는 알 수 없다.
2. **EC2 용량 확보 방안:** 실제 EBS·파티션·파일시스템을 조회하고 증설 또는 빌드 위치 분리를 결정한다. 현재 Terraform의 20 GB 설정은 신규 자원 정의이며 기존 루트 디스크가 증설됐다는 뜻이 아니다. 운영 DB 볼륨을 지우는 정리 방식은 사용하지 않는다.
3. **실데이터 제공:** 현재 프로젝트 `ml/data/cic-ids2017/`에 공식 PCAP과 `GeneratedLabelledFlows.zip`을 준비한다. 이전 README의 `/Users/ineb_lsj/Documents/eBPF-project/` 경로는 현재 존재하지 않는다. 데이터가 없어도 인프라 복구는 재개할 수 있으나 ML 학습/검증은 보류한다.
4. **Terraform 조건:** 9월 11일 기록상 EC2 조회 권한, OIDC 역할, S3 state bucket 미완료다. 이번에는 AWS 권한을 재조회하지 않았으므로 현재도 권한이 없다고 단정하지 않는다. 재개 시 조회 권한 및 실제 자원 값을 다시 확인한다.

### 다음 task 실행 순서 및 완료 기준

| 순서 | 관련 task | 재개할 작업 | 완료 근거 |
|---|---|---|---|
| 1 | 7-1, 8-1 | VM 접속 후 Collector·터널·runner 상태 확인 및 복구 | 두 systemd 서비스 active, runner 상태 확인, EC2 `collector_connected=true`, 신규 피처 수신 |
| 2 | 6-8, 8-7 | 용량 확보 후 CI/CD 배포 복구 | 테스트/이미지 push/대상 SHA 배포 성공 및 health 확인; 기존 DB 보존 |
| 3 | 4-9, 7-4 | 알림 보완 및 운영 검증 준비 | 현재 코드의 안전한 로그 처리 배포; 실제 채널 전송 검증은 명시적인 전송 지시를 받은 범위에서 수행 |
| 4 | 3-1~3-4, 9-1 | PCAP 변환·레이블 결합 → 전처리 → 학습 → 검증 | 실시간 피처 일치, 분리된 검증셋, F1 ≥ 0.80/FPR ≤ 0.05, 검증 통과 모델만 로드 |
| 5 | 6-5, 8-6, 9-3 | 기존 AWS 자원과 Terraform 정합성 확보 | 조회 결과, import 계획, 무교체 plan, SG 실측, OIDC/state 설정 확인 |
| 6 | 7-2~7-7, 9-2~9-5 | 통합 재검증·문서 정합화·최종 릴리즈 | 격리망 시연, 실제 DB/Redis, 사용자 경로 P95, 알림/모델 완료 근거 |

### 코드 검토에서 발견한 미완료 항목

- **모델 검증 상태 강제:** `ml.validate`는 `validated`를 기록하지만 `ml.engine.DetectionEngine`은 해당 메타데이터를 읽지 않는다. 검증 실패 모델도 파일만 있으면 로드를 시도한다. 모델 배포 전에 통과 여부·피처 순서·라이브러리 버전·모델/스케일러 일치 검증이 필요하다.
- **Redis 장애 알림:** `collector/cache.py`는 3회 실패 후 로그와 `False`만 반환하며 F-D04의 관리자 알림은 구현되지 않았다.
- **Port Scan 조건:** F-M03은 10초 내 20개 목적지 포트 접근을 요구하지만 규칙은 엔트로피 ≥ 3.5도 요구한다. 편중된 트래픽에서는 20개 포트여도 통과하지 않을 수 있어 요구사항과 코드의 기준을 정합화해야 한다.
- **CIC 변환·분리:** 현재 전처리기는 이미 계산된 6개 피처 CSV만 받는다. PCAP/레이블 결합, 같은 출발지·시간 윈도우가 학습/검증 양쪽에 섞이지 않는 분리 정책이 필요하다.
- **CI 검증 범위:** CI의 `pytest -q`에는 실 DB/Redis 테스트 환경 변수 설정이 없어 해당 2개 테스트가 기본 skip된다. 과거의 실서비스 통합 검증을 매 push마다 수행하는 구성은 아니다.
- **경로 이전:** `.venv/bin/pytest`의 shebang은 이전 프로젝트 절대 경로다. 이번 검사는 `.venv/bin/python -m pytest` 및 `-m ruff`로 실행했다. 다음 개발 재개 시 현재 경로에서 가상환경을 재생성한다.
- **문서 정합성:** 기존 체크리스트와 설계/Actions 예제에는 초기 Python/Node/PostgreSQL 버전, VM Docker 빌드, x64 runner 등이 남아 있다. 이번에는 재개 메모와 README의 현황·주소·데이터 경로를 우선 바로잡았으며 전체 문서 재작성은 보류했다.

### 2026-09-17 · 정답 정합과 시나리오 워크스페이스

- [x] 패킷 개수·방향·지속시간 기반 CSV 시각 복원 및 불확실·충돌 보존.
- [x] 전체 특징 행 정답 매칭률 9.12% → 82.12%, 동일 평가 구간의 6개/9개 피처 비교.
- [x] 시나리오 실행/중지, DB 샘플·이벤트 원자적 저장, WS 전달, 운영 트래픽과 분리.
- [x] DB 탐지 이벤트 페이지·집계 그래프·출처/실행/검토 필터·판정 메모.
- [x] 실제 PostgreSQL·Redis 포함 Python 56개, 데스크톱·모바일 E2E 14개 검증.
- [ ] 9개 피처 실험의 F1 62.92%는 목표 미달. 모든 공격 유형의 독립 평가와 모델 운영 승인은 후속 과제.

근거와 시연 순서는 [고도화 검증](verification-2026-09-17-upgrade.md), [시나리오 가이드](scenarios.md)에 기록합니다. 기존 일자의 중단 기록은 당시 상태이며 이번 사용자 지시에 따라 개발·배포를 재개했습니다.

배포: `d0648a5` main 푸시 및 Actions 테스트/빌드/EC2 배포 성공. 운영 리허설 1건의 15샘플·9이벤트·WebSocket·DB 검토를 확인했습니다. 운영 서버 화면과 README 캡처는 해당 모의 기록의 출처를 표시합니다.
