# eBPF 기반 이상 트래픽 탐지 및 대응 시스템 — Task 목록

> 작성 기준일: 2026-09-09
> 전략: 의존성 기반 순서 / 독립 테스트 가능 / 점진적 통합 / 단계별 체크포인트
> 상태: [ ] 미시작 / [-] 구현·검증 진행 또는 외부 조건 대기 / [v] 완료
> 최근 검증: 2026-09-11. 실측 결과·대기 조건은 `verification-2026-09-11.md` 참고.
> Docker 실행 위치: EC2. 로컬 Mac과 VM에는 Docker 데몬을 요구하지 않음.

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
- [v] 0-5. 백엔드 Python 가상환경 구성
  - Python 3.14+, `venv` 생성, `requirements.txt` 초안 작성
- [v] 0-6. 프론트엔드 Node 환경 구성
  - Node.js 24 LTS, Vite + React + TypeScript 프로젝트 생성
- [v] 0-7. 개발용 Docker Compose 구성 (`docker-compose.dev.yml`)
  - EC2 루프백에 PostgreSQL 17, Redis 7 개발용 컨테이너 기동 확인

---

## Phase 1. eBPF/XDP 커널 에이전트 (체크포인트 B)

> Phase 0 완료 후 시작. 독립 검증: bpftool, bpftrace로 맵/이벤트 확인.

- [v] 1-1. XDP 스켈레톤 작성 (`ebpf-agent/xdp_agent.c`)
  - Ethernet → IPv4 → TCP/UDP 헤더 파싱
  - `XDP_PASS` 반환 (패킷 통과만, 기능 없음)
  - `clang -O2 -target bpf` 컴파일 확인
- [v] 1-2. BPF 맵 정의
  - `BPF_MAP_TYPE_LRU_HASH`: `flow_stats_map` (max 65536)
  - `BPF_MAP_TYPE_RINGBUF`: `events` (4MB)
  - `BPF_MAP_TYPE_ARRAY`: `config_map` (임계값 저장용)
- [v] 1-3. 플로우 집계 로직 구현
  - `flow_key` 구성 (src_ip, dst_ip, src_port, dst_port, proto)
  - `pkt_cnt`, `byte_cnt` 증가
  - `first_seen_ns`, `last_seen_ns` 타임스탬프 기록
- [v] 1-4. SYN 패킷 카운트 구현
  - TCP 헤더 파싱 → SYN 플래그 확인 → `syn_cnt` 증가
- [v] 1-5. Port Scan 추적 구현
  - 커널 `dst_ports[16]`은 5-tuple 목적지 포트 보관용
  - Collector에서 출발지 IP별 10초 분포와 `port_cnt` 관리 (20개 이상 포트 탐지 확인)
- [v] 1-6. ring_buffer 이벤트 발행 구현
  - 100ms 주기로 `flow_event` 구조체 발행
  - `bpf_ringbuf_reserve` → `bpf_ringbuf_submit` 패턴
- [v] 1-7. XDP 프로그램 로드 및 동작 검증
  - BCC Python으로 로드 (`ip link set dev eth0 xdp obj ...`)
  - `bpftool map dump` 로 플로우 집계 확인
  - BCC ring_buffer 리더로 이벤트 수신 확인; bpftrace는 커널 함수 디버깅 보조
- [v] 1-8. 에이전트 종료 시 BPF 맵 정리 확인
  - 프로세스 종료 후 `/sys/fs/bpf` 잔여 맵 없음 검증
  - SIGKILL 후 이전 프로그램·맵 해제, systemd의 새 프로그램 재연결 확인

---

## Phase 2. Collector (데이터 수집 API) (체크포인트 C)

> Phase 1 완료 후 시작. 독립 검증: Redis CLI로 캐시 데이터 확인.

- [v] 2-1. BCC Python ring_buffer 이벤트 리더 구현
  - `BPF["events"].open_ring_buffer(callback)` 패턴
  - `ring_buffer_poll(timeout=100)` 메인 루프
- [v] 2-2. 피처 계산 모듈 구현 (`collector/features.py`)
  - `pkt_rate`, `byte_rate`, `syn_ratio`, `flow_duration`, `avg_pkt_size` 계산
  - `port_entropy` 계산 (Shannon entropy)
- [v] 2-3. Redis 슬라이딩 윈도우 캐시 구현 (`collector/cache.py`)
  - Sorted Set ZADD / ZRANGEBYSCORE / ZREMRANGEBYSCORE 패턴
  - TTL 60초 적용
  - Redis 연결 끊김 시 재연결 로직 (3회, 1초 간격)
- [v] 2-4. WebSocket 클라이언트 구현 (`collector/ws_client.py`)
  - FastAPI 백엔드로 피처 JSON 전송
  - 연결 끊김 시 지수 백오프 재연결 (최대 5회)
- [v] 2-5. Collector 메인 프로세스 통합 (`collector/main.py`)
  - ring_buffer 리더 → 피처 계산 → Redis 캐시 → WebSocket 전송 연결
- [v] 2-6. Collector 독립 테스트
  - Redis 모킹으로 피처 계산 단위 테스트
  - 실제 Redis에 슬라이딩 윈도우 데이터 적재 확인
  - FastAPI 없이 WebSocket 서버 모킹으로 전송 확인

---

## Phase 3. ML 분석 엔진 (체크포인트 D)

> Phase 0 완료 후 독립 진행 가능. Phase 4와 통합 전 독립 검증.

- [-] 3-1. CIC-IDS-2017 데이터셋 다운로드 및 탐색
  - 업로드 대기: 로컬 `ml/data/cic-ids2017/` (PCAP + `GeneratedLabelledFlows.zip`)
  - 정상/공격 트래픽 분포 확인
  - 사용할 피처 6개 컬럼 매핑 확인
- [-] 3-2. 데이터 전처리 스크립트 작성 (`ml/preprocess.py`)
  - 결측값 제거, 무한대 클리핑
  - 정상 트래픽 필터링
  - StandardScaler 학습 및 `scaler.pkl` 저장
- [-] 3-3. Isolation Forest 학습 스크립트 작성 (`ml/train_model.py`)
  - `n_estimators=100`, `contamination=0.05`, `random_state=42`
  - 학습 후 `isolation_forest.pkl` 저장
  - `model_version.json` 생성 (학습 일시, 성능 지표)
- [-] 3-4. 모델 검증 스크립트 작성 (`ml/validate.py`)
  - 호환 피처/레이블 입력의 Precision / Recall / F1 / FPR 계산 구현; 실제 CIC 데이터 확보 대기
  - 목표: F1 ≥ 0.80, FPR ≤ 0.05 통과 여부 출력
- [v] 3-5. Rule-based 탐지 엔진 구현 (`ml/rule_engine.py`)
  - SYN Flood 탐지 (syn_ratio, pkt_rate 임계값)
  - Port Scan 탐지 (port_entropy, port_cnt 임계값)
  - Traffic Spike, Large Flow 탐지
  - 임계값은 환경 변수에서 읽도록 구현
- [v] 3-6. 심각도 분류기 구현 (`ml/engine.py`)
  - Rule-based 결과 + anomaly_score 앙상블
  - Critical / High / Medium / Low 분류 반환
- [v] 3-7. ML 엔진 단위 테스트 (`ml/tests/`)
  - 각 Rule-based 임계값 경계 케이스 테스트
  - 모델 로드 실패 시 Rule-based 폴백 동작 확인
  - anomaly_score 범위 (-1.0 ~ 0.0) 검증

---

## Phase 4. FastAPI 백엔드 (체크포인트 E)

> Phase 3 완료 후 시작. 독립 검증: httpx로 API 응답 확인.

- [v] 4-1. FastAPI 프로젝트 구조 생성 (`backend/`)
  - 디렉토리: `api/`, `websocket/`, `ml/`, `db/`, `services/`, `core/`
  - `pydantic-settings` 기반 환경 변수 설정 (`core/config.py`)
- [v] 4-2. DB 모델 및 연결 설정
  - SQLAlchemy 비동기 엔진 설정 (`asyncpg`)
  - `detection_events`, `system_metrics` ORM 모델 정의
  - Alembic 마이그레이션 초기화 및 초기 마이그레이션 생성
- [v] 4-3. CRUD 함수 구현 (`db/crud.py`)
  - `create_event()`, `get_events()` (페이지네이션), `get_event_by_id()`
  - `create_metric()`, `get_latest_metric()`
- [v] 4-4. REST API 라우터 구현
  - `GET /api/events` (필터, 페이지네이션)
  - `GET /api/events/{id}`
  - `GET /api/metrics`, `GET /api/metrics/history`
  - `GET/PUT /api/config/thresholds`
  - `GET /health`
- [v] 4-5. 표준 에러 응답 핸들러 구현
  - 400 / 422 / 404 / 500 JSON 에러 포맷 통일
  - FastAPI `exception_handler` 등록
- [v] 4-6. WebSocket 연결 관리자 구현 (`websocket/manager.py`)
  - `ConnectionManager` 클래스 (연결 풀, broadcast, dead 연결 정리)
- [v] 4-7. Collector 수신 WebSocket 핸들러 구현 (`websocket/collector.py`)
  - Collector로부터 피처 JSON 수신
  - ML 엔진 호출 → 이상 탐지 시 DB 저장 + 프론트엔드 broadcast
- [v] 4-8. ML 엔진 FastAPI 통합
  - `startup` 이벤트에서 모델 로드
  - 모델 파일 없을 시 Rule-based 폴백 경고 로그
- [v] 4-9. Slack Webhook 알림 서비스 구현 (`services/alert.py`)
  - Critical 이벤트 발생 시 httpx 비동기 POST
  - 실패 시 로그 기록 (재시도 없음)
- [v] 4-10. psutil 메트릭 수집 태스크 구현 (`services/metrics_collector.py`)
  - 10초 간격 `asyncio` 백그라운드 태스크
  - CPU / 메모리 수집 → DB 저장
- [v] 4-11. 백엔드 단위 및 통합 테스트 (`backend/tests/`)
  - API 응답 형식 / 페이지네이션 / 에러 케이스 테스트
  - DB 연동 통합 테스트 (테스트용 DB 사용)
  - ML 엔진 모킹으로 탐지 흐름 테스트

---

## Phase 5. 프론트엔드 대시보드 (체크포인트 F)

> Phase 4 완료 후 시작. 독립 검증: Mock 데이터로 UI 컴포넌트 확인.

- [v] 5-1. TypeScript 타입 정의 (`src/types/index.ts`)
  - `DetectionEvent`, `SystemMetric`, `FlowInfo`, `Severity` 타입
- [v] 5-2. REST API 클라이언트 구현 (`src/api/client.ts`)
  - axios 기반, 에러 응답 파싱
- [v] 5-3. WebSocket 훅 구현 (`src/hooks/useWebSocket.ts`)
  - 연결 / 연결 끊김 / 재연결 상태 관리
  - 지수 백오프 재연결 (MAX_RETRY=5)
- [v] 5-4. Zustand 전역 상태 스토어 구성 (`src/store/eventStore.ts`)
  - 이벤트 목록, 메트릭 최신값, WebSocket 연결 상태 관리
- [v] 5-5. ConnectionStatus 컴포넌트 구현
  - connected / reconnecting / disconnected 상태 색상 표시
- [v] 5-6. SeverityBadge 컴포넌트 구현
  - Critical(빨강) / High(주황) / Medium(노랑) / Low(파랑) 배지
- [v] 5-7. TrafficChart 컴포넌트 구현 (Recharts)
  - 실시간 pps/bps 시계열 차트 (최근 5분)
  - 1초 갱신 주기
- [v] 5-8. AnomalyScoreChart 컴포넌트 구현 (Recharts)
  - anomaly_score 시계열 차트
  - 임계값(-0.1) 기준선 표시
- [v] 5-9. EventTable 컴포넌트 구현
  - 탐지 이벤트 목록 테이블
  - 심각도 / 시간 기준 필터링 (`src/hooks/useEventFilter.ts`)
- [v] 5-10. MetricsPanel 컴포넌트 구현
  - CPU / 메모리 게이지 (psutil 데이터)
- [v] 5-11. 대시보드 레이아웃 통합 (`src/App.tsx`)
  - 4개 컴포넌트 단일 화면 배치
  - WebSocket 수신 이벤트 → 스토어 업데이트 → 컴포넌트 반영
- [v] 5-12. 프론트엔드 빌드 확인
  - `npm run build` 오류 없음 확인
  - Mock 데이터로 전체 UI 동작 확인

---

## Phase 6. 인프라 구성 (체크포인트 G)

> Phase 0 완료 후 독립 진행 가능. EC2 배포 전 Terraform으로 환경 먼저 구성.

- [v] 6-1. Terraform 프로젝트 구조 생성 (`infra/`)
  - `main.tf`, `variables.tf`, `outputs.tf`, `terraform.tfvars.example`
  - `terraform.tfvars` → `.gitignore` 등록 확인
- [v] 6-2. AWS VPC / 서브넷 / IGW / 라우팅 테이블 정의
- [v] 6-3. Security Group 정의
  - SSH(22): 관리자 IP만 허용
  - HTTP(80) / HTTPS(443): 전체 허용
  - PostgreSQL(5432) / Redis(6379): 외부 차단
- [v] 6-4. EC2 인스턴스 정의
  - AMI: Ubuntu 22.04 LTS
  - 인스턴스 타입: `t3.medium`
  - `user_data` 스크립트: Docker / Docker Compose 자동 설치
- [-] 6-5. `terraform init` / `plan` / `apply` 실행 및 EC2 생성 확인
  - `outputs.tf`에서 EC2 퍼블릭 IP 출력 확인
  - AWS lsj04 인증 성공. `ec2:DescribeInstances` 권한 부재로 기존 자원 조회/import 대기
- [v] 6-6. EC2 운영용 Docker Compose 작성 (`docker-compose.yml`)
  - nginx, backend, frontend, postgres, redis 서비스 정의
  - `restart: unless-stopped` 전체 적용
  - PostgreSQL / Redis 외부 포트 바인딩 제거
- [v] 6-7. Nginx 리버스 프록시 설정 (`nginx/nginx.conf`)
  - `/api/*` → FastAPI, `/ws/*` → WebSocket, `/*` → React
- [v] 6-8. EC2에 Docker Compose 배포 및 전체 서비스 기동 확인
  - `docker compose up -d` 후 `/health` 응답 확인

---

## Phase 7. 통합 연동 및 E2E 검증 (체크포인트 H)

> Phase 1~6 모두 완료 후 시작. 전체 파이프라인 연결 검증.

- [v] 7-1. Collector ↔ FastAPI WebSocket 연동 확인
  - Linux VM Collector → EC2 FastAPI WebSocket 연결 확인
  - 피처 JSON 수신 로그 확인
- [v] 7-2. 탐지 이벤트 전체 파이프라인 검증
  - hping3 SYN Flood 발생 → 탐지 이벤트 PostgreSQL 저장 확인
  - nmap Port Scan 발생 → 탐지 이벤트 생성 확인
- [v] 7-3. 실시간 대시보드 WebSocket 브로드캐스트 확인
  - 탐지 이벤트 발생 → 프론트엔드 즉시 반영 확인 (≤ 1초)
- [-] 7-4. Slack Webhook 알림 확인
  - Critical 이벤트 발생 → Slack 채널 수신 확인 (≤ 1분)
- [v] 7-5. 오류 복구 시나리오 검증
  - Redis 컨테이너 강제 종료 → Rule-based 탐지 계속 동작 확인
  - FastAPI 컨테이너 재시작 → 자동 복구 및 Collector 재연결 확인
  - PostgreSQL 컨테이너 재시작 → 데이터 유실 없음 확인
- [v] 7-6. eBPF 오버헤드 측정
  - psutil로 eBPF 적용 전/후 CPU 사용률 측정
  - 증가분 ≤ 5% 확인 및 결과 기록
  - VM 격리 veth, 약 10,000 pps, 교차 순서 3쌍 측정: 0.59% → 0.62% (**+0.03%p**)
  - XDP·ring 리더 범위이며 전체 ML/백엔드 부하와 구분
- [-] 7-7. API 성능 테스트
  - 동시 접속 10명 기준 P95 응답 시간 ≤ 200ms 확인

---

## Phase 8. CI/CD 파이프라인 구성 (체크포인트 I)

> Phase 6 완료 후 시작. 자동화 배포 구성.

- [v] 8-1. GitHub Actions self-hosted runner Linux VM에 설치 및 등록
- [-] 8-2. GitHub Secrets 등록
  - `DOCKERHUB` (또는 `DOCKERHUB_USERNAME`), `DOCKERHUB_TOKEN`
  - `EC2_HOST`, `EC2_USER`, `EC2_SSH_KEY`, `EC2_KNOWN_HOSTS` 확인/등록
  - DB/Collector/Admin 비밀값은 EC2 `.env`에 생성. Slack Webhook 저장, 새 버전 활성화 검증 중
- [v] 8-3. 백엔드 Dockerfile 작성 (`backend/Dockerfile`)
  - 멀티스테이지 빌드, 불필요한 파일 제외
- [v] 8-4. 프론트엔드 Dockerfile 작성 (`frontend/Dockerfile`)
  - `npm run build` → Nginx static 서빙
- [v] 8-5. GitHub Actions 워크플로우 작성 (`.github/workflows/ci-cd.yml`)
  - 단계: 테스트 → Docker 빌드/푸시 → EC2 배포
  - main 브랜치 푸시 시 자동 실행
- [v] 8-6. Terraform 프로비저닝 워크플로우 작성 (`.github/workflows/infra.yml`)
  - `workflow_dispatch` 수동 트리거
  - S3 원격 state + 저장된 `terraform plan` → 선택적 `apply`; AWS OIDC와 state bucket 설정 대기
- [-] 8-7. CI/CD 파이프라인 동작 확인
  - 코드 푸시 → 테스트 통과 → 이미지 빌드 → EC2 자동 배포 확인

---

## Phase 9. 성능 검증 및 최종 마무리 (체크포인트 J)

> Phase 7~8 완료 후 시작. 졸업작품 제출 전 최종 검증.

- [-] 9-1. CIC-IDS-2017 기반 모델 성능 최종 측정
  - Precision / Recall / F1-Score / FPR 결과 기록
  - 목표 미달 시 contamination 재조정 후 재학습
- [-] 9-2. 시연 시나리오 리허설 실행
  - SYN Flood 시나리오 → 탐지 시간 측정 (목표 ≤ 3초)
  - Port Scan 시나리오 → 탐지 시간 측정 (목표 ≤ 5초)
  - 대시보드 시각화 및 Slack 알림 동작 확인
- [-] 9-3. 보안 점검
  - `.env` Git 미포함 확인
  - EC2 Security Group 규칙 검토
  - PostgreSQL 외부 접근 차단 확인
- [-] 9-4. 문서 최종 정리
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

## 서버 접속 및 운영 위치

```bash
ssh ubuntu@192.168.64.2
ssh -i "don forget.pem" ubuntu@52.62.165.10
```

- VM: `/home/ubuntu/ebpf-project`, `ebpf-tunnel.service`, `ebpf-collector.service`
- EC2: `/home/ubuntu/ebpf-project`, Compose 프로젝트 `ebpf-trace-app`
- 기존 EC2 `/home/ubuntu/ebpf-trace` 및 PostgreSQL 16 볼륨은 보존
- 대시보드: http://52.62.165.10
- 실제 모델 데이터는 로컬 `ml/data/cic-ids2017/` 업로드 대기. EC2 원본 데이터 업로드는 디스크 부족으로 권장하지 않음.
- AWS 계정 인증 성공, EC2 조회 권한 및 Terraform OIDC/state 설정 대기. Slack 실제 전송 검증 진행. 원격 API P95 목표는 추가 개선 필요.
