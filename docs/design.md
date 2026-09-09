# eBPF 기반 이상 트래픽 탐지 및 대응 시스템 — 아키텍처 설계 문서

> 작성 기준일: 2026-09-09  
> 참조 문서: requirements.md, context.md  
> 버전: v1.0

---

## 목차

1. [시스템 개요](#1-시스템-개요)
2. [아키텍처 다이어그램](#2-아키텍처-다이어그램)
3. [구성 요소 상세 설계](#3-구성-요소-상세-설계)
   - 3-1. eBPF/XDP 커널 수집 에이전트
   - 3-2. 데이터 수집 API (Collector)
   - 3-3. ML 분석 엔진
   - 3-4. 백엔드 (FastAPI)
   - 3-5. 프론트엔드 (React 대시보드)
   - 3-6. 인프라 (Terraform + Docker Compose)
4. [데이터 흐름 설계](#4-데이터-흐름-설계)
5. [DB 스키마 설계](#5-db-스키마-설계)
6. [API 명세](#6-api-명세)
7. [ML 모델 설계](#7-ml-모델-설계)
8. [오류 처리 및 복구 설계](#8-오류-처리-및-복구-설계)
9. [환경 설정 및 매개변수](#9-환경-설정-및-매개변수)
10. [개발 환경 구성](#10-개발-환경-구성)
11. [테스트 전략](#11-테스트-전략)
12. [성능 최적화](#12-성능-최적화)
13. [보안 설계](#13-보안-설계)
14. [CI/CD 파이프라인](#14-cicd-파이프라인)
15. [향후 확장 설계](#15-향후-확장-설계)

---

## 1. 시스템 개요

### 1-1. 목적

eBPF/XDP를 활용하여 커널 수준에서 패킷을 수집하고, ML 기반 이상 탐지와 Rule-based 즉각 탐지를
결합하여 네트워크 이상 트래픽을 실시간으로 탐지·분류·시각화·알림하는 시스템이다.

### 1-2. 설계 원칙

- **최소 오버헤드**: eBPF 커널 내 1차 집계로 사용자 공간 복사 최소화
- **역할 분리**: 수집(VM) / 분석·서빙(EC2) 물리적 분리
- **재현 가능성**: Terraform IaC + Docker Compose로 환경 코드화
- **단일 진실 원천**: 모든 이상 탐지 이벤트는 PostgreSQL에 단일 저장
- **장애 격리**: 각 컴포넌트 독립 재시작, Redis 장애 시 Rule-based 탐지 유지

### 1-3. 배포 토폴로지

```
[로컬 Linux VM]                    [AWS EC2 (Ubuntu 22.04)]
─────────────────                  ──────────────────────────────────
 eBPF/XDP 에이전트  ──WebSocket──▶  FastAPI 백엔드
 Collector (Python)                 PostgreSQL
 self-hosted runner                 Redis
                                    React 대시보드
                                    Nginx (리버스 프록시)
```

---

## 2. 아키텍처 다이어그램

### 2-1. 전체 시스템 아키텍처

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        로컬 Linux VM (eBPF 에이전트)                     │
│                                                                         │
│  NIC (eth0)                                                             │
│    │                                                                    │
│    ▼  XDP Hook (native 모드)                                            │
│  ┌────────────────────────────────┐                                     │
│  │   eBPF/XDP 프로그램 (C)        │  ← 커널 공간                        │
│  │   BPF_HASH: flow_stats         │                                     │
│  │   key: {src_ip, dst_ip,        │                                     │
│  │         src_port, dst_port,    │                                     │
│  │         proto}                 │                                     │
│  │   val: {pkt_cnt, byte_cnt,     │                                     │
│  │         syn_cnt, timestamp}    │                                     │
│  └────────────┬───────────────────┘                                     │
│               │ ring_buffer poll                                        │
│               ▼                                                         │
│  ┌────────────────────────────────┐                                     │
│  │   Collector (Python + BCC)     │  ← 사용자 공간                      │
│  │   - ring_buffer 이벤트 읽기    │                                     │
│  │   - 슬라이딩 윈도우 피처 계산  │                                     │
│  │   - Redis 캐싱                 │                                     │
│  └────────────┬───────────────────┘                                     │
│               │ WebSocket (ws://)                                       │
└───────────────┼─────────────────────────────────────────────────────────┘
                │
                ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                     AWS EC2 (Docker Compose 환경)                        │
│                                                                         │
│  ┌──────────────────────────────────────────────────────────────────┐   │
│  │  Nginx (포트 80/443)                                              │   │
│  │  - /api/*   → FastAPI (8000)                                     │   │
│  │  - /ws/*    → FastAPI WebSocket                                  │   │
│  │  - /*       → React 대시보드 (3000)                              │   │
│  └───────────┬──────────────────────────────────────────────────────┘   │
│              │                                                          │
│  ┌───────────▼──────────────┐    ┌──────────────────────────────────┐   │
│  │   FastAPI 백엔드 (8000)  │    │   React 대시보드 (3000)           │   │
│  │   - REST API             │    │   - Recharts 시계열 차트          │   │
│  │   - WebSocket 서버       │    │   - 실시간 이벤트 테이블          │   │
│  │   - ML 분석 엔진 통합    │    │   - 시스템 메트릭 패널            │   │
│  │   - Slack Webhook 알림   │    │   - WebSocket 클라이언트          │   │
│  │   - psutil 메트릭 수집   │    └──────────────────────────────────┘   │
│  └───────┬──────────┬───────┘                                          │
│          │          │                                                   │
│  ┌───────▼──┐  ┌────▼─────┐                                            │
│  │PostgreSQL│  │  Redis   │                                            │
│  │  (5432)  │  │  (6379)  │                                            │
│  │ 이벤트   │  │ 피처     │                                            │
│  │ 영속화   │  │ 캐시     │                                            │
│  └──────────┘  └──────────┘                                            │
└─────────────────────────────────────────────────────────────────────────┘
                                        │
                                        ▼
                              ┌─────────────────┐
                              │  Slack Webhook  │
                              │  (외부 알림)    │
                              └─────────────────┘
```

### 2-2. 탐지 파이프라인 흐름

```
패킷 수신
   │
   ▼
[XDP Hook] ── BPF_HASH 업데이트 ──▶ [ring_buffer 이벤트 발행]
                                            │
                                            ▼
                                    [Collector: 피처 계산]
                                    - pkt_rate (pps)
                                    - byte_rate (bps)
                                    - syn_ratio
                                    - port_entropy
                                    - flow_duration
                                            │
                              ┌─────────────┴─────────────┐
                              ▼                           ▼
                    [Rule-based 엔진]           [Isolation Forest]
                    SYN Flood 즉각 탐지         비지도 이상 점수
                    Port Scan 즉각 탐지         anomaly_score
                              │                           │
                              └─────────────┬─────────────┘
                                            ▼
                                    [심각도 분류기]
                                    Critical / High / Medium / Low
                                            │
                              ┌─────────────┴──────────────┐
                              ▼                            ▼
                      [PostgreSQL 저장]           [WebSocket 브로드캐스트]
                              │                            │
                              ▼                            ▼
                    [Slack 알림 (Critical)]      [React 대시보드 실시간 반영]
```

### 2-3. CI/CD 파이프라인

```
[개발자 로컬]
     │ git push (main)
     ▼
[GitHub]
     │ webhook
     ▼
[GitHub Actions (self-hosted runner on Linux VM)]
     │
     ├── 1. 코드 체크아웃
     ├── 2. Python 단위 테스트 (pytest)
     ├── 3. Docker 이미지 빌드
     ├── 4. Docker Hub 푸시
     └── 5. EC2 배포 (SSH + docker compose pull && up -d)
```

---

## 3. 구성 요소 상세 설계

### 3-1. eBPF/XDP 커널 수집 에이전트

#### 역할
NIC 레벨에서 XDP Hook으로 패킷을 인터셉트하여 커널 내에서 플로우별 1차 집계 후 ring_buffer로 이벤트 발행

#### 핵심 자료구조 (C)

```c
// 플로우 키 (BPF_HASH 맵 키)
struct flow_key {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8  protocol;   // IPPROTO_TCP=6, IPPROTO_UDP=17
    __u8  pad[3];     // 4바이트 정렬 패딩
};

// 플로우 통계 (BPF_HASH 맵 값)
struct flow_stats {
    __u64 pkt_cnt;        // 총 패킷 수
    __u64 byte_cnt;       // 총 바이트 수
    __u64 syn_cnt;        // SYN 패킷 수 (TCP only)
    __u64 first_seen_ns;  // 최초 관찰 타임스탬프 (nanosec)
    __u64 last_seen_ns;   // 최근 관찰 타임스탬프 (nanosec)
    __u16 dst_ports[16];  // 최근 접근 dst_port 목록 (Port Scan 탐지용)
    __u8  port_cnt;       // 고유 dst_port 수
};

// ring_buffer 이벤트 (사용자 공간 전달)
struct flow_event {
    struct flow_key  key;
    struct flow_stats stats;
    __u64 export_ts_ns;   // 이벤트 발행 시각
};
```

#### BPF 맵 설계

| 맵 이름 | 타입 | 키 | 값 | max_entries | 용도 |
|---|---|---|---|---|---|
| `flow_stats_map` | BPF_MAP_TYPE_HASH | flow_key | flow_stats | 65536 | 플로우별 통계 |
| `events` | BPF_MAP_TYPE_RINGBUF | - | flow_event | 4MB | 사용자 공간 이벤트 전달 |
| `config_map` | BPF_MAP_TYPE_ARRAY | __u32 index | __u64 value | 8 | 런타임 임계값 설정 |

#### XDP 프로그램 로직

```
xdp_packet_handler():
  1. Ethernet 헤더 파싱 → IPv4 확인
  2. IP 헤더 파싱 → TCP/UDP 확인
  3. flow_key 구성
  4. flow_stats_map에서 기존 통계 조회 (없으면 초기화)
  5. pkt_cnt++, byte_cnt += pkt_len
  6. TCP이면 SYN 플래그 확인 → syn_cnt++
  7. Port Scan 탐지: dst_port 배열 업데이트
  8. 100ms 마다 ring_buffer에 이벤트 발행
  9. XDP_PASS 반환 (패킷 정상 통과)
```

#### 실행 요구사항

```
- 커널 버전: 5.15 이상
- 필요 capability: CAP_BPF, CAP_NET_ADMIN
- 컴파일: clang -O2 -target bpf -c xdp_agent.c -o xdp_agent.o
- 로드: BCC Python 또는 libbpf
- 인터페이스: 환경 변수 IFACE로 지정 (기본값: eth0)
```

---

### 3-2. 데이터 수집 API (Collector)

#### 역할
ring_buffer 이벤트를 읽어 슬라이딩 윈도우 피처를 계산하고 Redis에 캐싱한 후 FastAPI로 WebSocket 스트리밍

#### 피처 계산 명세

| 피처명 | 계산식 | 단위 | 설명 |
|---|---|---|---|
| `pkt_rate` | pkt_cnt / window_sec | pps | 슬라이딩 윈도우 내 초당 패킷 수 |
| `byte_rate` | byte_cnt / window_sec | bps | 슬라이딩 윈도우 내 초당 바이트 수 |
| `syn_ratio` | syn_cnt / pkt_cnt | 0.0~1.0 | SYN 패킷 비율 (SYN Flood 지표) |
| `port_entropy` | -Σ p(port) * log2(p(port)) | bits | 목적지 포트 엔트로피 (Port Scan 지표) |
| `flow_duration` | last_seen_ns - first_seen_ns | ms | 플로우 지속 시간 |
| `avg_pkt_size` | byte_cnt / pkt_cnt | bytes | 평균 패킷 크기 |

#### 슬라이딩 윈도우 설계

```
window_size = 60초
slide_step  = 1초

Redis Key 패턴: flow:{src_ip}:{dst_ip}:{proto}
Redis 자료구조: Sorted Set (score = timestamp_ms)
TTL: 60초 (EXPIRE 자동 갱신)

윈도우 계산:
  1. ZRANGEBYSCORE key (now - 60000) now → 최근 60초 이벤트 조회
  2. 피처 계산
  3. ZADD key timestamp event_json
  4. ZREMRANGEBYSCORE key -inf (now - 60000) → 만료 데이터 정리
```

#### Collector 프로세스 구조

```python
# 메인 루프 (pseudo-code)
class Collector:
    def __init__(self):
        self.bpf = BPF(src_file="xdp_agent.c")
        self.redis = Redis(host=REDIS_HOST, port=6379, decode_responses=True)
        self.ws_client = WebSocketClient(BACKEND_WS_URL)

    def run(self):
        self.bpf["events"].open_ring_buffer(self.handle_event)
        while True:
            self.bpf.ring_buffer_poll(timeout=100)  # 100ms polling

    def handle_event(self, cpu, data, size):
        event = parse_flow_event(data)
        features = self.compute_features(event)   # 슬라이딩 윈도우 피처
        self.redis_cache(event.key, features)      # Redis 캐싱
        self.ws_client.send(features)              # 백엔드로 전송
```

---

### 3-3. ML 분석 엔진

#### 설계 원칙
Rule-based가 즉각성을 담당하고, Isolation Forest가 미지의 이상 패턴을 탐지한다.
두 결과를 앙상블하여 최종 심각도를 결정한다.

#### Rule-based 탐지 명세

| 탐지 유형 | 조건 | 기본 임계값 | 심각도 |
|---|---|---|---|
| SYN Flood | `syn_ratio > SYN_RATIO_THRESHOLD` AND `pkt_rate > SYN_PPS_THRESHOLD` | syn_ratio > 0.8, pkt_rate > 1000 pps | Critical |
| Port Scan | `port_entropy > PORT_ENTROPY_THRESHOLD` AND `port_cnt > PORT_CNT_THRESHOLD` | entropy > 3.5 bits, port_cnt > 20 (10초 내) | High |
| Traffic Spike | `pkt_rate > SPIKE_THRESHOLD` | 정상 기준 10배 초과 | Medium |
| Large Flow | `byte_rate > LARGE_FLOW_THRESHOLD` | > 100 Mbps | Medium |

#### Isolation Forest 모델 명세

```
알고리즘: sklearn.ensemble.IsolationForest

입력 피처 벡터 (6차원):
  [pkt_rate, byte_rate, syn_ratio, port_entropy, flow_duration, avg_pkt_size]

학습 데이터:
  - CIC-IDS-2017 데이터셋 (정상 트래픽 부분)
  - 전처리: StandardScaler 정규화

주요 하이퍼파라미터:
  n_estimators     = 100     # 트리 수 (성능-속도 균형)
  max_samples      = 'auto'  # min(256, n_samples)
  contamination    = 0.05    # 예상 이상 비율 5% (FPR 목표에 연동)
  max_features     = 1.0     # 전체 피처 사용
  random_state     = 42      # 재현성 보장

출력:
  anomaly_score: -1.0 ~ 0.0 (낮을수록 이상)
  is_anomaly: True / False (threshold: -0.1)
```

#### 심각도 분류 로직

```python
def classify_severity(rule_result, anomaly_score):
    """
    Rule-based 결과와 Isolation Forest 점수를 앙상블
    """
    if rule_result == "SYN_FLOOD":
        return Severity.CRITICAL

    if rule_result == "PORT_SCAN":
        if anomaly_score < -0.5:
            return Severity.CRITICAL
        return Severity.HIGH

    if anomaly_score < -0.5:
        return Severity.HIGH
    elif anomaly_score < -0.3:
        return Severity.MEDIUM
    elif anomaly_score < -0.1:
        return Severity.LOW
    else:
        return None  # 정상 트래픽

# 심각도 등급 정의
class Severity(Enum):
    CRITICAL = "critical"  # 즉각 대응 필요, Slack 알림
    HIGH     = "high"      # 대시보드 경고
    MEDIUM   = "medium"    # 대시보드 표시
    LOW      = "low"       # 로그 기록만
```

#### 모델 저장 및 로드

```
모델 파일:  models/isolation_forest.pkl
스케일러:   models/scaler.pkl
버전 파일:  models/model_version.json

로드 시점: FastAPI 서버 시작 시 startup event에서 로드
재학습:    수동 스크립트 실행 (train_model.py) → 파일 교체 → 서버 재시작
```

---

### 3-4. 백엔드 (FastAPI)

#### 프로젝트 구조

```
backend/
├── main.py                  # FastAPI 앱 진입점
├── api/
│   ├── events.py            # 이벤트 REST API 라우터
│   ├── metrics.py           # 시스템 메트릭 API 라우터
│   └── config.py            # 임계값 설정 API 라우터
├── websocket/
│   ├── manager.py           # WebSocket 연결 관리 (ConnectionManager)
│   └── collector.py         # Collector로부터 수신 WebSocket 핸들러
├── ml/
│   ├── engine.py            # ML 분석 엔진 (Isolation Forest + Rule-based)
│   ├── rule_engine.py       # Rule-based 탐지 로직
│   └── models/              # 학습된 모델 파일
├── db/
│   ├── database.py          # SQLAlchemy 엔진 및 세션 설정
│   ├── models.py            # ORM 모델 정의
│   └── crud.py              # DB CRUD 함수
├── services/
│   ├── alert.py             # Slack Webhook 알림 서비스
│   └── metrics_collector.py # psutil 메트릭 수집
├── core/
│   ├── config.py            # 환경 변수 설정 (pydantic BaseSettings)
│   └── logging.py           # 로깅 설정
└── tests/
    ├── test_api.py
    ├── test_ml_engine.py
    └── test_rule_engine.py
```

#### FastAPI 앱 초기화 (main.py 구조)

```python
app = FastAPI(title="eBPF IDS Backend", version="1.0.0")

@app.on_event("startup")
async def startup():
    # 1. DB 연결 확인 및 테이블 생성
    # 2. Redis 연결 확인
    # 3. ML 모델 로드
    # 4. Collector WebSocket 수신 태스크 시작
    # 5. psutil 메트릭 수집 태스크 시작

@app.on_event("shutdown")
async def shutdown():
    # 1. WebSocket 연결 정리
    # 2. DB 세션 풀 종료
    # 3. Redis 연결 종료
```

#### WebSocket 연결 관리 (ConnectionManager)

```python
class ConnectionManager:
    """
    프론트엔드 WebSocket 연결 풀 관리
    """
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, ws: WebSocket):
        await ws.accept()
        self.active_connections.append(ws)

    def disconnect(self, ws: WebSocket):
        self.active_connections.remove(ws)

    async def broadcast(self, message: dict):
        dead = []
        for ws in self.active_connections:
            try:
                await ws.send_json(message)
            except WebSocketDisconnect:
                dead.append(ws)
        for ws in dead:
            self.disconnect(ws)
```

---

### 3-5. 프론트엔드 (React 대시보드)

#### 프로젝트 구조

```
frontend/
├── src/
│   ├── components/
│   │   ├── TrafficChart.tsx       # Recharts 실시간 시계열 차트
│   │   ├── EventTable.tsx         # 이상 탐지 이벤트 테이블
│   │   ├── MetricsPanel.tsx       # CPU/메모리 게이지
│   │   ├── SeverityBadge.tsx      # 심각도 색상 배지
│   │   └── ConnectionStatus.tsx   # WebSocket 연결 상태 표시
│   ├── hooks/
│   │   ├── useWebSocket.ts        # WebSocket 연결 및 재연결 훅
│   │   └── useEventFilter.ts      # 이벤트 필터링 훅
│   ├── store/
│   │   └── eventStore.ts          # Zustand 상태 관리
│   ├── api/
│   │   └── client.ts              # REST API 클라이언트
│   ├── types/
│   │   └── index.ts               # TypeScript 타입 정의
│   └── App.tsx
├── vite.config.ts
└── tsconfig.json
```

#### WebSocket 재연결 훅 설계

```typescript
// useWebSocket.ts
const useWebSocket = (url: string) => {
  const [status, setStatus] = useState<'connected' | 'disconnected' | 'reconnecting'>('disconnected');

  useEffect(() => {
    let ws: WebSocket;
    let retryCount = 0;
    const MAX_RETRY = 5;
    const RETRY_DELAY_MS = 3000;

    const connect = () => {
      ws = new WebSocket(url);

      ws.onopen = () => {
        setStatus('connected');
        retryCount = 0;
      };

      ws.onclose = () => {
        setStatus(retryCount < MAX_RETRY ? 'reconnecting' : 'disconnected');
        if (retryCount < MAX_RETRY) {
          setTimeout(connect, RETRY_DELAY_MS * Math.pow(2, retryCount)); // 지수 백오프
          retryCount++;
        }
      };
    };

    connect();
    return () => ws?.close();
  }, [url]);

  return { status };
};
```

#### 대시보드 레이아웃 구성

```
┌─────────────────────────────────────────────────────────┐
│  [헤더] eBPF IDS Dashboard    [연결 상태] ● Connected   │
├─────────────────┬──────────────────┬────────────────────┤
│  실시간 트래픽  │   이상 점수 추이  │   시스템 메트릭    │
│  (pps/bps)      │  (anomaly score)  │  CPU ██████ 45%   │
│  Recharts       │  Recharts         │  MEM ████   32%   │
├─────────────────┴──────────────────┴────────────────────┤
│  이상 탐지 이벤트 목록                                   │
│  [필터: 심각도 ▼] [필터: 시간 ▼]                        │
│  ┌──────┬─────────┬────────┬──────────┬─────────────┐  │
│  │ 시각 │ src_ip  │ 유형   │ 심각도   │ 이상 점수   │  │
│  │ ...  │ ...     │ SYN F. │ CRITICAL │ -0.87       │  │
│  └──────┴─────────┴────────┴──────────┴─────────────┘  │
└─────────────────────────────────────────────────────────┘
```

---

### 3-6. 인프라 (Terraform + Docker Compose)

#### Terraform 리소스 구성

```
infra/
├── main.tf           # 프로바이더, VPC, EC2, SG 정의
├── variables.tf      # 변수 정의
├── outputs.tf        # EC2 퍼블릭 IP 등 출력값
└── terraform.tfvars  # 실제 변수값 (gitignore 대상)
```

```hcl
# 주요 리소스 구성 요약 (main.tf)

# VPC
resource "aws_vpc" "ebpf_ids_vpc" {
  cidr_block = "10.0.0.0/16"
}

# 퍼블릭 서브넷
resource "aws_subnet" "public" {
  vpc_id     = aws_vpc.ebpf_ids_vpc.id
  cidr_block = "10.0.1.0/24"
}

# Security Group (인바운드 허용 포트만 개방)
resource "aws_security_group" "ec2_sg" {
  ingress { from_port=22,   to_port=22,   protocol="tcp", cidr_blocks=["<관리자IP>/32"] }
  ingress { from_port=80,   to_port=80,   protocol="tcp", cidr_blocks=["0.0.0.0/0"] }
  ingress { from_port=443,  to_port=443,  protocol="tcp", cidr_blocks=["0.0.0.0/0"] }
  egress  { from_port=0,    to_port=0,    protocol="-1",  cidr_blocks=["0.0.0.0/0"] }
  # 5432(PostgreSQL)은 외부 개방 금지 — Docker 내부 네트워크만 접근
}

# EC2 인스턴스
resource "aws_instance" "backend" {
  ami           = "ami-xxxxxxxxx"  # Ubuntu 22.04 LTS
  instance_type = "t3.medium"      # vCPU 2, 메모리 4GB
  key_name      = var.key_name
  user_data     = file("scripts/init.sh")  # Docker, Docker Compose 설치
}
```

#### Docker Compose 서비스 구성 (EC2)

```yaml
# docker-compose.yml (EC2 배포용)
version: "3.9"

services:
  nginx:
    image: nginx:1.25-alpine
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx/nginx.conf:/etc/nginx/nginx.conf:ro
    depends_on: [backend, frontend]
    restart: unless-stopped

  backend:
    image: <dockerhub>/ebpf-ids-backend:latest
    environment:
      - DATABASE_URL=postgresql://user:pass@postgres:5432/ebpf_ids
      - REDIS_URL=redis://redis:6379
      - SLACK_WEBHOOK_URL=${SLACK_WEBHOOK_URL}
      - COLLECTOR_WS_URL=${COLLECTOR_WS_URL}   # Linux VM의 Collector 주소
      - MODEL_PATH=/app/models/isolation_forest.pkl
    depends_on: [postgres, redis]
    restart: unless-stopped

  frontend:
    image: <dockerhub>/ebpf-ids-frontend:latest
    restart: unless-stopped

  postgres:
    image: postgres:16-alpine
    environment:
      POSTGRES_DB: ebpf_ids
      POSTGRES_USER: ${POSTGRES_USER}
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD}
    volumes:
      - postgres_data:/var/lib/postgresql/data
    restart: unless-stopped
    # 외부 포트 바인딩 없음 (내부 네트워크만)

  redis:
    image: redis:7-alpine
    command: redis-server --maxmemory 256mb --maxmemory-policy allkeys-lru
    volumes:
      - redis_data:/data
    restart: unless-stopped

volumes:
  postgres_data:
  redis_data:
```

---

## 4. 데이터 흐름 설계

### 4-1. 정상 탐지 흐름 (Happy Path)

```
1. 패킷 도착 → XDP Hook 실행 (커널, ~수 마이크로초)
2. BPF_HASH 업데이트 → 100ms마다 ring_buffer 이벤트 발행
3. Collector ring_buffer poll → 피처 계산 (~1ms)
4. Redis 슬라이딩 윈도우 캐시 업데이트
5. Collector → FastAPI WebSocket 전송 (~수십 ms)
6. FastAPI: Rule-based 검사 (동기, ~1ms)
7. FastAPI: Isolation Forest 추론 (동기, ~5ms)
8. 이상 탐지 시:
   a. PostgreSQL INSERT (비동기)
   b. 프론트엔드 WebSocket broadcast (비동기)
   c. Critical이면 Slack Webhook 전송 (비동기, 최대 1분 내)
9. 프론트엔드 수신 → 차트/테이블 갱신 (~1초 이내)
```

### 4-2. 컴포넌트 간 인터페이스 요약

| 송신 | 수신 | 프로토콜 | 데이터 포맷 | 주기 |
|---|---|---|---|---|
| XDP (커널) | Collector | ring_buffer | C struct (binary) | 100ms |
| Collector | FastAPI | WebSocket | JSON | 이벤트 발생 시 |
| FastAPI | 프론트엔드 | WebSocket | JSON | 이상 탐지 시 즉시 |
| 프론트엔드 | FastAPI | REST HTTP | JSON | 페이지 로드 / 필터 |
| FastAPI | PostgreSQL | TCP (SQLAlchemy) | SQL | 이상 탐지 시 |
| FastAPI | Redis | TCP | Redis Protocol | 피처 조회 시 |
| FastAPI | Slack | HTTPS | JSON (Webhook) | Critical 탐지 시 |

---

## 5. DB 스키마 설계

### 5-1. detection_events 테이블

```sql
CREATE TABLE detection_events (
    id              BIGSERIAL PRIMARY KEY,
    detected_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    src_ip          INET        NOT NULL,
    dst_ip          INET        NOT NULL,
    src_port        INTEGER     CHECK (src_port BETWEEN 0 AND 65535),
    dst_port        INTEGER     CHECK (dst_port BETWEEN 0 AND 65535),
    protocol        SMALLINT    NOT NULL,  -- 6=TCP, 17=UDP
    attack_type     VARCHAR(32) NOT NULL,  -- 'SYN_FLOOD', 'PORT_SCAN', 'ANOMALY', 'TRAFFIC_SPIKE'
    severity        VARCHAR(8)  NOT NULL,  -- 'critical', 'high', 'medium', 'low'
    anomaly_score   REAL,                  -- Isolation Forest 점수 (-1.0 ~ 0.0)
    pkt_rate        REAL,                  -- 탐지 시점 pps
    byte_rate       REAL,                  -- 탐지 시점 bps
    syn_ratio       REAL,                  -- 탐지 시점 SYN 비율
    port_entropy    REAL,                  -- 탐지 시점 포트 엔트로피
    flow_duration   INTEGER,               -- 플로우 지속 시간 (ms)
    raw_features    JSONB,                 -- 전체 피처 벡터 (확장성)
    is_confirmed    BOOLEAN DEFAULT NULL,  -- 관리자 확인 여부 (NULL=미확인)
    note            TEXT                   -- 관리자 메모
);

-- 인덱스
CREATE INDEX idx_detected_at     ON detection_events (detected_at DESC);
CREATE INDEX idx_severity        ON detection_events (severity);
CREATE INDEX idx_src_ip          ON detection_events (src_ip);
CREATE INDEX idx_attack_type     ON detection_events (attack_type);
```

### 5-2. system_metrics 테이블

```sql
CREATE TABLE system_metrics (
    id              BIGSERIAL PRIMARY KEY,
    collected_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    cpu_percent     REAL        NOT NULL,
    memory_percent  REAL        NOT NULL,
    ebpf_cpu_delta  REAL,   -- eBPF 적용 전후 CPU 증가분
    pkt_total       BIGINT,
    event_total     BIGINT
);

CREATE INDEX idx_collected_at ON system_metrics (collected_at DESC);
```

---

## 6. API 명세

### 6-1. REST API

| Method | Path | 설명 | 응답 |
|---|---|---|---|
| GET | `/api/events` | 이상 탐지 이벤트 목록 (페이지네이션) | 200 / 400 |
| GET | `/api/events/{id}` | 특정 이벤트 상세 조회 | 200 / 404 |
| GET | `/api/metrics` | 최신 시스템 메트릭 | 200 |
| GET | `/api/metrics/history` | 메트릭 이력 (시계열) | 200 |
| GET | `/api/config/thresholds` | 현재 탐지 임계값 조회 | 200 |
| PUT | `/api/config/thresholds` | 탐지 임계값 수정 | 200 / 422 |
| GET | `/health` | 서비스 헬스체크 | 200 |

#### GET /api/events 쿼리 파라미터

```
severity   : string  (critical|high|medium|low)
attack_type: string  (SYN_FLOOD|PORT_SCAN|ANOMALY|TRAFFIC_SPIKE)
start_time : ISO8601 datetime
end_time   : ISO8601 datetime
page       : int (default: 1)
page_size  : int (default: 20, max: 100)
```

#### 표준 에러 응답 포맷

```json
{
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "page_size must be between 1 and 100",
    "timestamp": "2026-09-09T13:00:00Z"
  }
}
```

### 6-2. WebSocket 이벤트 포맷

#### Collector → FastAPI (수신)

```json
{
  "type": "flow_features",
  "timestamp": 1725850800000,
  "flow": {
    "src_ip": "192.168.1.100",
    "dst_ip": "10.0.1.50",
    "src_port": 54321,
    "dst_port": 80,
    "protocol": 6
  },
  "features": {
    "pkt_rate": 1250.5,
    "byte_rate": 980000,
    "syn_ratio": 0.92,
    "port_entropy": 1.2,
    "flow_duration": 3500,
    "avg_pkt_size": 784
  }
}
```

#### FastAPI → 프론트엔드 (송신)

```json
{
  "type": "detection_event",
  "event_id": 12345,
  "detected_at": "2026-09-09T13:00:05Z",
  "attack_type": "SYN_FLOOD",
  "severity": "critical",
  "anomaly_score": -0.87,
  "flow": { "src_ip": "...", "dst_ip": "...", "protocol": 6 },
  "features": { "pkt_rate": 1250.5, "syn_ratio": 0.92 }
}
```

---

## 7. ML 모델 설계

### 7-1. 학습 파이프라인

```
CIC-IDS-2017 데이터셋
       │
       ▼
1. 전처리 (preprocess.py)
   - 결측값 제거
   - 무한대 값 클리핑
   - 피처 선택: [pkt_rate, byte_rate, syn_ratio, port_entropy, flow_duration, avg_pkt_size]
   - 정상 트래픽만 추출 (비지도 학습)
       │
       ▼
2. StandardScaler 학습 및 저장 (scaler.pkl)
       │
       ▼
3. IsolationForest 학습 (contamination=0.05)
       │
       ▼
4. 검증 (validate.py)
   - CIC-IDS-2017 레이블 기반 Precision/Recall/F1/FPR 계산
   - 목표: F1 ≥ 0.80, FPR ≤ 0.05
       │
       ▼
5. 모델 저장 (isolation_forest.pkl) + model_version.json 업데이트
```

### 7-2. 하이퍼파라미터 튜닝 전략

```
튜닝 대상: contamination (0.01 ~ 0.10), n_estimators (50 ~ 200)
튜닝 방법: GridSearchCV (FPR 최소화 목적)
평가 지표: FPR (1차), Recall (2차)
교차 검증: StratifiedKFold(n_splits=5)
```

### 7-3. 모델 성능 모니터링

```
수집 지표:
  - 일별 탐지 건수 (attack_type별)
  - 관리자 확인(is_confirmed) 비율 → FPR 추정
  - 탐지 누락 의심 이벤트 (수동 분석)

임계값 재조정 기준:
  - FPR > 5% 지속 3일 이상 → contamination 값 하향 조정
  - 탐지 누락 증가 → contamination 값 상향 조정
```

---

## 8. 오류 처리 및 복구 설계

### 8-1. 컴포넌트별 오류 처리

| 컴포넌트 | 오류 유형 | 처리 방식 | 복구 전략 |
|---|---|---|---|
| eBPF 에이전트 | 커널 로드 실패 | stderr 출력 후 프로세스 종료 | 커널 버전/capability 확인 후 수동 재시작 |
| eBPF 에이전트 | BPF 맵 full | 오래된 엔트리 LRU 제거 (BPF_MAP_TYPE_LRU_HASH) | 맵 크기 조정 (config_map) |
| Collector | Redis 연결 끊김 | 3회 재연결 시도 (1초 간격) → 실패 시 Slack 알림 | Redis 컨테이너 자동 재시작 |
| Collector | WebSocket 연결 끊김 | 지수 백오프 재연결 (최대 5회) | FastAPI 재시작 후 자동 재연결 |
| FastAPI | DB 연결 실패 | SQLAlchemy 연결 풀 재시도 (3회) | PostgreSQL 컨테이너 `restart: unless-stopped` |
| FastAPI | ML 모델 로드 실패 | 경고 로그 + Rule-based만 활성화 | 모델 파일 복구 후 서버 재시작 |
| FastAPI | Slack Webhook 실패 | 로그 기록, 알림 유실 허용 (비치명적) | 재시도 없음 (단순 알림 기능) |
| 프론트엔드 | WebSocket 끊김 | UI 상태 표시 + 지수 백오프 재연결 | FastAPI 복구 후 자동 재연결 |

### 8-2. 장애 격리 원칙

```
Redis 장애 시:
  → Collector: 피처 캐싱 스킵, ring_buffer 직접 전송 유지
  → FastAPI: Rule-based 탐지만 동작 (Isolation Forest 피처 조회 불가)

PostgreSQL 장애 시:
  → FastAPI: 탐지 계속, DB 저장 실패는 로그로 기록
  → 프론트엔드: WebSocket 실시간 표시는 계속 동작

EC2 인스턴스 재시작 시:
  → Docker Compose restart 정책으로 모든 컨테이너 자동 복구
  → PostgreSQL 볼륨 영속화로 데이터 유실 없음
```

### 8-3. 로깅 설계

```python
# 로그 레벨 정의
CRITICAL: 서비스 중단 수준 오류 (eBPF 로드 실패, DB 연결 완전 실패)
ERROR:    단일 요청/이벤트 처리 실패 (DB INSERT 실패, 모델 추론 오류)
WARNING:  성능 저하 또는 복구 가능한 오류 (Redis 재연결, WebSocket 끊김)
INFO:     주요 이벤트 (서비스 시작/종료, 이상 탐지 이벤트)
DEBUG:    개발 중 상세 정보 (피처 값, BPF 맵 상태)

# 로그 포맷
{
  "timestamp": "2026-09-09T13:00:00Z",
  "level": "WARNING",
  "service": "collector",
  "message": "Redis connection lost, attempting reconnect (1/3)",
  "extra": { "redis_host": "redis", "retry_count": 1 }
}

# 출력 대상
개발환경: stdout (JSON)
운영환경: stdout → Docker logging driver → 파일 저장
```

---

## 9. 환경 설정 및 매개변수

### 9-1. 환경 변수 목록 (.env)

```bash
# DB
POSTGRES_USER=ebpf_ids_user
POSTGRES_PASSWORD=<strong_password>
POSTGRES_DB=ebpf_ids
DATABASE_URL=postgresql://${POSTGRES_USER}:${POSTGRES_PASSWORD}@postgres:5432/${POSTGRES_DB}

# Redis
REDIS_URL=redis://redis:6379
REDIS_WINDOW_SIZE_SEC=60       # 슬라이딩 윈도우 크기 (초)
REDIS_MAX_MEMORY=256mb

# ML 엔진
MODEL_PATH=/app/models/isolation_forest.pkl
SCALER_PATH=/app/models/scaler.pkl
ANOMALY_THRESHOLD=-0.1          # Isolation Forest 이상 판단 임계값
IF_CONTAMINATION=0.05           # 학습 시 contamination 파라미터

# Rule-based 임계값
SYN_RATIO_THRESHOLD=0.8         # SYN Flood: SYN 비율 임계값
SYN_PPS_THRESHOLD=1000          # SYN Flood: 초당 패킷 수 임계값
PORT_ENTROPY_THRESHOLD=3.5      # Port Scan: 포트 엔트로피 임계값
PORT_CNT_THRESHOLD=20           # Port Scan: 고유 포트 수 임계값 (10초 내)
SPIKE_THRESHOLD_MULTIPLIER=10   # Traffic Spike: 정상 기준 배수

# 알림
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/...
SLACK_MIN_SEVERITY=critical     # Slack 알림 최소 심각도

# 에이전트
IFACE=eth0                      # eBPF 모니터링 인터페이스
COLLECTOR_WS_URL=ws://localhost:8001/ws/collector
RING_BUFFER_POLL_MS=100         # ring_buffer 폴링 간격 (ms)
FEATURE_EXPORT_INTERVAL_MS=100  # 피처 내보내기 간격 (ms)

# 서버
BACKEND_HOST=0.0.0.0
BACKEND_PORT=8000
LOG_LEVEL=INFO
METRICS_COLLECT_INTERVAL_SEC=10
```

### 9-2. eBPF 커널 파라미터

```bash
# 커널 사전 설정 (Linux VM)
sysctl -w net.core.bpf_jit_enable=1          # BPF JIT 활성화 (성능)
sysctl -w kernel.perf_event_paranoid=-1       # BPF 이벤트 접근 허용
sysctl -w net.core.rmem_max=134217728         # ring_buffer 수신 버퍼 확대

# ulimit 설정
ulimit -l unlimited  # 메모리 잠금 제한 해제 (BPF 맵 메모리)
```

---

## 10. 개발 환경 구성

### 10-1. Linux VM (eBPF 에이전트 개발)

```bash
# OS: Ubuntu 22.04 LTS (커널 5.15+)
# 필수 패키지
apt-get install -y \
  linux-headers-$(uname -r) \
  clang llvm libelf-dev \
  bpftrace \
  python3-bcc python3-pip \
  redis-tools

# BCC Python 설치
pip install bcc pyroute2 redis websockets

# 개발 디버깅 도구
apt-get install -y bpftool tcpdump hping3 nmap

# 커널 파라미터 적용
sysctl -w net.core.bpf_jit_enable=1
```

### 10-2. 백엔드 개발 환경

```bash
# Python 3.11+
python -m venv venv
source venv/bin/activate

pip install \
  fastapi==0.111.0 \
  uvicorn[standard]==0.30.1 \
  sqlalchemy==2.0.30 \
  asyncpg==0.29.0 \          # PostgreSQL 비동기 드라이버
  redis==5.0.4 \
  scikit-learn==1.5.0 \
  numpy==1.26.4 \
  psutil==5.9.8 \
  httpx==0.27.0 \             # Slack Webhook 전송
  pydantic-settings==2.2.1 \
  pytest==8.2.2 \
  pytest-asyncio==0.23.7

# 로컬 DB/Redis (개발 시)
docker compose -f docker-compose.dev.yml up -d
```

### 10-3. 프론트엔드 개발 환경

```bash
# Node.js 20 LTS
npm create vite@latest frontend -- --template react-ts
cd frontend

npm install \
  recharts@2.12.7 \
  zustand@4.5.4 \
  axios@1.7.2 \
  @types/recharts

npm run dev  # localhost:3000
```

### 10-4. 개발용 Docker Compose (로컬)

```yaml
# docker-compose.dev.yml
services:
  postgres:
    image: postgres:16-alpine
    ports: ["5432:5432"]     # 로컬 개발 시에만 포트 개방
    environment:
      POSTGRES_DB: ebpf_ids
      POSTGRES_USER: dev
      POSTGRES_PASSWORD: dev

  redis:
    image: redis:7-alpine
    ports: ["6379:6379"]
```

---

## 11. 테스트 전략

### 11-1. 테스트 레이어 구성

```
┌──────────────────────────────────┐
│        E2E 테스트 (시연)          │  hping3 / nmap으로 실제 공격 시나리오
├──────────────────────────────────┤
│      통합 테스트 (Integration)    │  API + DB + Redis 연동 테스트
├──────────────────────────────────┤
│       단위 테스트 (Unit)          │  ML 엔진, Rule-based, API 응답
└──────────────────────────────────┘
```

### 11-2. 단위 테스트 항목

```python
# test_rule_engine.py
def test_syn_flood_detection():
    """syn_ratio > 0.8 AND pkt_rate > 1000 → SYN_FLOOD 탐지"""

def test_syn_flood_not_triggered_below_threshold():
    """syn_ratio = 0.7 → 탐지 안됨"""

def test_port_scan_detection():
    """port_entropy > 3.5 AND port_cnt > 20 → PORT_SCAN 탐지"""

# test_ml_engine.py
def test_isolation_forest_anomaly_score_range():
    """anomaly_score가 -1.0 ~ 0.0 범위인지 확인"""

def test_severity_classification():
    """anomaly_score별 심각도 분류 정확성 확인"""

def test_model_load_fallback():
    """모델 파일 없을 때 Rule-based만 동작하는지 확인"""

# test_api.py
def test_get_events_pagination():
    """page, page_size 파라미터 정상 동작 확인"""

def test_invalid_severity_filter():
    """잘못된 severity 값 → 422 응답 확인"""

def test_health_endpoint():
    """GET /health → 200 응답 확인"""
```

### 11-3. 성능 검증 테스트

```bash
# eBPF 오버헤드 측정 스크립트 (overhead_test.py)
# 1. eBPF 미적용 상태에서 10초간 CPU 사용률 측정 (psutil)
# 2. eBPF 에이전트 시작
# 3. eBPF 적용 상태에서 10초간 CPU 사용률 측정
# 4. 증가분 계산 → 5% 이하 확인

# API 부하 테스트
pip install locust
# locustfile.py 작성 → 동시 접속 10명, 60초 실행
# P95 응답 시간 200ms 이하 확인
```

### 11-4. 시연 시나리오 테스트

```bash
# 시나리오 1: SYN Flood
hping3 -S -p 80 --flood -c 10000 <target_ip>
# 기대 결과: 3초 이내 CRITICAL 탐지, Slack 알림 수신

# 시나리오 2: Port Scan
nmap -sS -p 1-1000 <target_ip>
# 기대 결과: 5초 이내 HIGH 탐지, 대시보드 표시

# 시연 환경: 동일 VPC 내 별도 EC2 또는 로컬 VM에서 실행
```

---

## 12. 성능 최적화

### 12-1. eBPF 레이어 최적화

```c
// 1. BPF JIT 컴파일 활성화 → 인터프리터 대비 3~10배 성능
sysctl -w net.core.bpf_jit_enable=1

// 2. LRU 맵 사용으로 메모리 자동 관리
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
} flow_stats_map SEC(".maps");

// 3. 불필요한 루프 제거, 인라인 최적화
static __always_inline int parse_ipv4(struct xdp_md *ctx, ...);

// 4. ring_buffer 배치 처리 (100ms 단위 발행)
// 이벤트마다 발행하지 않고 주기적 배치 발행
```

### 12-2. Python Collector 최적화

```python
# 1. asyncio 기반 비동기 처리 (I/O 대기 최소화)
# 2. Redis Pipeline으로 배치 명령 전송
async def batch_redis_update(self, events):
    pipe = self.redis.pipeline()
    for event in events:
        pipe.zadd(f"flow:{event.key}", {json.dumps(event): event.timestamp})
    await pipe.execute()

# 3. NumPy 벡터 연산으로 피처 계산 가속
features = np.array([pkt_rate, byte_rate, syn_ratio,
                     port_entropy, flow_duration, avg_pkt_size])
```

### 12-3. FastAPI 백엔드 최적화

```python
# 1. SQLAlchemy 비동기 엔진 (asyncpg)
engine = create_async_engine(DATABASE_URL, pool_size=10, max_overflow=20)

# 2. ML 추론 결과 캐싱 (동일 피처 벡터 재사용 방지)
from functools import lru_cache

# 3. WebSocket broadcast 비동기 병렬 처리
await asyncio.gather(*[ws.send_json(msg) for ws in connections])

# 4. uvicorn workers 설정 (운영 환경)
# uvicorn main:app --workers 2 --loop uvloop
```

### 12-4. Redis 최적화

```
maxmemory 256mb
maxmemory-policy allkeys-lru    # 메모리 초과 시 LRU 제거
hz 20                            # 만료 키 정리 빈도 증가 (기본 10)
```

---

## 13. 보안 설계

### 13-1. 네트워크 보안

```
EC2 Security Group 인바운드 규칙:
  - 22 (SSH): 관리자 IP/32만 허용
  - 80 (HTTP): 0.0.0.0/0 허용 (Nginx → HTTPS 리다이렉트)
  - 443 (HTTPS): 0.0.0.0/0 허용
  - 8000 (FastAPI): 차단 (Nginx 경유만 허용)
  - 5432 (PostgreSQL): 차단 (Docker 내부 네트워크만)
  - 6379 (Redis): 차단 (Docker 내부 네트워크만)
```

### 13-2. 컨테이너 보안

```yaml
# eBPF 에이전트 (Linux VM Docker)
services:
  ebpf-agent:
    cap_add:
      - CAP_BPF
      - CAP_NET_ADMIN
    cap_drop:
      - ALL          # 그 외 모든 capability 제거
    security_opt:
      - no-new-privileges:true
    read_only: true  # 루트 파일시스템 읽기 전용
```

### 13-3. 시크릿 관리

```
.env 파일:
  - .gitignore에 반드시 포함
  - GitHub Actions Secrets으로 주입 (CI/CD)
  - EC2 배포 시 scp로 전송 또는 AWS SSM Parameter Store 활용

민감 정보 목록:
  - POSTGRES_PASSWORD
  - SLACK_WEBHOOK_URL
  - AWS 키 (terraform.tfvars)
  - EC2 SSH 키 (GitHub Actions Secret)
```

---

## 14. CI/CD 파이프라인

### 14-1. GitHub Actions 워크플로우 (.github/workflows/deploy.yml)

```yaml
on:
  push:
    branches: [main]

jobs:
  test:
    runs-on: self-hosted  # Linux VM의 self-hosted runner
    steps:
      - uses: actions/checkout@v4
      - name: Run unit tests
        run: |
          cd backend
          pip install -r requirements.txt
          pytest tests/ -v --tb=short

  build-and-push:
    needs: test
    runs-on: self-hosted
    steps:
      - name: Build & Push Docker images
        run: |
          docker build -t $DOCKERHUB_USER/ebpf-ids-backend:$GITHUB_SHA ./backend
          docker build -t $DOCKERHUB_USER/ebpf-ids-frontend:$GITHUB_SHA ./frontend
          docker push $DOCKERHUB_USER/ebpf-ids-backend:$GITHUB_SHA
          docker push $DOCKERHUB_USER/ebpf-ids-frontend:$GITHUB_SHA

  deploy:
    needs: build-and-push
    runs-on: self-hosted
    steps:
      - name: Deploy to EC2
        run: |
          ssh -i $EC2_KEY ec2-user@$EC2_HOST \
            "cd ~/ebpf-ids && \
             docker compose pull && \
             docker compose up -d --no-build"
```

### 14-2. Terraform 자동 프로비저닝

```yaml
# infra-provision.yml (인프라 변경 시 수동 트리거)
on:
  workflow_dispatch:

jobs:
  terraform:
    runs-on: self-hosted
    steps:
      - uses: actions/checkout@v4
      - name: Terraform Init & Apply
        env:
          AWS_ACCESS_KEY_ID: ${{ secrets.AWS_ACCESS_KEY_ID }}
          AWS_SECRET_ACCESS_KEY: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
        run: |
          cd infra
          terraform init
          terraform plan
          terraform apply -auto-approve
```

---

## 15. 향후 확장 설계

### 15-1. AWS VPC Flow Logs 연동 (사후 분석 레이어)

```
Flow Logs → CloudWatch Logs → Lambda → FastAPI /api/flowlogs (POST)
                                         → PostgreSQL (별도 테이블)
                                         → 일별 리포트 생성

제약 사항:
  - 5~10분 집계 지연으로 실시간 탐지 불가
  - eBPF 실시간 탐지의 보완적 사후 검증 용도로만 활용
```

### 15-2. 쿠버네티스 마이그레이션 고려사항

```yaml
# eBPF 에이전트 DaemonSet 배포 예시 (참고용)
apiVersion: apps/v1
kind: DaemonSet
spec:
  template:
    spec:
      hostNetwork: true
      containers:
        - name: ebpf-agent
          securityContext:
            capabilities:
              add: [BPF, NET_ADMIN]
```

### 15-3. 온라인 학습 모델 교체

```
현재: Isolation Forest (오프라인 배치 학습)
목표: River 라이브러리의 Half-Space Trees (온라인 이상 탐지)
  → 재배포 없이 실시간 모델 갱신 가능
  → 정상 트래픽 패턴 변화에 자동 적응
```
