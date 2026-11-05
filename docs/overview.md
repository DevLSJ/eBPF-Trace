# eBPF Trace — 개요 · 아키텍처 · 요구사항

> 이 문서는 기존 `requirements.md` · `design.md` · `srs.md`의 핵심을 하나로 통합한 요약본이다.
> 구현 기준: Python 3.14 / Node 24 / PostgreSQL 17 / Redis 7. Collector는 Ubuntu 시스템 Python 3.10(BCC).

## 1. 목적과 한 줄 정의

Linux 커널의 eBPF/XDP Hook에서 관찰한 네트워크 트래픽을 실시간 피처로 환산하고, 규칙 기반·기계학습 기반
탐지를 거쳐 사건(Incident)으로 통합하며, **위험 평가 게이트가 자동 차단과 승인형 차단을 분기하는** 기한부
대응과 복구 확인까지 연결한다.

설계의 중심 명제는 "모델이 정확하므로 차단한다"가 아니라 **"모델이 틀려도 되도록 설계하므로 차단한다"**.
저위험은 사람 없이 적용하되 고위험은 2인 승인으로 넘기고, 어느 경로든 **커널 TTL이 정책을 스스로 만료**시킨다.

## 2. 설계 원칙

- **최소 오버헤드**: eBPF 커널 내 1차 집계로 사용자 공간 복사 최소화 (CPU 증가 ≤ 5%)
- **역할 분리**: 수집(VM) / 분석·서빙(EC2) / 대응(현장 호스트) 세 물리 경계
- **재현 가능성**: Terraform IaC + Docker Compose로 환경 코드화
- **단일 진실 원천**: 모든 탐지 이벤트는 PostgreSQL에 단일 저장
- **장애 격리**: 컴포넌트 독립 재시작, Redis 장애 시에도 규칙 기반 탐지 유지
- **회복 우선**: 자동 차단의 최악 고장은 "막지 못함"이 아니라 "풀지 못함". 커널이 스스로 만료시키는 구조 채택
- **안전한 기본값**: 실패하면 자동 차단이 아니라 **승인 경로로 폴백**

## 3. 배포 토폴로지

```
[로컬 Linux VM 192.168.64.2]          [AWS EC2 203.0.113.10 (Ubuntu 22.04)]
────────────────────────────          ─────────────────────────────────────
 eBPF/XDP 에이전트  ──WebSocket──▶      FastAPI 백엔드
 Collector (Python + BCC)              PostgreSQL 17 · Redis 7
 self-hosted runner                    React 대시보드 · Nginx(리버스 프록시)
                                            │ HTTPS + 지점 토큰 + HMAC
                                            ▼
                                       [현장 Linux 호스트]
                                        response_agent · nftables 전용 테이블
```

- CI·브라우저 E2E·amd64 이미지 빌드는 **GitHub Ubuntu runner**에서 실행. **VM runner**는 EC2에 배포를 요청하며 EC2는 완성된 이미지만 pull한다(VM에 Docker 불필요).
- Redis·Collector 인증 트래픽은 전용 SSH 터널을 통과한다. PostgreSQL·FastAPI는 공개 포트를 갖지 않는다.

## 4. 데이터 흐름

`NIC → XDP Hook(XDP_PASS 관찰 전용) → BPF 맵 플로우 집계 → ring_buffer → Collector 피처 계산
→ Redis 슬라이딩 윈도우(60초) → WebSocket → FastAPI(규칙/ML 탐지) → PostgreSQL 저장 → 대시보드 push`

- XDP는 모든 패킷에 `XDP_PASS`를 반환하는 **관측·집계 전용**이며 차단 판정에 관여하지 않는다.
- 탐지 이후의 차단은 XDP가 아니라 **현장 호스트의 nftables(netfilter)** 가 수행한다.

## 5. 구성 요소

| 계층 | 기술 | 역할 |
|---|---|---|
| Kernel | C · eBPF · XDP · BCC | 패킷 관찰·플로우 집계, LRU 플로우 맵, ring buffer |
| Collection | Python · Redis · SQLite outbox | 1초 피처·10초 포트 분포·ACK 기반 영속 전송 |
| API | FastAPI · SQLAlchemy · PostgreSQL 17 | 탐지·영속 저장·REST/WebSocket·관리자 설정 |
| Detection | Rules · scikit-learn | SYN Flood·Port Scan·Traffic Spike·Large Flow·실험 모델 검증 |
| Interface | React 19 · TypeScript · Vite · Recharts · Zustand | 대시보드·이벤트 조사·데이터 분석 |
| Response | response_agent · nftables | 별도 승인형·기한부 차단, 커널 timed set |
| Delivery | Docker Compose · Nginx · GitHub Actions · EC2 | 테스트 → 이미지 빌드 → VM runner 배포 |
| Infra | Terraform | EC2/VPC/SG 정의 (기존 자원 import/plan은 후속) |

## 6. 피처 스키마

- **스키마 1 (9개)**: `pkt_rate, byte_rate, syn_ratio, port_entropy, flow_duration, avg_pkt_size` 6개 + `source_pkt_rate, source_syn_rate, port_cnt` 3개
- **스키마 2 (25개)**: 위 9개 + 목적지/서비스별 PPS·bytes·SYN 유입량, 역방향 PPS/bytes, 양방향 비율, 10초 유입량 등 16개
- `byte_rate` 단위는 **bytes/s** (화면에서만 ×8하여 bits/s 표시). 모델 점수는 `clip(decision_function − 0.1, −1, 0)`, 모델 부재 시 `null`.

## 7. 기능 요구사항 요약

| 영역 | 핵심 요구 (우선순위) |
|---|---|
| 커널 수집 (F-K) | XDP native 관찰 1초 내 시작, 플로우 단위 BPF_HASH 집계, 종료 시 맵 자동 해제 |
| 수집 API (F-D) | ring_buffer→피처, Redis 60초 윈도우, WebSocket 스트리밍(≤500ms), 재연결 |
| ML 분석 (F-M) | IF 비지도(F1≥0.80/FPR≤0.05 목표), SYN Flood/Port Scan 규칙 탐지, 심각도 분류. F-M12 무재학습 적응은 Could |
| 백엔드 (F-B) | 이벤트 페이지네이션 REST(≤200ms), WebSocket push, PostgreSQL 저장, psutil 메트릭, 임계값 런타임 수정 |
| 프론트 (F-F) | 단일 대시보드 실시간 트래픽·이벤트·메트릭, Recharts 시계열, 심각도 색상, 재연결 표시, 필터 |
| 사건/대응 (F-R/F-S) | 사건 통합, 담당자 인수, 2인 승인 기한부 nftables, 차단 안전성 게이트, 커널 TTL fail-safe |

## 8. 비기능 요구사항 요약

- **성능(NF-P)**: eBPF CPU 오버헤드 ≤5%, API P95 ≤200ms, 10,000 pps 처리. (NF-P03 원격 지연·NF-P08 전체 파이프라인 처리량은 실측 미완)
- **신뢰성(NF-R)**: Docker restart 60초 내 자동 복구, PostgreSQL 볼륨 영속화, Redis 장애 시 규칙 탐지 유지
- **보안(NF-S)**: eBPF 컨테이너 최소 권한(CAP_BPF+CAP_NET_ADMIN), SG는 80/443/관리자SSH만, DB 외부 차단, 비밀값 .env·미커밋
- **유지보수(NF-M)**: `docker compose up -d` 단일 기동, Terraform 재현, GitHub Actions 자동 배포

## 9. 차단 안전성 게이트 (핵심 안전 설계)

`backend/services/risk_gate.py`의 설명 가능한 휴리스틱:
- 4개 신호: 정상 연결 비율(0.4) · 포트 다양성(0.2) · 관측 기간(0.2) · 보호 CIDR 근접도(0.2) + 강제 정지 3종
- 모든 출력에 한국어 근거 문장과 계산에 쓴 관측값 포함
- **저위험 → 자동 적용 / 그 외 → 2인 승인 경로**

`backend/services/autoresponse.py`의 자동 경로 순서:
`스위치·kill switch → 자산 옵트인 → 활성 정책 없음 → 시간당 상한(초과 시 자동 해제) → 게이트 → 예외 시 승인 경로 폴백 → TTL 60초`

환경 변수: `RESPONSE_AUTO_TTL_SECONDS`(60, 30~300), `RESPONSE_AUTO_HOURLY_LIMIT`(10), `RESPONSE_RISK_THRESHOLD`(0.4).

## 10. 제외 범위

인라인 패킷 차단(XDP_DROP)·무승인 차단, 실제 취약점 DB/SBOM 서명 연동, 외부 공인 IP 대상 공격 트래픽,
실시간 온라인 학습, 쿠버네티스 운영, VPC Flow Logs 연동.
