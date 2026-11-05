# eBPF Trace — 실행 · 배포 · 운영 가이드

> 이 문서는 기존 `operations.md` · `incident-operations.md` · `scenarios.md` · `github-actions-setup.md`의
> 핵심을 통합한 요약본이다.

## 1. 실행 환경

- 대시보드: http://203.0.113.10 (공개 포트 80, HTTPS 미설정)
- EC2: `ssh -i "don forget.pem" ubuntu@203.0.113.10`
- Ubuntu VM(Collector): `ssh ubuntu@192.168.64.2`
- 백엔드 Python 3.14 / 프론트 Node 24 / PostgreSQL 17 / Redis 7
- Collector는 BCC와 맞는 시스템 Python 3.10 `--system-site-packages` 가상환경 사용

## 2. 로컬 개발

```bash
python3.14 -m venv .venv
.venv/bin/pip install -r requirements-dev.txt
DATABASE_URL=sqlite+aiosqlite:///./ebpf.db .venv/bin/python -m alembic upgrade head
# 사건 대응 워크스페이스 체험 시 개인 계정 발급
DATABASE_URL=sqlite+aiosqlite:///./ebpf.db .venv/bin/python -m infra.operators --username operator --name 운영자 --role admin
DATABASE_URL=sqlite+aiosqlite:///./ebpf.db .venv/bin/python -m infra.operators --username approver --name 승인자 --role approver
DATABASE_URL=sqlite+aiosqlite:///./ebpf.db OPS_ALLOW_INSECURE_LOCAL=true .venv/bin/python -m uvicorn backend.main:app --reload

# 별도 터미널, Node 24
cd frontend && npm ci && npm run dev
```

- 기존 공개 관측 화면은 `/#overview`, 사건 대응 기본 화면은 `/#incidents`.
- 로컬 SQLite는 API 개발용. **Docker PostgreSQL·Redis로 로컬에서 돌리려면** `docker-compose.dev.yml`(25432/26379) + `DATABASE_URL=postgresql+asyncpg://…@127.0.0.1:25432/ebpf_test` + `alembic upgrade head` — 절차와 확인 명령은 [`api-live-inspection.md` §4](api-live-inspection.md#4-로컬-실행--웹앱--실제-api--docker-postgresql). 같은 URL을 `TEST_DATABASE_URL`로 주면 건너뛰던 PostgreSQL 통합 테스트 5개도 실행된다.

## 3. EC2 배포

흐름: `main 푸시 → 실 DB/Redis·브라우저 E2E·eBPF 컴파일 → GitHub 이미지 빌드/push → VM runner의 EC2 SSH 배포`.
Docker 파일시스템 최소 900 MiB 여유를 사전 검사한다(이미지 unpack 공간을 완전히 보장하지는 않음).

```bash
# 수동 배포 (이미 빌드·푸시한 이미지)
export DOCKERHUB_USERNAME=<레지스트리_사용자> IMAGE_TAG=<커밋_SHA>
cd /home/ubuntu/ebpf-releases/$IMAGE_TAG
python3 infra/check_disk.py --minimum-mib 900
docker compose -p ebpf-trace-app -f docker-compose.yml -f docker-compose.tunnel.yml pull backend frontend
bash infra/deploy.sh
```

- 프로젝트 `ebpf-trace-app`는 PostgreSQL 17 전용 볼륨 사용, 기존 `ebpf-trace` PostgreSQL 16 볼륨은 보존.
- 비밀값(DB 암호, Collector 토큰, 관리자 토큰)은 Git에 넣지 않는다.
- HTTPS는 `docker-compose.https.yml`(Caddy TLS-ALPN)로 별도 구성. 443 인바운드·공개 DNS 필요.

## 4. VM 수집기

```bash
cd /home/ubuntu/ebpf-project
python3 -m venv --system-site-packages .venv-collector
.venv-collector/bin/pip install -r collector/requirements.txt
make -C ebpf-agent
sudo python3 ebpf-agent/verify.py
sudo systemctl status ebpf-tunnel ebpf-collector
sudo journalctl -u ebpf-collector -f
```

- CI는 배포 후 VM runner에서 `infra/update_collector.py`를 실행(import 검사 후 서비스 재시작, 실패 시 복구).
- **runner 계정에 Collector start/stop 비대화식 sudo 권한이 필요**하다(아래 규칙). 미설정이면 v2 갱신이 보류된다.

```bash
printf '%s\n' 'ubuntu ALL=(root) NOPASSWD: /usr/bin/systemctl stop ebpf-collector.service, /usr/bin/systemctl start ebpf-collector.service' | sudo tee /etc/sudoers.d/ebpf-collector-deploy >/dev/null
sudo chmod 440 /etc/sudoers.d/ebpf-collector-deploy
sudo visudo -cf /etc/sudoers.d/ebpf-collector-deploy
```

- WS 미확인 메시지는 `collector-outbox.db`에 남고, 백엔드 ACK 기반 중복 저장 방지. BPF link가 attachment를 소유하므로 프로세스 종료 시 커널이 연결·맵을 해제한다.

## 5. 탐지 · 학습

기본 배포는 **규칙 기반 모드**(SYN Flood, Port Scan, Traffic Spike, Large Flow). 실험 ML 모델은 운영에 적용하지 않는다.

- 원본 캡처는 `pcap/`, 정답 레이블은 `label/`. Monday–Friday 5일 52.43 GB. 원본·생성 피처는 Git/Docker 제외, 작은 보고서만 `ml/reports/`.
- Port Scan은 F-M03에 따라 10초 내 고유 목적지 포트 수로 판정(`port_entropy_threshold`는 호환용 유지, 판정 미사용).

```bash
# 전체 요일 준비와 모델 비교
.venv/bin/python -m ml.pipeline --workers 2
.venv/bin/python -m ml.benchmark ml/data/context-v2/*-aligned.csv.gz

# 원본 PCAP 정리 전 파생 산출물 봉인 (SHA-256 기록)
.venv/bin/python -m ml.pipeline --seal
# 봉인 후에는 pcap/ 없이도 재개 가능
.venv/bin/python -m ml.pipeline --workers 1
```

| 작업 | 캡처 필요 |
|---|---|
| 모델 재학습·비교, 준비된 요일 재개 | 불필요 |
| 정답 CSV 결합 로직 변경 후 재결합 | 불필요 |
| 피처 계산 코드 변경, 새 피처 추가·정답 CSV 교체 | **필요** |

- 검증된 모델(F1≥0.80·FPR≤0.05, 시간 분리 이력, 피처 순서, sklearn 버전, 모델·스케일러 해시 확인)만 로드.
- 운영 로더는 정확한 순서의 6/9/25개 계약만 허용. 9/25개 모델에는 스키마 2 메타데이터와 완전한 v2 입력 필요.

## 6. 사건 대응 워크스페이스 (2026-09-18 구현, 운영 미배포)

흐름: `관측 → 사건 통합 → 내구성 알림 → 담당자 인수 → 조사 → 별도 승인 → 현장 적용 확인 → 억제 검증 → 정책 해제 → 복구 관찰 → 종결`

- **개인 계정**: scrypt 비밀번호, 서버 세션, HttpOnly/SameSite 쿠키, CSRF·Origin·HTTPS 검증, viewer/analyst/responder/approver/admin 역할
- **알림**: DB Outbox 기반 Slack/이메일, 중복 키, 최대 5회 재시도, Retry-After 준수, 결과 불명 `unknown` 표시
- **대응**: 보호 CIDR·TTL·현장 상태 검증, 정책 SHA-256 고정, 5분 미리보기, 요청자와 다른 운영자 승인, 30초 명령 유효기간
- **현장 에이전트**: HTTPS·지점 토큰·HMAC, SQLite 실행 원장, nftables 전용 테이블·커널 timed set, 즉시 해제·재시작 정리
- **ML 운영 단계**: Offline / Shadow / Advisory / Production. 승격 게이트(독립 검증·F1≥0.80·FPR≤0.05·7일 Shadow·1,000추론·p95≤100ms). 자동 차단은 모델 Production 승격과 무관하게 비활성.

기본값: 외부 알림·운영 방화벽 적용·ML Production 승격 모두 **비활성**.

## 7. 탐지 시나리오 리허설

`탐지 시나리오` 메뉴에서 실행. 외부에 공격 패킷을 보내지 않고 문서용 주소(`192.0.2.10 → 198.51.100.20`)의
합성 피처를 실제 엔진으로 보내 결과를 `SIMULATION` 출처로 PostgreSQL에 저장한다.

| 단계 | 모의 입력 | 기본 규칙 기대 결과 |
|---|---|---|
| 정상 접속 | 35 pps, 28,000 bytes/s | 정상 통과 |
| 포트 탐색 | 10초 고유 포트 48개, 80 pps | PORT_SCAN · high |
| SYN 폭주 | 4,800 pps 중 SYN 4,700/s | SYN_FLOOD · critical |
| 대량 전송 | ~13.5 MB/s, 9,500 pps | LARGE_FLOW · medium |
| 회복 | 정상 입력 복귀 | 정상 통과 |

15초 리허설은 15개 샘플·9개 이벤트 기대. 실행 ID로 DB 이벤트·집계·검토 연결. 동시 실행 1개 제한.

## 7-B. 실시간 검사 — 내 와이파이·랜선 트래픽 (2026-09-28 구현)

`실시간 검사` 메뉴(`/#live`). 백엔드가 돌아가는 **호스트 자신의 인터페이스**를 골라 정한 시간 동안 매초 관측을
수집기와 같은 경로(`process_flow`: 규칙 → 모델 → 사건 묶기 → 자동 경로 판단)에 넣는다. 결과는 `live` 출처의
실제 탐지 기록으로 저장되고, 관측은 대시보드 WebSocket으로도 흐른다. 모든 API(`/api/live/*`)는 관리자 토큰이 필요하다.

| 검사 방식 | 필요 조건 | 계산하는 것 | 판정 가능한 규칙 |
|---|---|---|---|
| 패킷 검사 | `pip install scapy` + 원시 소켓 권한(root/`CAP_NET_RAW`, macOS는 `/dev/bpf*` 읽기 권한·ChmodBPF) | 5-튜플 흐름별 25개 관측 항목(수집기 `FeatureCalculator` 재사용, 양방향 문맥) | 4개 규칙 전부 + AI 점수 |
| 카운터 검사 | 없음(psutil) | 인터페이스 수신 패킷·바이트/초. SYN·포트 항목은 0, 출발지는 `0.0.0.0` | 트래픽 급증 · 대용량 전송 |

- 검사 화면의 네 칸(수집 → 1차 방어선·규칙 → 2차 방어선·AI → 대응)은 서버가 매초 집계한 값이다. 2차 AI 칸은 모델이 없거나
  Redis가 없으면 이유와 함께 **건너뜀**으로 표시한다(실시간 경로와 같은 조건).
- **방어선 점검**(`POST /api/live/check`)은 아무것도 저장하지 않는다. 저장된 임계값에서 만든 표본 5개로 규칙 엔진을, 같은 표본으로
  모델을, 두 출발지 표본(단일 출발지 SYN 폭주 / 정상 사용자가 섞인 공유 출발지)으로 차단 안전 점검을 돌려 기대 경로(자동/승인)와 비교한다.
- 동시 검사 1개, 5~300초. 검사 행과 매초 관측 창은 `live_inspections` · `live_inspection_windows` 테이블에 저장돼 새로고침·재시작 뒤에도 `검사 기록`에서 다시 볼 수 있다(재시작으로 끊긴 검사는 `interrupted`). 창 행은 `ops_retention.py`가 보존 기간 뒤 정리한다.

## 8. 테스트와 검증

```bash
.venv/bin/python -m pytest -q
.venv/bin/python -m ruff check backend collector ml infra response_agent
cd frontend && npm run build
npx playwright install chromium && npm run test:e2e
# Ubuntu VM에서만: 격리 테스트망 커널 검증
sudo python3 infra/lab_e2e.py
sudo python3 infra/verify_response_kernel.py
```

- Python 123개(실 PostgreSQL·Redis, 사건·알림·승인·복구, ML 승격·폴백, 차단 안전성 게이트·자동 경로, 실시간 검사·방어선 점검). 외부 테스트 URL 없으면 5개 skip.
- 브라우저 17개 × 2 프로젝트(관측 기능 + 2인 승인 대응 완주·자산·모델·보고서 + 실시간 검사).
- 커널: 격리 namespace에서 실제 nftables 범위 제한·정상 연결 유지·커널 TTL 자동/명시 해제.

## 9. 주요 API·비밀 설정

- REST: `/health`, `/api/events`, `/api/events/{id}`, `/api/metrics`, `/api/metrics/history`, `/api/config/thresholds`, `/api/analysis/pcap`, `/api/analysis/model`
- 실시간 검사(관리자 토큰): `/api/live/interfaces`, `/api/live/check`, `/api/live/inspections`(GET·POST), `/api/live/inspections/{id}`, `/api/live/inspections/{id}/stop` — 요청·응답·테이블 명세는 [`api-live-inspection.md`](api-live-inspection.md)
- WS: `/ws/dashboard`, `/ws/collector`(Bearer Collector 토큰)
- Slack 자동 알림은 `SLACK_ENABLED=true`+`SLACK_WEBHOOK_URL` 동시 설정 필요. 임계값 PUT은 `Authorization: Bearer <ADMIN_TOKEN>`.
- AWS/Slack 비밀값은 `infra/configure_credentials.py --aws --slack`로 `.secrets/`에 0600 저장. 현재 계정 인증은 성공했으나 `ec2:DescribeInstances` 권한이 없어 Terraform import/plan은 보류.
