# eBPF Trace

Ubuntu VM의 native XDP로 TCP/UDP 트래픽을 관찰하고, EC2에서 이상 탐지·저장·실시간 대시보드를 제공하는 프로젝트입니다. 패킷은 항상 `XDP_PASS`로 통과시킵니다.

> **2026-09-16 개발·검증:** 목요일·금요일 PCAP **19,319,899개 패킷** 전체 변환, 레이블 결합 CLI, 모델 검증 보호, 홈페이지 상세·필터·설정·PCAP 선택 기능을 추가했습니다. 실제 PostgreSQL/Redis 포함 Python **43개**, 데스크톱/모바일 브라우저 **8개** 테스트 통과. 정답 CSV가 없어 실제 ML 학습·F1/FPR 평가는 대기 중입니다. [최신 검증 기록](docs/verification-2026-09-16.md), [남은 작업](docs/tasks.md#2026-09-16-개발-상태)을 참고하세요.

## 현재 실행 환경

- 대시보드: http://52.62.165.10
- EC2: `ssh -i "don forget.pem" ubuntu@52.62.165.10`
- Ubuntu VM: `ssh ubuntu@192.168.64.2`
- CI·브라우저 검증·amd64 Docker 빌드는 GitHub Ubuntu runner에서 실행합니다. VM runner는 EC2에 배포를 요청하며 EC2는 완성된 이미지만 pull합니다. VM에는 Docker가 필요 없습니다.
- 백엔드 Python 3.14, 프론트 Node 24, PostgreSQL 17, Redis 7.
- Collector는 Ubuntu BCC 패키지와 맞는 시스템 Python 3.10의 `--system-site-packages` 가상환경을 사용합니다.

## 구성

| 경로 | 역할 |
|---|---|
| `ebpf-agent/` | Ethernet/VLAN/IPv4/TCP/UDP 파싱, LRU 플로우 맵, ring buffer |
| `collector/` | 1초 피처 윈도우, 출발지별 10초 포트 분포, Redis 캐시, 영속 전송 큐 |
| `ml/` | 규칙 탐지, Isolation Forest 학습·검증·폴백 |
| `backend/` | FastAPI REST/WS, PostgreSQL, 메트릭, Slack 서비스 |
| `frontend/` | React·TypeScript·Recharts·Zustand 대시보드 |
| `infra/` | Terraform, runner 설정, systemd, 배포·검증 스크립트 |

## 로컬 개발

```bash
python3.14 -m venv .venv
.venv/bin/pip install -r requirements-dev.txt
DATABASE_URL=sqlite+aiosqlite:///./ebpf.db .venv/bin/alembic upgrade head
DATABASE_URL=sqlite+aiosqlite:///./ebpf.db .venv/bin/uvicorn backend.main:app --reload

# 별도 터미널, Node 24
cd frontend
npm ci
npm run dev
```

로컬 SQLite는 API 개발용입니다. 실제 PostgreSQL/Redis 테스트 서비스는 EC2에서 실행합니다.

```bash
# EC2
cd /home/ubuntu/ebpf-project
python3 infra/bootstrap_env.py  # .env가 없을 때만 0600 권한으로 생성
docker compose -f docker-compose.dev.yml up -d --wait

# 로컬 터널 (DB 외부 공개 없음)
ssh -i "don forget.pem" -N \
  -L 127.0.0.1:25432:127.0.0.1:25432 \
  -L 127.0.0.1:26379:127.0.0.1:26379 \
  -L 127.0.0.1:18080:127.0.0.1:80 ubuntu@52.62.165.10
.venv/bin/python infra/test_remote.py
```

## EC2 배포

`main` 푸시 → 실 DB/Redis·브라우저 E2E·eBPF 컴파일 → GitHub 이미지 빌드/push → VM runner의 EC2 SSH 배포 순서입니다. Docker 파일시스템의 최소 900 MiB 여유를 검사합니다. 이 값은 최소 중단 기준이며 모든 이미지의 unpack 공간을 보장하지는 않습니다.

수동 배포는 이미 빌드·푸시한 이미지의 레지스트리/커밋 SHA를 지정한 릴리즈 디렉터리에서 실행합니다.

```bash
export DOCKERHUB_USERNAME=<레지스트리_사용자> IMAGE_TAG=<커밋_SHA>
cd /home/ubuntu/ebpf-releases/$IMAGE_TAG
python3 infra/check_disk.py --minimum-mib 900
docker compose -p ebpf-trace-app -f docker-compose.yml -f docker-compose.tunnel.yml pull backend frontend
bash infra/deploy.sh
```

프로젝트 `ebpf-trace-app`의 PostgreSQL 17 전용 볼륨을 사용하며, 기존 `ebpf-trace` PostgreSQL 16 볼륨은 보존했습니다. `.env`에는 독립적인 DB 암호, Collector 토큰, 관리자 토큰을 사용합니다. 비밀값은 Git에 넣지 않습니다.

Nginx의 공개 포트는 80입니다. HTTPS 인증서/도메인은 아직 설정하지 않았습니다. Collector의 인증 토큰과 Redis 트래픽은 VM의 전용 SSH 터널로 전송합니다. Redis는 EC2 루프백 16379에만 바인딩됩니다. PostgreSQL과 FastAPI는 공개 포트를 갖지 않습니다.

## VM 수집기

```bash
cd /home/ubuntu/ebpf-project
python3 -m venv --system-site-packages .venv-collector
.venv-collector/bin/pip install -r collector/requirements.txt
make -C ebpf-agent
sudo python3 ebpf-agent/verify.py
sudo systemctl status ebpf-tunnel ebpf-collector
sudo journalctl -u ebpf-collector -f
```

환경 파일: `.env.collector`, `.env.tunnel`. 배포 정의: `infra/systemd/`. 수집기는 비특권 `ubuntu` 사용자와 제한된 BPF/네트워크 capability로 실행합니다. BPF link가 attachment를 소유하므로 프로세스 종료 시 커널이 연결과 맵을 해제합니다.

WS 미확인 메시지는 `collector-outbox.db`에 남습니다. 백엔드는 탐지 이벤트를 저장한 후 ACK를 보내며, 재전송된 메시지 ID를 중복 저장하지 않습니다. 재접속 5회 소진 후 systemd가 프로세스를 다시 시작합니다. Redis 캐시는 전송 경로와 독립적으로 처리합니다.

## 탐지·학습

규칙은 SYN Flood, Port Scan, Traffic Spike, Large Flow를 탐지합니다. `byte_rate` 단위는 **bytes/s**이고 화면에서만 8을 곱해 bits/s로 표시합니다. 100 Mbps 대용량 플로우 임계값은 12,500,000 bytes/s입니다. SYN 임계값은 패킷 수가 아닌 실제 SYN/s 기준입니다.

기본 배포는 **규칙 기반 모드**입니다. 실제 CIC-IDS-2017 기반 모델은 아직 제공되지 않았습니다. 누락된 ML 점수는 `null`/`—`로 표시하며, 합성 점수나 합성 성능을 운영 결과로 표시하지 않습니다.

원본 캡처는 **`pcap/`**, 정답 레이블은 **`ml/data/cic-ids2017/`**에 보관합니다. 현재 Thursday/Friday 캡처가 있으며 둘 다 PCAPNG 형식입니다. 원본과 생성 피처는 Git/Docker에서 제외하고 작은 보고서만 `ml/reports/`에 포함합니다. 시간·IP·포트·프로토콜을 가진 `GeneratedLabelledFlows` CSV가 필요하며, 피처만 있는 `MachineLearningCSV`로 정답 결합을 대체하지 않습니다.

`ml.replay`는 PCAP/PCAPNG를 스트리밍으로 읽고 커널과 같은 Ethernet/VLAN/IPv4/TCP/UDP 판정 및 Collector의 `FeatureCalculator`를 사용합니다. 100ms snapshot과 1초 flush를 모사하지만 실제 커널/스레드 스케줄링과 완전히 같지는 않습니다. 패킷을 네트워크로 재전송하지 않습니다. 정답 없는 행은 `UNLABELED`이며 규칙 탐지 횟수는 고유 공격 수나 정확도가 아닙니다. 레이블 결합기는 CSV/하위 폴더/ZIP 입력을 지원합니다. [공식 데이터 구성](https://www.unb.ca/cic/datasets/ids-2017.html).

원본은 로컬 Mac에 보관합니다. 검증된 모델·스케일러·`model_version.json` 세트만 EC2의 `/home/ubuntu/ebpf-project/ml/models/`에 배포합니다. 백엔드의 `/app/models`에 읽기 전용으로 마운트됩니다.

```bash
.venv/bin/python -m ml.replay pcap/Friday-WorkingHours.pcap \
  --output ml/data/friday-features.csv.gz --report ml/reports/friday.json
.venv/bin/python -m ml.replay pcap/Thursday-WorkingHours.pcap \
  --output ml/data/thursday-features.csv.gz --report ml/reports/thursday.json

# 레이블 확보 후 실제 시각 형식과 시간대를 확인해 지정합니다.
.venv/bin/python -m ml.labels ml/data/friday-features.csv.gz \
  ml/data/cic-ids2017/GeneratedLabelledFlows.zip \
  --output ml/data/friday-labeled.csv.gz \
  --timezone <확인한_IANA_시간대> --timestamp-format '<확인한_strptime_형식>'
.venv/bin/python -m ml.preprocess ml/data/friday-labeled.csv.gz
.venv/bin/python -m ml.train_model
.venv/bin/python -m ml.validate
```

6개 컬럼은 `pkt_rate, byte_rate, syn_ratio, port_entropy, flow_duration, avg_pkt_size`입니다. 원본 CIC의 장기 플로우 통계는 실시간 1초 윈도우 및 10초 포트 엔트로피와 동일하지 않습니다. PCAP을 같은 피처 계산 방식으로 변환하고 레이블을 결합해야 합니다. 호환되지 않는 CSV 입력은 명시적으로 거부합니다.

레이블 결합은 양방향 5-tuple과 전체 관찰 구간을 대조하고 미매칭·충돌 행을 학습에서 제외합니다. 시간 순서 70% 지점 양쪽 10초와 경계를 가로지른 장기 플로우를 제외합니다. 스케일러/모델은 분리 후 정상 학습 데이터에만 적합합니다. `--allow-random-split`은 타임스탬프 없는 실험 CSV용이며 운영 승인되지 않습니다.

점수는 `clip(decision_function - 0.1, -1, 0)`입니다. F1 ≥ 0.80·FPR ≤ 0.05, 시간 분리/레이블 결합 이력, 피처 순서, sklearn 버전, 모델·스케일러 해시를 확인한 모델만 로드합니다. -0.1의 검증 성능을 다른 임계값에 적용하지 않습니다. 공식 알고리즘: [IsolationForest](https://scikit-learn.org/stable/modules/generated/sklearn.ensemble.IsolationForest.html).

Port Scan은 F-M03에 따라 10초 내 고유 목적지 포트 수로 판정합니다. 기존 `port_entropy_threshold` API 필드는 호환성을 위해 유지하지만 판정에 사용하지 않습니다.

## 테스트와 운영 확인

```bash
.venv/bin/python -m pytest -q
.venv/bin/python -m ruff check backend collector ml infra
cd frontend && npm run build
npx playwright install chromium
npm run test:e2e
# Ubuntu VM에서만, 외부 기본 경로가 없는 임시 테스트망 생성·정리
sudo python3 infra/lab_e2e.py
```

REST: `/health`, `/api/events`, `/api/events/{id}`, `/api/metrics`, `/api/metrics/history`, `/api/config/thresholds`, `/api/analysis/pcap`.
WS: `/ws/dashboard`, `/ws/collector` (Bearer Collector 토큰 필수).
Slack 자동 알림은 `SLACK_ENABLED=true`와 `SLACK_WEBHOOK_URL`을 함께 설정해야 켜집니다. Webhook 저장만으로 재배포 시 활성화되지 않습니다.
임계값 PUT은 `Authorization: Bearer <ADMIN_TOKEN>`이 필요하며 PostgreSQL에 저장됩니다. WS 연결 관리와 런타임 설정 공유를 위해 현재는 백엔드 worker 1개를 사용합니다.

홈페이지는 이벤트 상세, 심각도/기간/유형 필터, 현재 페이지 JSON 내보내기, 캡처별 분석, 임계값 설정을 제공합니다. 관리자 토큰은 메모리에만 보관하고 저장 성공 시 지웁니다. 공개 주소는 HTTP이므로 설정 변경은 HTTPS 또는 위 SSH 터널의 `http://127.0.0.1:18080`에서 실행합니다.

진행 상태는 [tasks.md](docs/tasks.md), 최신 실측은 [9월 16일 검증](docs/verification-2026-09-16.md), 과거 커널·복구 실측은 [9월 11일 검증](docs/verification-2026-09-11.md)을 참고하세요.

AWS와 Slack 비밀값은 `infra/configure_credentials.py --aws --slack`로 입력하면 프로젝트 전용 `.secrets/`에 권한 `0600`으로 저장됩니다. 전역 AWS 설정은 변경하지 않습니다. `.venv/bin/python infra/aws_cli.py sts get-caller-identity`로 `ebpf-trace` 프로필을 확인할 수 있습니다. 현재 계정 인증은 성공했지만 `ec2:DescribeInstances` 권한이 없어 Terraform의 기존 자원 import/plan은 보류했습니다. 인프라 워크플로우에는 별도의 OIDC 역할 및 S3 state bucket 설정도 필요합니다.
