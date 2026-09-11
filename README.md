# eBPF Trace

Ubuntu VM의 native XDP로 TCP/UDP 트래픽을 관찰하고, EC2에서 이상 탐지·저장·실시간 대시보드를 제공하는 프로젝트입니다. 패킷은 항상 `XDP_PASS`로 통과시킵니다.

## 현재 실행 환경

- 대시보드: http://52.62.165.10
- EC2: `ssh -i "don forget.pem" ubuntu@52.62.165.10`
- Ubuntu VM: `ssh ubuntu@192.168.64.2`
- Docker는 **EC2에서만** 사용합니다. VM의 runner는 Python 테스트·프론트 빌드를 수행하고 EC2에 Docker 빌드를 요청합니다.
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
  -L 127.0.0.1:18080:127.0.0.1:80 ubuntu@52.62.165.10
.venv/bin/python infra/test_remote.py
```

## EC2 배포

```bash
cd /home/ubuntu/ebpf-project
python3 infra/bootstrap_env.py
mkdir -p ml/models
docker compose -p ebpf-trace-app -f docker-compose.yml -f docker-compose.tunnel.yml build
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

데이터 업로드 위치는 로컬 Mac의 `/Users/ineb_lsj/Documents/eBPF-project/ml/data/cic-ids2017/`입니다. 폴더는 생성했으며 Git에서 제외됩니다. 공식 PCAP 파일과 `GeneratedLabelledFlows.zip`을 이 폴더에 넣어 주세요. 압축은 그대로 두어도 됩니다. 정상 데이터와 SYN/DDoS·PortScan 공격 데이터가 모두 필요합니다. 실시간 피처와의 시간·5-tuple 레이블 결합이 필요하므로 `MachineLearningCSV`만으로는 최종 검증을 대체할 수 없습니다.

EC2 루트 디스크의 여유 공간은 검증 당시 약 1.5 GB이므로 원본 데이터는 EC2/Docker에 업로드하지 않습니다. 로컬 전처리·학습·검증 후 승인된 모델만 EC2의 `/home/ubuntu/ebpf-project/ml/models/`에 배포합니다. 이 디렉터리는 백엔드의 `/app/models`에 읽기 전용으로 마운트됩니다.

```bash
.venv/bin/python -m ml.preprocess <정답_Label_컬럼이_있는_피처.csv>
.venv/bin/python -m ml.train_model
.venv/bin/python -m ml.validate
```

6개 컬럼은 `pkt_rate, byte_rate, syn_ratio, port_entropy, flow_duration, avg_pkt_size`입니다. 원본 CIC의 장기 플로우 통계는 실시간 1초 윈도우 및 10초 포트 엔트로피와 동일하지 않습니다. PCAP을 같은 피처 계산 방식으로 변환하고 레이블을 결합해야 합니다. 호환되지 않는 CSV 입력은 명시적으로 거부합니다.

스케일러/모델은 학습 분리 후 정상 데이터에만 적합하며 검증 데이터는 분리 보관합니다. 점수는 `clip(decision_function - 0.1, -1, 0)`을 사용합니다. `ml.validate`는 F1 0.80·FPR 0.05 기준 실패 시 종료 코드 1을 반환합니다. 공식 자료: [CIC-IDS-2017](https://www.unb.ca/cic/datasets/ids-2017.html), [IsolationForest](https://scikit-learn.org/stable/modules/generated/sklearn.ensemble.IsolationForest.html).

## 테스트와 운영 확인

```bash
.venv/bin/pytest -q
.venv/bin/ruff check backend collector ml infra
cd frontend && npm run build
# Ubuntu VM에서만, 외부 기본 경로가 없는 임시 테스트망 생성·정리
sudo python3 infra/lab_e2e.py
```

REST: `/health`, `/api/events`, `/api/events/{id}`, `/api/metrics`, `/api/metrics/history`, `/api/config/thresholds`.
WS: `/ws/dashboard`, `/ws/collector` (Bearer Collector 토큰 필수).
임계값 PUT은 `Authorization: Bearer <ADMIN_TOKEN>`이 필요하며 PostgreSQL에 저장됩니다. WS 연결 관리와 런타임 설정 공유를 위해 현재는 백엔드 worker 1개를 사용합니다.

진행 및 미완료 검증은 [docs/tasks.md](docs/tasks.md), 실측 근거는 [docs/verification-2026-09-11.md](docs/verification-2026-09-11.md)를 참고하세요.

AWS와 Slack 비밀값은 `infra/configure_credentials.py --aws --slack`로 입력하면 프로젝트 전용 `.secrets/`에 권한 `0600`으로 저장됩니다. 전역 AWS 설정은 변경하지 않습니다. `.venv/bin/python infra/aws_cli.py sts get-caller-identity`로 `ebpf-trace` 프로필을 확인할 수 있습니다. 현재 계정 인증은 성공했지만 `ec2:DescribeInstances` 권한이 없어 Terraform의 기존 자원 import/plan은 보류했습니다. 인프라 워크플로우에는 별도의 OIDC 역할 및 S3 state bucket 설정도 필요합니다.
