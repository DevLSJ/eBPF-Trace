# 실행 및 운영 가이드

[프로젝트 홈](../README.md) · [최신 검증](verification-2026-09-17-context.md)

새 사건 대응·개인 계정·알림·별도 승인·현장 에이전트·ML Shadow 설정은 [사건 대응 운영 가이드](incident-operations.md)를 참고하세요. 2026-09-18 구현은 아직 운영 배포하지 않았습니다.

## 현재 실행 환경

- 대시보드: http://52.62.165.10
- EC2: `ssh -i "don forget.pem" ubuntu@52.62.165.10`
- Ubuntu VM: `ssh ubuntu@192.168.64.2`
- CI·브라우저 검증·amd64 Docker 빌드는 GitHub Ubuntu runner에서 실행합니다. VM runner는 EC2에 배포를 요청하며 EC2는 완성된 이미지만 pull합니다. VM에는 Docker가 필요 없습니다.
- 백엔드 Python 3.14, 프론트 Node 24, PostgreSQL 17, Redis 7.
- Collector는 Ubuntu BCC 패키지와 맞는 시스템 Python 3.10의 `--system-site-packages` 가상환경을 사용합니다.

### SSH 오류 구분

2026-09-17 재확인: EC2 키 접속은 정상이며 runner는 online입니다. 제한된 로컬 실행 환경에서 Python이 시작한 SSH의 `Operation not permitted`는 로컬 네트워크 실행 권한 문제였습니다. 해당 테스트 명령 권한 승인 후 실제 DB·Redis 검증이 통과했습니다.

VM의 `Permission denied (publickey,password)`는 서버에 도달했지만 지정 키로 `ubuntu` 인증에 실패했다는 뜻입니다. VM을 켜거나 runner를 재시작하는 것과 SSH 공개키 등록은 별개입니다. VM 비밀번호로 로그인할 수 있다면 Mac에서 다음 명령으로 공개키를 등록합니다.

```bash
ssh-copy-id -i "/Users/ineb_lsj/Documents/my-project/key/id_rsa.pub" ubuntu@192.168.64.2
ssh -i "/Users/ineb_lsj/Documents/my-project/key/id_rsa" ubuntu@192.168.64.2
```

비밀번호 접속이 불가능하면 VM 콘솔의 `ubuntu` 계정에서 같은 공개키 한 줄을 `~/.ssh/authorized_keys`에 추가합니다. `.ssh` 권한은 700, `authorized_keys`는 600이며 소유자는 해당 계정이어야 합니다. 개인키(`id_rsa`)는 복사하거나 공유하지 않습니다. 현재 CI의 Collector 업데이트는 VM runner 내부에서 실행되므로 VM SSH 접속 복구와 독립적입니다.

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
DATABASE_URL=sqlite+aiosqlite:///./ebpf.db .venv/bin/python -m alembic upgrade head
DATABASE_URL=sqlite+aiosqlite:///./ebpf.db .venv/bin/python -m uvicorn backend.main:app --reload

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

CI는 백엔드 배포 후 VM runner에서 `infra/update_collector.py`를 실행합니다. 검증된 커밋의 Collector Python 패키지를 준비하고 import 검사 후 서비스를 재시작합니다. `/health`에서 연결 및 피처 스키마 2 관측을 확인하지 못하면 이전 Python 패키지로 복구합니다. 환경 파일·outbox·가상환경·커널 소스는 보존합니다. 이 업데이트는 BPF ABI를 변경하지 않습니다.

VM의 runner 계정은 Collector 시작·중지만 비대화식 sudo로 실행할 수 있어야 합니다. VM 관리자가 아래 전용 규칙을 설정합니다. `sudo -n -l` 확인은 서비스 상태를 변경하지 않습니다.

```bash
printf '%s\n' 'ubuntu ALL=(root) NOPASSWD: /usr/bin/systemctl stop ebpf-collector.service, /usr/bin/systemctl start ebpf-collector.service' | sudo tee /etc/sudoers.d/ebpf-collector-deploy >/dev/null
sudo chmod 440 /etc/sudoers.d/ebpf-collector-deploy
sudo visudo -cf /etc/sudoers.d/ebpf-collector-deploy
sudo -n -l /usr/bin/systemctl stop ebpf-collector.service
sudo -n -l /usr/bin/systemctl start ebpf-collector.service
```

WS 미확인 메시지는 `collector-outbox.db`에 남습니다. 백엔드는 탐지 이벤트를 저장한 후 ACK를 보내며, 재전송된 메시지 ID를 중복 저장하지 않습니다. 재접속 5회 소진 후 systemd가 프로세스를 다시 시작합니다. Redis 캐시는 전송 경로와 독립적으로 처리합니다.

## 탐지·학습

규칙은 SYN Flood, Port Scan, Traffic Spike, Large Flow를 탐지합니다. `byte_rate` 단위는 **bytes/s**이고 화면에서만 8을 곱해 bits/s로 표시합니다. 100 Mbps 대용량 플로우 임계값은 12,500,000 bytes/s입니다. SYN 임계값은 패킷 수가 아닌 실제 SYN/s 기준입니다.

기본 배포는 **규칙 기반 모드**입니다. 5일 PCAP의 25개 피처 지도학습 실험에서 시험 F1 90.98%를 얻었지만, 엄격한 분리 후 시험에 남은 공격은 14종 중 4종뿐입니다. DDoS·PortScan 등과 새로운 환경의 성능을 보장하지 않아 실험 모델을 운영에 적용하지 않습니다. 누락된 ML 점수는 `null`/`—`로 표시합니다. 이전 목·금요일 IF 실험 F1 62.92%와는 평가 표본·분리 기준이 다릅니다.

원본 캡처는 **`pcap/`**, 정답 레이블은 **`label/`**에 보관합니다. Monday–Friday 5일 캡처 52.43 GB를 사용합니다. 원본과 생성 피처는 Git/Docker에서 제외하고 작은 보고서만 `ml/reports/`에 포함합니다. 제공된 `label/TrafficLabelling ` 폴더(이름 끝 공백 포함)의 CSV에 시간·IP·포트·프로토콜·정답이 포함되어 있으며, 피처만 있는 `MachineLearningCSV`로 정답 결합을 대체하지 않습니다.

### 전체 요일 준비와 모델 비교

```bash
.venv/bin/python -m ml.pipeline --workers 2
.venv/bin/python -m ml.benchmark \
  ml/data/context-v2/monday-aligned.csv.gz \
  ml/data/context-v2/tuesday-aligned.csv.gz \
  ml/data/context-v2/wednesday-aligned.csv.gz \
  ml/data/context-v2/thursday-aligned.csv.gz \
  ml/data/context-v2/friday-aligned.csv.gz
```

준비 과정은 원본·라벨·피처 계산 코드·출력 해시를 검증해 중단 후 재개합니다. 월요일은 초 단위, 나머지는 분 단위이며 둘 다 AM/PM 없는 근무시간 12시간 시계로 해석합니다. 음수 지속시간 등 잘못된 라벨은 제외하며 미매칭을 정상으로 대체하지 않습니다. 상태는 `ml/reports/evaluation/preparation.json`에 기록합니다.

벤치마크는 미리 저장한 프로토콜로 5분 블록과 양방향 연결을 60/20/20 슬롯에 각각 배정하고 배정이 일치하는 구간만 유지합니다. 경계 30초·경계를 넘는 장기 연결은 제외합니다. 실제 표본 비율은 60/20/20과 다를 수 있습니다. 정상 학습 표본 최대 20만, 공격 유형별 최대 3만으로 메모리를 제한하고, 보정·시험은 남은 전체 표본을 평가합니다. IF 6/9/25개는 같은 100트리·256표본 설정입니다. 확장 IF와 지도학습 HGB도 사전 정의한 설정을 사용합니다. 임계값과 추천 후보는 보정 F1·오탐률로만 선택합니다. `attack_coverage`에서 시험에 없는 유형을 확인해야 합니다.

결과는 `ml/reports/evaluation/context-v2.json`, 비공개 실험 모델·분리 자료는 `ml/models/context-v2/`에 저장합니다. 이 모델 묶음은 운영용 모델/스케일러 형식이 아니며 자동 배포하지 않습니다. 프로토콜을 바꾸면 새 `--directory`와 `--report`를 지정해야 합니다. 원본 IP·포트·시간은 정답/분리용이며 모델 입력으로 사용하지 않습니다.

### 개별 캡처와 기존 실험 재현

`ml.replay`는 PCAP/PCAPNG를 스트리밍으로 읽고 커널과 같은 Ethernet/VLAN/IPv4/TCP/UDP 판정 및 Collector의 `FeatureCalculator`를 사용합니다. 100ms snapshot과 1초 flush를 모사하지만 실제 커널/스레드 스케줄링과 완전히 같지는 않습니다. 패킷을 네트워크로 재전송하지 않습니다. 정답 없는 행은 `UNLABELED`이며 규칙 탐지 횟수는 고유 공격 수나 정확도가 아닙니다. 레이블 결합기는 CSV/하위 폴더/ZIP 입력을 지원합니다. [공식 데이터 구성](https://www.unb.ca/cic/datasets/ids-2017.html).

원본은 로컬 Mac에 보관합니다. 검증된 모델·스케일러·`model_version.json` 세트만 EC2의 `/home/ubuntu/ebpf-project/ml/models/`에 배포합니다. 백엔드의 `/app/models`에 읽기 전용으로 마운트됩니다.

```bash
.venv/bin/python -m ml.replay pcap/Friday-WorkingHours.pcap \
  --output ml/data/friday-features.csv.gz --report ml/reports/friday.json
.venv/bin/python -m ml.replay pcap/Thursday-WorkingHours.pcap \
  --output ml/data/thursday-features.csv.gz --report ml/reports/thursday.json

# 패킷 수·방향·지속시간으로 분 단위 CSV 시각을 복원합니다.
.venv/bin/python -m ml.alignment pcap/Thursday-WorkingHours.pcap label \
  --features ml/data/thursday-features.csv.gz --day Thursday \
  --output ml/data/thursday-intervals.jsonl.gz --report ml/reports/alignment/thursday.json
.venv/bin/python -m ml.alignment pcap/Friday-WorkingHours.pcap label \
  --features ml/data/friday-features.csv.gz --day Friday \
  --output ml/data/friday-intervals.jsonl.gz --report ml/reports/alignment/friday.json
.venv/bin/python -m ml.labels ml/data/thursday-features.csv.gz label \
  --output ml/data/thursday-aligned.csv.gz --profile cicids2017 --day Thursday \
  --alignment ml/data/thursday-intervals.jsonl.gz --report ml/reports/labels/thursday.json
.venv/bin/python -m ml.labels ml/data/friday-features.csv.gz label \
  --output ml/data/friday-aligned.csv.gz --profile cicids2017 --day Friday \
  --alignment ml/data/friday-intervals.jsonl.gz --report ml/reports/labels/friday.json
.venv/bin/python -m ml.evaluate_dataset \
  ml/data/thursday-aligned.csv.gz ml/data/friday-aligned.csv.gz \
  --directory ml/models/cic2017-aligned --source-context
```

6개 컬럼은 `pkt_rate, byte_rate, syn_ratio, port_entropy, flow_duration, avg_pkt_size`입니다. 원본 CIC의 장기 플로우 통계는 실시간 1초 윈도우 및 10초 포트 엔트로피와 동일하지 않습니다. PCAP을 같은 피처 계산 방식으로 변환하고 레이블을 결합해야 합니다. 호환되지 않는 CSV 입력은 명시적으로 거부합니다.

레이블 결합은 양방향 5-tuple과 전체 관찰 구간을 대조하고 미매칭·충돌 행을 학습에서 제외합니다. 제공 CSV는 CP1252 인코딩, day/month 날짜, AM/PM 없는 12시간 시계, America/Halifax 기준입니다. PCAP에서 유일하게 일치하는 연속 패킷 구간을 찾고, 시작 방향·양방향 개수·지속시간(±2µs)을 검증합니다. 복원하지 못한 행은 원본 정밀도에 따라 월요일 1초, 나머지 60초의 시작 시각 불확실성을 유지합니다. 해당 불확실 구간이 다른 정답과 겹치면 확정 매칭하지 않습니다. 결합 전 피처·원본 CSV 해시 및 전체 정답 분포를 확인합니다. 5일 전체에서 빈 행 288,602개와 잘못된 라벨 115개를 제외했습니다. 기존 목·금요일 실험의 시간 정합 근거는 [이전 검증](verification-2026-09-17-upgrade.md)을 참조하세요. 기존 `ml.evaluate_dataset`은 시간 순서 70% 지점 양쪽 10초와 경계를 가로지른 장기 플로우를 제외합니다. 스케일러/모델은 분리 후 정상 학습 데이터에만 적합합니다. `--allow-random-split`은 타임스탬프 없는 실험 CSV용이며 운영 승인되지 않습니다.

기존 9개 피처 실험은 6개에 `source_pkt_rate`, `source_syn_rate`, `port_cnt`를 더합니다. 과거 보고서는 `ml/reports/evaluation/combined.json`에 유지합니다. 현재 스키마 2는 이 9개와 목적지/서비스 유입량·역방향·양방향·10초 유입량 16개를 합친 25개를 필수로 전달합니다. 구버전 메시지도 수신하지만 누락 문맥은 `null`로 저장해 0과 구분합니다. 역방향 미관측은 연결 실패를 뜻하지 않습니다. 목적지 서비스 SYN 유입량도 기존 SYN 임계값에 대조합니다.

운영 로더는 정확한 순서의 6/9/25개 계약만 허용합니다. 9/25개 모델에는 스키마 2 메타데이터와 완전한 v2 입력이 필요합니다. 이벤트 `raw_features` JSON에 새 피처를 보존하므로 DB 컬럼 추가 없이 상세 화면에서 확인할 수 있습니다.

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

REST: `/health`, `/api/events`, `/api/events/{id}`, `/api/metrics`, `/api/metrics/history`, `/api/config/thresholds`, `/api/analysis/pcap`, `/api/analysis/model`. `/api/events?ip=192.0.2.1`은 출발지와 목적지 IP를 모두 검색합니다.
WS: `/ws/dashboard`, `/ws/collector` (Bearer Collector 토큰 필수).
Slack 자동 알림은 `SLACK_ENABLED=true`와 `SLACK_WEBHOOK_URL`을 함께 설정해야 켜집니다. Webhook 저장만으로 재배포 시 활성화되지 않습니다.
임계값 PUT은 `Authorization: Bearer <ADMIN_TOKEN>`이 필요하며 PostgreSQL에 저장됩니다. WS 연결 관리와 런타임 설정 공유를 위해 현재는 백엔드 worker 1개를 사용합니다.

홈페이지는 대시보드·탐지 이벤트·탐지 시나리오·데이터 분석·탐지 설정 화면을 분리하고 모바일 메뉴를 제공합니다. 이벤트 상세, 심각도/기간/유형/IP 필터, 현재 페이지 JSON 내보내기, 캡처별 타임라인·정답 분포·모델 평가, 분석 JSON 다운로드를 지원합니다. 관리자 토큰은 메모리에만 보관하고 저장 성공 시 지웁니다. 공개 주소는 HTTP이므로 설정 변경은 HTTPS 또는 위 SSH 터널의 `http://127.0.0.1:18080`에서 실행합니다.

진행 상태는 [tasks.md](tasks.md), 최신 실측은 [9월 17일 검증](verification-2026-09-17-upgrade.md), 과거 커널·복구 실측은 [9월 11일 검증](verification-2026-09-11.md)을 참고하세요.

AWS와 Slack 비밀값은 `infra/configure_credentials.py --aws --slack`로 입력하면 프로젝트 전용 `.secrets/`에 권한 `0600`으로 저장됩니다. 전역 AWS 설정은 변경하지 않습니다. `.venv/bin/python infra/aws_cli.py sts get-caller-identity`로 `ebpf-trace` 프로필을 확인할 수 있습니다. 현재 계정 인증은 성공했지만 `ec2:DescribeInstances` 권한이 없어 Terraform의 기존 자원 import/plan은 보류했습니다. 인프라 워크플로우에는 별도의 OIDC 역할 및 S3 state bucket 설정도 필요합니다.

## 시나리오 및 검토

[시나리오 시연 가이드](scenarios.md)에 실행 버튼·DB 그래프·이벤트 판정 순서를 정리했습니다. 새 Alembic revision `89c6d1e42a10`은 기존 이벤트를 보존하며 출처/실행 FK/검토 시각과 실행·샘플 테이블을 추가합니다. 배포 시 백엔드 시작 명령이 `alembic upgrade head`를 실행합니다. 시나리오 데이터는 실행별로 명시적으로 저장되며 실시간 그래프에 합산하지 않습니다.
