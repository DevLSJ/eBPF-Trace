# 검증 기록 — 2026-09-11

완료 표시는 소스 작성과 실제 실행 확인을 구분합니다. 비밀번호·토큰·개인키는 이 문서에 기록하지 않습니다.

> 2026-09-11 15:28 KST 사용자 요청으로 작업 일시 중단. 재개 절차는 [tasks.md의 재개 메모](tasks.md#다음-작업-재개-메모)에 기록했다. 운영 서비스는 유지하고 추가 구현·배포는 멈춘다.

## 환경 확인

| 항목 | 실제 확인 |
|---|---|
| Ubuntu VM | 22.04.5 LTS, ARM64, 5.15.0-191-generic, `enp0s1` |
| BPF 도구 | clang/LLVM 14, BCC 0.18, libbpf 0.5, bpftrace 0.14, bpftool 5.15 |
| 커널 설정 | `bpf_jit_enable=1`, `perf_event_paranoid=-1`, 현재 커널 headers 설치 |
| Runner | `ebpf-linux-vm`, online, Linux/ARM64/ebpf 레이블 |
| EC2 | Ubuntu **24.04.4 LTS**, x86_64, 커널 7.0.0-1012-aws, Docker Compose 5.5.1 |
| 기존 EC2 데이터 | PostgreSQL 16·Redis 정상, 사용자 테이블 없음. 기존 컨테이너/볼륨 보존 |
| 신규 서비스 | `ebpf-trace-app`: Nginx, FastAPI, React, PostgreSQL 17, Redis 7 |
| 개발 DB | `ebpf-dev`, PostgreSQL 17 및 Redis 7, EC2 루프백에만 포트 바인딩 |
| 로컬 개발 | Python 3.14.6, 프로젝트 전용 Node 24.21.0 |

기존 Actions 실패 원인은 존재하지 않는 `frontend/package-lock.json`의 npm 캐시 설정이었다. Docker Hub Secret은 `DOCKERHUB`으로 등록되어 있었으나 기존 워크플로우가 `DOCKERHUB_USERNAME`만 참조했다. 실제 Docker가 있는 EC2에서 amd64 이미지를 빌드하도록 변경했다.

## 테스트 결과

| 검증 | 결과 | 범위 |
|---|---|---|
| Python 단위/통합 | **30개 통과**, skip 없음 | 실제 PostgreSQL 17·Redis, WS 재전송, Slack 보안 로그 회귀 포함 |
| 프론트엔드 | Node 24 TypeScript·Vite production build 통과 | Chrome에서 실제 EC2 페이지/실시간 연결 확인 |
| eBPF 컴파일 | `make -C ebpf-agent` 성공 | ARM64 VM에서 BPF ELF 생성 |
| 커널 패킷 테스트 | TCP 110, SYN 100, UDP 5, 22개 플로우/이벤트 검증 | `BPF_PROG_TEST_RUN`, 외부 패킷 발송 없음 |
| XDP 로드 | native `enp0s1` attach 확인 | BPF link 사용, ring ABI 112 bytes |
| bpftrace 보조 검증 | 2초 동안 `bpf_ringbuf_submit` **11회** 확인 | Ubuntu bpftrace 0.14에서 오류를 유발하던 BEGIN probe 제거 |
| 실제 SYN Flood | **1,604.10 ms** | 2,400개 제한, 격리 veth namespace |
| 실제 Port Scan | **646.16 ms** | 격리 namespace 내부 30개 포트, Nmap |
| 이벤트 전달 | **8.93 ms** | EC2 Docker 네트워크, DB commit → WS 확인 |
| API 부하 | P95 **155.37 ms**, 평균 **66.35 ms** | EC2 내부, 동시 10명·100요청 |
| 원격 경로 부하 | P95 **798.95 ms**, 평균 **308.21 ms** | 한국 로컬 → SSH 터널 → 호주 EC2; 200 ms 목표 미달 |
| Terraform | init / validate / fmt 성공 | 실제 AWS 생성/변경은 하지 않음 |
| BPF 강제 종료 정리 | 프로그램 90·맵 14/15/16 해제, 새 프로그램 92 attach | SIGKILL 후 systemd 자동 재시작 |
| 장애 복구 | Redis 중단 중 이벤트 23 저장, PG 재시작 후 유지 | 백엔드 재시작 후 Collector 재연결 **4.68초**, 22 → 23건 유지 |
| eBPF CPU 오버헤드 | baseline **0.59%**, XDP **0.62%**, 증가 **0.03%p** | 106-byte UDP, 약 9,960~9,975 pps, 6초씩 교차 순서 3쌍 |
| GitHub Actions CI | 테스트·프론트 빌드·eBPF 컴파일 **성공** | 커밋 `1430899`, 실행 34569076981 |
| GitHub Actions 배포 | **실패**: backend 이미지 unpack 중 디스크 부족 | 이미지 push/서비스 교체 전 실패, 기존 수동 배포 유지 |

CPU 테스트(`infra/verify_overhead.py`)는 별도 `10.201.0.0/30` veth namespace에 기본 경로 없이 수행했다. 매 회차 60,000개 패킷을 전송했으며 XDP 사용 회차의 커널 카운터도 각각 60,000개였다. 첫 1초를 제외한 psutil 표본으로 평균을 계산했다. 이 수치는 해당 VM의 XDP + ring 리더 오버헤드만 뜻하며 전체 Collector 전송·ML 파이프라인의 10,000 pps 처리량 보증은 아니다. 검증 namespace와 veth는 정리했다.

SYN/스캔 검증은 외부 기본 경로가 없는 `10.200.0.0/30` 임시 네트워크에서 실행했다. 테스트가 만든 namespace·veth는 종료 시 정리했다. 두 시나리오는 10초 포트 관찰 윈도우가 겹치지 않도록 분리했다.

## 구현 시 보완한 설계

- 5-tuple 한 개의 목적지 포트는 고정이므로 커널의 16칸 배열로 20개 포트를 탐지할 수 없다. 출발지 IP 전체의 10초 포트 분포를 Collector에서 계산한다.
- 피처는 누적 카운터의 차분으로 계산한다. 같은 snapshot을 ring/맵 flush에서 두 번 보더라도 중복 가산하지 않는다.
- 마지막 패킷 이후 이벤트가 없는 짧은 플로우는 1초마다 맵을 읽어 마지막 카운터를 반영한다.
- BCC 0.18의 중첩 ring 구조체 자동 추론 한계를 명시적 ctypes 구조체로 처리했다.
- ACK 전 DB 저장, 메시지 ID 중복 방지, SQLite 전송 큐, 최대 256개 동시 전송으로 재접속과 네트워크 왕복 지연을 처리한다.
- 모델 없는 상태에서 정상/이상 점수를 만들어내지 않으며 규칙 기반 모드로 상태를 명시한다.

## 남은 외부 조건 및 한계

- CIC 공식 다운로드 페이지가 연구자 정보 입력을 요구한다. 실제 PCAP/레이블 데이터가 없어 모델 학습 및 F1/FPR 목표 달성은 검증하지 않았다.
- Slack Webhook을 EC2 비밀 설정에 저장했다. HTTPX의 URL 로그 차단 및 HTTP 200/`ok`, 오류 응답, 비밀 로그 누출 방지 테스트는 커밋 `1430899`에 있다. 이 이미지의 배포가 실패했으므로 운영 서비스에는 아직 적용되지 않았고 Slack도 미활성이다. 실제 전송 검증 전 작업을 중단했다.
- AWS 프로젝트 전용 `ebpf-trace` 프로필의 STS 인증 성공: 계정 `529921977354`, IAM 사용자 `lsj04`. `ec2:DescribeInstances`가 `UnauthorizedOperation`으로 거부되었다. EC2 조회 권한 확보 후 기존 자원 import/plan을 검토해야 하며, 임의로 IAM 권한을 확장하거나 새 EC2를 만들지 않았다. Terraform CI의 OIDC 역할/S3 state 설정도 미완료다.
- 실제 EC2는 Ubuntu 24.04.4이고 신규 구축용 Terraform 초안의 AMI는 22.04이다. 기존 자원을 import할 때 실제 AMI·VPC·서브넷·볼륨 값으로 조정한 무교체 plan이 필요하다. 현재 초안을 기존 인스턴스에 무조건 apply해서는 안 된다.
- EC2 UFW는 inactive다. 기존 PostgreSQL 16·Redis와 신규 백엔드/DB는 모두 외부 포트 바인딩이 없고 신규 Redis/개발 DB는 루프백에만 바인딩되어 있지만, 이것만으로 AWS SG 규칙 확인을 대신하지 않는다.
- 공개 페이지는 HTTP이다. HTTPS용 도메인·인증서 설정은 아직 없다. Collector 자격증명 및 Redis는 SSH 터널 안에서 전송한다.
- 원격 사용자 경로의 P95 200 ms 목표는 미달이다. EC2 내부 통과 결과와 구분한다.
- 저빈도 단일 패킷 피처는 고정 1초 윈도우를 사용하며, 65,536 플로우 LRU 한도를 초과하면 커널에서 과거 플로우가 제거된다.
- 이 단계에서는 최종 `v1.0.0` 릴리즈를 발행하지 않는다. 모델 성능, Slack, 인프라 및 나머지 최종 검증을 먼저 완료해야 한다.

## 자동 배포 실패 및 중단 시점

- [Actions 실행 로그](https://github.com/DevLSJ/eBPF-Trace/actions/runs/34569076981): CI 2분 9초 성공, EC2 배포 작업 1분 20초 후 실패. Registry 로그인 및 frontend 빌드는 성공했지만 backend export/unpack에서 `no space left on device`가 발생했다. DB 마이그레이션/운영 컨테이너 교체 단계에는 도달하지 않았다.
- 실패 과정에서 EC2 여유 공간이 약 175 MB까지 감소했다. 이번 빌드에서 생성한 미사용 캐시 ID 5개만 지정하여 약 628.8 MB를 정리했다. 캐시는 재생성 가능하다. 실행 이미지·기존 컨테이너·DB 볼륨은 삭제하지 않았다.
- 마지막 확인: 루트 6.8 GB / 사용 6.0 GB / 여유 **775 MB**. 신규 서비스 5개, 개발 DB·Redis, 기존 PostgreSQL 16·Redis 모두 running. `/health`의 DB·Redis 정상, Collector 연결 true, rules_only.
- VM 수집기·운영 SSH 터널은 active이며 테스트 namespace는 없음. 로컬 임시 테스트 터널/대화형 SSH만 종료하고 운영은 유지한다.
- 현재 운영 이미지는 `local/ebpf-ids-backend:dev`, `local/ebpf-ids-frontend:dev`이다. SHA `1430899` 이미지가 목록에 보이더라도 backend의 unpack이 실패했으므로 배포 성공으로 간주하지 않는다.
- 디스크 증설, 전용 임시 builder/registry 직접 push, `pip --no-compile`, Actions Node 24 런타임 업데이트는 **검토 메모만 남겼고 미구현**이다. 중단 요청 이후 재배포/Actions 재실행/AWS 변경을 하지 않았다.

## 외부 연동 참고

- EC2 읽기 권한: [AWS AmazonEC2ReadOnlyAccess](https://docs.aws.amazon.com/aws-managed-policy/latest/reference/AmazonEC2ReadOnlyAccess.html). 먼저 조회 권한만 요청했으며 변경 권한은 별도 계획 검토 대상이다.
- 기존 자원 재사용: [Terraform import](https://developer.hashicorp.com/terraform/language/import).
- Slack 성공 기준과 비밀 URL 관리: [공식 Incoming Webhook 문서](https://docs.slack.dev/messaging/sending-messages-using-incoming-webhooks/). HTTP 200 및 본문 `ok`를 API 발송 성공으로 판단하고, Slack 화면에서의 확인 여부는 별도로 기록한다.

## 2026-09-15 재점검

위의 9월 11일 결과는 당시 기록으로 보존한다. 아래 결과가 현재 재개 판단의 근거다. 세부 분석은 [코드·인프라 조사 보고서](research-2026-09-15.md), 재개 절차는 [tasks.md](tasks.md#다음-작업-재개-메모)를 참조한다.

| 검증 | 이번 결과 | 범위 및 한계 |
|---|---|---|
| EC2 SSH | 성공 | `BatchMode=yes`, 호스트 키 검증 사용 |
| 루트 파일시스템 | 6.8 GB 중 6.1 GB 사용, **608 MB** 여유, 92% | 9월 11일 775 MB보다 감소; 재빌드 미실행 |
| EC2 서비스 | 9개 컨테이너 running | 앱 5 + 개발 2 + 기존 2; backend는 `local/ebpf-ids-backend:dev` |
| EC2 내부 `/health` | `status=ok`, `database=ok`, `redis=ok`, `detection_mode=rules_only`, **`collector_connected=false`** | 공개 웹 화면/실제 신규 패킷 수신은 검증하지 않음 |
| Ubuntu VM SSH | **시간 초과**, exit 255 | `192.168.64.2:22`, 접속 timeout 8초; sandbox 밖에서 재확인. 전원/IP/경로/sshd 중 원인은 미확정 |
| CIC 데이터 | 파일 0개 | 현재 프로젝트 `ml/data/cic-ids2017/`; 로컬 `ml/models/`도 없음 |
| Python | **28 passed, 2 skipped**, 2 warnings | Python 3.14.6; 실 PostgreSQL/Redis 환경 변수 미설정으로 각 1개 skip |
| Ruff | 통과 | `backend collector ml infra` |
| TypeScript / Vite | 통과 | Node 24.21.0, Vite 7.3.6; JS 675.03 kB / gzip 207.26 kB, 큰 청크 경고 |

Python 검사의 최초 WebSocket 재전송 테스트는 sandbox의 `127.0.0.1` 포트 바인딩 제한으로 실패했다. 승인된 외부 실행에서 같은 테스트를 포함한 전체 30개를 재실행해 28개 통과, 외부 서비스 2개 skip을 확인했다. 기존 `.venv/bin/pytest` 실행 파일에는 이전 경로가 남아 있어 모듈 방식으로 호출했다.

재현 명령:

```bash
.venv/bin/python -m pytest -q -rs
.venv/bin/python -m ruff check backend collector ml infra
# frontend/에서 실행; 시스템 Node 대신 기존 프로젝트 Node 24 사용
../.tools/node_modules/node/bin/node node_modules/typescript/bin/tsc -b
../.tools/node_modules/node/bin/node node_modules/vite/bin/vite.js build
```

테스트 경고는 Starlette의 httpx TestClient 및 AnyIO BlockingPortal deprecated API에 관한 것이다. 빌드 및 Python 검사 통과를 VM XDP·실 DB/Redis·Slack·CIC 모델·실제 브라우저 E2E 통과로 확대 해석하지 않는다. AWS 권한, Actions 최신 실행 및 원격 사용자 경로 성능은 이번에 재확인하지 않았다.

사용자가 지정한 서버 접속 문제/보충 사항 발생 시 중단 조건에 따라 구현·배포를 중지했다. 서버 설정 변경·서비스 재시작·Docker 정리·Terraform apply·Slack 실제 전송·커밋/푸시는 하지 않았다.

## 2026-09-15 디스크 정리 후 확인

이후 사용자의 EC2 불필요 파일 삭제 지시에 따라 정리를 수행했다. 직전 단락의 미실행 범위는 최초 재점검 당시 기록이다.

| 항목 | 정리 전 | 정리 후 |
|---|---|---|
| 루트 여유 (`df -h`) | 608 MB | 약 1.6 GB |
| 루트 사용률 | 92% | 77% |
| 이미지 | 8개, 6개 사용 | 6개, 모두 사용 |
| 컨테이너 | 9개 running | 동일 ID 9개 running |
| 볼륨 | 6개, 모두 사용 | 6개, 모두 사용 |
| Collector health | 최초 미연결 | VM 기동 후 `collector_connected=true` |

삭제 내역:

- 실패한 배포의 미사용 `devlsj/ebpf-ids-backend:1430899db3d9048fb7e216afcb697c3ff0ae4969`, `devlsj/ebpf-ids-frontend:1430899db3d9048fb7e216afcb697c3ff0ae4969`. `docker image rm`을 사용했고 강제 삭제 옵션은 사용하지 않았다.
- `docker buildx prune --force --filter until=24h`: 회수 726.1 MB. 먼저 조회한 전체 캐시는 이번 프로젝트 빌드 기록이었고 진행 중인 빌드는 없었다. `private=true` 필터의 최초 실행은 0 B를 반환했으며, 이후 24시간 미사용 조건으로 정리했다.
- `sudo apt-get clean`: `/var/cache/apt` 약 208 MiB → 20 KiB. 설치된 APT 패키지는 제거하지 않았다.
- `snap list --all`에서 disabled를 확인한 `amazon-ssm-agent` revision 13595, `core22` revision 2437, `snapd` revision 26865를 각각 `snap remove --revision`으로 제거했다. 활성 revision 13349/2955/27738은 유지했다.
- `/var/lib/snapd/cache` 안에서 `-type f -links 1 -mtime +1` 조건에 해당한 다운로드 캐시 1개 삭제. 활성/seed 파일과 hardlink를 공유하는 나머지 캐시는 유지했다.

최종 루트 크기 7,203,201,024 bytes, 사용 5,496,545,280 bytes, 가용 **1,689,878,528 bytes**. Docker 공간 보고의 공유 레이어 크기를 실제 디스크 회수량으로 중복 합산하지 않는다. 남은 빌드 캐시 784.5 MB는 Docker 보고상 회수 가능 0 B였다.

컨테이너 ID 및 실행 시간이 정리 전후 유지되었으며 DB/Redis health도 정상이다. EC2 내부 `/ws/dashboard`에 읽기 연결하여 최신 `traffic` 메시지를 수신했고 timestamp 기준 age 150 ms를 확인했다. `/health`는 `rules_only`, `collector_connected=true`였다. VM 직접 SSH는 시간 초과에서 **인증 거부**로 바뀌었으며 내부 서비스/runner 상태까지 검증한 것은 아니다.

참고: [Docker buildx prune 공식 문서](https://docs.docker.com/reference/cli/docker/buildx/prune/), [CIC 데이터 구성](https://www.unb.ca/cic/datasets/ids-2017.html). 재배포·AWS 자원 변경·Slack 전송·ML 학습은 이번 작업에 포함하지 않았다.

## 2026-09-15 VM 관리 접속 확인

사용자가 제공한 비밀번호로 대화형 `ssh ubuntu@192.168.64.2` 로그인 성공. 최초 네트워크 시간 초과, 이후 비밀번호 입력 없는 자동 접속의 인증 거부, 이번 대화형 로그인 성공을 구분한다. 현재 VM SSH 접근은 가능하며 비밀번호는 저장하지 않았다.

| 조회 | 결과 |
|---|---|
| OS/커널 | Ubuntu 22.04.5 LTS, ARM64, `5.15.0-191-generic` |
| Collector | `active/running`, `ExecMainStatus=0`, `NRestarts=0` |
| 운영 SSH 터널 | `active/running`, `ExecMainStatus=0`, `NRestarts=0` |
| Actions runner | systemd 서비스 `loaded/active/running` |
| 네트워크/XDP | `enp0s1` UP, `192.168.64.2`, XDP program ID 16 |

서비스 재시작·설정 변경 없이 상태만 확인하고 세션을 종료했다. runner 서비스 실행을 GitHub 측 online 상태나 CI 실행 성공으로 확대 해석하지 않는다.
