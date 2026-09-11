# 검증 기록 — 2026-09-11

완료 표시는 소스 작성과 실제 실행 확인을 구분합니다. 비밀번호·토큰·개인키는 이 문서에 기록하지 않습니다.

## 환경 확인

| 항목 | 실제 확인 |
|---|---|
| Ubuntu VM | 22.04.5 LTS, ARM64, 5.15.0-191-generic, `enp0s1` |
| BPF 도구 | clang/LLVM 14, BCC 0.18, libbpf 0.5, bpftrace 0.14, bpftool 5.15 |
| 커널 설정 | `bpf_jit_enable=1`, `perf_event_paranoid=-1`, 현재 커널 headers 설치 |
| Runner | `ebpf-linux-vm`, online, Linux/ARM64/ebpf 레이블 |
| EC2 | x86_64, 커널 7.0.0-1012-aws, Docker Compose 5.5.1 |
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
| 실제 SYN Flood | **1,604.10 ms** | 2,400개 제한, 격리 veth namespace |
| 실제 Port Scan | **646.16 ms** | 격리 namespace 내부 30개 포트, Nmap |
| 이벤트 전달 | **8.93 ms** | EC2 Docker 네트워크, DB commit → WS 확인 |
| API 부하 | P95 **155.37 ms**, 평균 **66.35 ms** | EC2 내부, 동시 10명·100요청 |
| 원격 경로 부하 | P95 **798.95 ms**, 평균 **308.21 ms** | 한국 로컬 → SSH 터널 → 호주 EC2; 200 ms 목표 미달 |
| Terraform | init / validate / fmt 성공 | 실제 AWS 생성/변경은 하지 않음 |
| BPF 강제 종료 정리 | 프로그램 90·맵 14/15/16 해제, 새 프로그램 92 attach | SIGKILL 후 systemd 자동 재시작 |
| 장애 복구 | Redis 중단 중 이벤트 23 저장, PG 재시작 후 유지 | 백엔드 재시작 후 Collector 재연결 **4.68초**, 22 → 23건 유지 |
| eBPF CPU 오버헤드 | baseline **0.59%**, XDP **0.62%**, 증가 **0.03%p** | 106-byte UDP, 약 9,960~9,975 pps, 6초씩 교차 순서 3쌍 |

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
- Slack Webhook을 EC2 비밀 설정에 저장했다. HTTPX의 URL 로그를 차단하고 HTTP 200/`ok`, 오류 응답, 비밀 로그 누출 방지 테스트를 추가했다. 새 버전 배포 및 실제 전송 검증 진행 중이다.
- AWS 프로젝트 전용 `ebpf-trace` 프로필의 STS 인증 성공: 계정 `529921977354`, IAM 사용자 `lsj04`. `ec2:DescribeInstances`가 `UnauthorizedOperation`으로 거부되었다. EC2 조회 권한 확보 후 기존 자원 import/plan을 검토해야 하며, 임의로 IAM 권한을 확장하거나 새 EC2를 만들지 않았다. Terraform CI의 OIDC 역할/S3 state 설정도 미완료다.
- 공개 페이지는 HTTP이다. HTTPS용 도메인·인증서 설정은 아직 없다. Collector 자격증명 및 Redis는 SSH 터널 안에서 전송한다.
- 원격 사용자 경로의 P95 200 ms 목표는 미달이다. EC2 내부 통과 결과와 구분한다.
- 저빈도 단일 패킷 피처는 고정 1초 윈도우를 사용하며, 65,536 플로우 LRU 한도를 초과하면 커널에서 과거 플로우가 제거된다.
- 이 단계에서는 최종 `v1.0.0` 릴리즈를 발행하지 않는다. 모델 성능, Slack, 인프라 및 나머지 최종 검증을 먼저 완료해야 한다.
