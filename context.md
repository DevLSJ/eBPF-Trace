[프로젝트 주제] : eBPF 기반 이상 트래픽 탐지 및 대응 시스템 
주제 선정 이유 : 최근 가장 떠오른 이슈인 오픈 소스 공급망 공격으로 인해 부상되고 있는 네트워크 보안 이슈를 봄.
 비정상적인 네트워크 트래픽을 자동화 프로그램으로 감지하고 대응하는 시스템이 있으면 좋겠다고 생각함.
 또한, 개인적인 기업 목표가 "SK 텔레콤 Core Infra" 이기 때문에 해당 프로젝트로 본인의 기량을 올리고 싶음.
 

 [사용 기술] *
(요약)
- C+Python+FastAPI
- Vite + TypeScript
- Github Actions -> Docker+PostgreSQL
- Github, VsCode, IntelliJ, Linux VM + AWS EC2 (백엔드/대시보드 호스팅)
- Terraform (EC2/VPC/SG IaC)
------------------------------------------------------------
  커널 수집
  - eBPF/XDP (C) — 커널 내 플로우별 패킷/바이트 수 1차 집계
  - BCC — 프로토타이핑 및 알고리즘 검증용 eBPF 로드 도구
  - bpftrace — 개발 중 디버깅 보조
  
  데이터 수집 API
  - Python + BCC — ring_buffer 이벤트 읽기 및 플로우 집계
  - Redis — 슬라이딩 윈도우 피처 캐싱
  - WebSocket — 실시간 이벤트 스트리밍
  
  ML 분석 엔진
  - scikit-learn (Isolation Forest) — 비지도 이상 트래픽 탐지
  - Rule-based — SYN flood, 포트스캔 임계값 즉각 탐지

  탐지 기준
  - 데이터셋 : CIC-IDS-2017 (캐나다 사이버보안연구소 공개)
  - 참고 문헌 : KISA 이상징후 탐지 기술 안내서, 해외 공급망 공격 관련 데이터 자료
  - 성능 지표 : Precision / Recall / F1-Score / FPR (목표 FPR 5% 이하)
  - 오버헤드 검증 : psutil 기반 eBPF 적용 전후 CPU 사용률 비교
    ※ EC2 환경에서 XDP는 generic 모드(XDP_SKB)로 동작하므로 native 모드 대비 성능 차이 존재.
       eBPF 에이전트는 로컬 Linux VM에서 실행하여 XDP native 모드 성능 특성을 유지함.
 
 대응 방법 
  
  프론트엔드
  - Vite + TypeScript + React — 단일 대시보드 UI
  - Recharts — 트래픽/이상 점수 시계열 차트
  - WebSocket 클라이언트 — 실시간 데이터 수신
  
  백엔드 
  - Python 
  - FastAPI (Python) — REST API 및 WebSocket 서버
  - PostgreSQL — 이상 탐지 이벤트 로그 저장
  - psutil — CPU/메모리 시스템 메트릭 수집
  
  인프라
  - Docker Compose — 전체 서비스 컨테이너화
    ※ eBPF 에이전트 컨테이너는 privileged 모드 또는 CAP_BPF + CAP_NET_ADMIN 권한 필요
  - AWS EC2 (Ubuntu 22.04 / Amazon Linux 2023) — 백엔드 API 및 대시보드 서비스 호스팅
    ※ eBPF 에이전트는 로컬 Linux VM에서 실행 (하이브리드 구조)
    ※ GitHub Actions self-hosted runner는 Linux VM에 위치 (EC2 NIC의 XDP native 미지원으로 인한 설계)
  - Terraform — EC2 인스턴스 / VPC / Security Group IaC 구성
    ※ GitHub Actions 연동으로 terraform apply 기반 테스트 환경 자동 프로비저닝

  향후 확장 방향 (졸업작품 범위 외)
  - AWS VPC Flow Logs 연동 — 클라우드 환경 사후 분석(post-hoc) 레이어 추가 가능
    ※ Flow Logs는 5~10분 단위 집계로 실시간 탐지 파이프라인과 직접 연동 불가.
       실시간 탐지는 eBPF 에이전트가 담당하고, VPC Flow Logs는 보완적 분석 용도로 활용 가능.
   
  [기능 및 역할] **
  커널 수집 : XDP Hook으로 패킷을 복사 없이 관찰하고 BPF_HASH 맵에서 커널 내 1차 집계하여 오버헤드 최소화
              (로컬 Linux VM에서 실행, XDP native 모드 유지)
  데이터 수집 API : 커널 이벤트를 플로우 단위로 집계하여 피처 계산 후 백엔드에 전달

  ML 분석 엔진 : 이상 트래픽 탐지 및 심각도 분류

  프론트엔드 : 실시간 트래픽 현황, 이상 탐지 이벤트, 시스템 메트릭을 단일 대시보드로 시각화

  백엔드 : 수집/분석/저장/알림을 통합 처리 및 총괄적인 단위 통합 (AWS EC2에서 호스팅)

  인프라 & 시각화 : Docker Compose로 전체 서비스를 컨테이너화하여 환경 일관성 보장
                    Terraform으로 EC2/VPC/SG를 코드로 관리하여 재현 가능한 배포 환경 확보

[검증 방법] ***
  - 데이터셋 : CIC-IDS-2017 (캐나다 사이버보안연구소 공개)
  - 참고 문헌 : KISA 이상징후 탐지 기술 안내서
  - 성능 지표 : Precision / Recall / F1-Score / FPR (목표 FPR 5% 이하)
  - 오버헤드 검증 : psutil 기반 eBPF 적용 전후 CPU 사용률 비교
  - 시연 도구 : hping3 (SYN Flood), nmap (Port Scan)
    ※ 시연 트래픽은 동일 VPC 내 별도 인스턴스 또는 로컬 VM에서 발생시킴
       (외부 공인 IP 대상 공격성 트래픽은 AWS 이용약관 위반 소지)

 [시연 방향] ****
  - Web UI를 통한 네트워크 트래픽 이상 징후 탐지 알림
  - Slack Webhook 활용 알림 발송

개발 도구 * : Linux VM 여러 대 (eBPF 에이전트 실행 및 self-hosted runner), VSCode, IntelliJ,
              GitHub Actions (self-hosted runner) → Docker 연동으로 푸시마다 자동 이미지 빌드,
              Terraform (EC2/VPC 환경 자동 프로비저닝)

----

인프라 구성 요약 (확정)

  ┌──────────────────────┬────────────────────────────────────────────┬──────────────────────────────┐
  │ 구성 요소            │ 방법                                       │ 포인트                       │
  ├──────────────────────┼────────────────────────────────────────────┼──────────────────────────────┤
  │ AWS EC2 배포         │ 백엔드 API + 대시보드를 EC2에 호스팅       │ 클라우드 배포 경험           │
  │                      │ eBPF 에이전트는 Linux VM 유지 (하이브리드) │ XDP native 모드 성능 보존    │
  ├──────────────────────┼────────────────────────────────────────────┼──────────────────────────────┤
  │ Terraform            │ EC2 / VPC / Security Group IaC 구성        │ IaC 경험 / 재현 가능한 환경  │
  │                      │ GitHub Actions 연동 자동 프로비저닝        │ CI/CD 파이프라인 확장        │
  ├──────────────────────┼────────────────────────────────────────────┼──────────────────────────────┤
  │ VPC Flow Logs        │ 향후 확장 방향으로 명시                    │ 클라우드 네트워크 이해       │
  │ (향후 확장)          │ 실시간 탐지 아닌 사후 분석 레이어로 활용   │ (졸업작품 범위 외)           │
  └──────────────────────┴────────────────────────────────────────────┴──────────────────────────────┘
