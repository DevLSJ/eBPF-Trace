---
name: finish-ebpf
description: eBPF Trace 프로젝트의 남은 운영화 작업을 정해진 순서대로 진행한다. 인자로 특정 단계 번호나 키워드를 주면 그 단계부터 시작한다.
---

# eBPF Trace — 남은 작업 진행 프롬프트

너는 eBPF Trace 프로젝트의 운영화(운영 배포·검증)를 완료하는 작업을 맡는다.
아래 순서를 **위에서부터** 진행하되, `$ARGUMENTS`가 주어지면 해당 단계/키워드부터 시작한다.
각 단계는 **완료 근거(검증 결과)를 확인한 뒤에만** 다음으로 넘어간다. 근거 없이 완료로 처리하지 않는다.

## 진행 원칙 (매 단계 공통)

- 규칙 기반 탐지가 운영 기본이다. 실험 ML 모델을 함부로 운영에 승격하지 않는다.
- 자동 차단·외부 알림·ML Production 승격은 기본 비활성이다. 활성화는 명시적 지시와 근거가 있을 때만.
- 파괴적 작업(운영 DB 삭제, 볼륨 제거, force push, SG 대량 변경)은 실행 전 사용자 확인을 받는다.
- 비밀값(.env, 토큰, 키)은 Git에 넣지 않고 값을 출력하지 않는다.
- 접속: EC2 `ssh -i "don forget.pem" ubuntu@203.0.113.10`, VM `ssh ubuntu@192.168.64.2`.
- 참고 문서: `docs/overview.md`, `docs/operations-guide.md`, `docs/status-and-verification.md`.

## 작업 순서

### 1. VM Collector v2 갱신 (스키마 1 → 2)
현재 운영 Collector는 스키마 1로 연결돼 있다. v2(25개 피처)로 갱신한다.
- VM runner 계정에 Collector start/stop 비대화식 sudo 권한 부여 (`/etc/sudoers.d/ebpf-collector-deploy`, `sudo visudo -cf`로 검증).
- CI의 `infra/update_collector.py` 배포 job을 재실행. import 검사 후 서비스 재시작.
- **완료 근거**: `sudo systemctl status ebpf-tunnel ebpf-collector` active, `/health`에서 연결 및 **피처 스키마 2** 관측 확인, 실패 시 이전 패키지로 복구되지 않았음.

### 2. EC2 용량 확보 후 CI/CD 배포 복구
디스크 787 MiB < 최소 900 MiB로 배포가 중단된 이력이 있다.
- 실제 EBS/파티션/파일시스템을 조회하고 증설 또는 빌드 위치 분리를 결정. **운영 DB 볼륨은 삭제하지 않는다.**
- 사용 중이지 않은 오래된 이미지만 정리. `python3 infra/check_disk.py --minimum-mib 900` 통과 확인.
- `main` 푸시 → 테스트 → 이미지 빌드/push → VM runner의 EC2 배포.
- **완료 근거**: CI 테스트/이미지 push/대상 SHA 배포 성공, `/health` 응답 정상, 기존 DB 보존 확인.

### 3. 실제 알림(Slack/SMTP) 전달 검증
사건 대응 Outbox 기반 알림의 실제 채널 전달을 검증한다.
- `.env`에 `OPS_NOTIFICATIONS_ENABLED=true`, Slack Bot 토큰·팀 ID·채널, `SLACK_SIGNING_SECRET`, SMTP 설정.
- 개인 계정 CLI `--slack-user-id`로 승인자 매핑. Slack Interactivity Request URL 설정.
- **완료 근거**: 제공자 접수/실패/불명 상태가 구분되어 기록되고, 실제 채널에서 P1/P2 알림 수신 및 담당자 인수 확인. 결과 불명(`unknown`)은 자동 재전송하지 않음.

### 4. 독립 ML 검증 · LIVE Shadow 7일
시험 F1 90.98%는 4/14종 공격 한정 개발 실험이다. 운영 승격 근거를 만든다.
- 시험에 없던 10종(DDoS·PortScan·DoS 4종·Heartbleed·Infiltration·Web SQLi/XSS) + Bot을 포함한 **신규 실행**을 학습과 다른 환경에서 수집. 센서 위치·타임존·NAT·공격 시작/종료 시각 기록.
- 독립 평가로 F1 ≥ 0.80, FPR ≤ 0.05 확인. `ml.package_shadow`로 신뢰하는 로컬 묶음만 패키징 → `SHADOW_MANIFEST_PATH` 설정 → 모델 화면에서 Shadow 시작.
- LIVE Shadow 7일·정상 추론 1,000개·피처/추론 실패 ≤ 1%·p95 추론 ≤ 100ms 축적.
- **완료 근거**: 독립 검증 manifest와 축적된 관측이 승격 게이트를 통과. (통과 전에는 승격 API/버튼이 막혀 있어야 정상.)

### 5. Terraform 기존 자원 정합
- `ec2:DescribeInstances` 등 조회 권한 확보 후 실제 자원 조회. 기존 EC2/VPC/SG를 `terraform import`.
- 무교체 `terraform plan` 확인, SG 규칙 실측(80/443/관리자 SSH만, 5432/6379/8000 미개방).
- 인프라 워크플로우용 OIDC 역할·S3 state bucket 설정.
- **완료 근거**: import 계획, 자원 교체 없는 plan, SG 실측 결과, OIDC/state 설정 확인. (NF-M02 충족)

### 6. HTTPS 종단 구성
- `docker-compose.https.yml`(Caddy TLS-ALPN). 443 인바운드 + 공개 DNS 필요.
- `PUBLIC_BASE_URL`/`ALLOWED_ORIGINS`를 실제 HTTPS origin으로. 신뢰 프록시만 `X-Forwarded-Proto` 전달, `FORWARDED_ALLOW_IPS` 명시. `OPS_ALLOW_INSECURE_LOCAL=false` 유지.
- **완료 근거**: 유효 TLS 인증서로 공개 HTTPS 접속, 인증서 자동 갱신 동작, 기존 HTTP Collector 연결 유지.

### 7. 비기능 실측 · 통합 재검증 · 릴리즈
- 비기능 실측: NF-P08(전체 파이프라인 처리량), NF-S01(eBPF capability 축소 `docker inspect`), NF-P03(원격 P95 — 한국↔호주 거리 한계 명시).
- 통합 재검증: 격리망 `infra/lab_e2e.py`·`infra/verify_response_kernel.py`, 실 PostgreSQL/Redis, 사용자 경로 P95, 시연 시나리오(SYN Flood ≤ 3초, Port Scan ≤ 5초).
- 문서 정합화(`docs/` 3개 요약본 갱신), 최종 태그·릴리즈.
- **완료 근거**: 실측 수치 기록, 전체 테스트 통과(pytest/ruff/Vite/Playwright), 릴리즈 태그 생성. 시험용 관측값으로 실제 SLA를 대체하지 않음.

## 선택: 사건 대응 · 차단 게이트 운영 배포
2026-09-18/09-23 구현(개인계정·2인승인·nftables·risk_gate·autoresponse)은 **커밋·운영 배포 전** 상태다.
배포하려면: DB 백업 → 디스크 여유 → 마이그레이션 → 계정·승인자 발급 → 이전 버전 롤백 경로 확보(새 테이블은 보존, Alembic downgrade로 삭제 금지).
자동 경로는 기본 꺼짐이며, 켜도 게이트 저위험만 자동 적용되고 나머지는 2인 승인으로 분기한다.

## 인자 처리
- `$ARGUMENTS`가 비어 있으면 1단계부터 순서대로 진행한다.
- 숫자(예: `3`)면 해당 단계부터, 키워드(예: `terraform`, `https`, `shadow`)면 매칭 단계부터 시작한다.
- 시작 전에 `docs/status-and-verification.md`의 현재 상태를 먼저 읽어 이미 끝난 단계를 건너뛴다.
