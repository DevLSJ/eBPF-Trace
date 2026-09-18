# 사건 대응 워크스페이스 · 구현과 운영

2026-09-18. 기존 설계의 핵심 승인형 흐름을 구현했다. 이 문서는 **구현·시험 결과와 실제 운영 활성화 조건을 구분**한다. 외부 알림, 운영 방화벽 적용, ML Production 승격은 기본 비활성이다.

## 이번에 구현한 흐름

`피처·규칙/모델 관측 → 사건 통합 → 내구성 알림 → 담당자 인수 → 조사 → 별도 승인 → 현장 적용 확인 → 억제 검증 → 정책 해제 확인 → 복구 관찰 → 종결`

| 영역 | 구현 |
| --- | --- |
| 사건·백엔드 | 탐지 이벤트와 사건·알림 Outbox를 같은 트랜잭션으로 저장. 스캔은 출발지·대상, Flood는 대상 서비스 중심으로 묶고 LIVE/훈련 실행을 분리. 원본 이벤트 연결 유지 |
| 개인 계정 | scrypt 비밀번호, 서버 저장 세션, HttpOnly/SameSite 쿠키, CSRF·Origin·HTTPS 검증, 로그인 시도 제한, viewer/analyst/responder/approver/admin 역할 |
| 인수·인계 | 중복 인수 방지, 버전 기반 동시 수정 충돌 처리, 담당자·판단 근거·시각의 감사 기록 |
| 알림 | P1 Slack·이메일, P2 Slack, 내부 알림함. 인수 기한 초과 시 상향 알림. 제공자 접수와 사람 인수를 별도 기록 |
| 전달 신뢰성 | DB Outbox, 중복 키, 발송 lease, 최대 5회 재시도, Slack Retry-After 준수, 결과 불명 `unknown` 표시. 불명 상태의 자동 재전송은 하지 않음 |
| Slack 인수 | 원문 HMAC 서명·5분 타임스탬프·워크스페이스·개인 사용자 매핑 검증. 버튼으로 인수만 가능; 차단 승인은 인증된 웹 화면에서 수행 |
| 대응 | 대상 서비스·관측 출발지·보호 CIDR·TTL·현장 상태 검증, 정책 SHA-256 고정, 5분 미리보기, 요청자와 다른 운영자 승인, 30초 명령 유효기간 |
| 현장 에이전트 | HTTPS·지점별 토큰·HMAC 명령, SQLite 실행 원장, 중복 명령으로 TTL 연장 금지, nftables 전용 테이블과 커널 timed set, 즉시 해제·재시작 정리 |
| 복구 | 적용 접수와 효과 확인을 구분. 정상 요청 성공률·유입 감소·정책 해제 영수증·연속 관측을 확인해야 종결 가능 |
| ML 운영 | 25개 피처·schema 2·artifact hash·라이브러리 버전 확인, Offline/Shadow/Advisory/Production 단계, 승격 게이트, 판정 모델·점수의 근거 저장, 운영 추론 오류 시 Shadow로 폴백 |
| UI/UX | 사건 받은편지함, 내 사건·미배정 필터, 단계별 다음 행동, 개요·증거·대응·타임라인, 승인함, 알림 센터, 자산·대응 지점, 모델 운영, JSON 사건 보고서 |

기존 탐지 대시보드는 `/#overview`, 새 기본 화면은 `/#incidents`다. 모바일에서는 다음 행동을 사건 헤더 바로 아래에 배치한다. 화면의 상태는 서버에 저장되고 새로고침 후 유지된다. 세션 만료 시 로그인 화면으로 돌아온다.

## 성공지표와 완료 조건

| 지표/조건 | 기준과 측정 방식 |
| --- | --- |
| MTTA | 사건 생성 → 담당자 인수, 평균·p95·표본 수, LIVE/훈련 별도 |
| MTTC | 사건 생성 → 관측 근거를 확인한 억제 상태. 명령 접수 시각을 성공으로 계산하지 않음 |
| MTTR | 사건 생성 → 정책 해제와 복구 관찰을 마친 종결 |
| MTTD | 독립된 실제 공격 시작 시각이 없으면 미측정. 0초로 채우지 않음 |
| 억제 확인 | 현장 적용 영수증 + 정상 성공률 ≥99%인 관측 2개 이상 + 최신 유입량이 사건 최대 유입량의 50% 이하 |
| 복구 확인 | 활성·결과 불명 정책 없음 + 해제 영수증 + 기본 60초의 정상 관측. 관측 공백은 기본 30초 이하 |
| 알림 | 제공자 접수/실패/불명/미설정/담당자 인수 구분. 실제 채널이 미설정이면 전달 성공률을 만들지 않음 |
| 안전성 | 자기 승인·보호 주소·범위 밖 서비스·과도한 TTL·오래된 에이전트·같은 대응 지점의 중복 실행 거부 |
| ML 승격 | 독립 환경·공격 범위 시험, F1 ≥0.80, FPR ≤0.05, LIVE Shadow 7일·정상 추론 1,000개, 피처/추론 실패 ≤1%, p95 추론 ≤100ms, 운영자 검토 |

ML 게이트는 독립 평가 자료를 만드는 기능이 아니다. 배포 관리자가 공급한 manifest의 근거와 축적된 관측을 검사한다. 개발용 묶음은 독립 검증을 `false`로 생성하며 운영 승격이 거부된다. 관측 점수 변화는 진단용 평균 차이이고 검증된 드리프트 통계 검정이 아니다. 미라벨 운영 관측으로 F1·정확도·FPR을 추정하지 않는다. Shadow는 LIVE에서 기본 1/100 결정적 표본추출, Production은 모든 추론을 기록한다.

## 검증

- 백엔드 테스트: 인증·CSRF·역할·개인 세션, 사건/Outbox 원자성, 원본·LIVE/훈련 격리, 인수 충돌, 2인 승인, TTL·보호 주소·전역 중지, 적용/해제 영수증, 복구 관찰, Slack 서명·429·재전송, ML 승격 거부·판정 근거·자동 폴백.
- PostgreSQL 전용 `ebpf_test` DB의 새 Alembic migration과 Redis 통합 테스트. 운영 DB에는 적용하지 않았다.
- 브라우저 전체 20개: 기존 16개 회귀 검사 + 데스크톱/모바일의 2인 승인형 대응 완주·자산 등록·화면 이동·보고서·가로 넘침 검사. 새 훈련 실행 ID로 바로 이동하므로 기존 사건과 혼동하지 않는다.
- 에이전트 단위 테스트: HMAC·허용 범위·명령 삽입 방지·보호 주소·재전송·오프라인 만료·재시작·권한 오류.
- Linux `unshare --net` 격리 시험: 선택 출발지 차단, 다른 출발지와 서비스 연결 유지, 백엔드/워커 없이 커널 TTL 자동 만료, 명시적 해제, rate-limit 설치·해제, 별도 테이블 보존을 실제 nftables로 확인했다. 시험 TTL 3초는 커널 시험에만 사용하며 API의 최소 30초 조건은 유지한다.

커널 시험은 **패킷 레벨 어댑터 검증**이다. 공격 부하에서 rate-limit 처리량이나 전체 운영 환경의 정상 서비스 SLA를 입증한 것은 아니다. 브라우저 완주 시험의 서비스 관측은 명시된 모의 어댑터의 값이다.

```bash
.venv/bin/python -m ruff check backend collector ml infra response_agent
.venv/bin/python -m pytest -q
# TEST_DATABASE_URL / TEST_REDIS_URL이 없으면 외부 통합 4개는 skip
cd frontend
npm run build
npm run test:e2e
```

Linux의 독립 namespace 시험은 `sudo`·`nft`·`ip`·`unshare`가 필요하다. 호스트 namespace와 분리되지 않으면 시험 코드는 중단한다.

```bash
.venv/bin/python infra/verify_response_kernel.py
```

## 로컬에서 체험

Python 3.14 / Node 24. 저장소 루트에서 실행한다. 비밀번호는 대화형 입력이며 기본 운영 계정을 만들지 않는다.

```bash
DATABASE_URL=sqlite+aiosqlite:///./ebpf.db .venv/bin/python -m alembic upgrade head
DATABASE_URL=sqlite+aiosqlite:///./ebpf.db .venv/bin/python -m infra.operators --username operator --name 운영자 --role admin
DATABASE_URL=sqlite+aiosqlite:///./ebpf.db .venv/bin/python -m infra.operators --username approver --name 승인자 --role approver
DATABASE_URL=sqlite+aiosqlite:///./ebpf.db OPS_ALLOW_INSECURE_LOCAL=true PUBLIC_BASE_URL=http://127.0.0.1:5173 .venv/bin/python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000
```

별도 터미널에서 `cd frontend && npm run dev`. `http://127.0.0.1:5173/#incidents`에 접속한다.

1. 운영자 로그인 → `대응 훈련 시작`. 새 사건으로 자동 이동한다.
2. `확인하고 맡기` → 판단 근거 입력 → `조사 시작`.
3. 대응 탭 → 범위·기한 검토 → `대응 미리보기 생성`.
4. 다른 브라우저 프로필에서 승인자로 로그인 → 같은 사건 → 근거와 확인 체크 후 승인.
5. 적용 확인과 정상 관측을 기다림 → `억제 효과 확인`.
6. 해제 근거 → `즉시 해제 요청` → 해제 영수증/정상 관측 확인 → `복구 관찰 시작`.
7. 기본 60초 연속 관찰 후 `정상 복구 확인`. 타임라인과 보고서 확인.

훈련은 실제 패킷을 만들지 않고 외부 메시지를 전송하지 않는다. 개인 비밀번호나 토큰을 localStorage에 저장하지 않는다.

## 실제 운영 활성화 전 준비

### HTTPS·계정·배포

이번 작업에서는 EC2 운영 배포·Git push를 하지 않았다. 기존 운영 화면은 자동 변경되지 않는다. 배포 전에 DB 백업, 디스크 여유, 마이그레이션, 계정과 별도 승인자를 준비한다. 변경은 추가 테이블 중심이므로 롤백은 우선 이전 애플리케이션 버전으로 복귀하고 새 테이블을 보존한다. 감사 이력이 필요한 상태에서 Alembic downgrade로 새 테이블을 삭제하지 않는다.

- 공개 접속에는 유효한 TLS 인증서가 필요하다. 현재 기본 Nginx 예제는 HTTP용이므로 별도 HTTPS 종단을 구성해야 한다.
- `PUBLIC_BASE_URL`과 `ALLOWED_ORIGINS`를 실제 HTTPS origin으로 맞춘다.
- 신뢰하는 프록시만 `X-Forwarded-Proto: https`를 전달하고 Uvicorn의 `FORWARDED_ALLOW_IPS`를 그 프록시의 명시적 주소로 설정한다. 외부에서 backend로 직접 접속하지 못하게 한다. 임의의 전달 헤더를 신뢰하도록 공개하지 않는다.
- `OPS_ALLOW_INSECURE_LOCAL=false` 유지. 공개 HTTP 로그인은 의도적으로 거부한다.
- 컨테이너에서도 `docker compose exec backend python -m infra.operators ...`로 개인 계정을 발급할 수 있다. 계정을 재발급하면 기존 세션은 폐기된다.
- 기존 관리자 토큰은 기존 설정/시나리오 API용이며 새 워크스페이스 개인 계정을 대체하지 않는다.

### Slack·이메일

`.env.example`의 `OPS_NOTIFICATIONS_ENABLED=true`, Slack Bot 토큰·팀 ID·채널, 필요시 escalation 채널을 설정한다. 개인 계정 CLI의 `--slack-user-id`로 실제 승인된 사용자를 매핑한다. Slack의 Interactivity Request URL은 `https://<서비스>/api/integrations/slack/interactions`이다. `SLACK_SIGNING_SECRET`이 필요하다.

이메일은 `SMTP_HOST`, `SMTP_PORT`, `SMTP_FROM`, `NOTIFICATION_EMAIL`, 필요한 SMTP 인증을 설정한다. 465는 SSL, 나머지는 STARTTLS 사용이다. Gmail 주소를 **수신자**로 쓰는 데 메일함 읽기 권한은 필요 없다. 실제 제공자 전달·반송·수신과 사람의 인수 확인은 별도 현장 시험이 필요하다. 기존 `SLACK_WEBHOOK_URL` 직접 이벤트 발송 경로는 Collector에서 제거했고, 새 사건 Outbox를 사용한다.

P1 인수 기한은 2분, P2 10분, P3 1시간, P4 24시간이다. P1/P2 사건의 미인수 상향 알림은 별도 채널/이메일 설정을 사용한다. 제공자 응답을 잃은 `unknown`은 담당자가 중복 가능성을 검토하고 근거를 남긴 뒤 수동 재시도한다.

### 모델 후보

관리자가 신뢰하는 **로컬** benchmark 묶음만 패키징한다. 업로드된 pickle을 읽는 HTTP API는 없다.

```bash
.venv/bin/python -m ml.package_shadow /path/to/trusted-benchmark.pkl ml/models/shadow/candidate-v1 --id candidate-v1
```

`SHADOW_MANIFEST_PATH`를 생성한 `manifest.json` 경로로 설정해 backend를 재시작한다. Docker의 기존 models 읽기 전용 마운트를 사용하면 `/app/models/shadow/candidate-v1/manifest.json`이다. 모델 화면에서 근거를 입력하고 `Shadow 시작`을 선택한다. version·해시·피처·런타임 검사가 실패하면 사용할 수 없다. 독립 검증과 LIVE 관측을 충족하기 전에는 다음 단계 버튼과 API가 승격을 막는다. 자동 차단은 모델 Production 승격과 무관하게 비활성이다.

### 현장 대응 지점

실제 Linux 대상의 자산/서비스·관리/DNS/Collector 보호 CIDR을 먼저 등록하고, UI에서 `nftables` 지점의 일회 표시 토큰을 발급한다. 토큰은 비밀 저장소/권한 제한된 실행 환경으로 전달한다. `response_agent/config.example.json`은 TEST-NET 예시이며 실주소가 아니다.

- 서버 `RESPONSE_LIVE_ENABLED=true`와 현장 `--execute`가 모두 필요하다. 전역 중지가 꺼져 있고 다른 승인자가 승인해야 한다.
- 현장 `allowed_services`는 정확한 `IP:port/protocol` 목록이다. 서버 정책보다 넓게 허용하지 않는다.
- 에이전트는 `nft` 실행 권한이 필요하다. backend 컨테이너에 호스트 방화벽 권한을 부여하지 않는다.
- 로컬 SQLite 원장은 재시작 후 유지되는 디렉터리와 제한된 권한을 사용한다.
- 보호 CIDR·서비스·최대 TTL은 서버와 현장 모두에서 검사한다. 정상 서비스 상태나 제어 채널 확인에 실패하면 현장 해제를 시도하고, 커널 TTL은 독립적으로 유지된다.

```bash
# EBPF_RESPONSE_TOKEN은 비밀 환경으로 주입; CLI 인수에 토큰을 넣지 않는다.
.venv/bin/python -m response_agent.agent --config /etc/ebpf-response/config.json --execute
```

현장 서비스 probe가 `observation_file`에 다음 JSON을 원자적으로 갱신해야 한다. 파일이 15초보다 오래되거나 값이 없으면 정상 상태를 꾸미지 않고 대응을 중단한다. ingress의 관측 위치, 정상 요청의 분모, 정책 적중량 산출을 환경에 맞게 연결해야 하며 **이번 작업에서 실제 서비스 probe를 배포하지 않았다**.

```json
{"healthy": true, "success_rate": 0.999, "latency_ms": 12.4, "ingress_pps": 350, "policy_hits": 4200, "normal_sessions": 12}
```

이는 형식 예시이며 측정 결과가 아니다. 요청 성공률은 독립 정상 요청 probe, 유입량은 명시된 관측 위치, 적중량은 실제 정책 카운터에서 가져온다. UI 미리보기의 출발지별 정상 세션 영향은 아직 `미확인`이다. NAT·공유 프록시, 상위 회선 포화, 애플리케이션 공격은 별도 검토/어댑터가 필요하다.

### 보존과 유지보수

관측 테이블의 기본 보존 기준은 `OPS_RETENTION_DAYS=30`. 아래 명령은 기본 dry-run이며 `--apply`를 명시해야 실제 정리한다. 사건·원본 이벤트·알림·승인·감사 이력은 이 명령에서 삭제하지 않는다. 정책에 따라 승인된 스케줄러로 실행하며 이번 작업에서는 운영 정리를 실행하지 않았다.

```bash
.venv/bin/python -m infra.ops_retention
# 정리 범위 확인 및 백업 후에만:
.venv/bin/python -m infra.ops_retention --apply
```

## 아직 남은 운영 검증

### 공개 HTTPS 테스트 배포

`docker-compose.https.yml`은 Caddy의 TLS-ALPN 인증과 자동 갱신을 사용한다. 서버의 TCP 443 인바운드와 해당 서버를 가리키는 공개 DNS가 필요하다. 기존 HTTP Collector 연결은 유지한다. `infra/configure_public_test.py --env-file /home/ubuntu/ebpf-project/.env --host <공개호스트> --proxy-subnet <Docker-내부서브넷>`으로 기존 비밀 설정을 백업하고 테스트 모드를 명시적으로 활성화한다. `infra/deploy.sh`는 HTTPS 인증서 검증을 통과한 후에만 테스트 계정을 준비한다.

사용자 요청에 따른 `admin/admin`은 `OPS_TEST_ACCOUNT_MODE=true`에서만 로그인할 수 있다. 비밀번호 변경을 강제하지 않으며, 일반 계정의 12자 이상 정책은 유지한다. 이 모드와 실제 대응·사건 외부 알림·레거시 Slack 전송은 함께 활성화할 수 없다. `OPS_TEST_ACCOUNT_MODE=false`로 전환하면 기존 테스트 세션도 거부된다. 공개 테스트 계정으로 민감한 실제 데이터를 다루지 않는다. 운영 전환에는 테스트 계정 중단과 별도 개인 계정 발급이 필요하다.

실제 Slack/SMTP 송수신, HTTPS·프록시 설정, 개별 서비스 probe 연동, 운영 부하에서 지연/정상 트래픽 영향, 독립 ML 평가와 최소 7일 Shadow 관측이 필요하다. SMS·당직표 연동, 이메일 요약, Slack 스레드 지속 갱신, 정상 세션별 영향 추정, 자동 승인형 대응은 이번 구현 범위에 포함하지 않았다. 완료율이나 실제 SLA 달성률을 시험용 관측값으로 대체하지 않는다.
