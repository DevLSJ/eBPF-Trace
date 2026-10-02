# Supply Chain Watch

LLM 기반 오픈소스 커밋 실시간 악성 행위 탐지 시스템 (캡스톤).
전 세계 공개 GitHub 레포지토리의 커밋을 실시간 수집하고, 정적 분석(1차) → LLM(2차) 파이프라인으로
공급망 공격(C2 연결·환경변수 탈취·난독화·CI 시크릿 유출 등)을 배포 전 단계에서 탐지·시각화·경보한다.

설계 문서는 `docs/`, 작업 규칙은 `CLAUDE.md`, 로드맵은 `docs/08-roadmap.md` 참고.

## 구성

| 서비스 | 경로 | 스택 | 포트 |
|---|---|---|---|
| web | `apps/web` | Next.js 15, Tailwind | 3000 |
| gateway | `apps/gateway` | Node 22, Express, ws, pg, ioredis | 4000 |
| engine | `apps/engine` | Python 3.12(uv), FastAPI, anthropic | 8000 |
| postgres | docker | PostgreSQL 16 | 5433→5432 |
| redis | docker | Redis 7 | 6380→6379 |

공용 타입: `packages/shared-types`.

## 사전 준비

- Node 22 + pnpm(`corepack enable`), Python용 `uv`, Docker Desktop
- `.env` 작성 (`.env.example` 복사). LLM 키·GitHub 토큰은 `.env`에만 둔다(커밋 금지).
- (선택) `brew install ngrok` — 로컬 Webhook 수신 터널

## 실행

```bash
pnpm install
pnpm dev                 # 인프라 up + 마이그레이션 + engine·gateway·web 동시 기동
```

개별 실행:

```bash
pnpm infra:up            # postgres·redis (docker compose)
pnpm migrate             # infra/sql/*.sql 적용 (멱등)
pnpm dev:engine          # FastAPI :8000
pnpm dev:gateway         # Express + ws :4000
pnpm dev:web             # Next.js :3000
pnpm tunnel              # ngrok 고정 도메인으로 gateway 노출
```

접속: http://localhost:3000 (관리자 비밀번호는 `.env` `ADMIN_PASSWORD`).

## 상태 확인

```bash
curl localhost:8000/health    # engine
curl localhost:4000/health    # gateway (db·redis·engine 체크)
```

## 검증

```bash
pnpm -r typecheck
cd apps/engine && uv run pytest
```

## 배포 (EC2)

```bash
docker compose -f infra/docker-compose.full.yml up -d --build
```

자세한 외부 서비스 설정은 `docs/11-setup-guides.md`.
