# SupplyGuard 로컬 개발 진입점. 커널이 없는 macOS/Windows 에서는 mock 이벤트 소스로 돈다.
SHELL := /bin/bash
COMPOSE_MOCK := docker compose -p supplyguard-mock --project-directory . -f deploy/docker-compose.yml -f deploy/docker-compose.mock.yml
MOCK_ORIGINS := http://localhost:5173,http://127.0.0.1:5173,http://127.0.0.1:8766,http://localhost:8766,null
# 로컬 개발 로그인(11/04): admin / admin 으로 바로 대시보드 — OTP 끔 · AUTH_DEV_MODE 로 비밀번호 변경 · 라이선스 단계 건너뜀.
# AUTH_DEV_MODE 는 EVENT_SOURCE=mock 에서만 켜진다(가젯이면 백엔드가 시작 거부). 메모리 저장소라 재시작마다 이 비밀번호로 다시 시작한다.
# 개발 전용 고정값 — 운영 .env 에 쓰지 않는다 (.env.example 참고)
DEV_ADMIN_PW := admin
DEV_AUTH := AUTH_OTP_REQUIRED=false AUTH_DEV_MODE=true ADMIN_INITIAL_PASSWORD=$(DEV_ADMIN_PW)
# sandbox-up(실제 가젯)은 개발 모드를 켜지 않는다 — 아이디와 다른 비밀번호 · 첫 로그인 비밀번호 변경 → 라이선스 → OTP 그대로
SANDBOX_ADMIN_PW := sg-dev-admin-pw
# 평가 결과(GET /api/evaluation): 로컬 개발은 저장소의 bench/reports 를 읽는다(이미지는 /bench/reports)
DEV_EVAL := EVAL_REPORTS_DIR=$(CURDIR)/bench/reports

.PHONY: dev backend frontend mock stack-up stack-down test build sandbox-up sandbox-down

## dev: 백엔드(mock, :8000) + Vite(:5173) 를 같이 띄운다. Ctrl-C 로 둘 다 종료.
dev:
	@trap 'kill 0' EXIT INT TERM; \
	  (cd backend && EVENT_SOURCE=mock ENFORCE_KILL=true DEMO_ENABLED=true ALLOWED_ORIGINS=$(MOCK_ORIGINS) $(DEV_AUTH) $(DEV_EVAL) go run ./cmd/server) & \
	  (cd frontend && npm run dev) & \
	  wait

## backend: mock 소스 백엔드만 (목업 '실제 백엔드' 모드가 붙을 수 있게 CORS 출처 포함)
backend:
	cd backend && EVENT_SOURCE=mock ENFORCE_KILL=true DEMO_ENABLED=true ALLOWED_ORIGINS=$(MOCK_ORIGINS) $(DEV_AUTH) $(DEV_EVAL) go run ./cmd/server

frontend:
	cd frontend && npm run dev

## mock: 정적 목업을 http://127.0.0.1:8766 로 서빙 (파일로 바로 열어도 된다)
mock:
	cd mock && python3 -m http.server 8766 --bind 127.0.0.1

## stack-up / stack-down: 컨테이너 전체 스택(nginx·backend·frontend·postgres·redis) — 루트 .env 필요
##   개발 로그인은 기본 꺼짐. 켜려면 make stack-up AUTH_DEV_MODE=true (또는 .env). 빈 DB 에서 ADMIN_INITIAL_PASSWORD 로 시드할 때만 admin/admin 이 된다
stack-up:
	$(COMPOSE_MOCK) up -d --build --wait
	@curl -fsS "http://127.0.0.1:$${HTTP_PORT:-80}/health" && echo
stack-down:
	$(COMPOSE_MOCK) down

test:
	cd backend && go vet ./... && GOOS=linux go vet ./... && go test -race ./...
	cd frontend && npm run lint && npm run build

build:
	$(COMPOSE_MOCK) build

## sandbox-up: 실제 eBPF 가젯 백엔드를 :8000 에 띄운다 (Docker Desktop VM 위). tools/sg-install 이 여기에 붙는다.
##   설치 샌드박스만 격리하도록 WATCH_CONTAINERS=sg-install-* 로 제한 → 개발 PC 의 다른 컨테이너는 건드리지 않는다.
##   로그인: 메모리 저장소라 실행할 때마다 OTP 비밀값 암호화 키를 새로 만들고, 관리자 admin / $(SANDBOX_ADMIN_PW) 로 시작한다(OTP 는 켜 둠 · AUTH_DEV_MODE 없음).
##   키는 셸 변수로 넘겨(-e AUTH_SECRET_KEY 값 없이) 화면 · docker run 인자에 찍히지 않는다.
sandbox-up:
	docker rm -f supplyguard-sandbox >/dev/null 2>&1 || true
	AUTH_SECRET_KEY=$$(openssl rand -hex 32) && export AUTH_SECRET_KEY && \
	docker run -d --name supplyguard-sandbox --privileged --pid=host \
	  -v /:/host:ro -v /var/run/docker.sock:/var/run/docker.sock \
	  -v /sys/kernel/debug:/sys/kernel/debug -v /sys/fs/bpf:/sys/fs/bpf \
	  -e EVENT_SOURCE=gadget -e HOST_ROOT=/host -e ENFORCE_KILL=true \
	  -e WATCH_CONTAINERS='sg-install-*' -e IGNORE_CONTAINERS='supplyguard-*' \
	  -e AUTH_SECRET_KEY -e ADMIN_INITIAL_PASSWORD=$(SANDBOX_ADMIN_PW) \
	  -p 127.0.0.1:8000:8000 local/supplyguard-backend:dev
	@echo "가젯 이미지 pull 에 시간이 걸릴 수 있습니다. 로그: docker logs -f supplyguard-sandbox"
	@echo "사용: tools/sg-install pip <패키지>   |   tools/sg-install pip ./deploy/demo/reqeusts"

sandbox-down:
	docker rm -f supplyguard-sandbox >/dev/null 2>&1 || true
