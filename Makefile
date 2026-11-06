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
# 공급망 검사(11/06): 백엔드가 맥에서 직접 돌면 /scan 을 만들 수 없고 검사기 컨테이너와 이름 있는 볼륨을 나눌 수도 없다 —
# 저장소 안 .scan-work 를 작업 폴더로 쓰고 검사기에는 같은 폴더를 bind(SCAN_VOLUME 이 절대 경로면 bind). Docker Desktop 이 켜져 있어야 한다
DEV_SCAN := SCAN_DIR=$(CURDIR)/.scan-work SCAN_VOLUME=$(CURDIR)/.scan-work

.PHONY: setup dev backend frontend mock stack-up stack-down test build sandbox-up sandbox-down vm-open vm-close

# sg-vm(이 Mac 의 UTM VM) 화면을 http://localhost:$(VM_PORT) 로 — SSH 터널(별칭 sg-vm)이 VM 의 nginx 80 으로 넘긴다(11/05).
# nginx 가 Host 를 포트 없이 넘겨 로그인 Origin 검사는 같은 호스트로 통과한다 — ALLOWED_ORIGINS 를 바꾸지 않는다. UTM VM 이 켜져 있어야 한다
VM_PORT ?= 8080
VM_TUNNEL := 127.0.0.1:$(VM_PORT):127.0.0.1:80

## setup: 새 PC · 새 clone 에서 처음 한 번(11/06) — 도구 확인 → 프론트 의존성(npm ci) · e2e 브라우저(chromium) · Go 모듈
setup:
	@command -v go >/dev/null || { echo "Go 1.26 이상이 필요합니다 — https://go.dev/dl"; exit 1; }
	@command -v node >/dev/null || { echo "Node 22.12 이상이 필요합니다(frontend/.nvmrc) — https://nodejs.org"; exit 1; }
	@command -v docker >/dev/null || echo "참고: Docker 가 없으면 공급망 검사 · make stack-up · sandbox-up 은 쓸 수 없습니다(make dev · make test 는 됨)"
	@echo "go $$(go env GOVERSION) · node $$(node -v)"
	cd backend && go mod download
	cd frontend && npm ci --no-audit --no-fund && npx playwright install chromium
	@echo "준비 끝 — make dev(http://127.0.0.1:5173, admin/admin) · make test · cd frontend && npx playwright test"

## dev: 백엔드(mock, :8000) + Vite(:5173) 를 같이 띄운다. Ctrl-C 로 둘 다 종료. 프론트 의존성이 없으면 먼저 npm ci(새 clone)
dev:
	@test -d frontend/node_modules || { echo "frontend 의존성이 없어 먼저 설치합니다(npm ci) — 처음 한 번은 make setup 권장"; cd frontend && npm ci --no-audit --no-fund; }
	@trap 'kill 0' EXIT INT TERM; \
	  (cd backend && EVENT_SOURCE=mock ENFORCE_KILL=true DEMO_ENABLED=true ALLOWED_ORIGINS=$(MOCK_ORIGINS) $(DEV_AUTH) $(DEV_EVAL) $(DEV_SCAN) go run ./cmd/server) & \
	  (cd frontend && npm run dev) & \
	  wait

## backend: mock 소스 백엔드만 (목업 '실제 백엔드' 모드가 붙을 수 있게 CORS 출처 포함)
backend:
	cd backend && EVENT_SOURCE=mock ENFORCE_KILL=true DEMO_ENABLED=true ALLOWED_ORIGINS=$(MOCK_ORIGINS) $(DEV_AUTH) $(DEV_EVAL) $(DEV_SCAN) go run ./cmd/server

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
	@test -d frontend/node_modules || { echo "frontend 의존성이 없어 먼저 설치합니다(npm ci)"; cd frontend && npm ci --no-audit --no-fund; }
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

vm-open:
	@if pgrep -f 'L $(VM_TUNNEL) sg-vm' >/dev/null; then echo "터널 이미 열림"; \
	else ssh -f -N -o ExitOnForwardFailure=yes -o ServerAliveInterval=30 -L $(VM_TUNNEL) sg-vm && echo "터널 열림"; fi
	@curl -sf -m 5 -o /dev/null http://localhost:$(VM_PORT)/health && echo "sg-vm → http://localhost:$(VM_PORT)" || { echo "health 응답 없음 — UTM VM(utmctl start Linux-VM) · 스택 확인"; exit 1; }

vm-close:
	@pkill -f 'L $(VM_TUNNEL) sg-vm' && echo "터널 닫음" || echo "열린 터널 없음"
