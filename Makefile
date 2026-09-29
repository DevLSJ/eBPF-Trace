# SupplyGuard 로컬 개발 진입점. 커널이 없는 macOS/Windows 에서는 mock 이벤트 소스로 돈다.
SHELL := /bin/bash
COMPOSE_MOCK := docker compose -p supplyguard-mock --project-directory . -f deploy/docker-compose.yml -f deploy/docker-compose.mock.yml
MOCK_ORIGINS := http://localhost:5173,http://127.0.0.1:5173,http://127.0.0.1:8766,http://localhost:8766,null

.PHONY: dev backend frontend mock stack-up stack-down test build

## dev: 백엔드(mock, :8000) + Vite(:5173) 를 같이 띄운다. Ctrl-C 로 둘 다 종료.
dev:
	@trap 'kill 0' EXIT INT TERM; \
	  (cd backend && EVENT_SOURCE=mock ENFORCE_KILL=true ALLOWED_ORIGINS=$(MOCK_ORIGINS) go run ./cmd/server) & \
	  (cd frontend && npm run dev) & \
	  wait

## backend: mock 소스 백엔드만 (목업 '실제 백엔드' 모드가 붙을 수 있게 CORS 출처 포함)
backend:
	cd backend && EVENT_SOURCE=mock ENFORCE_KILL=true ALLOWED_ORIGINS=$(MOCK_ORIGINS) go run ./cmd/server

frontend:
	cd frontend && npm run dev

## mock: 정적 목업을 http://127.0.0.1:8766 로 서빙 (파일로 바로 열어도 된다)
mock:
	cd mock && python3 -m http.server 8766 --bind 127.0.0.1

## stack-up / stack-down: 컨테이너 전체 스택(nginx·backend·frontend·postgres·redis) — 루트 .env 필요
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
