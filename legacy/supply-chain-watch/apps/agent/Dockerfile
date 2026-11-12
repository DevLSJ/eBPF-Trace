# syntax=docker/dockerfile:1
# 런타임 축 에이전트 빌드 (docs/13 §10). bpf2go가 clang으로 eBPF C를 컴파일해 Go에 임베드한다.
# 빌드 컨텍스트는 저장소 루트(compose/`docker build` 시 지정).
FROM golang:1.23-bookworm AS build
RUN apt-get update && apt-get install -y --no-install-recommends \
    clang llvm libbpf-dev && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY apps/agent/ ./
RUN go mod download
RUN go generate ./...
RUN CGO_ENABLED=0 go build -trimpath -o /agent .

FROM debian:bookworm-slim
COPY --from=build /agent /agent
COPY apps/agent/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
