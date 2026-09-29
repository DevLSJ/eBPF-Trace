// Package config reads runtime settings from the environment (.env via compose).
package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/model"
)

type Config struct {
	Port string // BACKEND_PORT, eBPF-project와 동일하게 8000

	// EventSource: "gadget"(Linux, root 필요) | "mock"(로컬 개발·데모)
	EventSource string
	Gadgets     []model.Kind
	// ContainerName: 특정 컨테이너만 관찰 (1단계 --containername 대응). 비우면 전체.
	ContainerName string
	// IgnoreContainers: 관찰 대상에서 제외할 컨테이너 이름 glob (자기 스택 보호)
	IgnoreContainers []string
	// WatchContainers: 비우면 전체, 채우면 맞는 이름만 평가·격리 (예: sg-install-* — 설치 샌드박스만)
	WatchContainers []string

	// ContainerDiscovery: 가젯 소스가 컨테이너를 찾는 방법 — docker-events(기본) | fanotify(IG 기본 runc 훅, Docker Desktop 에선 동작 안 함)
	ContainerDiscovery string

	// ResolveDNS: trace_dns 를 함께 돌려 connect 이벤트에 목적지 도메인을 붙인다 (allowHosts/denyHosts 에 필요)
	ResolveDNS bool

	// EnforceKill=false면 kill 정책도 알림만 (전역 dry-run)
	EnforceKill bool
	DockerHost  string

	DatabaseURL string
	RedisURL    string
	PolicyFile  string

	AdminToken     string
	AllowedOrigins []string

	// NormalEventRate: 정상 판정 이벤트를 WebSocket으로 보내는 초당 상한 (위반은 항상 전송)
	NormalEventRate int
	EventBuffer     int
	StatsInterval   time.Duration
}

func Load() (Config, error) {
	c := Config{
		Port:               env("BACKEND_PORT", "8000"),
		EventSource:        env("EVENT_SOURCE", "gadget"),
		ContainerName:      env("CONTAINER_NAME", ""),
		IgnoreContainers:   list(env("IGNORE_CONTAINERS", "supplyguard-*")),
		WatchContainers:    list(env("WATCH_CONTAINERS", "")),
		ContainerDiscovery: env("CONTAINER_DISCOVERY", "docker-events"),
		DockerHost:         env("DOCKER_HOST", "unix:///var/run/docker.sock"),
		DatabaseURL:        env("DATABASE_URL", ""),
		RedisURL:           env("REDIS_URL", ""),
		PolicyFile:         env("POLICY_FILE", "policies/default.yaml"),
		AdminToken:         env("ADMIN_TOKEN", ""),
		AllowedOrigins:     list(env("ALLOWED_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173")),
	}
	var err error
	if c.EnforceKill, err = boolEnv("ENFORCE_KILL", false); err != nil {
		return c, err
	}
	if c.ResolveDNS, err = boolEnv("RESOLVE_DNS", true); err != nil {
		return c, err
	}
	if c.NormalEventRate, err = intEnv("NORMAL_EVENT_RATE", 50); err != nil {
		return c, err
	}
	if c.EventBuffer, err = intEnv("EVENT_BUFFER", 4096); err != nil {
		return c, err
	}
	secs, err := intEnv("STATS_INTERVAL_SEC", 1)
	if err != nil {
		return c, err
	}
	c.StatsInterval = time.Duration(secs) * time.Second

	for _, g := range list(env("GADGETS", "exec,open,connect")) {
		k := model.Kind(g)
		if !k.Valid() {
			return c, fmt.Errorf("GADGETS: unknown kind %q (exec, open, connect)", g)
		}
		c.Gadgets = append(c.Gadgets, k)
	}
	if c.ContainerDiscovery != "docker-events" && c.ContainerDiscovery != "fanotify" {
		return c, fmt.Errorf("CONTAINER_DISCOVERY: %q (docker-events | fanotify)", c.ContainerDiscovery)
	}
	if c.EventSource != "gadget" && c.EventSource != "mock" {
		return c, fmt.Errorf("EVENT_SOURCE: %q (gadget | mock)", c.EventSource)
	}
	return c, nil
}

func env(key, def string) string {
	if v, ok := os.LookupEnv(key); ok && strings.TrimSpace(v) != "" {
		return strings.TrimSpace(v)
	}
	return def
}

func list(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func boolEnv(key string, def bool) (bool, error) {
	v := env(key, "")
	if v == "" {
		return def, nil
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return def, fmt.Errorf("%s: %w", key, err)
	}
	return b, nil
}

func intEnv(key string, def int) (int, error) {
	v := env(key, "")
	if v == "" {
		return def, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil || n <= 0 {
		return def, fmt.Errorf("%s: positive integer required", key)
	}
	return n, nil
}
