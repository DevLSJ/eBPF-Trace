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

	// ContainerDiscovery: 가젯 소스가 컨테이너를 찾는 방법 — auto(기본: fanotify 를 먼저, 만들 수 없으면 docker-events)
	// | fanotify(IG 기본 runc 훅, 시작 직후 동작까지 본다. Docker Desktop 에선 EINVAL) | docker-events(Docker 이벤트 API, 시작 직후 약 0.1초를 놓칠 수 있다)
	ContainerDiscovery string

	// ResolveDNS: trace_dns 를 함께 돌려 connect 이벤트에 목적지 도메인을 붙인다 (allowHosts/denyHosts 에 필요)
	ResolveDNS bool
	// DNSGrace: connect 가 DNS 응답보다 먼저 올 때(경쟁) 도메인 없는 공인 IP 연결을 이만큼 기다렸다 다시 조회한다 (DNS_GRACE_MS, 0 = 안 기다림)
	DNSGrace time.Duration

	// EnforceKill=false면 kill 정책도 알림만 (전역 dry-run)
	EnforceKill bool
	DockerHost  string
	// 공급망 검사(10/16): 작업 볼륨(백엔드 경로 · Docker 볼륨 이름) · 검사기 이미지
	ScanDir, ScanVolume, GuardDogImage, OSVImage string

	DatabaseURL string
	RedisURL    string
	PolicyFile  string

	AdminToken string
	// SandboxToken: sg-install CLI 의 세션 보고 · 차단 확인 전용 (ADMIN_TOKEN 과 달라야 한다)
	SandboxToken   string
	AllowedOrigins []string
	// ActorName: 판정 · 적용 · 정책 변경의 처리자 이름 — 요청자를 모를 때(로그인 전 경로 · 내부 작업)만 쓴다
	ActorName string

	// 로그인(10/20): 계정이 없을 때만 쓰는 초기 관리자 · OTP 필수 · 쿠키 Secure · OTP 비밀값 암호화 키
	AdminUser            string
	AdminInitialPassword string
	AuthOTPRequired      bool
	AuthCookieSecure     bool
	AuthSecretKey        string
	// 외부 알림(10/20): 둘 다 비면 비활성. PublicURL 은 알림의 대시보드 링크 앞에 붙는다
	NotifyWebhookURL, NotifySlackURL, PublicURL string
	// AI 도우미(10/20): OLLAMA_URL 이 비면 챗봇 비활성(라우트 없음). 모델은 로컬 Ollama — 데이터가 서버 밖으로 나가지 않는다
	OllamaURL, OllamaModel, OllamaKeepAlive string

	// 시연 실행(10/30): DEMO_ENABLED=true 면 /api/demo 가 열린다(시연 전용 — 운영은 끈다). DemoImage 는 시연 컨테이너 이미지(SG_PIP_IMAGE, sg-install 과 같은 변수)
	DemoEnabled bool
	DemoImage   string

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
		ContainerDiscovery: env("CONTAINER_DISCOVERY", "auto"),
		DockerHost:         env("DOCKER_HOST", "unix:///var/run/docker.sock"),
		ScanDir:            env("SCAN_DIR", "/scan"),
		ScanVolume:         env("SCAN_VOLUME", "supplyguard_scan_work"),
		GuardDogImage:      env("GUARDDOG_IMAGE", "ghcr.io/datadog/guarddog:latest"),
		OSVImage:           env("OSV_SCANNER_IMAGE", "ghcr.io/google/osv-scanner:latest"),
		DatabaseURL:        env("DATABASE_URL", ""),
		RedisURL:           env("REDIS_URL", ""),
		PolicyFile:         env("POLICY_FILE", "policies/default.yaml"),
		AdminToken:         env("ADMIN_TOKEN", ""),
		SandboxToken:       env("SANDBOX_TOKEN", ""),
		ActorName:          env("ACTOR_NAME", "보안 담당자"),
		NotifyWebhookURL:   env("NOTIFY_WEBHOOK_URL", ""),
		NotifySlackURL:     env("NOTIFY_SLACK_URL", ""),
		PublicURL:          env("PUBLIC_URL", ""),
		OllamaURL:          env("OLLAMA_URL", ""),
		OllamaModel:        env("OLLAMA_MODEL", "qwen2.5:3b"),
		OllamaKeepAlive:    env("OLLAMA_KEEP_ALIVE", "30m"),
		DemoImage:          env("SG_PIP_IMAGE", "python:3.12-slim"),
		AllowedOrigins:     list(env("ALLOWED_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173")),
		// 로그인(10/20). 비밀번호 · 키 형식 검사는 쓰는 쪽(auth.SeedAdmin · main 의 validateAuthSecret)이 한다
		AdminUser:            env("ADMIN_USER", "admin"),
		AdminInitialPassword: env("ADMIN_INITIAL_PASSWORD", ""),
		AuthSecretKey:        env("AUTH_SECRET_KEY", ""),
	}
	var err error
	if c.EnforceKill, err = boolEnv("ENFORCE_KILL", false); err != nil {
		return c, err
	}
	if c.AuthOTPRequired, err = boolEnv("AUTH_OTP_REQUIRED", true); err != nil { // 기본 필수 — 끄는 것은 개발 · e2e 만
		return c, err
	}
	if c.AuthCookieSecure, err = boolEnv("AUTH_COOKIE_SECURE", false); err != nil {
		return c, err
	}
	if c.ResolveDNS, err = boolEnv("RESOLVE_DNS", true); err != nil {
		return c, err
	}
	if c.DemoEnabled, err = boolEnv("DEMO_ENABLED", false); err != nil {
		return c, err
	}
	if c.NormalEventRate, err = intEnv("NORMAL_EVENT_RATE", 50); err != nil {
		return c, err
	}
	graceMS, err := nonNegIntEnv("DNS_GRACE_MS", 200)
	if err != nil {
		return c, err
	}
	c.DNSGrace = time.Duration(graceMS) * time.Millisecond
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
		if k == model.KindDNS {
			// trace_dns 는 connect 의 보조 가젯이자 dns 질의 규칙의 소스 — 가젯 목록이 아니라 RESOLVE_DNS 로 켠다(10/30)
			return c, fmt.Errorf("GADGETS: dns 는 가젯 목록에 넣지 않는다 — trace_dns 는 RESOLVE_DNS=true 로 켠다")
		}
		if !k.Valid() {
			return c, fmt.Errorf("GADGETS: unknown kind %q (exec, open, connect)", g)
		}
		c.Gadgets = append(c.Gadgets, k)
	}
	switch c.ContainerDiscovery {
	case "auto", "fanotify", "docker-events":
	default:
		return c, fmt.Errorf("CONTAINER_DISCOVERY: %q (auto | fanotify | docker-events)", c.ContainerDiscovery)
	}
	if c.EventSource != "gadget" && c.EventSource != "mock" {
		return c, fmt.Errorf("EVENT_SOURCE: %q (gadget | mock)", c.EventSource)
	}
	// 같은 값이면 CLI 토큰으로 관리자 쓰기가 열린다 — 두 토큰의 분리가 무너지므로 시작하지 않는다
	if c.AdminToken != "" && c.AdminToken == c.SandboxToken {
		return c, fmt.Errorf("SANDBOX_TOKEN 은 ADMIN_TOKEN 과 달라야 함")
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

// nonNegIntEnv: 0 을 허용하는 정수 (0 = 기능 끔)
func nonNegIntEnv(key string, def int) (int, error) {
	v := env(key, "")
	if v == "" {
		return def, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 0 {
		return def, fmt.Errorf("%s: non-negative integer required", key)
	}
	return n, nil
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
