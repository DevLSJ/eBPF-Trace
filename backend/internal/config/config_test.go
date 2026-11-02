package config

import (
	"strings"
	"testing"
	"time"
)

func TestTokensMustDiffer(t *testing.T) {
	t.Setenv("ADMIN_TOKEN", "same")
	t.Setenv("SANDBOX_TOKEN", "same")
	if _, err := Load(); err == nil {
		t.Fatal("equal ADMIN_TOKEN and SANDBOX_TOKEN must be rejected")
	}
	t.Setenv("SANDBOX_TOKEN", "other")
	c, err := Load()
	if err != nil || c.SandboxToken != "other" || c.ActorName != "보안 담당자" {
		t.Fatalf("%+v %v", c, err)
	}
	t.Setenv("ADMIN_TOKEN", "")
	t.Setenv("SANDBOX_TOKEN", "")
	t.Setenv("ACTOR_NAME", "심사 위원")
	if c, err := Load(); err != nil || c.ActorName != "심사 위원" {
		t.Fatalf("%+v %v", c, err)
	}
}

// CONTAINER_DISCOVERY(10/20): 기본 auto(fanotify 먼저, 안 되면 docker-events). 세 값만 받는다
func TestContainerDiscovery(t *testing.T) {
	c, err := Load()
	if err != nil || c.ContainerDiscovery != "auto" {
		t.Fatalf("default: %q %v", c.ContainerDiscovery, err)
	}
	for _, ok := range []string{"auto", "fanotify", "docker-events"} {
		t.Setenv("CONTAINER_DISCOVERY", ok)
		if c, err := Load(); err != nil || c.ContainerDiscovery != ok {
			t.Fatalf("%q: %q %v", ok, c.ContainerDiscovery, err)
		}
	}
	for _, bad := range []string{"runc", "Auto", "docker"} {
		t.Setenv("CONTAINER_DISCOVERY", bad)
		if _, err := Load(); err == nil {
			t.Fatalf("CONTAINER_DISCOVERY=%q must be rejected", bad)
		}
	}
}

func TestDNSGrace(t *testing.T) {
	c, err := Load()
	if err != nil || c.DNSGrace != 200*time.Millisecond {
		t.Fatalf("default grace: %v %v", c.DNSGrace, err)
	}
	t.Setenv("DNS_GRACE_MS", "350")
	if c, err = Load(); err != nil || c.DNSGrace != 350*time.Millisecond {
		t.Fatalf("%v %v", c.DNSGrace, err)
	}
	t.Setenv("DNS_GRACE_MS", "0") // 0 = 지연 없음
	if c, err = Load(); err != nil || c.DNSGrace != 0 {
		t.Fatalf("%v %v", c.DNSGrace, err)
	}
	for _, bad := range []string{"abc", "-5"} {
		t.Setenv("DNS_GRACE_MS", bad)
		if _, err := Load(); err == nil {
			t.Fatalf("DNS_GRACE_MS=%q must be rejected", bad)
		}
	}
}

// 로그인(10/20): OTP 는 기본 필수, 쿠키 Secure 는 기본 끔, 초기 관리자 이름 기본 admin.
// AUTH_SECRET_KEY 길이 검사는 여기서 하지 않는다(main 의 validateAuthSecret) — 이 파일의 다른 테스트가 기본 gadget 으로 돈다
func TestAuthSettings(t *testing.T) {
	c, err := Load()
	if err != nil || !c.AuthOTPRequired || c.AuthCookieSecure || c.AdminUser != "admin" || c.AdminInitialPassword != "" || c.AuthSecretKey != "" {
		t.Fatalf("defaults: %+v %v", c, err)
	}
	t.Setenv("AUTH_OTP_REQUIRED", "false")
	t.Setenv("AUTH_COOKIE_SECURE", "true")
	t.Setenv("ADMIN_USER", "root-admin")
	t.Setenv("ADMIN_INITIAL_PASSWORD", "dev-pass-123")
	t.Setenv("AUTH_SECRET_KEY", "k")
	c, err = Load()
	if err != nil || c.AuthOTPRequired || !c.AuthCookieSecure || c.AdminUser != "root-admin" || c.AdminInitialPassword != "dev-pass-123" || c.AuthSecretKey != "k" {
		t.Fatalf("set: %+v %v", c, err)
	}
	t.Setenv("AUTH_OTP_REQUIRED", "maybe")
	if _, err := Load(); err == nil {
		t.Fatal("AUTH_OTP_REQUIRED=maybe must be rejected")
	}
}

// 시연 실행(10/30): 기본 꺼짐, 이미지는 sg-install 과 같은 SG_PIP_IMAGE
func TestDemoEnabled(t *testing.T) {
	c, err := Load()
	if err != nil || c.DemoEnabled || c.DemoImage != "python:3.12-slim" {
		t.Fatalf("defaults: %v %q %v", c.DemoEnabled, c.DemoImage, err)
	}
	t.Setenv("DEMO_ENABLED", "true")
	t.Setenv("SG_PIP_IMAGE", "python:3.13-slim")
	if c, err = Load(); err != nil || !c.DemoEnabled || c.DemoImage != "python:3.13-slim" {
		t.Fatalf("set: %v %q %v", c.DemoEnabled, c.DemoImage, err)
	}
	t.Setenv("DEMO_ENABLED", "sometimes")
	if _, err := Load(); err == nil {
		t.Fatal("DEMO_ENABLED=sometimes must be rejected")
	}
}

// GADGETS 에 dns 를 넣으면 설정 오류 — trace_dns 는 RESOLVE_DNS=true 로 켠다(10/30). 나머지 모르는 값도 거부
func TestGadgetsDNSNotAllowed(t *testing.T) {
	t.Setenv("GADGETS", "exec,open,connect,dns")
	_, err := Load()
	if err == nil || !strings.Contains(err.Error(), "RESOLVE_DNS=true") {
		t.Fatalf("GADGETS=dns must be rejected with a RESOLVE_DNS hint, got %v", err)
	}
	t.Setenv("GADGETS", "exec,read")
	if _, err := Load(); err == nil {
		t.Fatal("unknown gadget kind must be rejected")
	}
	t.Setenv("GADGETS", "exec,open,connect")
	if c, err := Load(); err != nil || len(c.Gadgets) != 3 {
		t.Fatalf("%+v %v", c.Gadgets, err)
	}
}
