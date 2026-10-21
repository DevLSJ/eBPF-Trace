package config

import "testing"

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
