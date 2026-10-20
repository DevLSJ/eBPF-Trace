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
