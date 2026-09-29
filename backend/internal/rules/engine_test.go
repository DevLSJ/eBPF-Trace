package rules

import (
	"testing"

	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/model"
)

func TestDefaultPolicyParses(t *testing.T) {
	rs, err := LoadFile("../../policies/default.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if len(rs) == 0 {
		t.Fatal("no rules")
	}
}

func TestEvaluate(t *testing.T) {
	rs, err := LoadFile("../../policies/default.yaml")
	if err != nil {
		t.Fatal(err)
	}
	e := New(rs)

	cases := []struct {
		name   string
		ev     model.Event
		rule   string
		action model.Action
	}{
		{"shadow", model.Event{Kind: model.KindOpen, Path: "/etc/shadow"}, "sensitive-files", model.ActionKill},
		{"ssh glob", model.Event{Kind: model.KindOpen, Path: "/home/app/.ssh/id_rsa"}, "sensitive-files", model.ActionKill},
		{"normal open", model.Event{Kind: model.KindOpen, Path: "/etc/hosts"}, "", ""},
		{"curl comm", model.Event{Kind: model.KindExec, Comm: "curl", Args: "curl -s http://x"}, "no-shell-download", model.ActionKill},
		{"argv0 path", model.Event{Kind: model.KindExec, Comm: "busybox", Args: "/usr/bin/wget -q x"}, "no-shell-download", model.ActionKill},
		{"pipe to shell", model.Event{Kind: model.KindExec, Comm: "sh", Args: "sh -c curl x | sh"}, "pipe-to-shell", model.ActionKill},
		{"normal exec", model.Event{Kind: model.KindExec, Comm: "cat", Args: "cat /dev/null"}, "", ""},
		{"https ok", model.Event{Kind: model.KindConnect, DstIP: "93.184.216.34", DstPort: 443}, "", ""},
		{"odd port alert", model.Event{Kind: model.KindConnect, DstIP: "203.0.113.10", DstPort: 8081}, "egress-allowlist", model.ActionAlert},
		// 4444는 egress(alert)와 reverse-shell(kill) 둘 다 걸리지만 kill이 이긴다
		{"reverse shell wins", model.Event{Kind: model.KindConnect, DstIP: "203.0.113.10", DstPort: 4444}, "reverse-shell-ports", model.ActionKill},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			v := e.Evaluate(c.ev)
			if v.RuleID != c.rule || v.Action != c.action || v.Matched != (c.rule != "") {
				t.Fatalf("got rule=%q action=%q matched=%v, want rule=%q action=%q", v.RuleID, v.Action, v.Matched, c.rule, c.action)
			}
		})
	}
}

func TestContainerScopeAndDryRun(t *testing.T) {
	e := New([]Rule{
		{ID: "scoped", Kind: model.KindOpen, Action: model.ActionKill, DryRun: true,
			Containers: []string{"victim*"}, DenyPaths: []string{"/etc/shadow"}},
	})
	v := e.Evaluate(model.Event{Kind: model.KindOpen, ContainerName: "api", Path: "/etc/shadow"})
	if v.Matched {
		t.Fatal("rule must not apply outside its container scope")
	}
	v = e.Evaluate(model.Event{Kind: model.KindOpen, ContainerName: "victim-1", Path: "/etc/shadow"})
	if !v.Matched || !v.DryRun {
		t.Fatalf("want dry-run match, got %+v", v)
	}
}

func TestAllowCIDR(t *testing.T) {
	e := New([]Rule{{ID: "cidr", Kind: model.KindConnect, Action: model.ActionAlert,
		AllowCIDRs: []string{"10.0.0.0/8", "172.16.0.0/12"}}})
	if e.Evaluate(model.Event{Kind: model.KindConnect, DstIP: "10.1.2.3", DstPort: 9999}).Matched {
		t.Fatal("private CIDR must be allowed")
	}
	if !e.Evaluate(model.Event{Kind: model.KindConnect, DstIP: "8.8.8.8", DstPort: 443}).Matched {
		t.Fatal("public IP outside allowCidrs must match")
	}
}

func TestValidate(t *testing.T) {
	bad := []Rule{
		{ID: "Bad ID", Kind: model.KindOpen, Action: model.ActionKill, DenyPaths: []string{"/x"}},
		{ID: "no-cond", Kind: model.KindExec, Action: model.ActionAlert},
		{ID: "bad-kind", Kind: "read", Action: model.ActionAlert},
		{ID: "bad-cidr", Kind: model.KindConnect, Action: model.ActionAlert, AllowCIDRs: []string{"nope"}},
	}
	for _, r := range bad {
		if r.Validate() == nil {
			t.Errorf("%s: expected validation error", r.ID)
		}
	}
}

func TestAllowlistIsOr(t *testing.T) {
	rs, err := LoadFile("../../policies/default.yaml")
	if err != nil {
		t.Fatal(err)
	}
	e := New(rs)
	if v := e.Evaluate(model.Event{Kind: model.KindConnect, DstIP: "172.18.0.4", DstPort: 5432}); v.Matched {
		t.Fatalf("internal DB connection must pass, got %+v", v)
	}
}
