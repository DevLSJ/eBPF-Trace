package rules

import (
	"strings"
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

func TestAllowHostsUseResolvedDomain(t *testing.T) {
	e := New([]Rule{{ID: "sandbox-egress", Kind: model.KindConnect, Action: model.ActionKill,
		AllowHosts: []string{"pypi.org", "files.pythonhosted.org"}, AllowCIDRs: []string{"127.0.0.0/8"},
		DenyHosts: []string{"reqeusts-update.test"}}})
	ok := model.Event{Kind: model.KindConnect, ContainerID: "c1", DstIP: "151.101.0.223", DstPort: 443, DstHost: "files.pythonhosted.org"}
	if v := e.Evaluate(ok); v.Matched {
		t.Fatalf("registry host must pass, got %+v", v)
	}
	sub := ok
	sub.DstHost = "Mirror.PyPI.org." // 하위 도메인·대소문자·끝 점
	if v := e.Evaluate(sub); v.Matched {
		t.Fatalf("subdomain of allowed host must pass, got %+v", v)
	}
	unknown := ok
	unknown.DstHost = ""
	if v := e.Evaluate(unknown); v.Matched {
		t.Fatalf("unknown host must fail open (DNS unavailable), got %+v", v)
	}
	deny := ok
	deny.DstHost = "cdn.reqeusts-update.test"
	if v := e.Evaluate(deny); !v.Matched || !strings.Contains(v.Reason, "금지 도메인") {
		t.Fatalf("denyHosts must win, got %+v", v)
	}
	if err := (Rule{ID: "bad", Kind: model.KindConnect, Action: model.ActionAlert, AllowHosts: []string{"not a host!"}}).Validate(); err == nil {
		t.Fatal("invalid host must fail validation")
	}
}

// directIp: trace_dns 가 켜져 있는데 도메인 없이 공인 IP 로 바로 붙는 연결을 규칙 옵션대로 처리한다.
func TestDirectIP(t *testing.T) {
	base := Rule{ID: "sandbox-egress", Kind: model.KindConnect, Action: model.ActionKill,
		AllowHosts: []string{"pypi.org"}, AllowCIDRs: []string{"10.0.0.0/8"}}
	pub := model.Event{Kind: model.KindConnect, ContainerID: "c1", DstIP: "203.0.113.7", DstPort: 443, DNSTraced: true}
	with := func(d string) Rule { r := base; r.DirectIP = d; return r }

	t.Run("kill", func(t *testing.T) {
		v := New([]Rule{with("kill")}).Evaluate(pub)
		if !v.Matched || v.Action != model.ActionKill || !strings.Contains(v.Reason, "도메인 조회 없는 IP 직접 연결: 203.0.113.7:443") {
			t.Fatalf("got %+v", v)
		}
	})
	t.Run("directIp overrides rule action", func(t *testing.T) {
		r := with("alert") // 규칙은 kill, directIp 는 alert → alert
		if v := New([]Rule{r}).Evaluate(pub); !v.Matched || v.Action != model.ActionAlert {
			t.Fatalf("want alert, got %+v", v)
		}
		r = with("kill")
		r.Action = model.ActionAlert // 규칙은 alert, directIp 는 kill → kill
		if v := New([]Rule{r}).Evaluate(pub); !v.Matched || v.Action != model.ActionKill {
			t.Fatalf("want kill, got %+v", v)
		}
	})
	t.Run("allow", func(t *testing.T) {
		if v := New([]Rule{with("allow")}).Evaluate(pub); v.Matched {
			t.Fatalf("directIp allow must pass, got %+v", v)
		}
	})
	t.Run("deny wins over allow", func(t *testing.T) {
		r := with("allow")
		r.DenyPorts = []uint16{443}
		if v := New([]Rule{r}).Evaluate(pub); !v.Matched || !strings.Contains(v.Reason, "금지 포트") {
			t.Fatalf("deny must win, got %+v", v)
		}
	})
	t.Run("private, loopback, link-local exempt", func(t *testing.T) {
		r := with("kill")
		r.AllowCIDRs = nil // CIDR 허용 없이도 사설 주소는 직접 연결로 보지 않는다
		for _, ip := range []string{"10.1.2.3", "172.16.5.5", "192.168.0.9", "127.0.0.1", "169.254.1.1", "fd00::1", "::1", "0.0.0.0"} {
			ev := pub
			ev.DstIP = ip
			if v := New([]Rule{r}).Evaluate(ev); v.Matched {
				t.Fatalf("%s: non-public address must not be a direct-IP violation, got %+v", ip, v)
			}
		}
	})
	t.Run("dns off keeps fail-open", func(t *testing.T) {
		ev := pub
		ev.DNSTraced = false
		if v := New([]Rule{with("kill")}).Evaluate(ev); v.Matched {
			t.Fatalf("without trace_dns the connection must fail open, got %+v", v)
		}
	})
	t.Run("empty directIp keeps fail-open", func(t *testing.T) {
		if v := New([]Rule{base}).Evaluate(pub); v.Matched {
			t.Fatalf("directIp unset must keep the old fail-open, got %+v", v)
		}
	})
	t.Run("known host still judged by allowHosts", func(t *testing.T) {
		ev := pub
		ev.DstHost = "evil.test"
		v := New([]Rule{with("alert")}).Evaluate(ev)
		if !v.Matched || v.Action != model.ActionKill || !strings.Contains(v.Reason, "허용 목록 밖") {
			t.Fatalf("known host outside allowHosts must hit the rule action, got %+v", v)
		}
		ev.DstHost = "files.pypi.org"
		if v := New([]Rule{with("kill")}).Evaluate(ev); v.Matched {
			t.Fatalf("allowed host must pass, got %+v", v)
		}
	})
	t.Run("rule without allowHosts judges only direct ip", func(t *testing.T) {
		// 기본 정책 runtime-direct-ip 꼴: 사설 대역 예외 + directIp alert. 도메인을 아는 연결과 DNS 꺼진 연결은 이 규칙이 보지 않는다.
		r := Rule{ID: "runtime-direct-ip", Kind: model.KindConnect, Action: model.ActionAlert, DirectIP: "alert",
			AllowCIDRs: []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "::1"}}
		if err := r.Validate(); err != nil {
			t.Fatal(err)
		}
		e := New([]Rule{r})
		if v := e.Evaluate(pub); !v.Matched || v.Action != model.ActionAlert {
			t.Fatalf("direct ip must alert, got %+v", v)
		}
		known := pub
		known.DstHost = "api.github.com"
		if v := e.Evaluate(known); v.Matched {
			t.Fatalf("resolved host must pass a direct-ip-only rule, got %+v", v)
		}
		off := pub
		off.DNSTraced = false
		if v := e.Evaluate(off); v.Matched {
			t.Fatalf("dns off must pass a direct-ip-only rule, got %+v", v)
		}
	})
	t.Run("directIp alone is a condition", func(t *testing.T) {
		if err := (Rule{ID: "d", Kind: model.KindConnect, Action: model.ActionAlert, DirectIP: "alert"}).Validate(); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("validate rejects other values", func(t *testing.T) {
		for _, bad := range []string{"block", "KILL", "true"} {
			if err := (Rule{ID: "d", Kind: model.KindConnect, Action: model.ActionAlert, DirectIP: bad}).Validate(); err == nil {
				t.Fatalf("directIp %q must be rejected", bad)
			}
		}
	})
	t.Run("yaml field", func(t *testing.T) {
		rs, err := ParseYAML([]byte("rules:\n  - id: d\n    kind: connect\n    action: alert\n    directIp: kill\n"))
		if err != nil || len(rs) != 1 || rs[0].DirectIP != "kill" {
			t.Fatalf("%+v %v", rs, err)
		}
	})
}

func TestDefaultPolicyDirectIP(t *testing.T) {
	rs, err := LoadFile("../../policies/default.yaml")
	if err != nil {
		t.Fatal(err)
	}
	e := New(rs)
	direct := model.Event{Kind: model.KindConnect, ContainerID: "c1", ContainerName: "sg-install-pip-1", DstIP: "203.0.113.7", DstPort: 443, DNSTraced: true}
	if v := e.Evaluate(direct); !v.Matched || v.RuleID != "sandbox-egress" || v.Action != model.ActionKill {
		t.Fatalf("sandbox direct ip must be killed, got %+v", v)
	}
	direct.ContainerName = "web-api"
	if v := e.Evaluate(direct); !v.Matched || v.RuleID != "runtime-direct-ip" || v.Action != model.ActionAlert {
		t.Fatalf("runtime direct ip must alert, got %+v", v)
	}
	direct.DstHost = "api.github.com"
	if v := e.Evaluate(direct); v.Matched {
		t.Fatalf("resolved https must pass, got %+v", v)
	}
}

func TestIsPublicAddr(t *testing.T) {
	for ip, want := range map[string]bool{"203.0.113.7": true, "8.8.8.8": true, "2001:db8::1": true, "::ffff:1.2.3.4": true,
		"10.0.0.1": false, "172.31.255.1": false, "192.168.1.1": false, "127.0.0.1": false, "169.254.0.1": false,
		"fc00::1": false, "fe80::1": false, "::1": false, "0.0.0.0": false, "::": false, "not-an-ip": false} {
		if got := IsPublicAddr(ip); got != want {
			t.Errorf("IsPublicAddr(%q) = %v, want %v", ip, got, want)
		}
	}
}
