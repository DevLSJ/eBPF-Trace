package rules

import (
	"strings"
	"testing"

	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/model"
)

func dnsEv(name, qtype string) model.Event {
	return model.Event{Kind: model.KindDNS, ContainerID: "c1", ContainerName: "web-api", DstHost: name, Qtype: qtype, DstIP: "127.0.0.11", DstPort: 53}
}

// DNS 질의 규칙(kind: dns, 10/30): 매칭 순서 denyHosts → allowHosts → denyQtypes → 라벨 길이 → 이름 길이 → 허용 목록 밖
func TestDNSRules(t *testing.T) {
	long := strings.Repeat("deadbeef", 6) + ".exfil.example" // 라벨 48자
	wide := strings.Repeat("a", 30) + "." + strings.Repeat("b", 30) + "." + strings.Repeat("c", 30) + "." + strings.Repeat("d", 30) + ".example"
	c2 := New([]Rule{{ID: "block-c2-dns", Kind: model.KindDNS, Action: model.ActionKill, DenyHosts: []string{"attacker.test"}, DenyQtypes: []string{"TXT", "ALL"}}})
	exfil := New([]Rule{{ID: "exfil", Kind: model.KindDNS, Action: model.ActionAlert, MaxLabelLength: 40, MaxNameLength: 120}})
	allow := New([]Rule{{ID: "allow", Kind: model.KindDNS, Action: model.ActionKill, AllowHosts: []string{"pypi.org"}, DenyQtypes: []string{"TXT"}}})
	both := New([]Rule{{ID: "both", Kind: model.KindDNS, Action: model.ActionKill, AllowHosts: []string{"example"}, DenyHosts: []string{"bad.example"}}})
	scoped := New([]Rule{{ID: "scoped", Kind: model.KindDNS, Action: model.ActionKill, Containers: []string{"sg-install-*"}, DenyHosts: []string{"evil.test"}}})

	cases := []struct {
		name   string
		e      *Engine
		ev     model.Event
		rule   string
		reason string
	}{
		{"deny host (subdomain)", c2, dnsEv("c2.attacker.test", "A"), "block-c2-dns", "금지 도메인 질의: c2.attacker.test (A)"},
		{"deny qtype", c2, dnsEv("other.example", "TXT"), "block-c2-dns", "금지 질의 유형: TXT — other.example"},
		{"deny qtype ALL", c2, dnsEv("other.example", "ALL"), "block-c2-dns", "금지 질의 유형: ALL — other.example"},
		{"normal query passes deny rule", c2, dnsEv("pypi.org", "A"), "", ""},
		{"long label", exfil, dnsEv(long, "A"), "exfil", "긴 DNS 라벨(유출 의심): " + long + " (라벨 48자 > 40)"},
		{"long name", exfil, dnsEv(wide, "AAAA"), "exfil", "긴 DNS 이름(유출 의심): " + wide + " (131자 > 120)"},
		{"label beats name", exfil, dnsEv(strings.Repeat("x", 48)+"."+wide, "A"), "exfil", "긴 DNS 라벨(유출 의심): "},
		{"short name passes", exfil, dnsEv("files.pythonhosted.org", "A"), "", ""},
		{"outside allowlist", allow, dnsEv("files.pythonhosted.org", "A"), "allow", "허용 목록 밖 도메인 질의: files.pythonhosted.org (A)"},
		{"allowed host passes", allow, dnsEv("files.pypi.org", "A"), "", ""},
		{"allowed host beats deny qtype", allow, dnsEv("pypi.org", "TXT"), "", ""},
		{"deny qtype outside allowlist", allow, dnsEv("data.exfil.example", "TXT"), "allow", "금지 질의 유형: TXT — data.exfil.example"},
		{"single label excluded", allow, dnsEv("localhost", "A"), "", ""},
		{"arpa excluded", allow, dnsEv("11.0.0.127.in-addr.arpa", "PTR"), "", ""},
		{"local excluded", allow, dnsEv("printer.local", "A"), "", ""},
		{"internal excluded", allow, dnsEv("db.internal", "A"), "", ""},
		{"deny host beats allow host", both, dnsEv("c2.bad.example", "A"), "both", "금지 도메인 질의: c2.bad.example (A)"},
		{"allow host under both", both, dnsEv("good.example", "A"), "", ""},
		{"container scope", scoped, dnsEv("evil.test", "A"), "", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			v := c.e.Evaluate(c.ev)
			if v.RuleID != c.rule || v.Matched != (c.rule != "") || !strings.HasPrefix(v.Reason, c.reason) {
				t.Fatalf("got rule=%q matched=%v reason=%q, want rule=%q reason=%q", v.RuleID, v.Matched, v.Reason, c.rule, c.reason)
			}
		})
	}
	// 컨테이너 범위는 다른 kind 와 같다
	in := dnsEv("evil.test", "A")
	in.ContainerName = "sg-install-pip-1"
	if v := scoped.Evaluate(in); !v.Matched || v.Action != model.ActionKill {
		t.Fatalf("scoped rule must apply inside sg-install-*: %+v", v)
	}
	// 대소문자 · 끝 점: 이름은 소문자 · 끝 점 없이 비교
	if v := c2.Evaluate(dnsEv("C2.Attacker.TEST.", "A")); !v.Matched {
		t.Fatalf("host match must ignore case and trailing dot: %+v", v)
	}

	// Validate: 조건 1개 이상 · 범위 · connect 전용 필드 거부 · dns 전용 필드는 dns 에서만
	good := []Rule{
		{ID: "a", Kind: model.KindDNS, Action: model.ActionAlert, DenyQtypes: []string{"TXT"}},
		{ID: "b", Kind: model.KindDNS, Action: model.ActionAlert, MaxLabelLength: 63},
		{ID: "c", Kind: model.KindDNS, Action: model.ActionAlert, MaxNameLength: 253},
		{ID: "d", Kind: model.KindDNS, Action: model.ActionKill, AllowHosts: []string{"pypi.org"}},
		{ID: "e", Kind: model.KindDNS, Action: model.ActionKill, DenyHosts: []string{"attacker.test"}, Containers: []string{"sg-install-*"}, DryRun: true},
	}
	for _, r := range good {
		if err := r.Validate(); err != nil {
			t.Errorf("%s: unexpected validation error: %v", r.ID, err)
		}
	}
	bad := []Rule{
		{ID: "no-cond", Kind: model.KindDNS, Action: model.ActionAlert},
		{ID: "name-0", Kind: model.KindDNS, Action: model.ActionAlert, MaxNameLength: 254},
		{ID: "name-neg", Kind: model.KindDNS, Action: model.ActionAlert, MaxNameLength: -1},
		{ID: "label-64", Kind: model.KindDNS, Action: model.ActionAlert, MaxLabelLength: 64},
		{ID: "lower-qtype", Kind: model.KindDNS, Action: model.ActionAlert, DenyQtypes: []string{"txt"}},
		{ID: "empty-qtype", Kind: model.KindDNS, Action: model.ActionAlert, DenyQtypes: []string{""}},
		{ID: "cidr", Kind: model.KindDNS, Action: model.ActionAlert, DenyHosts: []string{"x.test"}, AllowCIDRs: []string{"10.0.0.0/8"}},
		{ID: "ports", Kind: model.KindDNS, Action: model.ActionAlert, DenyHosts: []string{"x.test"}, DenyPorts: []uint16{53}},
		{ID: "direct", Kind: model.KindDNS, Action: model.ActionAlert, DenyHosts: []string{"x.test"}, DirectIP: "kill"},
		{ID: "connect-qtype", Kind: model.KindConnect, Action: model.ActionAlert, DenyPorts: []uint16{4444}, DenyQtypes: []string{"TXT"}},
		{ID: "open-label", Kind: model.KindOpen, Action: model.ActionAlert, DenyPaths: []string{"/x"}, MaxLabelLength: 10},
	}
	for _, r := range bad {
		if r.Validate() == nil {
			t.Errorf("%s: expected validation error", r.ID)
		}
	}
	// 사용자 규칙 예시가 YAML 로 들어온다
	rs, err := ParseYAML([]byte("rules:\n  - id: block-c2-dns\n    kind: dns\n    action: kill\n    denyHosts: [attacker.test]\n    denyQtypes: [TXT, ALL]\n"))
	if err != nil || len(rs) != 1 || len(rs[0].DenyQtypes) != 2 {
		t.Fatalf("yaml dns rule: %+v %v", rs, err)
	}
}

// 기본 정책의 dns 규칙 2개(10/30): runtime-dns-exfil(alert) · sandbox-dns(kill · sg-install-*)
// sandbox-dns 는 11/03 sg-vm 실측(정상 설치 27건 중 새 오탐 0, 유출 질의 탐지) 뒤 dryRun 을 해제했다
func TestDefaultPolicyDNS(t *testing.T) {
	rs, err := LoadFile("../../policies/default.yaml")
	if err != nil {
		t.Fatal(err)
	}
	ids := map[string]Rule{}
	for _, r := range rs {
		ids[r.ID] = r
	}
	if r, ok := ids["runtime-dns-exfil"]; !ok || r.Kind != model.KindDNS || r.Action != model.ActionAlert || r.MaxLabelLength != 40 || r.MaxNameLength != 120 || len(r.DenyQtypes) != 1 || r.DenyQtypes[0] != "TXT" {
		t.Fatalf("runtime-dns-exfil: %+v (present %v)", r, ok)
	}
	if r, ok := ids["sandbox-dns"]; !ok || r.Kind != model.KindDNS || r.Action != model.ActionKill || r.DryRun || len(r.Containers) != 1 || r.MaxLabelLength != 40 || len(r.AllowHosts) != 10 {
		t.Fatalf("sandbox-dns: %+v (present %v)", r, ok)
	}
	e := New(rs)
	long := strings.Repeat("deadbeef", 6) + ".exfil.example"
	if v := e.Evaluate(dnsEv(long, "A")); !v.Matched || v.RuleID != "runtime-dns-exfil" || v.Action != model.ActionAlert || !strings.HasPrefix(v.Reason, "긴 DNS 라벨(유출 의심)") {
		t.Fatalf("48-char label at runtime: %+v", v)
	}
	if v := e.Evaluate(dnsEv("data.exfil.example", "TXT")); !v.Matched || v.RuleID != "runtime-dns-exfil" || v.Reason != "금지 질의 유형: TXT — data.exfil.example" {
		t.Fatalf("TXT at runtime: %+v", v)
	}
	if v := e.Evaluate(dnsEv("files.pythonhosted.org", "A")); v.Matched {
		t.Fatalf("registry query at runtime must pass: %+v", v)
	}
	sb := dnsEv("evil.test", "A")
	sb.ContainerName = "sg-install-pip-1"
	if v := e.Evaluate(sb); !v.Matched || v.RuleID != "sandbox-dns" || v.Action != model.ActionKill || v.DryRun || v.Reason != "허용 목록 밖 도메인 질의: evil.test (A)" {
		t.Fatalf("sandbox query outside allowlist: %+v", v)
	}
	ok := dnsEv("files.pythonhosted.org", "A")
	ok.ContainerName = "sg-install-pip-1"
	if v := e.Evaluate(ok); v.Matched {
		t.Fatalf("registry query in sandbox must pass: %+v", v)
	}
	// 샌드박스의 48자 라벨: sandbox-dns(kill) 가 runtime-dns-exfil(alert) 보다 세다
	lb := dnsEv(long, "A")
	lb.ContainerName = "sg-install-pip-1"
	if v := e.Evaluate(lb); v.RuleID != "sandbox-dns" || v.DryRun {
		t.Fatalf("sandbox long label: %+v", v)
	}
}
