package review

import (
	"slices"
	"strings"
	"testing"

	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/model"
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/rules"
)

// dns 규칙 2개를 더한 환경(10/30): 샌드박스 허용 목록(sandbox-dns) · 런타임 유출 패턴(runtime-dns-exfil, allowHosts 없음)
func newDNSEnv(t *testing.T) *env {
	t.Helper()
	e := newEnv(t)
	rs := append(slices.Clone(testRules),
		rules.Rule{ID: "sandbox-dns", Kind: model.KindDNS, Action: model.ActionKill, Containers: []string{"sg-install-*"},
			AllowHosts: []string{"pypi.org", "pythonhosted.org"}, MaxLabelLength: 40},
		rules.Rule{ID: "runtime-dns-exfil", Kind: model.KindDNS, Action: model.ActionAlert, MaxLabelLength: 40, MaxNameLength: 120, DenyQtypes: []string{"TXT"}})
	if err := e.store.ReplacePolicies(t.Context(), rs); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.Reload(t.Context()); err != nil {
		t.Fatal(err)
	}
	return e
}

func dnsQuery(ctr, name, qtype string) model.Event {
	ev := sandboxEv(ctr)
	ev.Kind, ev.DstHost, ev.Qtype, ev.DstIP, ev.DstPort = model.KindDNS, name, qtype, "127.0.0.11", 53
	return ev
}

// dns 증거(10/30): 악성 판정은 질의한 도메인을 차단 목록에 올리고(허용 도메인은 안내만), 오탐 판정은 허용 목록이 있는 규칙에만 allowHosts 예외를 더한다
func TestDNSEvidenceProposal(t *testing.T) {
	e := newDNSEnv(t)
	ctx := t.Context()
	s, err := e.svc.StartInstall(ctx, StartInput{Manager: "pip", Packages: []string{"./reqeusts"}, Container: "sg-install-pip-1", Image: "python:3.12-slim"})
	if err != nil {
		t.Fatal(err)
	}
	v := e.observe(t, dnsQuery(s.Container, "evil.test", "A"))
	if !v.Matched || v.RuleID != "sandbox-dns" || !v.Enforced || v.CaseID == nil || v.Install == nil {
		t.Fatalf("sandbox dns query must be isolated and open a case: %+v", v)
	}
	e.observe(t, dnsQuery(s.Container, "files.pythonhosted.org", "A")) // 허용 도메인 — 정상
	sess, _ := e.svc.GetInstall(s.ID)
	if sess.Activity.Kinds[model.KindDNS] != 2 || sess.Status != model.InstallIsolated {
		t.Fatalf("session must count dns activity: %+v", sess.Activity.Kinds)
	}
	_, p, err := e.svc.Decide(ctx, *v.CaseID, model.DecisionMalicious, "")
	if err != nil {
		t.Fatal(err)
	}
	want := []model.ProposalChange{
		{Op: "block", List: model.ListPackages, Value: "pip:reqeusts"},
		{Op: "block", List: model.ListHosts, Value: "evil.test"},
	}
	if !slices.Equal(p.Changes, want) {
		t.Fatalf("malicious dns evidence must block the queried domain: %+v", p.Changes)
	}

	// 오탐: sandbox-dns 는 허용 목록이 있으므로 allowHosts 에 질의 이름을 더한다
	s2, _ := e.svc.StartInstall(ctx, StartInput{Manager: "pip", Packages: []string{"colourama"}, Container: "sg-install-pip-2"})
	v2 := e.observe(t, dnsQuery(s2.Container, "telemetry.vendor.example", "A"))
	_, p2, err := e.svc.Decide(ctx, *v2.CaseID, model.DecisionFalsePositive, "")
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(p2.Changes, []model.ProposalChange{{Op: "except", RuleID: "sandbox-dns", Field: "allowHosts", Value: "telemetry.vendor.example"}}) {
		t.Fatalf("false positive on an allowlist dns rule must add an allowHosts exception: %+v %v", p2.Changes, p2.Notes)
	}
	if _, _, err := e.svc.Apply(ctx, p2.ID, ""); err != nil {
		t.Fatal(err)
	}
	r, _ := ruleByID(e.engine.Rules(), "sandbox-dns")
	if !slices.Contains(r.AllowHosts, "telemetry.vendor.example") {
		t.Fatalf("applied exception: %+v", r.AllowHosts)
	}
	if again := e.engine.Evaluate(dnsQuery("sg-install-pip-3", "telemetry.vendor.example", "A")); again.Matched {
		t.Fatalf("excepted query must pass: %+v", again)
	}

	// 런타임: 허용 목록이 없는 runtime-dns-exfil 의 오탐은 자동 예외 없이 안내만(allowHosts 를 넣으면 다른 도메인이 모두 위반이 되므로)
	kill := model.Event{Kind: model.KindOpen, ContainerID: sandboxCID, ContainerName: "web-api", Path: "/etc/shadow"}
	kv := e.observe(t, kill)
	tx := dnsQuery("web-api", "data.exfil.example", "TXT")
	tv := e.observe(t, tx)
	if !tv.Matched || tv.RuleID != "runtime-dns-exfil" || tv.CaseID == nil || *tv.CaseID != *kv.CaseID {
		t.Fatalf("runtime TXT alert must join the open case: %+v", tv)
	}
	_, p3, err := e.svc.Decide(ctx, *kv.CaseID, model.DecisionFalsePositive, "")
	if err != nil {
		t.Fatal(err)
	}
	if slices.ContainsFunc(p3.Changes, func(c model.ProposalChange) bool { return c.RuleID == "runtime-dns-exfil" }) {
		t.Fatalf("no automatic exception for a dns rule without allowHosts: %+v", p3.Changes)
	}
	if !slices.ContainsFunc(p3.Notes, func(n string) bool {
		return strings.Contains(n, "runtime-dns-exfil") && strings.Contains(n, "allowHosts")
	}) {
		t.Fatalf("a note must explain why runtime-dns-exfil got no exception: %v", p3.Notes)
	}
	// 허용 도메인 아래의 긴 라벨: sandbox-dns 는 allowHosts 일치(②)가 라벨 길이(④)보다 먼저라 통과하고,
	// 전 컨테이너 대상인 runtime-dns-exfil(허용 목록 없음)만 경고한다
	s4, _ := e.svc.StartInstall(ctx, StartInput{Manager: "pip", Packages: []string{"pkg-four"}, Container: "sg-install-pip-4"})
	if v4 := e.observe(t, dnsQuery(s4.Container, strings.Repeat("deadbeef", 6)+".files.pythonhosted.org", "A")); !v4.Matched || v4.RuleID != "runtime-dns-exfil" || v4.Action != model.ActionAlert {
		t.Fatalf("long label under an allowed host: sandbox-dns passes, runtime-dns-exfil alerts — got %+v", v4)
	}
}
