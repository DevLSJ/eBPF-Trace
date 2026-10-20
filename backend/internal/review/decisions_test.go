package review

import (
	"slices"
	"strings"
	"testing"

	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/model"
)

// 2026-10-15 확정 결정 (Tier 1 — 차단 범위 · 규칙)

// 결정 1 — 차단 이미지로 다시 뜬 컨테이너를 blocked-image 로 격리할 때는 새 건을 열지 않고,
// 판정에 차단 목록 항목의 caseId 를 붙인다.
func TestBlockedImageDoesNotOpenCase(t *testing.T) {
	e := newEnv(t)
	ctx := t.Context()
	ev := model.Event{Kind: model.KindOpen, ContainerID: sandboxCID, ContainerName: "pkg-reqeusts", ImageName: "demo/reqeusts:1.0.2", Path: "/etc/shadow"}
	v := e.observe(t, ev)
	_, p, _ := e.svc.Decide(ctx, *v.CaseID, model.DecisionMalicious, "")
	if _, _, err := e.svc.Apply(ctx, p.ID); err != nil {
		t.Fatal(err)
	}
	before := len(e.svc.ListCases(CaseQuery{}))

	bv := model.Verdict{Matched: true, RuleID: model.RuleBlockedImage, Action: model.ActionKill, Enforced: true,
		Event: model.Event{Kind: model.KindExec, ContainerID: sandboxCID, ContainerName: "pkg-reqeusts", ImageName: "demo/reqeusts:1.0.2", Comm: "container-start"}}
	e.svc.Observe(&bv)
	if n := len(e.svc.ListCases(CaseQuery{})); n != before {
		t.Fatalf("blocked-image must not open a case: %d → %d", before, n)
	}
	if bv.CaseID == nil || *bv.CaseID != *v.CaseID {
		t.Fatalf("blocked-image verdict must carry the blocklist entry's caseId %s, got %v", *v.CaseID, bv.CaseID)
	}
	if c, _ := e.svc.GetCase(*v.CaseID); c.State != model.CaseClosed || c.Violations != 1 {
		t.Fatalf("the closed case must stay as it was: %+v", c)
	}
}

// 결정 2 — 악성 제안의 도메인 차단에서, 어느 규칙의 allowHosts 에 있는(접미사 일치 포함) 도메인은 빼고 안내한다.
func TestMaliciousSkipsAllowedHosts(t *testing.T) {
	e := newEnv(t)
	ctx := t.Context()
	s, _ := e.svc.StartInstall(ctx, StartInput{Manager: "pip", Packages: []string{"colourama"}, Container: "sg-install-pip-7"})
	var cid string
	for _, host := range []string{"files.pythonhosted.org", "pypi.org", "telemetry.colourama.test"} {
		ev := sandboxEv(s.Container)
		ev.Kind, ev.DstIP, ev.DstPort, ev.DstHost = model.KindConnect, "203.0.113.9", 4444, host // reverse-shell-ports(kill)
		if v := e.observe(t, ev); v.CaseID != nil {
			cid = *v.CaseID
		}
	}
	_, p, err := e.svc.Decide(ctx, cid, model.DecisionMalicious, "")
	if err != nil {
		t.Fatal(err)
	}
	want := []model.ProposalChange{
		{Op: "block", List: model.ListPackages, Value: "pip:colourama"},
		{Op: "block", List: model.ListHosts, Value: "telemetry.colourama.test"},
	}
	if !slices.Equal(p.Changes, want) {
		t.Fatalf("allowed domains must not be blocked: %+v", p.Changes)
	}
	for _, h := range []string{"files.pythonhosted.org", "pypi.org"} {
		if !slices.ContainsFunc(p.Notes, func(n string) bool { return strings.Contains(n, h) }) {
			t.Errorf("a note must explain why %s was not blocked: %v", h, p.Notes)
		}
	}
}

// 결정 3 — 오탐 예외: 대상 규칙에 원래 allowHosts 가 없으면 allowCidrs IP/32 (DNS 미확인 fail-open 방지),
// 이미 allowHosts 가 있는 규칙은 allowHosts.
func TestFalsePositiveHostException(t *testing.T) {
	e := newEnv(t)
	ctx := t.Context()
	// 런타임: egress-allowlist(allowHosts 없음) 경고 + kill 로 건을 연다
	run := model.Event{Kind: model.KindConnect, ContainerID: sandboxCID, ContainerName: "web-api", DstIP: "140.82.112.3", DstPort: 9418, DstHost: "github.com"}
	kill := model.Event{Kind: model.KindOpen, ContainerID: sandboxCID, ContainerName: "web-api", Path: "/etc/shadow"}
	v := e.observe(t, kill)
	e.observe(t, run)
	_, p, err := e.svc.Decide(ctx, *v.CaseID, model.DecisionFalsePositive, "")
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(p.Changes, model.ProposalChange{Op: "except", RuleID: "egress-allowlist", Field: "allowCidrs", Value: "140.82.112.3/32"}) ||
		slices.ContainsFunc(p.Changes, func(c model.ProposalChange) bool { return c.Field == "allowHosts" }) {
		t.Fatalf("a rule without allowHosts gets allowCidrs IP/32: %+v", p.Changes)
	}

	// 설치: sandbox-egress(allowHosts 있음) → allowHosts
	s, _ := e.svc.StartInstall(ctx, StartInput{Manager: "npm", Packages: []string{"tiny-git-dep"}, Container: "sg-install-npm-3"})
	ev := sandboxEv(s.Container)
	ev.Kind, ev.DstIP, ev.DstPort, ev.DstHost = model.KindConnect, "140.82.112.3", 443, "github.com"
	sv := e.observe(t, ev)
	_, p2, err := e.svc.Decide(ctx, *sv.CaseID, model.DecisionFalsePositive, "")
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(p2.Changes, []model.ProposalChange{{Op: "except", RuleID: "sandbox-egress", Field: "allowHosts", Value: "github.com"}}) {
		t.Fatalf("a rule with allowHosts keeps allowHosts: %+v", p2.Changes)
	}
}

// 결정 5 — 런타임 건이 열려 있으면(open · decided) 같은 컨테이너의 경고도 그 건에 넣는다. 경고만으로 새 건은 열지 않는다.
func TestRuntimeAlertJoinsOpenCase(t *testing.T) {
	e := newEnv(t)
	alert := model.Event{Kind: model.KindConnect, ContainerID: sandboxCID, ContainerName: "worker", DstIP: "198.51.100.4", DstPort: 8443}
	if v := e.observe(t, alert); v.CaseID != nil {
		t.Fatal("an alert alone must not open a case")
	}
	v := e.observe(t, model.Event{Kind: model.KindOpen, ContainerID: sandboxCID, ContainerName: "worker", Path: "/etc/shadow"})
	av := e.observe(t, alert)
	if av.CaseID == nil || *av.CaseID != *v.CaseID {
		t.Fatalf("an alert while a case is open must join it: %v", av.CaseID)
	}
	c, _ := e.svc.GetCase(*v.CaseID)
	if c.Violations != 2 || c.Level != model.LevelKilled || !slices.Equal(c.RuleIDs, []string{"sensitive-files", "egress-allowlist"}) {
		t.Fatalf("case: %+v", c)
	}
	_, p, _ := e.svc.Decide(t.Context(), c.ID, model.DecisionFalsePositive, "")
	if !slices.Contains(p.Changes, model.ProposalChange{Op: "except", RuleID: "egress-allowlist", Field: "allowCidrs", Value: "198.51.100.4/32"}) {
		t.Fatalf("the joined alert must get an exception too: %+v", p.Changes)
	}
	if av2 := e.observe(t, alert); av2.CaseID == nil || *av2.CaseID != c.ID {
		t.Fatal("a decided case still collects alerts")
	}
}

// 설치 목록 항목의 violationCount = 위반 수 합
func TestViolationCount(t *testing.T) {
	e := newEnv(t)
	s, _ := e.svc.StartInstall(t.Context(), StartInput{Manager: "pip", Packages: []string{"x"}, Container: "sg-install-pip-8"})
	for range 3 {
		ev := sandboxEv(s.Container)
		ev.Kind, ev.Path = model.KindOpen, "/etc/shadow"
		e.observe(t, ev)
	}
	ev := sandboxEv(s.Container)
	ev.Kind, ev.Comm, ev.Args = model.KindExec, "curl", "curl x"
	e.observe(t, ev)
	got := e.svc.ListInstalls(InstallQuery{})
	if len(got) != 1 || got[0].ViolationCount != 4 || len(got[0].Violations) != 2 {
		t.Fatalf("violationCount: %+v", got[0])
	}
}

// 표기 — 건의 label 은 설치 건이면 입력 그대로(「pip ./reqeusts」), 런타임 건이면 컨테이너 이름.
// 정규화 키(pip:reqeusts)는 package 에만 둔다.
func TestCaseLabel(t *testing.T) {
	e := newEnv(t)
	s, _ := e.svc.StartInstall(t.Context(), StartInput{Manager: "pip", Packages: []string{"./reqeusts"}, Container: "sg-install-pip-9"})
	ev := sandboxEv(s.Container)
	ev.Kind, ev.Path = model.KindOpen, "/etc/shadow"
	iv := e.observe(t, ev)
	ic, _ := e.svc.GetCase(*iv.CaseID)
	if ic.Label != "pip ./reqeusts" || ic.Package != "pip:reqeusts" {
		t.Fatalf("install case label/package: %q / %q", ic.Label, ic.Package)
	}
	rv := e.observe(t, model.Event{Kind: model.KindOpen, ContainerID: sandboxCID, ContainerName: "worker", Path: "/etc/shadow"})
	if rc, _ := e.svc.GetCase(*rv.CaseID); rc.Label != "worker" {
		t.Fatalf("runtime case label: %q", rc.Label)
	}
}
