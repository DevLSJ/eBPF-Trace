package review

import (
	"slices"
	"testing"

	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/model"
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/rules"
)

// Tier 1 — 적용은 모두 되거나 모두 안 된다.

// 저장소 커밋이 실패하면 차단 목록 · 엔진 규칙 · 제안 · 건 · 변경 이력이 하나도 바뀌지 않는다.
// 다시 시도해 성공하면 전부 한꺼번에 바뀐다.
func TestApplyIsAtomic(t *testing.T) {
	e := newEnv(t)
	ctx := t.Context()
	c, p := e.maliciousInstallCase(t)
	rulesBefore := e.engine.Rules()

	e.store.setFail(true)
	if _, _, err := e.svc.Apply(ctx, p.ID, ""); err == nil {
		t.Fatal("apply must fail when the store commit fails")
	}
	if got, _ := e.svc.GetProposal(p.ID); got.State != model.ProposalDraft {
		t.Fatalf("proposal must stay draft, got %s", got.State)
	}
	if got, _ := e.svc.GetCase(c.ID); got.State != model.CaseDecided || got.ClosedAt != nil {
		t.Fatalf("case must stay decided, got %s", got.State)
	}
	if bl := e.svc.Blocklist(); len(bl.Packages)+len(bl.Hosts)+len(bl.Images) != 0 {
		t.Fatalf("blocklist must stay empty, got %+v", bl)
	}
	if !slices.EqualFunc(e.engine.Rules(), rulesBefore, func(a, b rules.Rule) bool { return a.ID == b.ID && slices.Equal(a.DenyHosts, b.DenyHosts) }) {
		t.Fatal("engine rules must not change on a failed apply")
	}
	if n := len(e.svc.ListChanges(0)); n != 0 {
		t.Fatalf("no change record on failure, got %d", n)
	}
	snap, _ := e.store.Memory.LoadReview(ctx)
	if len(snap.Blocklist) != 0 || len(snap.Changes) != 0 {
		t.Fatalf("store must hold nothing from the failed apply: %+v", snap.Blocklist)
	}

	e.store.setFail(false)
	gotP, gotC, err := e.svc.Apply(ctx, p.ID, "")
	if err != nil {
		t.Fatal(err)
	}
	if gotP.State != model.ProposalApplied || gotP.AppliedAt == nil || gotP.AppliedBy == nil || *gotP.AppliedBy != DefaultActor {
		t.Fatalf("proposal must be applied by the actor: %+v", gotP)
	}
	if gotC.State != model.CaseClosed || gotC.ClosedAt == nil {
		t.Fatalf("case must be closed: %+v", gotC)
	}
	bl := e.svc.Blocklist()
	if len(bl.Packages) != 1 || bl.Packages[0].Value != "pip:reqeusts" || bl.Packages[0].CaseID == nil || *bl.Packages[0].CaseID != c.ID {
		t.Fatalf("package block: %+v", bl.Packages)
	}
	if len(bl.Hosts) != 1 || bl.Hosts[0].Value != "cdn.reqeusts-update.test" {
		t.Fatalf("host block: %+v", bl.Hosts)
	}
	sys, ok := ruleByID(e.engine.Rules(), rules.SystemBlocklistHosts)
	if !ok || !slices.Equal(sys.DenyHosts, []string{"cdn.reqeusts-update.test"}) {
		t.Fatalf("engine must carry blocklist-hosts with the blocked domain: %+v", sys)
	}
	chs := e.svc.ListChanges(0)
	if len(chs) != 1 || chs[0].Kind != model.ChangeProposalApplied || chs[0].ProposalID == nil || *chs[0].ProposalID != p.ID ||
		chs[0].Summary != "패키지 pip:reqeusts 차단 · 도메인 1개 차단" {
		t.Fatalf("change record: %+v", chs)
	}
	snap, _ = e.store.Memory.LoadReview(ctx)
	if len(snap.Blocklist) != 2 || len(snap.Changes) != 1 {
		t.Fatalf("store must hold the applied state: %d blocks, %d changes", len(snap.Blocklist), len(snap.Changes))
	}

	if _, _, err := e.svc.Apply(ctx, p.ID, ""); ErrorKind(err) != KindConflict {
		t.Fatalf("second apply must be a conflict, got %v", err)
	}
}

// 오탐 제안을 적용하면 규칙 필드에 값이 더해지고, 저장된 정책과 엔진이 같은 규칙을 갖는다.
func TestApplyFalsePositiveAddsException(t *testing.T) {
	e := newEnv(t)
	ctx := t.Context()
	ev := model.Event{Kind: model.KindConnect, ContainerID: sandboxCID, ContainerName: "web-api", ImageName: "node:22",
		DstIP: "140.82.112.3", DstPort: 9418, DstHost: "github.com"}
	// 경고(alert)만으로는 런타임 건이 열리지 않으므로, 같은 연결이 kill 규칙에 걸리도록 dry-run 아닌 kill 규칙을 둔다
	e.engine.Replace(append(e.engine.Rules(), rules.Rule{ID: "git-port", Kind: model.KindConnect, Action: model.ActionKill, AllowPorts: []uint16{443}}))
	_ = e.store.Memory.UpsertPolicy(ctx, rules.Rule{ID: "git-port", Kind: model.KindConnect, Action: model.ActionKill, AllowPorts: []uint16{443}})
	v := e.observe(t, ev)
	if v.CaseID == nil {
		t.Fatal("kill must open a runtime case")
	}
	_, p, err := e.svc.Decide(ctx, *v.CaseID, model.DecisionFalsePositive, "git 의존성")
	if err != nil {
		t.Fatal(err)
	}
	// 두 규칙 모두 원래 allowHosts 가 없으므로 allowCidrs IP/32 (결정 2026-10-15)
	want := []model.ProposalChange{
		{Op: "except", RuleID: "git-port", Field: "allowCidrs", Value: "140.82.112.3/32"},
		{Op: "except", RuleID: "egress-allowlist", Field: "allowCidrs", Value: "140.82.112.3/32"},
	}
	if !slices.Equal(p.Changes, want) {
		t.Fatalf("changes = %+v, want %+v", p.Changes, want)
	}
	if _, _, err := e.svc.Apply(ctx, p.ID, ""); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"git-port", "egress-allowlist"} {
		stored, _ := e.store.Memory.ListPolicies(ctx)
		sr, _ := ruleByID(stored, id)
		er, _ := ruleByID(e.engine.Rules(), id)
		if !slices.Contains(sr.AllowCIDRs, "140.82.112.3/32") || !slices.Contains(er.AllowCIDRs, "140.82.112.3/32") {
			t.Fatalf("%s: stored %v engine %v", id, sr.AllowCIDRs, er.AllowCIDRs)
		}
	}
	if v := e.engine.Evaluate(ev); v.Matched {
		t.Fatalf("event must pass after the exception, got %+v", v)
	}
}

// 제안을 만든 뒤 규칙이 지워졌으면 적용은 409 이고 아무것도 바뀌지 않는다.
func TestApplyMissingRuleConflicts(t *testing.T) {
	e := newEnv(t)
	ctx := t.Context()
	ev := sandboxEv("web-api")
	ev.Kind, ev.Path = model.KindOpen, "/etc/shadow"
	v := e.observe(t, ev)
	_, p, err := e.svc.Decide(ctx, *v.CaseID, model.DecisionFalsePositive, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.store.Memory.DeletePolicy(ctx, "sensitive-files"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := e.svc.Apply(ctx, p.ID, ""); ErrorKind(err) != KindConflict {
		t.Fatalf("want conflict, got %v", err)
	}
	if got, _ := e.svc.GetProposal(p.ID); got.State != model.ProposalDraft {
		t.Fatal("proposal must stay draft")
	}
}

// 차단 도메인은 시스템 규칙 blocklist-hosts(connect · kill · denyHosts)로 엔진에 들어가 모든 관찰 컨테이너에 먹는다.
// 마지막 도메인을 해제하면 규칙도 사라진다.
func TestBlocklistHostsSystemRule(t *testing.T) {
	e := newEnv(t)
	ctx := t.Context()
	_, p := e.maliciousInstallCase(t)
	if _, _, err := e.svc.Apply(ctx, p.ID, ""); err != nil {
		t.Fatal(err)
	}
	ev := model.Event{Kind: model.KindConnect, ContainerID: sandboxCID, ContainerName: "web-api", DstIP: "203.0.113.7", DstPort: 443, DstHost: "a.cdn.reqeusts-update.test"}
	v := e.engine.Evaluate(ev)
	if !v.Matched || v.RuleID != rules.SystemBlocklistHosts || v.Action != model.ActionKill {
		t.Fatalf("blocked domain must be killed by %s, got %+v", rules.SystemBlocklistHosts, v)
	}
	// 재시작해도(저장소에서 다시 읽어도) 같은 규칙이 만들어진다
	e2 := New(Options{Store: e.store, Policies: e.store.Memory, Audit: e.store.Memory, Engine: rules.New(nil)})
	if err := e2.Load(ctx); err != nil {
		t.Fatal(err)
	}
	if err := e2.Reload(ctx); err != nil {
		t.Fatal(err)
	}
	if _, ok := ruleByID(e2.o.Engine.Rules(), rules.SystemBlocklistHosts); !ok {
		t.Fatal("reload from store must rebuild blocklist-hosts")
	}
	stored, _ := e.store.Memory.ListPolicies(ctx)
	if _, ok := ruleByID(stored, rules.SystemBlocklistHosts); ok {
		t.Fatal("system rule must not be stored as a policy (one source: the blocklist)")
	}

	if err := e.svc.RemoveBlock(ctx, model.ListHosts, "cdn.reqeusts-update.test", ""); err != nil {
		t.Fatal(err)
	}
	if _, ok := ruleByID(e.engine.Rules(), rules.SystemBlocklistHosts); ok {
		t.Fatal("removing the last host must drop the system rule")
	}
	chs := e.svc.ListChanges(0)
	if chs[0].Kind != model.ChangeBlocklistRemove {
		t.Fatalf("unblock must be recorded, got %+v", chs[0])
	}
}
