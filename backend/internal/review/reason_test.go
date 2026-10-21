package review

import (
	"strings"
	"testing"

	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/model"
)

// W15 사유: 적용 · 버림 · 차단 해제의 사유(선택, 500자)는 변경 이력 Change.reason 에 남는다.

func TestApplyReasonRecorded(t *testing.T) {
	e := newEnv(t)
	ctx := t.Context()
	_, p := e.maliciousInstallCase(t)
	if _, _, err := e.svc.Apply(ctx, p.ID, "  타이포스쿼팅 확인 — 팀 공유함  "); err != nil {
		t.Fatal(err)
	}
	ch := e.svc.ListChanges(1)[0]
	if ch.Kind != model.ChangeProposalApplied || ch.Reason != "타이포스쿼팅 확인 — 팀 공유함" {
		t.Fatalf("apply change: %+v", ch)
	}
	// 저장소에서 다시 읽어도 남는다
	e2 := New(Options{Store: e.store, Policies: e.store.Memory, Audit: e.store.Memory, Engine: e.engine})
	if err := e2.Load(ctx); err != nil {
		t.Fatal(err)
	}
	if got := e2.ListChanges(1)[0]; got.Reason != ch.Reason {
		t.Fatalf("reloaded change: %+v", got)
	}
}

func TestDiscardRecordsChangeWithReason(t *testing.T) {
	e := newEnv(t)
	ctx := t.Context()
	c, p := e.maliciousInstallCase(t)
	before := len(e.svc.ListChanges(0))
	gotP, gotC, err := e.svc.Discard(ctx, p.ID, "사내 미러에서 받은 정상 패키지")
	if err != nil {
		t.Fatal(err)
	}
	if gotP.State != model.ProposalDiscarded || gotC.State != model.CaseClosed {
		t.Fatalf("discard: %+v %+v", gotP, gotC)
	}
	chs := e.svc.ListChanges(0)
	if len(chs) != before+1 {
		t.Fatalf("discard must be recorded in the change history: %d → %d", before, len(chs))
	}
	ch := chs[0]
	if ch.Kind != model.ChangeProposalDiscarded || ch.Reason != "사내 미러에서 받은 정상 패키지" ||
		ch.CaseID == nil || *ch.CaseID != c.ID || ch.ProposalID == nil || *ch.ProposalID != p.ID || ch.Summary == "" {
		t.Fatalf("discard change: %+v", ch)
	}
	// 사유 없이 버려도 이력은 남는다(reason "")
	_, p2 := e.runtimeCaseDecided(t, model.DecisionMalicious)
	if _, _, err := e.svc.Discard(ctx, p2.ID, ""); err != nil {
		t.Fatal(err)
	}
	if ch := e.svc.ListChanges(1)[0]; ch.Kind != model.ChangeProposalDiscarded || ch.Reason != "" {
		t.Fatalf("discard without reason: %+v", ch)
	}
}

func TestRemoveBlockReasonRecorded(t *testing.T) {
	e := newEnv(t)
	ctx := t.Context()
	_, p := e.maliciousInstallCase(t)
	if _, _, err := e.svc.Apply(ctx, p.ID, ""); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.RemoveBlock(ctx, model.ListPackages, "pip:reqeusts", "오탐 재확인"); err != nil {
		t.Fatal(err)
	}
	if ch := e.svc.ListChanges(1)[0]; ch.Kind != model.ChangeBlocklistRemove || ch.Reason != "오탐 재확인" {
		t.Fatalf("unblock change: %+v", ch)
	}
}

// 사유는 500자(문자 수) 이하 — 넘으면 400 이고 아무것도 바뀌지 않는다.
func TestReasonTooLong(t *testing.T) {
	e := newEnv(t)
	ctx := t.Context()
	_, p := e.maliciousInstallCase(t)
	long := strings.Repeat("가", 501)
	ok := strings.Repeat("가", 500)

	if _, _, err := e.svc.Apply(ctx, p.ID, long); ErrorKind(err) != KindInvalid {
		t.Fatalf("apply 501: %v", err)
	}
	if _, _, err := e.svc.Discard(ctx, p.ID, long); ErrorKind(err) != KindInvalid {
		t.Fatalf("discard 501: %v", err)
	}
	if got, _ := e.svc.GetProposal(p.ID); got.State != model.ProposalDraft {
		t.Fatalf("rejected reason must not change the proposal: %+v", got)
	}
	if n := len(e.svc.ListChanges(0)); n != 0 {
		t.Fatalf("rejected reason must not record a change: %d", n)
	}
	if _, _, err := e.svc.Apply(ctx, p.ID, ok); err != nil {
		t.Fatalf("500 characters must pass: %v", err)
	}
	if err := e.svc.RemoveBlock(ctx, model.ListPackages, "pip:reqeusts", long); ErrorKind(err) != KindInvalid {
		t.Fatalf("unblock 501: %v", err)
	}
	if !e.svc.mustCheck(t, "pip", "reqeusts") {
		t.Fatal("rejected unblock must keep the entry")
	}
}

// 판정 메모(note)는 건에 남는다 — 판정 사유는 건 메모, 적용 · 버림 · 해제 사유는 변경 이력(목업 10/20 B 와 같은 구분)
func TestDecideNoteOnCase(t *testing.T) {
	e := newEnv(t)
	ctx := t.Context()
	s, err := e.svc.StartInstall(ctx, StartInput{Manager: "pip", Packages: []string{"./reqeusts"}, Container: "sg-install-pip-1", Image: "python:3.12-slim"})
	if err != nil {
		t.Fatal(err)
	}
	ev := sandboxEv(s.Container)
	ev.Kind, ev.DstIP, ev.DstPort, ev.DstHost = model.KindConnect, "203.0.113.7", 8081, "cdn.reqeusts-update.test"
	v := e.observe(t, ev)
	if _, _, err := e.svc.Decide(ctx, *v.CaseID, model.DecisionMalicious, "C2 도메인 확인"); err != nil {
		t.Fatal(err)
	}
	if c, _ := e.svc.GetCase(*v.CaseID); c.Note != "C2 도메인 확인" {
		t.Fatalf("note: %+v", c)
	}
}

func (s *Service) mustCheck(t *testing.T, mgr, pkg string) bool {
	t.Helper()
	r, err := s.CheckPackage(mgr, pkg)
	if err != nil {
		t.Fatal(err)
	}
	return r.Blocked
}

// runtimeCaseDecided: 런타임 컨테이너 격리 → 건 → 판정
func (e *env) runtimeCaseDecided(t *testing.T, d model.Decision) (model.Case, model.Proposal) {
	t.Helper()
	c := e.runtimeCase(t, "pkg-runtime-1", "demo/reqeusts:1.0.2")
	gotC, p, err := e.svc.Decide(t.Context(), c.ID, d, "")
	if err != nil {
		t.Fatal(err)
	}
	return gotC, p
}

// runtimeCase: 런타임 컨테이너가 /etc/shadow 를 열어 격리됨 → 열린 건
func (e *env) runtimeCase(t *testing.T, container, image string) model.Case {
	t.Helper()
	v := e.observe(t, model.Event{Kind: model.KindOpen, ContainerID: sandboxCID, ContainerName: container, ImageName: image, Path: "/etc/shadow"})
	if v.CaseID == nil {
		t.Fatalf("runtime kill must open a case: %+v", v)
	}
	c, err := e.svc.GetCase(*v.CaseID)
	if err != nil {
		t.Fatal(err)
	}
	return c
}
