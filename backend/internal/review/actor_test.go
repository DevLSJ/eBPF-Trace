package review

import (
	"context"
	"strings"
	"testing"

	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/model"
)

type whoKey struct{}

func as(ctx context.Context, name string) context.Context {
	return context.WithValue(ctx, whoKey{}, name)
}

// Tier 1 감사 처리자: 판정 · 적용 · 차단 해제 · 정책 변경의 처리자는 요청자(ActorFrom). 모르면 ACTOR_NAME
func TestActorFromRequest(t *testing.T) {
	e := newEnv(t)
	e.svc.o.ActorFrom = func(ctx context.Context) string { s, _ := ctx.Value(whoKey{}).(string); return s }
	ctx := t.Context()

	s, err := e.svc.StartInstall(ctx, StartInput{Manager: "pip", Packages: []string{"./reqeusts"}, Container: "sg-install-pip-9", Image: "python:3.12-slim"})
	if err != nil {
		t.Fatal(err)
	}
	ev := sandboxEv(s.Container)
	ev.Kind, ev.DstIP, ev.DstPort, ev.DstHost = model.KindConnect, "203.0.113.7", 8081, "cdn.reqeusts-update.test"
	v := e.observe(t, ev)
	if v.CaseID == nil {
		t.Fatal("case")
	}

	// 1. Decide — 판정자 · 제안 작성자
	c, p, err := e.svc.Decide(as(ctx, "홍길동"), *v.CaseID, model.DecisionMalicious, "")
	if err != nil {
		t.Fatal(err)
	}
	if c.DecidedBy == nil || *c.DecidedBy != "홍길동" || p.CreatedBy != "홍길동" {
		t.Fatalf("decide: decidedBy=%v createdBy=%q", c.DecidedBy, p.CreatedBy)
	}

	// 2. Apply — 적용자 · 차단 항목 · 변경 이력
	p, _, err = e.svc.Apply(as(ctx, "cli"), p.ID, "")
	if err != nil {
		t.Fatal(err)
	}
	if p.AppliedBy == nil || *p.AppliedBy != "cli" {
		t.Fatalf("appliedBy %v", p.AppliedBy)
	}
	bl := e.svc.Blocklist()
	if len(bl.Packages) == 0 || bl.Packages[0].By != "cli" {
		t.Fatalf("block entry: %+v", bl.Packages)
	}
	if ch := e.svc.ListChanges(1)[0]; ch.By != "cli" || ch.Kind != model.ChangeProposalApplied {
		t.Fatalf("apply change: %+v", ch)
	}

	// 3. RemoveBlock — 요청자를 모르면(빈 값) ACTOR_NAME
	if err := e.svc.RemoveBlock(ctx, bl.Packages[0].List, bl.Packages[0].Value, ""); err != nil {
		t.Fatal(err)
	}
	if ch := e.svc.ListChanges(1)[0]; ch.By != DefaultActor || ch.Kind != model.ChangeBlocklistRemove {
		t.Fatalf("remove change: %+v", ch)
	}

	// 4. PolicyWrite
	if err := e.svc.PolicyWrite(as(ctx, "김조회"), model.ChangePolicyEdit, "정책 x 저장", []string{"x"}, func(context.Context) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if ch := e.svc.ListChanges(1)[0]; ch.By != "김조회" {
		t.Fatalf("policy change: %+v", ch)
	}
}

// 판정 메모 상한은 글자 수 2000(10/20 — 바이트로 세면 한글 약 666자에서 잘렸다)
func TestDecideNoteCountsRunes(t *testing.T) {
	e := newEnv(t)
	ctx := t.Context()
	open := func(name string) string {
		s, err := e.svc.StartInstall(ctx, StartInput{Manager: "pip", Packages: []string{"./" + name}, Container: "sg-install-pip-" + name, Image: "python:3.12-slim"})
		if err != nil {
			t.Fatal(err)
		}
		ev := sandboxEv(s.Container)
		ev.Kind, ev.DstIP, ev.DstPort, ev.DstHost = model.KindConnect, "203.0.113.7", 8081, "cdn."+name+".test"
		v := e.observe(t, ev)
		if v.CaseID == nil {
			t.Fatal("case")
		}
		return *v.CaseID
	}
	if _, _, err := e.svc.Decide(ctx, open("a"), model.DecisionMalicious, strings.Repeat("가", 2000)); err != nil {
		t.Fatalf("한글 2000자는 통과해야 함: %v", err)
	}
	if _, _, err := e.svc.Decide(ctx, open("b"), model.DecisionMalicious, strings.Repeat("가", 2001)); err == nil {
		t.Fatal("2001자는 거부해야 함")
	}
}
