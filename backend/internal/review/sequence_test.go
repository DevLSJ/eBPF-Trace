package review

import (
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/model"
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/rules"
)

// 연쇄 규칙(11/04) 「오탐」: 자동 예외 제안은 상태 없는 Evaluate 로 재평가하므로 연쇄 규칙을 다시 맞히지 못한다.
// 빈 제안을 말없이 돌려주지 않고, 연쇄 규칙은 자동 예외를 만들지 않는다는 안내를 남긴다.
func TestFalsePositiveSequenceNote(t *testing.T) {
	e := newEnv(t)
	ctx := t.Context()
	chain := rules.Rule{ID: "chain-test", Kind: model.KindSequence, Action: model.ActionKill, WindowSeconds: 10,
		Steps: []rules.Rule{
			{Kind: model.KindExec, DenyComms: []string{"wget"}},
			{Kind: model.KindConnect, AllowCIDRs: []string{"10.0.0.0/8", "127.0.0.0/8"}},
			{Kind: model.KindOpen, DenyPaths: []string{"/root/.netrc"}},
		}}
	if err := e.store.ReplacePolicies(ctx, append(slices.Clone(testRules), chain)); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.Reload(ctx); err != nil {
		t.Fatal(err)
	}

	// 파이프라인처럼 Observe(연쇄 진행) → 격리 표시 → 건 반영 → 감사 저장
	observe := func(ev model.Event, at time.Duration) model.Verdict {
		t.Helper()
		ev.ContainerID, ev.ContainerName, ev.ImageName = sandboxCID, "web-api", "python:3.12-slim"
		ev.Timestamp = e.now.Add(at)
		v := e.engine.Observe(ev)
		if v.Matched && v.Action == model.ActionKill && !v.DryRun {
			v.Enforced = true
		}
		e.svc.Observe(&v)
		if v.Matched {
			if _, err := e.store.SaveAudit(ctx, v); err != nil {
				t.Fatal(err)
			}
		}
		return v
	}
	observe(model.Event{Kind: model.KindExec, Comm: "wget"}, 0)
	observe(model.Event{Kind: model.KindConnect, Comm: "wget", DstIP: "203.0.113.7", DstPort: 443}, 2*time.Second)
	v := observe(model.Event{Kind: model.KindOpen, Comm: "python3", Path: "/root/.netrc"}, 3*time.Second)
	if !v.Matched || v.RuleID != "chain-test" || v.Sequence == nil || v.CaseID == nil {
		t.Fatalf("completed sequence must be the verdict and open a case: %+v", v)
	}

	_, p, err := e.svc.Decide(ctx, *v.CaseID, model.DecisionFalsePositive, "")
	if err != nil {
		t.Fatal(err)
	}
	if slices.ContainsFunc(p.Changes, func(c model.ProposalChange) bool { return c.RuleID == "chain-test" }) {
		t.Fatalf("no automatic exception for a sequence rule: %+v", p.Changes)
	}
	if !slices.ContainsFunc(p.Notes, func(n string) bool {
		return strings.Contains(n, "연쇄 규칙 chain-test") && strings.Contains(n, "자동 예외를 만들지 않습니다") && strings.Contains(n, "정책 탭")
	}) {
		t.Fatalf("a note must explain why the sequence rule got no exception: changes=%+v notes=%v", p.Changes, p.Notes)
	}
}
