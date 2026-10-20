package review

import (
	"slices"
	"testing"

	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/model"
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/rules"
)

// 정책 저장 전 확인(10/16): 정책 하나를 바꾼 사본으로 감사 로그를 다시 평가 — 엔진은 그대로
func TestPreviewRule(t *testing.T) {
	e := newEnv(t)
	ctx := t.Context()
	for range 2 {
		e.observe(t, model.Event{Kind: model.KindConnect, ContainerID: sandboxCID, ContainerName: "web-api", DstIP: "140.82.112.3", DstPort: 9418, DstHost: "github.com"})
	}
	i := slices.IndexFunc(e.engine.Rules(), func(r rules.Rule) bool { return r.ID == "egress-allowlist" })
	egress := e.engine.Rules()[i]
	egress.Action = model.ActionKill

	pv, err := e.svc.PreviewRule(ctx, egress)
	if err != nil {
		t.Fatal(err)
	}
	if pv.Evaluated != 2 || pv.Counts.ToBlocked != 2 || len(pv.Changed) != 2 || pv.NextOnly == nil || len(pv.NextOnly) != 0 {
		t.Fatalf("preview: %+v", pv)
	}
	if r := pv.Changed[0]; r.Before != model.LevelAlert || r.After != model.LevelKilled || r.RuleID != "egress-allowlist" {
		t.Fatalf("row: %+v", r)
	}
	if e.engine.Rules()[i].Action != model.ActionAlert {
		t.Fatal("preview must not change the engine")
	}

	// 새 정책(목록에 없는 id)은 더해서 평가
	allow := rules.Rule{ID: "allow-github", Kind: model.KindConnect, Action: model.ActionKill, DenyHosts: []string{"github.com"}}
	if pv, err = e.svc.PreviewRule(ctx, allow); err != nil || pv.Counts.ToBlocked != 2 {
		t.Fatalf("new rule preview: %+v %v", pv, err)
	}
	// 형식이 틀린 정책 · 시스템 규칙
	if _, err := e.svc.PreviewRule(ctx, rules.Rule{ID: "Bad ID", Kind: model.KindOpen, Action: model.ActionAlert}); ErrorKind(err) != KindInvalid {
		t.Fatalf("invalid rule: %v", err)
	}
	if _, err := e.svc.PreviewRule(ctx, rules.Rule{ID: rules.SystemBlocklistHosts, Kind: model.KindConnect, Action: model.ActionKill}); ErrorKind(err) != KindConflict {
		t.Fatalf("system rule: %v", err)
	}
}
