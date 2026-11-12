package review

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/model"
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/rules"
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/store"
)

// 정책별 변경 이력 · 되돌리기(11/09, 사용자 결정 「전부 지금」).
// 변경 기록 = 다룬 정책 id(ruleIds) + 정책 id 별 변경 전 · 후 정책 전체(before · after, 키가 없으면 그때 정책 없음).
// 되돌리기 = 정책 하나 전체를 그 변경 직전 값으로(사유 필수) — 되돌린 것도 변경 기록(policy_revert · revertOf)에 남는다.

var (
	shadowKill  = rules.Rule{ID: "shadow", Kind: model.KindOpen, Action: model.ActionKill, DenyPaths: []string{"/etc/shadow"}}
	shadowAlert = rules.Rule{ID: "shadow", Kind: model.KindOpen, Action: model.ActionAlert, DenyPaths: []string{"/etc/shadow"}}
)

func ruleJSON(t *testing.T, r rules.Rule) string {
	t.Helper()
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func keys(m map[string]json.RawMessage) []string {
	out := []string{}
	for k := range m {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

// save · del: 정책 API 가 하는 것과 같은 쓰기(PolicyWrite + 저장소)
func (e *env) save(t *testing.T, ctx context.Context, r rules.Rule) model.Change {
	t.Helper()
	if err := e.svc.PolicyWrite(ctx, model.ChangePolicyEdit, "정책 "+r.ID+" 저장", []string{r.ID}, func(ctx context.Context) error {
		return e.store.Memory.UpsertPolicy(ctx, r)
	}); err != nil {
		t.Fatal(err)
	}
	return e.svc.ListChanges(1)[0]
}

func (e *env) del(t *testing.T, ctx context.Context, id string) model.Change {
	t.Helper()
	if err := e.svc.PolicyWrite(ctx, model.ChangePolicyEdit, "정책 "+id+" 삭제", []string{id}, func(ctx context.Context) error {
		_, err := e.store.Memory.DeletePolicy(ctx, id)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return e.svc.ListChanges(1)[0]
}

func storedRule(t *testing.T, e *env, id string) (rules.Rule, bool) {
	t.Helper()
	ps, err := e.store.Memory.ListPolicies(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	return ruleByID(ps, id)
}

// 저장(새로 만듦 · 고침) · 삭제 · YAML 교체가 정책 id 와 변경 전 · 후 값을 남긴다.
func TestPolicyWriteRecordsRuleValues(t *testing.T) {
	e := newEnv(t)
	ctx := t.Context()

	// 새로 만듦: before 에 키 없음
	c := e.save(t, ctx, shadowKill)
	if !slices.Equal(c.RuleIDs, []string{"shadow"}) || c.Before != nil || string(c.After["shadow"]) != ruleJSON(t, shadowKill) {
		t.Fatalf("create: ruleIds=%v before=%v after=%s", c.RuleIDs, c.Before, c.After["shadow"])
	}
	// 고침
	c = e.save(t, ctx, shadowAlert)
	if !slices.Equal(c.RuleIDs, []string{"shadow"}) || string(c.Before["shadow"]) != ruleJSON(t, shadowKill) || string(c.After["shadow"]) != ruleJSON(t, shadowAlert) {
		t.Fatalf("edit: %+v", c)
	}
	// 같은 값을 다시 저장해도 그 정책의 기록(앞뒤 같음)
	c = e.save(t, ctx, shadowAlert)
	if !slices.Equal(c.RuleIDs, []string{"shadow"}) || string(c.Before["shadow"]) != string(c.After["shadow"]) {
		t.Fatalf("same save: %+v", c)
	}
	// 삭제: after 에 키 없음
	c = e.del(t, ctx, "shadow")
	if !slices.Equal(c.RuleIDs, []string{"shadow"}) || string(c.Before["shadow"]) != ruleJSON(t, shadowAlert) || c.After != nil {
		t.Fatalf("delete: %+v", c)
	}

	// YAML 교체: 실제로 바뀐 정책만(고침 · 새로 · 빠짐), 그대로인 정책은 넣지 않는다
	var next []rules.Rule
	for _, r := range testRules {
		switch r.ID {
		case "reverse-shell-ports":
			continue
		case "egress-allowlist":
			r.Action = model.ActionKill
		}
		next = append(next, r)
	}
	newOne := rules.Rule{ID: "new-one", Kind: model.KindExec, Action: model.ActionAlert, DenyComms: []string{"nc"}}
	next = append(next, newOne)
	if err := e.svc.PolicyWrite(ctx, model.ChangePolicyReplace, "YAML 로 정책 6개 교체", nil, func(ctx context.Context) error {
		return e.store.Memory.ReplacePolicies(ctx, next)
	}); err != nil {
		t.Fatal(err)
	}
	c = e.svc.ListChanges(1)[0]
	if !slices.Equal(c.RuleIDs, []string{"egress-allowlist", "new-one", "reverse-shell-ports"}) {
		t.Fatalf("replace ruleIds: %v", c.RuleIDs)
	}
	if !slices.Equal(keys(c.Before), []string{"egress-allowlist", "reverse-shell-ports"}) || !slices.Equal(keys(c.After), []string{"egress-allowlist", "new-one"}) {
		t.Fatalf("replace before=%v after=%v", keys(c.Before), keys(c.After))
	}
	if string(c.After["new-one"]) != ruleJSON(t, newOne) {
		t.Fatalf("replace after: %s", c.After["new-one"])
	}
}

// 판정 제안 적용 · 차단 해제도 정책 id 를 남긴다. 예외를 더한 규칙은 변경 전 · 후 값까지,
// 도메인 차단 · 해제는 시스템 규칙 blocklist-hosts(값은 차단 목록이 기준이라 남기지 않음), 패키지 · 이미지는 정책 없음.
func TestApplyAndUnblockRecordRuleIDs(t *testing.T) {
	e := newEnv(t)
	ctx := t.Context()
	ev := model.Event{Kind: model.KindConnect, ContainerID: sandboxCID, ContainerName: "web-api", ImageName: "node:22",
		DstIP: "140.82.112.3", DstPort: 9418, DstHost: "github.com"}
	gitPort := rules.Rule{ID: "git-port", Kind: model.KindConnect, Action: model.ActionKill, AllowPorts: []uint16{443}}
	e.engine.Replace(append(e.engine.Rules(), gitPort))
	_ = e.store.Memory.UpsertPolicy(ctx, gitPort)
	egressBefore, _ := storedRule(t, e, "egress-allowlist")
	v := e.observe(t, ev)
	_, p, err := e.svc.Decide(ctx, *v.CaseID, model.DecisionFalsePositive, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := e.svc.Apply(ctx, p.ID, ""); err != nil {
		t.Fatal(err)
	}
	c := e.svc.ListChanges(1)[0]
	if c.Kind != model.ChangeProposalApplied || !slices.Equal(c.RuleIDs, []string{"egress-allowlist", "git-port"}) {
		t.Fatalf("apply ruleIds: %+v", c)
	}
	gitAfter, _ := storedRule(t, e, "git-port")
	egressAfter, _ := storedRule(t, e, "egress-allowlist")
	if string(c.Before["git-port"]) != ruleJSON(t, gitPort) || string(c.After["git-port"]) != ruleJSON(t, gitAfter) ||
		string(c.Before["egress-allowlist"]) != ruleJSON(t, egressBefore) || string(c.After["egress-allowlist"]) != ruleJSON(t, egressAfter) {
		t.Fatalf("apply values: before=%v after=%v", c.Before, c.After)
	}
	if !slices.Contains(gitAfter.AllowCIDRs, "140.82.112.3/32") {
		t.Fatalf("exception must be stored: %+v", gitAfter)
	}

	// 악성: 패키지 + 도메인 차단 → blocklist-hosts 만, 값 없음
	_, p2 := e.maliciousInstallCase(t)
	if _, _, err := e.svc.Apply(ctx, p2.ID, ""); err != nil {
		t.Fatal(err)
	}
	c = e.svc.ListChanges(1)[0]
	if !slices.Equal(c.RuleIDs, []string{rules.SystemBlocklistHosts}) || c.Before != nil || c.After != nil {
		t.Fatalf("block apply: %+v", c)
	}
	if err := e.svc.RemoveBlock(ctx, model.ListPackages, "pip:reqeusts", ""); err != nil {
		t.Fatal(err)
	}
	if c = e.svc.ListChanges(1)[0]; len(c.RuleIDs) != 0 {
		t.Fatalf("package unblock has no policy: %+v", c)
	}
	if err := e.svc.RemoveBlock(ctx, model.ListHosts, "cdn.reqeusts-update.test", ""); err != nil {
		t.Fatal(err)
	}
	if c = e.svc.ListChanges(1)[0]; !slices.Equal(c.RuleIDs, []string{rules.SystemBlocklistHosts}) || c.Before != nil {
		t.Fatalf("host unblock: %+v", c)
	}
}

// 되돌리기: 그 변경 직전 값으로 정책 하나 전체를 되돌리고(저장소 · 엔진), 되돌린 것도 기록한다. 되돌린 것을 다시 되돌릴 수도 있다.
func TestRevertPolicy(t *testing.T) {
	e := newEnv(t)
	e.svc.o.ActorFrom = func(ctx context.Context) string { s, _ := ctx.Value(whoKey{}).(string); return s }
	ctx := t.Context()
	created := e.save(t, ctx, shadowKill)
	edited := e.save(t, ctx, shadowAlert)

	got, err := e.svc.RevertPolicy(as(ctx, "김관리"), "shadow", edited.ID, "  오탐 증가  ")
	if err != nil {
		t.Fatal(err)
	}
	if ruleJSON(t, got) != ruleJSON(t, shadowKill) {
		t.Fatalf("revert result: %+v", got)
	}
	if r, _ := storedRule(t, e, "shadow"); ruleJSON(t, r) != ruleJSON(t, shadowKill) {
		t.Fatalf("stored: %+v", r)
	}
	if r, _ := ruleByID(e.engine.Rules(), "shadow"); r.Action != model.ActionKill {
		t.Fatalf("engine must reload: %+v", r)
	}
	rv := e.svc.ListChanges(1)[0]
	if rv.Kind != model.ChangePolicyRevert || !slices.Equal(rv.RuleIDs, []string{"shadow"}) || rv.RevertOf == nil || *rv.RevertOf != edited.ID ||
		rv.Reason != "오탐 증가" || rv.By != "김관리" || rv.Summary != "정책 shadow 되돌림("+edited.ID+" 이전 값)" ||
		string(rv.Before["shadow"]) != ruleJSON(t, shadowAlert) || string(rv.After["shadow"]) != ruleJSON(t, shadowKill) {
		t.Fatalf("revert change: %+v", rv)
	}

	// 오류 — 기록 · 정책은 그대로
	n := len(e.svc.ListChanges(500))
	for _, tc := range []struct {
		name, id, change, reason string
		kind                     ErrKind
	}{
		{"사유 없음", "shadow", edited.ID, "", KindInvalid},
		{"공백 사유", "shadow", edited.ID, "   ", KindInvalid},
		{"사유 501자", "shadow", edited.ID, strings.Repeat("가", 501), KindInvalid},
		{"변경 id 없음", "shadow", "", "r", KindInvalid},
		{"없는 변경", "shadow", "chg-0999", "r", KindNotFound},
		{"다른 정책의 변경", "egress-allowlist", edited.ID, "r", KindNotFound},
		{"새로 만든 변경", "shadow", created.ID, "r", KindConflict},
		{"이미 그 값", "shadow", edited.ID, "r", KindConflict},
		{"시스템 규칙", rules.SystemBlocklistHosts, edited.ID, "r", KindConflict},
	} {
		if _, err := e.svc.RevertPolicy(ctx, tc.id, tc.change, tc.reason); ErrorKind(err) != tc.kind {
			t.Errorf("%s: err %v, want kind %d", tc.name, err, tc.kind)
		}
	}
	if got := len(e.svc.ListChanges(500)); got != n {
		t.Fatalf("failed reverts must not record changes: %d → %d", n, got)
	}
	if r, _ := storedRule(t, e, "shadow"); r.Action != model.ActionKill {
		t.Fatalf("failed reverts must not touch the policy: %+v", r)
	}

	// 되돌린 것을 다시 되돌림 → shadowAlert. 시스템 규칙(차단 목록)은 그대로 엔진에 남는다
	_, p := e.maliciousInstallCase(t)
	if _, _, err := e.svc.Apply(ctx, p.ID, ""); err != nil {
		t.Fatal(err)
	}
	if got, err = e.svc.RevertPolicy(ctx, "shadow", rv.ID, "다시"); err != nil || got.Action != model.ActionAlert {
		t.Fatalf("revert of revert: %+v %v", got, err)
	}
	if _, ok := ruleByID(e.engine.Rules(), rules.SystemBlocklistHosts); !ok {
		t.Fatal("revert must keep the blocklist system rule in the engine")
	}

	// 지운 정책 되돌리기 = 다시 만듦(변경 전 값 없음)
	deleted := e.del(t, ctx, "shadow")
	if got, err = e.svc.RevertPolicy(ctx, "shadow", deleted.ID, "실수로 지움"); err != nil || got.Action != model.ActionAlert {
		t.Fatalf("revert delete: %+v %v", got, err)
	}
	if _, ok := ruleByID(e.engine.Rules(), "shadow"); !ok {
		t.Fatal("restored policy must be in the engine")
	}
	restore := e.svc.ListChanges(1)[0]
	if restore.Before != nil || string(restore.After["shadow"]) != ruleJSON(t, shadowAlert) {
		t.Fatalf("restore change: %+v", restore)
	}
	// 다시 만든 기록을 되돌리는 것 = 삭제 — 되돌리기로는 하지 않는다(정책 삭제를 쓴다)
	if _, err := e.svc.RevertPolicy(ctx, "shadow", restore.ID, "r"); ErrorKind(err) != KindConflict {
		t.Fatalf("revert of a re-create: %v", err)
	}
}

// 저장소 커밋이 실패하면 정책 · 엔진 · 변경 기록이 하나도 바뀌지 않는다(제안 적용과 같은 원자성).
func TestRevertIsAtomic(t *testing.T) {
	e := newEnv(t)
	ctx := t.Context()
	e.save(t, ctx, shadowKill)
	edited := e.save(t, ctx, shadowAlert)
	n := len(e.svc.ListChanges(500))
	e.store.setFail(true)
	if _, err := e.svc.RevertPolicy(ctx, "shadow", edited.ID, "r"); err == nil {
		t.Fatal("revert must fail when the store commit fails")
	}
	e.store.setFail(false)
	if r, _ := storedRule(t, e, "shadow"); r.Action != model.ActionAlert {
		t.Fatalf("stored policy must stay: %+v", r)
	}
	if r, _ := ruleByID(e.engine.Rules(), "shadow"); r.Action != model.ActionAlert {
		t.Fatalf("engine must stay: %+v", r)
	}
	if got := len(e.svc.ListChanges(500)); got != n {
		t.Fatalf("no change record on failure: %d → %d", n, got)
	}
}

// 저장된 변경 전 값이 지금 규칙 검사를 통과하지 않으면(옛 판 · 손상) 되돌리지 않는다(409).
func TestRevertRejectsInvalidSnapshot(t *testing.T) {
	e := newEnv(t)
	ctx := t.Context()
	bad := model.Change{ID: "chg-0042", At: e.now, By: "x", Kind: model.ChangePolicyEdit, Summary: "정책 sensitive-files 저장",
		RuleIDs: []string{"sensitive-files"},
		Before:  map[string]json.RawMessage{"sensitive-files": json.RawMessage(`{"id":"sensitive-files","kind":"bogus","action":"kill"}`)},
		After:   map[string]json.RawMessage{"sensitive-files": json.RawMessage(ruleJSON(t, testRules[0]))}}
	if err := e.store.Memory.CommitReview(ctx, store.ReviewCommit{Changes: []model.Change{bad}}); err != nil {
		t.Fatal(err)
	}
	e2 := New(Options{Store: e.store, Policies: e.store.Memory, Audit: e.store.Memory, Engine: e.engine, Now: func() time.Time { return e.now }})
	if err := e2.Load(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := e2.RevertPolicy(ctx, "sensitive-files", "chg-0042", "r"); ErrorKind(err) != KindConflict {
		t.Fatalf("invalid snapshot: %v", err)
	}
}

// 조회: 정책 id(ruleIds 포함) · 종류로 거르고 최신순 쪽 넘김. 정책으로 거르면 before · after 는 그 정책 값만 싣는다(캐시는 그대로).
// ruleIds 는 늘 배열(정책과 무관한 기록은 []).
func TestQueryChanges(t *testing.T) {
	e := newEnv(t)
	ctx := t.Context()
	a := rules.Rule{ID: "a", Kind: model.KindExec, Action: model.ActionAlert, DenyComms: []string{"nc"}}
	b := rules.Rule{ID: "b", Kind: model.KindExec, Action: model.ActionAlert, DenyComms: []string{"socat"}}
	c1 := e.save(t, ctx, a)
	e.save(t, ctx, b)
	a2 := a
	a2.Action = model.ActionKill
	c3 := e.save(t, ctx, a2)
	if err := e.svc.RecordChange(ctx, model.ChangeDemoRun, "시연 실행: shell"); err != nil {
		t.Fatal(err)
	}
	a3, b3 := a2, b
	a3.Disabled, b3.Disabled = true, true
	if err := e.svc.PolicyWrite(ctx, model.ChangePolicyReplace, "YAML", nil, func(ctx context.Context) error {
		return e.store.Memory.ReplacePolicies(ctx, append(slices.Clone(testRules), a3, b3))
	}); err != nil {
		t.Fatal(err)
	}
	c5 := e.svc.ListChanges(1)[0]
	if !slices.Equal(c5.RuleIDs, []string{"a", "b"}) {
		t.Fatalf("replace ruleIds: %v", c5.RuleIDs)
	}

	items, total := e.svc.QueryChanges(ChangeQuery{RuleID: "a"})
	if total != 3 || len(items) != 3 || items[0].ID != c5.ID || items[1].ID != c3.ID || items[2].ID != c1.ID {
		t.Fatalf("rule a: total=%d %v", total, ids(items))
	}
	if !slices.Equal(keys(items[0].Before), []string{"a"}) || !slices.Equal(keys(items[0].After), []string{"a"}) || !slices.Equal(items[0].RuleIDs, []string{"a", "b"}) {
		t.Fatalf("filtered values must hold only rule a: before=%v after=%v ruleIds=%v", keys(items[0].Before), keys(items[0].After), items[0].RuleIDs)
	}
	if all, _ := e.svc.QueryChanges(ChangeQuery{}); !slices.Equal(keys(all[0].After), []string{"a", "b"}) {
		t.Fatalf("narrowing must not touch the cache: %v", keys(all[0].After))
	}
	if items, total = e.svc.QueryChanges(ChangeQuery{RuleID: "a", Offset: 1, Limit: 1}); total != 3 || len(items) != 1 || items[0].ID != c3.ID {
		t.Fatalf("page: total=%d %v", total, ids(items))
	}
	if items, total = e.svc.QueryChanges(ChangeQuery{RuleID: "a", Offset: 9}); total != 3 || len(items) != 0 || items == nil {
		t.Fatalf("past the end: total=%d %v", total, items)
	}
	if items, total = e.svc.QueryChanges(ChangeQuery{RuleID: "nope"}); total != 0 || items == nil {
		t.Fatalf("no match must be an empty list: %v", items)
	}
	items, total = e.svc.QueryChanges(ChangeQuery{Kind: model.ChangeDemoRun})
	if total != 1 || items[0].RuleIDs == nil || len(items[0].RuleIDs) != 0 {
		t.Fatalf("demo: total=%d %+v", total, items)
	}
	if items, total = e.svc.QueryChanges(ChangeQuery{Kind: model.ChangePolicyEdit, RuleID: "b"}); total != 1 {
		t.Fatalf("kind + rule: %d %v", total, ids(items))
	}
	// 기본 50 · 상한 500 (ListChanges 와 같음)
	for _, x := range e.svc.ListChanges(0) {
		if x.RuleIDs == nil {
			t.Fatalf("ruleIds must always be a list: %+v", x)
		}
	}
	if _, total = e.svc.QueryChanges(ChangeQuery{Limit: 100000}); total != 5 {
		t.Fatalf("total: %d", total)
	}
}

func ids(cs []model.Change) []string {
	out := []string{}
	for _, c := range cs {
		out = append(out, c.ID)
	}
	return out
}

// 정책 목록의 최근 수정 = 그 정책을 다룬 마지막 변경 기록의 시각 · 처리자. 기록이 없는 정책(시드)은 없음.
func TestPolicyMeta(t *testing.T) {
	e := newEnv(t)
	e.svc.o.ActorFrom = func(ctx context.Context) string { s, _ := ctx.Value(whoKey{}).(string); return s }
	ctx := t.Context()
	t0 := e.now
	e.save(t, as(ctx, "김관리"), shadowKill)
	e.now = t0.Add(time.Minute)
	e.save(t, as(ctx, "이편집"), shadowAlert)
	e.now = t0.Add(2 * time.Minute)
	if err := e.svc.RecordChange(ctx, model.ChangeDemoRun, "시연 실행: shell"); err != nil {
		t.Fatal(err)
	}
	m := e.svc.PolicyMeta()
	if got := m["shadow"]; !got.At.Equal(t0.Add(time.Minute)) || got.By != "이편집" {
		t.Fatalf("shadow meta: %+v", got)
	}
	if _, ok := m["sensitive-files"]; ok {
		t.Fatal("seeded policy without a change record has no meta")
	}
	_, p := e.maliciousInstallCase(t)
	e.now = t0.Add(3 * time.Minute)
	if _, _, err := e.svc.Apply(as(ctx, "cli"), p.ID, ""); err != nil {
		t.Fatal(err)
	}
	if got := e.svc.PolicyMeta()[rules.SystemBlocklistHosts]; !got.At.Equal(t0.Add(3*time.Minute)) || got.By != "cli" {
		t.Fatalf("system rule meta: %+v", got)
	}
}
