package store

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/model"
)

// 정책별 변경 이력(11/09): ruleIds · before · after · revertOf 는 changes.doc(jsonb) 에 함께 저장된다 — 스키마 변경 없음(W15 reason 과 같은 방식).
// 키가 없던 옛 행은 빈 값으로 읽힌다.

func historyChange(at time.Time) model.Change {
	of := "chg-0001"
	return model.Change{ID: "chg-0002", At: at, By: "admin", Kind: model.ChangePolicyRevert, Summary: "정책 shadow 되돌림", Reason: "오탐 증가",
		RuleIDs:  []string{"shadow"},
		Before:   map[string]json.RawMessage{"shadow": json.RawMessage(`{"id":"shadow","kind":"open","action":"kill"}`)},
		After:    map[string]json.RawMessage{"shadow": json.RawMessage(`{"id":"shadow","kind":"open","action":"alert"}`)},
		RevertOf: &of}
}

func checkHistory(t *testing.T, got model.Change) {
	t.Helper()
	if len(got.RuleIDs) != 1 || got.RuleIDs[0] != "shadow" || got.RevertOf == nil || *got.RevertOf != "chg-0001" ||
		got.Kind != model.ChangePolicyRevert || got.Reason != "오탐 증가" {
		t.Fatalf("change: %+v", got)
	}
	var b, a map[string]any
	if err := json.Unmarshal(got.Before["shadow"], &b); err != nil || b["action"] != "kill" {
		t.Fatalf("before: %s %v", got.Before["shadow"], err)
	}
	if err := json.Unmarshal(got.After["shadow"], &a); err != nil || a["action"] != "alert" {
		t.Fatalf("after: %s %v", got.After["shadow"], err)
	}
}

func TestPostgresChangeHistory(t *testing.T) {
	p := testPG(t)
	ctx := t.Context()
	at := time.Date(2026, 11, 9, 9, 0, 0, 0, time.UTC)
	if err := p.CommitReview(ctx, ReviewCommit{Changes: []model.Change{historyChange(at)}}); err != nil {
		t.Fatal(err)
	}
	if _, err := p.pool.Exec(ctx, `INSERT INTO changes (id, at, doc) VALUES ('chg-0003', $1, '{"id":"chg-0003","kind":"policy_edit","summary":"정책 x 저장"}')`, at.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	s, err := p.LoadReview(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Changes) != 2 {
		t.Fatalf("changes: %+v", s.Changes)
	}
	checkHistory(t, s.Changes[0])
	if old := s.Changes[1]; old.RuleIDs != nil || old.Before != nil || old.After != nil || old.RevertOf != nil {
		t.Fatalf("old row must read empty: %+v", old)
	}
}

// 메모리 저장소도 사본을 가진다 — 커밋한 쪽 · 읽은 쪽이 ruleIds · before · after 를 바꿔도 저장된 기록은 그대로
func TestMemoryChangeHistoryIsCopied(t *testing.T) {
	m := NewMemory()
	ctx := t.Context()
	in := historyChange(time.Now().UTC())
	if err := m.CommitReview(ctx, ReviewCommit{Changes: []model.Change{in}}); err != nil {
		t.Fatal(err)
	}
	in.RuleIDs[0] = "mutated"
	in.Before["shadow"] = json.RawMessage(`{"action":"mutated"}`)
	s, _ := m.LoadReview(ctx)
	if len(s.Changes) != 1 {
		t.Fatalf("changes: %+v", s.Changes)
	}
	checkHistory(t, s.Changes[0])
	s.Changes[0].RuleIDs[0] = "mutated"
	s.Changes[0].After["shadow"] = json.RawMessage(`{"action":"mutated"}`)
	s2, _ := m.LoadReview(ctx)
	checkHistory(t, s2.Changes[0])
}
