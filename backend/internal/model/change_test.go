package model

import (
	"encoding/json"
	"strings"
	"testing"
)

// 정책별 변경 이력(11/09): 변경 기록은 다룬 정책 id(ruleIds) · 정책 id 별 변경 전 · 후 정책 전체(before · after) ·
// 되돌린 변경 id(revertOf)를 함께 가진다. changes.doc(jsonb) 에 그대로 저장되므로 옛 행은 이 키들이 없다.
func TestChangeHistoryJSON(t *testing.T) {
	if ChangePolicyRevert != "policy_revert" {
		t.Fatalf("kind %q", ChangePolicyRevert)
	}
	of := "chg-0002"
	c := Change{ID: "chg-0003", Kind: ChangePolicyRevert, Summary: "정책 shadow 되돌림", Reason: "오탐 증가",
		RuleIDs:  []string{"shadow"},
		Before:   map[string]json.RawMessage{"shadow": json.RawMessage(`{"id":"shadow","kind":"open","action":"alert"}`)},
		After:    map[string]json.RawMessage{"shadow": json.RawMessage(`{"id":"shadow","kind":"open","action":"kill"}`)},
		RevertOf: &of}
	got := mustJSON(t, c)
	for _, want := range []string{
		`"ruleIds":["shadow"]`,
		`"before":{"shadow":{"id":"shadow","kind":"open","action":"alert"}}`,
		`"after":{"shadow":{"id":"shadow","kind":"open","action":"kill"}}`,
		`"revertOf":"chg-0002"`,
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("JSON lacks %s\n got %s", want, got)
		}
	}

	// 옛 행: 키가 없으면 빈 값으로 읽히고, 다시 낼 때 before · after · revertOf 키도 없다
	var old Change
	if err := json.Unmarshal([]byte(`{"id":"chg-0001","kind":"policy_edit","summary":"옛 행"}`), &old); err != nil {
		t.Fatal(err)
	}
	if old.RuleIDs != nil || old.Before != nil || old.After != nil || old.RevertOf != nil {
		t.Fatalf("old row: %+v", old)
	}
	out := mustJSON(t, old)
	for _, k := range []string{`"before"`, `"after"`, `"revertOf"`} {
		if strings.Contains(out, k) {
			t.Fatalf("old row must not grow %s: %s", k, out)
		}
	}
}

// Touches: 이 변경이 그 정책을 다뤘는지(ruleIds 기준)
func TestChangeTouches(t *testing.T) {
	c := Change{RuleIDs: []string{"a", "blocklist-hosts"}}
	if !c.Touches("a") || !c.Touches("blocklist-hosts") || c.Touches("b") || (Change{}).Touches("a") {
		t.Fatal("Touches")
	}
}

// Clone: 저장소 · 캐시가 사본을 가진다 — 사본의 ruleIds · before · after 를 바꿔도 원본은 그대로
func TestChangeClone(t *testing.T) {
	of := "chg-0001"
	c := Change{RuleIDs: []string{"a"}, Before: map[string]json.RawMessage{"a": json.RawMessage(`{"id":"a"}`)},
		After: map[string]json.RawMessage{"a": json.RawMessage(`{"id":"a","disabled":true}`)}, RevertOf: &of}
	d := c.Clone()
	d.RuleIDs[0] = "x"
	d.Before["a"][2] = 'X'
	d.After["b"] = json.RawMessage(`{}`)
	*d.RevertOf = "chg-9999"
	if c.RuleIDs[0] != "a" || string(c.Before["a"]) != `{"id":"a"}` || len(c.After) != 1 || *c.RevertOf != "chg-0001" {
		t.Fatalf("clone shares state: %+v", c)
	}
	if e := (Change{}).Clone(); e.RuleIDs != nil || e.Before != nil || e.After != nil || e.RevertOf != nil {
		t.Fatalf("empty clone: %+v", e)
	}
}
