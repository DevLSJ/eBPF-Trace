package model

import (
	"encoding/json"
	"strings"
	"testing"
)

// 연쇄 규칙(kind: sequence, 11/03): 판정 jsonb 에 sequence 가 있으면 읽고 다시 낼 때 그대로 남는다. 없으면 키도 없다(omitempty).
func TestVerdictSequenceJSONRoundTrip(t *testing.T) {
	in := `{"event":{"kind":"open","timestamp":"2026-11-03T09:00:02.4Z","containerId":"c1","containerName":"web","imageName":"","comm":"python","pid":7,"path":"/root/.netrc"},` +
		`"matched":true,"ruleId":"chain-download-secrets","action":"kill","reason":"r","caseId":null,"install":null,` +
		`"sequence":{"ruleId":"chain-download-secrets","action":"kill","dryRun":true,"steps":[` +
		`{"kind":"exec","timestamp":"2026-11-03T09:00:00Z","comm":"wget","pid":5,"detail":"wget http://x"},` +
		`{"kind":"connect","timestamp":"2026-11-03T09:00:01Z","comm":"wget","pid":5,"detail":"203.0.113.7:80"},` +
		`{"kind":"open","timestamp":"2026-11-03T09:00:02.4Z","comm":"python","pid":7,"detail":"/root/.netrc"}]}}`
	var v Verdict
	if err := json.Unmarshal([]byte(in), &v); err != nil {
		t.Fatal(err)
	}
	got := mustJSON(t, v)
	for _, want := range []string{
		`"sequence":{"ruleId":"chain-download-secrets","action":"kill","dryRun":true,"steps":[`,
		`{"kind":"exec","timestamp":"2026-11-03T09:00:00Z","comm":"wget","pid":5,"detail":"wget http://x"}`,
		`{"kind":"open","timestamp":"2026-11-03T09:00:02.4Z","comm":"python","pid":7,"detail":"/root/.netrc"}]}`,
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("round trip lost %s\n got %s", want, got)
		}
	}
	if s := mustJSON(t, Verdict{Event: Event{Kind: KindOpen}, Matched: true}); strings.Contains(s, "sequence") {
		t.Fatalf("sequence must be omitted when empty: %s", s)
	}
}

// KindSequence 는 규칙 kind 일 뿐 이벤트 kind 가 아니다 — Kinds(이벤트 검증 · 감사 필터)에 넣지 않는다.
func TestKindSequenceIsNotEventKind(t *testing.T) {
	if KindSequence != "sequence" {
		t.Fatalf("KindSequence = %q", KindSequence)
	}
	if KindSequence.Valid() {
		t.Fatal("sequence must not be a valid event kind")
	}
	for _, k := range Kinds {
		if k == KindSequence {
			t.Fatal("Kinds must not list sequence")
		}
	}
	hit := SequenceHit{RuleID: "r", Action: ActionKill, Steps: []SequenceStep{{Kind: KindExec, Comm: "wget", Pid: 5, Detail: "wget x"}}}
	if s := mustJSON(t, hit); strings.Contains(s, "dryRun") || !strings.Contains(s, `"steps":[{"kind":"exec"`) {
		t.Fatalf("hit json: %s", s)
	}
}
