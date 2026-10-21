package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/model"
)

// W15: 적용 · 버림 · 차단 해제의 사유(본문 {reason}, 선택, 500자) → GET /api/changes 의 reason.
// 판정 미리보기 POST /api/cases/{id}/preview → {caseId, decision, changes, notes, effects[{kind, text, count?}]} (저장 없음).

func (s *reviewServer) openInstallCase(t *testing.T, container string) string {
	t.Helper()
	r := do(t, "POST", s.srv.URL+"/api/installs", "", `{"manager":"pip","packages":["./reqeusts"],"container":"`+container+`","image":"python:3.12-slim"}`)
	want(t, r, http.StatusCreated, "start")
	v := s.observe(t, model.Event{Kind: model.KindConnect, ContainerID: strings.Repeat("a", 64), ContainerName: container,
		ImageName: "python:3.12-slim", DstIP: "203.0.113.7", DstPort: 8081, DstHost: "cdn.reqeusts-update.test"})
	if v.CaseID == nil {
		t.Fatal("violation must open a case")
	}
	return *v.CaseID
}

func (s *reviewServer) decide(t *testing.T, caseID, decision string) string {
	t.Helper()
	r := do(t, "POST", s.srv.URL+"/api/cases/"+caseID+"/decide", "", `{"decision":"`+decision+`","note":"판정 메모"}`)
	want(t, r, http.StatusOK, "decide")
	out := decode[map[string]map[string]any](t, r)
	if out["case"]["note"] != "판정 메모" {
		t.Fatalf("decide note must be on the case: %v", out["case"])
	}
	return out["proposal"]["id"].(string)
}

func TestReasonInChangesHTTP(t *testing.T) {
	s := newReviewServer(t, "", "", true, seedRules)
	u := s.srv.URL
	long := `{"reason":"` + strings.Repeat("가", 501) + `"}`

	// 적용
	pid := s.decide(t, s.openInstallCase(t, "sg-install-pip-1-1"), "malicious")
	want(t, do(t, "POST", u+"/api/proposals/"+pid+"/apply", "", long), http.StatusBadRequest, "apply 501")
	want(t, do(t, "POST", u+"/api/proposals/"+pid+"/apply", "", `{"reason":"x","bogus":1}`), http.StatusBadRequest, "apply unknown field")
	want(t, do(t, "POST", u+"/api/proposals/"+pid+"/apply", "", `{"reason":"C2 도메인 확인"}`), http.StatusOK, "apply")
	chs := decode[[]map[string]any](t, do(t, "GET", u+"/api/changes", "", ""))
	if len(chs) != 1 || chs[0]["kind"] != "proposal_applied" || chs[0]["reason"] != "C2 도메인 확인" {
		t.Fatalf("apply change: %v", chs)
	}

	// 차단 해제 (DELETE 본문)
	want(t, do(t, "DELETE", u+"/api/blocklist/packages/pip:reqeusts", "", long), http.StatusBadRequest, "unblock 501")
	want(t, do(t, "DELETE", u+"/api/blocklist/packages/pip:reqeusts", "", `{"reason":"오탐 재확인"}`), http.StatusNoContent, "unblock")
	chs = decode[[]map[string]any](t, do(t, "GET", u+"/api/changes", "", ""))
	if chs[0]["kind"] != "blocklist_remove" || chs[0]["reason"] != "오탐 재확인" {
		t.Fatalf("unblock change: %v", chs[0])
	}
	// 본문 없이도 된다(예전 호출 · CLI) — reason ""
	want(t, do(t, "DELETE", u+"/api/blocklist/hosts/cdn.reqeusts-update.test", "", ""), http.StatusNoContent, "unblock without body")
	chs = decode[[]map[string]any](t, do(t, "GET", u+"/api/changes", "", ""))
	if r, ok := chs[0]["reason"]; !ok || r != "" {
		t.Fatalf("reason must always be present: %v", chs[0])
	}

	// 버림 → 변경 이력 proposal_discarded
	pid = s.decide(t, s.openInstallCase(t, "sg-install-pip-1-2"), "false_positive")
	want(t, do(t, "POST", u+"/api/proposals/"+pid+"/discard", "", long), http.StatusBadRequest, "discard 501")
	want(t, do(t, "POST", u+"/api/proposals/"+pid+"/discard", "", `{"reason":"이번엔 그대로 둔다"}`), http.StatusOK, "discard")
	chs = decode[[]map[string]any](t, do(t, "GET", u+"/api/changes", "", ""))
	if chs[0]["kind"] != "proposal_discarded" || chs[0]["reason"] != "이번엔 그대로 둔다" || chs[0]["proposalId"] != pid {
		t.Fatalf("discard change: %v", chs[0])
	}

	// 사유 없는 적용(빈 본문)도 그대로 된다
	pid = s.decide(t, s.openInstallCase(t, "sg-install-pip-1-3"), "malicious")
	want(t, do(t, "POST", u+"/api/proposals/"+pid+"/apply", "", ""), http.StatusOK, "apply without body")
}

func TestDecisionPreviewHTTP(t *testing.T) {
	s := newReviewServer(t, "", "", true, seedRules)
	u := s.srv.URL
	cid := s.openInstallCase(t, "sg-install-pip-1-1")

	want(t, do(t, "POST", u+"/api/cases/"+cid+"/preview", "", `{"decision":"pending"}`), http.StatusBadRequest, "bad decision")
	want(t, do(t, "POST", u+"/api/cases/case-9999/preview", "", `{"decision":"malicious"}`), http.StatusNotFound, "missing case")

	r := do(t, "POST", u+"/api/cases/"+cid+"/preview", "", `{"decision":"malicious"}`)
	want(t, r, http.StatusOK, "preview")
	pv := decode[map[string]any](t, r)
	for _, k := range []string{"caseId", "decision", "changes", "notes", "effects"} {
		if _, ok := pv[k]; !ok {
			t.Errorf("preview JSON lacks %q: %v", k, pv)
		}
	}
	effects, _ := pv["effects"].([]any)
	if len(effects) == 0 {
		t.Fatalf("effects: %v", pv)
	}
	if e0, _ := effects[0].(map[string]any); e0["kind"] == nil || e0["text"] == nil {
		t.Fatalf("effect shape: %v", effects[0])
	}
	// 저장 안 됨
	if c := decode[map[string]any](t, do(t, "GET", u+"/api/cases/"+cid, "", "")); c["state"] != "open" || c["decision"] != "pending" || c["proposalId"] != nil {
		t.Fatalf("preview must not change the case: %v", c)
	}

	// 판정 결과 제안 = 미리보기
	r = do(t, "POST", u+"/api/cases/"+cid+"/decide", "", `{"decision":"malicious"}`)
	want(t, r, http.StatusOK, "decide")
	got := decode[map[string]map[string]any](t, r)
	if !jsonEqual(got["proposal"]["changes"], pv["changes"]) || !jsonEqual(got["proposal"]["notes"], pv["notes"]) {
		t.Fatalf("preview ≠ decide: %v vs %v", pv["changes"], got["proposal"]["changes"])
	}
	want(t, do(t, "POST", u+"/api/cases/"+cid+"/preview", "", `{"decision":"malicious"}`), http.StatusConflict, "decided")
}

func jsonEqual(a, b any) bool {
	x, err1 := json.Marshal(a)
	y, err2 := json.Marshal(b)
	return err1 == nil && err2 == nil && string(x) == string(y)
}
