package api

import (
	"net/http"
	"slices"
	"testing"
	"time"

	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/rules"
)

// 정책 화면 분리(11/09) — 정책별 변경 이력 · 되돌리기 · 목록의 최근 수정.
//   GET  /api/changes?rule=&kind=&offset=&limit=   offset 이 있으면 {items, total, offset, limit}, 없으면 예전처럼 배열
//   POST /api/policies/{id}/revert {changeId, reason}   관리자 · 사유 필수 → 되돌린 정책(updatedAt · updatedBy 포함)
//   GET  /api/policies   항목에 updatedAt · updatedBy(그 정책을 다룬 마지막 변경 기록, 없으면 키 없음)

const ruleAlert = `{"id":"shadow","kind":"open","action":"alert","denyPaths":["/etc/shadow"]}`

type changesPage struct {
	Items  []map[string]any `json:"items"`
	Total  int              `json:"total"`
	Offset int              `json:"offset"`
	Limit  int              `json:"limit"`
}

func ruleIDsOf(t *testing.T, c map[string]any) []string {
	t.Helper()
	raw, ok := c["ruleIds"].([]any)
	if !ok {
		t.Fatalf("ruleIds must be a list: %v", c)
	}
	out := []string{}
	for _, x := range raw {
		out = append(out, x.(string))
	}
	return out
}

func valueOf(c map[string]any, side, id, field string) any {
	m, _ := c[side].(map[string]any)
	r, _ := m[id].(map[string]any)
	return r[field]
}

func TestChangesByRuleHTTP(t *testing.T) {
	s := newReviewServer(t, "", "", true, seedRules)
	u := s.srv.URL
	want(t, do(t, "POST", u+"/api/policies", "", rule), http.StatusOK, "create shadow")
	want(t, do(t, "POST", u+"/api/policies", "", ruleAlert), http.StatusOK, "edit shadow")
	want(t, do(t, "POST", u+"/api/policies", "", `{"id":"egress-allowlist","kind":"connect","action":"kill","allowPorts":[443]}`), http.StatusOK, "edit egress")
	want(t, do(t, "PUT", u+"/api/policies", "", "rules:\n  - id: shadow\n    kind: open\n    action: alert\n    denyPaths: [/etc/shadow]\n"), http.StatusOK, "replace")

	// 쪽: 그 정책의 기록만 최신순 + 전체 수
	r := do(t, "GET", u+"/api/changes?rule=shadow&offset=0&limit=2", "", "")
	want(t, r, http.StatusOK, "changes by rule")
	pg := decode[changesPage](t, r)
	if pg.Total != 2 || len(pg.Items) != 2 || pg.Offset != 0 || pg.Limit != 2 {
		t.Fatalf("page: %+v", pg)
	}
	edit := pg.Items[0]
	if edit["id"] != "chg-0002" || edit["kind"] != "policy_edit" || !slices.Equal(ruleIDsOf(t, edit), []string{"shadow"}) ||
		valueOf(edit, "before", "shadow", "action") != "kill" || valueOf(edit, "after", "shadow", "action") != "alert" {
		t.Fatalf("edit item: %v", edit)
	}
	if _, ok := edit["revertOf"]; ok {
		t.Fatalf("revertOf only on reverts: %v", edit)
	}
	if created := pg.Items[1]; created["id"] != "chg-0001" || created["before"] != nil || valueOf(created, "after", "shadow", "action") != "kill" {
		t.Fatalf("create item (no before): %v", created)
	}
	// YAML 교체는 바뀐 정책(sensitive-files · egress-allowlist · sandbox-egress 빠짐)에만 — 그대로인 shadow 는 아님
	pg = decode[changesPage](t, do(t, "GET", u+"/api/changes?rule=sandbox-egress&offset=0", "", ""))
	if pg.Total != 1 || pg.Items[0]["kind"] != "policy_replace" || pg.Limit != 50 || valueOf(pg.Items[0], "before", "sandbox-egress", "action") != "kill" {
		t.Fatalf("replace by rule: %+v", pg)
	}
	if b, _ := pg.Items[0]["before"].(map[string]any); len(b) != 1 {
		t.Fatalf("filtered values hold only that policy: %v", pg.Items[0]["before"])
	}
	if got := ruleIDsOf(t, pg.Items[0]); !slices.Equal(got, []string{"egress-allowlist", "sandbox-egress", "sensitive-files"}) {
		t.Fatalf("replace ruleIds: %v", got)
	}
	// 다음 쪽 · 종류
	if pg = decode[changesPage](t, do(t, "GET", u+"/api/changes?rule=shadow&offset=1&limit=1", "", "")); pg.Total != 2 || len(pg.Items) != 1 || pg.Items[0]["id"] != "chg-0001" {
		t.Fatalf("second page: %+v", pg)
	}
	if pg = decode[changesPage](t, do(t, "GET", u+"/api/changes?kind=policy_edit&offset=0", "", "")); pg.Total != 3 {
		t.Fatalf("kind filter: %+v", pg)
	}

	// offset 없으면 예전처럼 배열(하위 호환) — rule 거르기는 같이 먹고, ruleIds 는 늘 배열
	arr := decode[[]map[string]any](t, do(t, "GET", u+"/api/changes?rule=shadow", "", ""))
	if len(arr) != 2 {
		t.Fatalf("array by rule: %v", arr)
	}
	arr = decode[[]map[string]any](t, do(t, "GET", u+"/api/changes?limit=10", "", ""))
	if len(arr) != 4 {
		t.Fatalf("array: %d", len(arr))
	}
	for _, c := range arr {
		ruleIDsOf(t, c)
	}

	for _, q := range []string{"offset=-1", "offset=x", "limit=0", "limit=x"} {
		want(t, do(t, "GET", u+"/api/changes?"+q, "", ""), http.StatusBadRequest, q)
	}
}

func TestRevertPolicyHTTP(t *testing.T) {
	s := newReviewServer(t, "", "", true, seedRules)
	u := s.srv.URL
	want(t, do(t, "POST", u+"/api/policies", "", rule), http.StatusOK, "create")    // chg-0001
	want(t, do(t, "POST", u+"/api/policies", "", ruleAlert), http.StatusOK, "edit") // chg-0002

	for _, c := range []struct{ name, path, body string }{
		{"사유 없음", "/api/policies/shadow/revert", `{"changeId":"chg-0002"}`},
		{"공백 사유", "/api/policies/shadow/revert", `{"changeId":"chg-0002","reason":"  "}`},
		{"변경 id 없음", "/api/policies/shadow/revert", `{"reason":"x"}`},
		{"모르는 필드", "/api/policies/shadow/revert", `{"changeId":"chg-0002","reason":"x","bogus":1}`},
		{"JSON 아님", "/api/policies/shadow/revert", `nope`},
	} {
		want(t, do(t, "POST", u+c.path, "", c.body), http.StatusBadRequest, c.name)
	}
	want(t, do(t, "POST", u+"/api/policies/shadow/revert", "", `{"changeId":"chg-0099","reason":"x"}`), http.StatusNotFound, "missing change")
	want(t, do(t, "POST", u+"/api/policies/egress-allowlist/revert", "", `{"changeId":"chg-0002","reason":"x"}`), http.StatusNotFound, "other policy's change")
	want(t, do(t, "POST", u+"/api/policies/shadow/revert", "", `{"changeId":"chg-0001","reason":"x"}`), http.StatusConflict, "revert a create")
	want(t, do(t, "POST", u+"/api/policies/"+rules.SystemBlocklistHosts+"/revert", "", `{"changeId":"chg-0002","reason":"x"}`), http.StatusConflict, "system rule")

	r := do(t, "POST", u+"/api/policies/shadow/revert", "", `{"changeId":"chg-0002","reason":"오탐 증가"}`)
	want(t, r, http.StatusOK, "revert")
	got := decode[map[string]any](t, r)
	if got["id"] != "shadow" || got["action"] != "kill" || got["updatedBy"] != "보안 담당자" {
		t.Fatalf("revert response: %v", got)
	}
	if at, err := time.Parse(time.RFC3339, str(got, "updatedAt")); err != nil || time.Since(at) > time.Minute {
		t.Fatalf("updatedAt: %v %v", got["updatedAt"], err)
	}
	if er, _ := findRule(s.engine.Rules(), "shadow"); er.Action != "kill" {
		t.Fatalf("engine: %+v", er)
	}
	want(t, do(t, "POST", u+"/api/policies/shadow/revert", "", `{"changeId":"chg-0002","reason":"x"}`), http.StatusConflict, "already that value")

	pg := decode[changesPage](t, do(t, "GET", u+"/api/changes?rule=shadow&offset=0&limit=1", "", ""))
	c := pg.Items[0]
	if pg.Total != 3 || c["kind"] != "policy_revert" || c["revertOf"] != "chg-0002" || c["reason"] != "오탐 증가" ||
		valueOf(c, "before", "shadow", "action") != "alert" || valueOf(c, "after", "shadow", "action") != "kill" {
		t.Fatalf("revert change: %+v", pg)
	}

	// 지운 정책도 그 삭제 기록으로 되돌린다
	want(t, do(t, "DELETE", u+"/api/policies/shadow", "", ""), http.StatusNoContent, "delete")
	pg = decode[changesPage](t, do(t, "GET", u+"/api/changes?rule=shadow&offset=0&limit=1", "", ""))
	r = do(t, "POST", u+"/api/policies/shadow/revert", "", `{"changeId":"`+str(pg.Items[0], "id")+`","reason":"실수로 지움"}`)
	want(t, r, http.StatusOK, "restore deleted")
	if _, ok := findRule(decode[[]rules.Rule](t, do(t, "GET", u+"/api/policies", "", "")), "shadow"); !ok {
		t.Fatal("restored policy must be listed")
	}
}

// 목록 항목: 정책 필드 그대로 + 최근 수정 시각 · 처리자(변경 기록이 없는 시드 정책은 키 없음)
func TestPolicyListUpdatedHTTP(t *testing.T) {
	s := newReviewServer(t, "", "", true, seedRules)
	u := s.srv.URL
	for _, p := range decode[[]map[string]any](t, do(t, "GET", u+"/api/policies", "", "")) {
		if _, ok := p["updatedAt"]; ok {
			t.Fatalf("seeded policy has no updatedAt: %v", p)
		}
		if _, ok := p["updatedBy"]; ok {
			t.Fatalf("seeded policy has no updatedBy: %v", p)
		}
	}
	want(t, do(t, "POST", u+"/api/policies", "", rule), http.StatusOK, "save")
	var shadow, seeded map[string]any
	for _, p := range decode[[]map[string]any](t, do(t, "GET", u+"/api/policies", "", "")) {
		switch p["id"] {
		case "shadow":
			shadow = p
		case "sensitive-files":
			seeded = p
		}
	}
	if shadow["updatedBy"] != "보안 담당자" || shadow["kind"] != "open" || shadow["action"] != "kill" {
		t.Fatalf("shadow: %v", shadow)
	}
	if _, err := time.Parse(time.RFC3339, str(shadow, "updatedAt")); err != nil {
		t.Fatalf("updatedAt: %v", shadow["updatedAt"])
	}
	if _, ok := seeded["updatedAt"]; ok || seeded["kind"] != "open" {
		t.Fatalf("seeded: %v", seeded)
	}
}

// 로그인 조립: 되돌리기는 관리자(쿠키 · CLI Bearer)만, 조회자 403, 다른 출처 쿠키 403(CSRF). 처리자 = 계정 표시 이름
func TestRevertWiredAuth(t *testing.T) {
	e := newWiredEnv(t)
	admin := e.browser(t)
	activateAdmin(t, e.authEnv, admin, false)
	admin.must(200, "POST", "/api/policies", rule)
	admin.must(200, "POST", "/api/policies", ruleAlert)
	body := `{"changeId":"chg-0002","reason":"오탐 증가"}`

	anon := e.browser(t)
	anon.must(401, "POST", "/api/policies/shadow/revert", body)
	evil := &browser{t: t, env: e.authEnv, c: admin.c, origin: "http://evil.example"}
	evil.must(403, "POST", "/api/policies/shadow/revert", body)

	r := admin.must(201, "POST", "/api/users", `{"username":"viewer1","displayName":"김조회","role":"viewer"}`)
	temp := str(r.body, "tempPassword")
	viewer := e.browser(t)
	viewer.must(200, "POST", "/api/auth/login", `{"username":"viewer1","password":"`+temp+`"}`)
	viewer.must(200, "POST", "/api/auth/password", `{"current":"`+temp+`","next":"viewer-pass-12"}`)
	viewer.must(403, "POST", "/api/policies/shadow/revert", body)
	viewer.must(200, "GET", "/api/changes?rule=shadow&offset=0", "")

	r = admin.must(200, "POST", "/api/policies/shadow/revert", body)
	if str(r.body, "updatedBy") != "admin" || str(r.body, "action") != "kill" {
		t.Fatalf("admin revert: %v", r.body)
	}
	if ch := e.rv.ListChanges(1)[0]; ch.By != "admin" || ch.RevertOf == nil || *ch.RevertOf != "chg-0002" {
		t.Fatalf("revert change: %+v", ch)
	}
	// CLI Bearer 는 관리자 — 인증은 통과하고(이미 그 값이라) 409
	if r := e.bearer(t, flowAdminTok, "POST", "/api/policies/shadow/revert", body); r.code != http.StatusConflict {
		t.Fatalf("CLI revert: %d %v", r.code, r.body)
	}
}
