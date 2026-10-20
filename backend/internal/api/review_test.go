package api

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/model"
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/osv"
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/rules"
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/stats"
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/store"
)

var seedRules = []rules.Rule{
	{ID: "sensitive-files", Kind: model.KindOpen, Action: model.ActionKill, DenyPaths: []string{"/etc/shadow"}},
	{ID: "egress-allowlist", Kind: model.KindConnect, Action: model.ActionAlert, AllowPorts: []uint16{443}},
	{ID: "sandbox-egress", Kind: model.KindConnect, Action: model.ActionKill, Containers: []string{"sg-install-*"}, AllowHosts: []string{"pypi.org"}},
}

func decode[T any](t *testing.T, r *http.Response) T {
	t.Helper()
	var v T
	b, _ := io.ReadAll(r.Body)
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatalf("decode %s: %v", b, err)
	}
	return v
}

func want(t *testing.T, r *http.Response, code int, what string) {
	t.Helper()
	if r.StatusCode != code {
		b, _ := io.ReadAll(r.Body)
		t.Fatalf("%s: status %d, want %d (%s)", what, r.StatusCode, code, b)
	}
}

// observeViolation: 파이프라인 대신 판정 하나를 건 묶기 · 감사 로그에 넣는다.
func (s *reviewServer) observe(t *testing.T, ev model.Event) model.Verdict {
	t.Helper()
	v := s.engine.Evaluate(ev)
	if v.Matched && v.Action == model.ActionKill {
		v.Enforced = true
	}
	s.svc.Observe(&v)
	if v.Matched {
		_ = s.mem.SaveAudit(t.Context(), v)
	}
	return v
}

// 계약 흐름 한 바퀴: 세션 시작 → 위반 → 건 → 판정 → 미리보기 → 적용 → 차단 확인 → 거부 세션
func TestInstallCaseFlowHTTP(t *testing.T) {
	s := newReviewServer(t, "", "", true, seedRules)
	u := s.srv.URL

	r := do(t, "POST", u+"/api/installs", "", `{"manager":"pip","packages":["./reqeusts"],"container":"sg-install-pip-1-2","image":"python:3.12-slim"}`)
	want(t, r, http.StatusCreated, "start")
	id := decode[map[string]string](t, r)["id"]
	if id != "ins-0001" {
		t.Fatalf("id %q", id)
	}
	want(t, do(t, "POST", u+"/api/installs", "", `{"manager":"pip","packages":["x"],"container":"sg-install-pip-1-2","image":""}`), http.StatusConflict, "duplicate container")
	want(t, do(t, "POST", u+"/api/installs", "", `{"manager":"apt","packages":["x"],"container":"sg-install-1","image":""}`), http.StatusBadRequest, "bad manager")
	want(t, do(t, "POST", u+"/api/installs", "", `{"manager":"pip","packages":["x"],"container":"web","image":""}`), http.StatusBadRequest, "not a sandbox container")
	want(t, do(t, "POST", u+"/api/installs", "", `{"manager":"pip","bogus":1}`), http.StatusBadRequest, "unknown field")

	v := s.observe(t, model.Event{Kind: model.KindConnect, ContainerID: strings.Repeat("a", 64), ContainerName: "sg-install-pip-1-2",
		ImageName: "python:3.12-slim", DstIP: "203.0.113.7", DstPort: 8081, DstHost: "cdn.reqeusts-update.test"})
	if v.CaseID == nil {
		t.Fatal("violation must open a case")
	}

	want(t, do(t, "PUT", u+"/api/installs/"+id+"/finish", "", `{}`), http.StatusBadRequest, "finish without exitCode")
	want(t, do(t, "PUT", u+"/api/installs/ins-0099/finish", "", `{"exitCode":0}`), http.StatusNotFound, "finish missing")
	r = do(t, "PUT", u+"/api/installs/"+id+"/finish", "", `{"exitCode":137}`)
	want(t, r, http.StatusOK, "finish")
	want(t, do(t, "PUT", u+"/api/installs/"+id+"/finish", "", `{"exitCode":137}`), http.StatusConflict, "finish twice")

	// 세션 단건 · 목록 — 계약 모양
	r = do(t, "GET", u+"/api/installs/"+id, "", "")
	want(t, r, http.StatusOK, "get install")
	raw := decode[map[string]any](t, r)
	for _, k := range []string{"id", "manager", "packages", "container", "containerId", "image", "startedAt", "finishedAt", "exitCode",
		"containerExitedAt", "status", "refusedBy", "caseId", "violations", "violationCount", "activity"} {
		if _, ok := raw[k]; !ok {
			t.Errorf("install JSON lacks %q", k)
		}
	}
	if raw["status"] != "isolated" || raw["caseId"] != *v.CaseID || raw["refusedBy"] != nil || raw["containerExitedAt"] != nil {
		t.Fatalf("install: %v", raw)
	}
	act := raw["activity"].(map[string]any)
	if _, ok := act["kinds"].(map[string]any)["connect"]; !ok || act["hosts"] == nil || act["programs"] == nil {
		t.Fatalf("activity: %v", act)
	}
	want(t, do(t, "GET", u+"/api/installs/ins-0099", "", ""), http.StatusNotFound, "missing install")
	if got := decode[[]model.InstallSession](t, do(t, "GET", u+"/api/installs?status=isolated&manager=pip&limit=10", "", "")); len(got) != 1 || got[0].ViolationCount != 1 {
		t.Fatalf("filtered list: %+v", got)
	}
	if got := decode[[]model.InstallSession](t, do(t, "GET", u+"/api/installs?status=passed", "", "")); len(got) != 0 {
		t.Fatal("status filter")
	}
	want(t, do(t, "GET", u+"/api/installs?status=bogus", "", ""), http.StatusBadRequest, "bad status")
	want(t, do(t, "GET", u+"/api/installs?manager=apt", "", ""), http.StatusBadRequest, "bad manager filter")
	want(t, do(t, "GET", u+"/api/installs?limit=-1", "", ""), http.StatusBadRequest, "bad limit")

	// 건
	cases := decode[[]map[string]any](t, do(t, "GET", u+"/api/cases?state=open&source=install", "", ""))
	if len(cases) != 1 {
		t.Fatalf("cases: %v", cases)
	}
	for _, k := range []string{"id", "source", "installId", "container", "image", "package", "openedAt", "level", "violations", "ruleIds",
		"state", "decision", "decidedAt", "decidedBy", "note", "proposalId", "closedAt"} {
		if _, ok := cases[0][k]; !ok {
			t.Errorf("case JSON lacks %q", k)
		}
	}
	if _, ok := cases[0]["evidence"]; ok {
		t.Error("case JSON must not expose evidence")
	}
	caseID := *v.CaseID
	want(t, do(t, "GET", u+"/api/cases?state=bogus", "", ""), http.StatusBadRequest, "bad case state")
	want(t, do(t, "GET", u+"/api/cases?source=bogus", "", ""), http.StatusBadRequest, "bad case source")
	want(t, do(t, "GET", u+"/api/cases/case-0099", "", ""), http.StatusNotFound, "missing case")
	want(t, do(t, "GET", u+"/api/cases/"+caseID, "", ""), http.StatusOK, "get case")

	want(t, do(t, "POST", u+"/api/cases/"+caseID+"/decide", "", `{"decision":"maybe"}`), http.StatusBadRequest, "bad decision")
	want(t, do(t, "POST", u+"/api/cases/case-0099/decide", "", `{"decision":"malicious"}`), http.StatusNotFound, "decide missing")
	r = do(t, "POST", u+"/api/cases/"+caseID+"/decide", "", `{"decision":"malicious","note":"타이포스쿼팅"}`)
	want(t, r, http.StatusOK, "decide")
	dec := decode[struct {
		Case     model.Case     `json:"case"`
		Proposal model.Proposal `json:"proposal"`
	}](t, r)
	if dec.Case.State != model.CaseDecided || dec.Case.Note != "타이포스쿼팅" || dec.Proposal.State != model.ProposalDraft || len(dec.Proposal.Changes) != 2 {
		t.Fatalf("decide: %+v", dec)
	}
	want(t, do(t, "POST", u+"/api/cases/"+caseID+"/decide", "", `{"decision":"false_positive"}`), http.StatusConflict, "decide twice")
	pid := dec.Proposal.ID

	// 제안
	if got := decode[[]model.Proposal](t, do(t, "GET", u+"/api/proposals?state=draft", "", "")); len(got) != 1 {
		t.Fatal("draft proposals")
	}
	want(t, do(t, "GET", u+"/api/proposals?state=bogus", "", ""), http.StatusBadRequest, "bad proposal state")
	want(t, do(t, "GET", u+"/api/proposals/"+pid, "", ""), http.StatusOK, "get proposal")
	want(t, do(t, "GET", u+"/api/proposals/prop-0099", "", ""), http.StatusNotFound, "missing proposal")
	r = do(t, "POST", u+"/api/proposals/"+pid+"/preview", "", "")
	want(t, r, http.StatusOK, "preview")
	pv := decode[map[string]any](t, r)
	for _, k := range []string{"evaluated", "changed", "counts", "nextOnly"} {
		if _, ok := pv[k]; !ok {
			t.Errorf("preview JSON lacks %q", k)
		}
	}
	want(t, do(t, "POST", u+"/api/proposals/prop-0099/apply", "", ""), http.StatusNotFound, "apply missing")
	r = do(t, "POST", u+"/api/proposals/"+pid+"/apply", "", "")
	want(t, r, http.StatusOK, "apply")
	want(t, do(t, "POST", u+"/api/proposals/"+pid+"/apply", "", ""), http.StatusConflict, "apply twice")
	want(t, do(t, "POST", u+"/api/proposals/"+pid+"/discard", "", ""), http.StatusConflict, "discard applied")

	// 차단 목록 · 시스템 규칙 · 변경 이력
	bl := decode[map[string][]map[string]any](t, do(t, "GET", u+"/api/blocklist", "", ""))
	if len(bl["packages"]) != 1 || bl["packages"][0]["value"] != "pip:reqeusts" || bl["packages"][0]["caseId"] != caseID || len(bl["hosts"]) != 1 || bl["images"] == nil {
		t.Fatalf("blocklist: %v", bl)
	}
	pols := decode[[]rules.Rule](t, do(t, "GET", u+"/api/policies", "", ""))
	if _, ok := findRule(pols, rules.SystemBlocklistHosts); !ok {
		t.Fatal("policy list must show the system rule")
	}
	r = do(t, "GET", u+"/api/policies/export", "", "")
	if b, _ := io.ReadAll(r.Body); strings.Contains(string(b), rules.SystemBlocklistHosts) {
		t.Fatal("export must leave out the system rule so it can be re-applied")
	}
	chs := decode[[]model.Change](t, do(t, "GET", u+"/api/changes?limit=5", "", ""))
	if len(chs) != 1 || chs[0].Kind != model.ChangeProposalApplied {
		t.Fatalf("changes: %+v", chs)
	}
	want(t, do(t, "GET", u+"/api/changes?limit=x", "", ""), http.StatusBadRequest, "bad changes limit")

	// CLI: 차단 확인 → 거부 세션
	r = do(t, "GET", u+"/api/blocklist/check?manager=pip&package="+url.QueryEscape("./deploy/demo/reqeusts"), "", "")
	want(t, r, http.StatusOK, "check")
	chk := decode[map[string]any](t, r)
	if chk["blocked"] != true || chk["value"] != "pip:reqeusts" || chk["caseId"] != caseID {
		t.Fatalf("check: %v", chk)
	}
	want(t, do(t, "GET", u+"/api/blocklist/check?manager=pip", "", ""), http.StatusBadRequest, "check without package")
	r = do(t, "POST", u+"/api/installs/refused", "", `{"manager":"pip","packages":["./reqeusts"],"value":"pip:reqeusts"}`)
	want(t, r, http.StatusCreated, "refused")
	want(t, do(t, "POST", u+"/api/installs/refused", "", `{"manager":"pip","packages":["x"],"value":""}`), http.StatusBadRequest, "refused without value")
	if got := decode[[]model.InstallSession](t, do(t, "GET", u+"/api/installs?status=refused", "", "")); len(got) != 1 || got[0].RefusedBy == nil {
		t.Fatalf("refused list: %+v", got)
	}

	// 감사 로그 행: caseId · install
	rows := decode[[]map[string]any](t, do(t, "GET", u+"/api/audit", "", ""))
	if len(rows) != 1 || rows[0]["caseId"] != caseID || rows[0]["install"].(map[string]any)["id"] != id {
		t.Fatalf("audit rows: %v", rows)
	}

	// 차단 해제
	want(t, do(t, "DELETE", u+"/api/blocklist/bogus/x", "", ""), http.StatusBadRequest, "bad list")
	want(t, do(t, "DELETE", u+"/api/blocklist/hosts/nope.test", "", ""), http.StatusNotFound, "unblock missing")
	want(t, do(t, "DELETE", u+"/api/blocklist/hosts/cdn.reqeusts-update.test", "", ""), http.StatusNoContent, "unblock host")
	if _, ok := findRule(s.engine.Rules(), rules.SystemBlocklistHosts); ok {
		t.Fatal("unblocking the last host must drop the system rule")
	}
}

func findRule(rs []rules.Rule, id string) (rules.Rule, bool) {
	for _, r := range rs {
		if r.ID == id {
			return r, true
		}
	}
	return rules.Rule{}, false
}

// 이미지 이름의 / 도 차단 해제 경로에 쓸 수 있다.
func TestUnblockImageWithSlash(t *testing.T) {
	s := newReviewServer(t, "", "", true, seedRules)
	v := s.observe(t, model.Event{Kind: model.KindOpen, ContainerID: strings.Repeat("b", 64), ContainerName: "pkg-reqeusts", ImageName: "demo/reqeusts:1.0.2", Path: "/etc/shadow"})
	want(t, do(t, "POST", s.srv.URL+"/api/cases/"+*v.CaseID+"/decide", "", `{"decision":"malicious"}`), http.StatusOK, "decide")
	want(t, do(t, "POST", s.srv.URL+"/api/proposals/prop-0001/apply", "", ""), http.StatusOK, "apply")
	if bl := decode[model.Blocklist](t, do(t, "GET", s.srv.URL+"/api/blocklist", "", "")); len(bl.Images) != 1 {
		t.Fatalf("image block: %+v", bl)
	}
	want(t, do(t, "DELETE", s.srv.URL+"/api/blocklist/images/"+url.PathEscape("demo/reqeusts:1.0.2"), "", ""), http.StatusNoContent, "unblock image")
	chs := decode[[]model.Change](t, do(t, "GET", s.srv.URL+"/api/changes", "", ""))
	if len(chs) != 2 || chs[0].Kind != model.ChangeBlocklistRemove || chs[0].Summary != "이미지 demo/reqeusts:1.0.2 차단 해제" {
		t.Fatalf("changes: %+v", chs)
	}
}

// 버린 제안은 건을 변경 없이 닫는다.
func TestDiscardHTTP(t *testing.T) {
	s := newReviewServer(t, "", "", true, seedRules)
	v := s.observe(t, model.Event{Kind: model.KindOpen, ContainerID: strings.Repeat("c", 64), ContainerName: "worker", Path: "/etc/shadow"})
	want(t, do(t, "POST", s.srv.URL+"/api/cases/"+*v.CaseID+"/decide", "", `{"decision":"false_positive"}`), http.StatusOK, "decide")
	r := do(t, "POST", s.srv.URL+"/api/proposals/prop-0001/discard", "", "")
	want(t, r, http.StatusOK, "discard")
	got := decode[struct {
		Proposal model.Proposal `json:"proposal"`
		Case     model.Case     `json:"case"`
	}](t, r)
	if got.Proposal.State != model.ProposalDiscarded || got.Case.State != model.CaseClosed {
		t.Fatalf("discard: %+v", got)
	}
	want(t, do(t, "POST", s.srv.URL+"/api/proposals/prop-0001/apply", "", ""), http.StatusConflict, "apply discarded")
	if n := len(decode[[]model.Change](t, do(t, "GET", s.srv.URL+"/api/changes", "", ""))); n != 0 {
		t.Fatalf("discard records no change, got %d", n)
	}
}

// 기존 정책 쓰기도 변경 이력을 남긴다.
func TestPolicyWritesRecordChanges(t *testing.T) {
	s := newReviewServer(t, "", "", true, seedRules)
	u := s.srv.URL
	want(t, do(t, "POST", u+"/api/policies", "", rule), http.StatusOK, "save")
	want(t, do(t, "DELETE", u+"/api/policies/shadow", "", ""), http.StatusNoContent, "delete")
	want(t, do(t, "DELETE", u+"/api/policies/shadow", "", ""), http.StatusNotFound, "delete missing")
	want(t, do(t, "PUT", u+"/api/policies", "", "rules:\n  - id: a\n    kind: exec\n    action: alert\n    denyComms: [nc]\n"), http.StatusOK, "replace")
	chs := decode[[]model.Change](t, do(t, "GET", u+"/api/changes", "", ""))
	if len(chs) != 3 || chs[0].Kind != model.ChangePolicyReplace || chs[1].Summary != "정책 shadow 삭제" || chs[2].Kind != model.ChangePolicyEdit ||
		chs[2].By != "보안 담당자" || chs[2].CaseID != nil {
		t.Fatalf("changes: %+v", chs)
	}
}

// OSV: osv.dev 프록시. 실패해도 200 + error, 성공은 1시간 캐시.
func TestOSVProxy(t *testing.T) {
	var calls atomic.Int32
	fail := atomic.Bool{}
	fake := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if fail.Load() {
			http.Error(w, "boom", http.StatusBadGateway)
			return
		}
		var q struct {
			Package struct{ Name, Ecosystem string } `json:"package"`
		}
		_ = json.NewDecoder(r.Body).Decode(&q)
		if q.Package.Name == "requests" && q.Package.Ecosystem == "PyPI" {
			_, _ = io.WriteString(w, `{"vulns":[{"id":"GHSA-1"},{"id":"PYSEC-2"}]}`)
			return
		}
		_, _ = io.WriteString(w, `{}`)
	}))
	t.Cleanup(fake.Close)
	mem := store.NewMemory()
	srv := httptest.NewServer(Router(Deps{Engine: rules.New(nil), Policies: mem, Audit: mem, Buffer: mem, Stats: stats.New().Snapshot,
		Review: newReviewServer(t, "", "", true, nil).svc, OSV: &osv.Client{URL: fake.URL}}))
	t.Cleanup(srv.Close)

	r := do(t, "GET", srv.URL+"/api/osv?ecosystem=PyPI&name=requests", "", "")
	want(t, r, http.StatusOK, "osv")
	got := decode[map[string]any](t, r)
	if got["vulns"] != float64(2) || got["source"] != "osv.dev" || got["error"] != nil || len(got["ids"].([]any)) != 2 || got["queriedAt"] == "" {
		t.Fatalf("osv: %v", got)
	}
	do(t, "GET", srv.URL+"/api/osv?ecosystem=PyPI&name=requests", "", "")
	if calls.Load() != 1 {
		t.Fatalf("second lookup must hit the cache, calls=%d", calls.Load())
	}
	if got := decode[model.Osv](t, do(t, "GET", srv.URL+"/api/osv?ecosystem=PyPI&name=reqeusts", "", "")); got.Vulns != 0 || got.Error != nil || got.IDs == nil {
		t.Fatalf("no vulns: %+v", got)
	}
	fail.Store(true)
	r = do(t, "GET", srv.URL+"/api/osv?ecosystem=npm&name=lodash", "", "")
	want(t, r, http.StatusOK, "osv failure is still 200")
	if got := decode[model.Osv](t, r); got.Error == nil || got.Vulns != 0 {
		t.Fatalf("failure: %+v", got)
	}
	want(t, do(t, "GET", srv.URL+"/api/osv?ecosystem=Maven&name=x", "", ""), http.StatusBadRequest, "bad ecosystem")
	want(t, do(t, "GET", srv.URL+"/api/osv?ecosystem=npm&name=", "", ""), http.StatusBadRequest, "empty name")
}
