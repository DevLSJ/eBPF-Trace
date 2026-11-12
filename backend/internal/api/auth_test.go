package api

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/osv"
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/review"
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/rules"
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/stats"
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/store"
)

type reviewServer struct {
	srv    *httptest.Server
	svc    *review.Service
	engine *rules.Engine
	mem    *store.Memory
}

func newReviewServer(t *testing.T, admin, sandbox string, mock bool, seed []rules.Rule) *reviewServer {
	t.Helper()
	mem := store.NewMemory()
	if err := mem.ReplacePolicies(t.Context(), seed); err != nil {
		t.Fatal(err)
	}
	engine := rules.New(seed)
	svc := review.New(review.Options{Store: mem, Policies: mem, Audit: mem, Engine: engine, EnforceKill: true})
	if err := svc.Load(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := svc.Reload(t.Context()); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(Router(Deps{
		Engine: engine, Policies: mem, Audit: mem, Buffer: mem, Stats: stats.New().Snapshot,
		AdminToken: admin, SandboxToken: sandbox, AllowAnonymousWrites: mock,
		Review: svc, OSV: &osv.Client{URL: "http://127.0.0.1:1"},
	}))
	t.Cleanup(srv.Close)
	return &reviewServer{srv: srv, svc: svc, engine: engine, mem: mem}
}

const installBody = `{"manager":"pip","packages":["requests"],"container":"sg-install-pip-1-1","image":"python:3.12-slim"}`

// sandboxCalls: CLI(SANDBOX_TOKEN) 쪽 엔드포인트. 본문은 성공할 만한 값.
var sandboxCalls = []struct{ method, path, body string }{
	{"POST", "/api/installs", installBody},
	{"POST", "/api/installs/refused", `{"manager":"pip","packages":["reqeusts"],"value":"pip:reqeusts"}`},
	{"GET", "/api/blocklist/check?manager=pip&package=requests", ""},
}

// adminCalls: 화면(ADMIN_TOKEN) 쪽 쓰기. 대상이 없어 인증만 통과하면 404/400 이 난다.
var adminCalls = []struct{ method, path, body string }{
	{"POST", "/api/cases/case-0001/decide", `{"decision":"malicious"}`},
	{"POST", "/api/proposals/prop-0001/apply", ""},
	{"POST", "/api/proposals/prop-0001/discard", ""},
	{"DELETE", "/api/blocklist/hosts/x.test", ""},
	{"POST", "/api/policies", rule},
	{"POST", "/api/policies/x/revert", `{"changeId":"chg-0001","reason":"r"}`}, // 되돌리기(11/09)
}

func authPassed(code int) bool {
	return code != http.StatusUnauthorized && code != http.StatusForbidden
}

// Tier 1 — CLI 토큰과 관리자 토큰은 서로의 엔드포인트에 쓸 수 없다.
func TestTokensAreSeparated(t *testing.T) {
	s := newReviewServer(t, "admin-tok", "sandbox-tok", false, nil)
	for _, c := range sandboxCalls {
		if r := do(t, c.method, s.srv.URL+c.path, "", c.body); r.StatusCode != http.StatusUnauthorized {
			t.Errorf("%s %s without token: %d, want 401", c.method, c.path, r.StatusCode)
		}
		if r := do(t, c.method, s.srv.URL+c.path, "admin-tok", c.body); r.StatusCode != http.StatusUnauthorized {
			t.Errorf("%s %s with ADMIN token: %d, want 401", c.method, c.path, r.StatusCode)
		}
		if r := do(t, c.method, s.srv.URL+c.path, "sandbox-tok", c.body); !authPassed(r.StatusCode) || r.StatusCode >= 500 {
			t.Errorf("%s %s with SANDBOX token: %d", c.method, c.path, r.StatusCode)
		}
	}
	for _, c := range adminCalls {
		if r := do(t, c.method, s.srv.URL+c.path, "sandbox-tok", c.body); r.StatusCode != http.StatusUnauthorized {
			t.Errorf("%s %s with SANDBOX token: %d, want 401", c.method, c.path, r.StatusCode)
		}
		if r := do(t, c.method, s.srv.URL+c.path, "admin-tok", c.body); !authPassed(r.StatusCode) {
			t.Errorf("%s %s with ADMIN token: %d", c.method, c.path, r.StatusCode)
		}
	}
}

// Tier 1 — 토큰이 비어 있으면 그 쓰기는 403 (mock 소스가 아닐 때).
func TestEmptyTokensForbid(t *testing.T) {
	s := newReviewServer(t, "", "", false, nil)
	for _, c := range append(sandboxCalls, adminCalls...) {
		for _, tok := range []string{"", "anything"} {
			if r := do(t, c.method, s.srv.URL+c.path, tok, c.body); r.StatusCode != http.StatusForbidden {
				t.Errorf("%s %s token=%q: %d, want 403", c.method, c.path, tok, r.StatusCode)
			}
		}
	}
}

// Tier 1 — EVENT_SOURCE=mock 이면 비어 있는 토큰의 쓰기는 토큰 없이 허용한다. 토큰을 정했으면 mock 이어도 검사한다.
func TestMockSourceAllowsAnonymous(t *testing.T) {
	s := newReviewServer(t, "", "", true, nil)
	for _, c := range append(sandboxCalls, adminCalls...) {
		if r := do(t, c.method, s.srv.URL+c.path, "", c.body); !authPassed(r.StatusCode) {
			t.Errorf("mock %s %s: %d", c.method, c.path, r.StatusCode)
		}
	}
	s2 := newReviewServer(t, "admin-tok", "sandbox-tok", true, nil)
	if r := do(t, "POST", s2.srv.URL+"/api/installs", "", installBody); r.StatusCode != http.StatusUnauthorized {
		t.Errorf("mock with SANDBOX_TOKEN set must still check it: %d", r.StatusCode)
	}
	if r := do(t, "POST", s2.srv.URL+"/api/proposals/prop-0001/apply", "", ""); r.StatusCode != http.StatusUnauthorized {
		t.Errorf("mock with ADMIN_TOKEN set must still check it: %d", r.StatusCode)
	}
}

// 읽기와 미리보기는 토큰 없이 된다.
func TestReadsNeedNoToken(t *testing.T) {
	s := newReviewServer(t, "admin-tok", "sandbox-tok", false, nil)
	for _, p := range []string{"/api/installs", "/api/cases", "/api/proposals", "/api/blocklist", "/api/changes"} {
		if r := do(t, "GET", s.srv.URL+p, "", ""); r.StatusCode != http.StatusOK {
			t.Errorf("GET %s: %d", p, r.StatusCode)
		}
	}
	if r := do(t, "POST", s.srv.URL+"/api/proposals/prop-0009/preview", "", ""); r.StatusCode != http.StatusNotFound {
		t.Errorf("preview of a missing proposal: %d, want 404", r.StatusCode)
	}
}

// Tier 1 — 시스템 규칙 blocklist-hosts 는 정책 API 로 만들거나 고치거나 지울 수 없다(409). YAML 교체도 마찬가지.
func TestSystemRuleProtected(t *testing.T) {
	s := newReviewServer(t, "", "", true, nil)
	sys := `{"id":"blocklist-hosts","kind":"connect","action":"alert","denyHosts":["x.test"]}`
	if r := do(t, "POST", s.srv.URL+"/api/policies", "", sys); r.StatusCode != http.StatusConflict {
		t.Fatalf("POST system rule: %d, want 409", r.StatusCode)
	}
	if r := do(t, "DELETE", s.srv.URL+"/api/policies/blocklist-hosts", "", ""); r.StatusCode != http.StatusConflict {
		t.Fatalf("DELETE system rule: %d, want 409", r.StatusCode)
	}
	yamlBody := "rules:\n  - id: blocklist-hosts\n    kind: connect\n    action: alert\n    denyHosts: [x.test]\n"
	if r := do(t, "PUT", s.srv.URL+"/api/policies", "", yamlBody); r.StatusCode != http.StatusConflict {
		t.Fatalf("PUT yaml with system rule: %d, want 409", r.StatusCode)
	}
	stored, _ := s.mem.ListPolicies(t.Context())
	if len(stored) != 0 {
		t.Fatalf("nothing must be stored, got %+v", stored)
	}
}
