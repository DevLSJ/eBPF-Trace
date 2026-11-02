package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/model"
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/rules"
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/stats"
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/store"
)

func newServer(t *testing.T, token string, anon bool) (*httptest.Server, *rules.Engine, *store.Memory) {
	t.Helper()
	mem := store.NewMemory()
	engine := rules.New(nil)
	agg := stats.New()
	srv := httptest.NewServer(Router(Deps{
		Engine: engine, Policies: mem, Audit: mem, Buffer: mem,
		Stats: agg.Snapshot, AdminToken: token, AllowAnonymousWrites: anon,
	}))
	t.Cleanup(srv.Close)
	return srv, engine, mem
}

func do(t *testing.T, method, url, token, body string) *http.Response {
	t.Helper()
	req, _ := http.NewRequest(method, url, strings.NewReader(body))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	return resp
}

const rule = `{"id":"shadow","kind":"open","action":"kill","denyPaths":["/etc/shadow"]}`

func TestPolicyAuth(t *testing.T) {
	srv, engine, _ := newServer(t, "s3cret", false)
	if r := do(t, "POST", srv.URL+"/api/policies", "", rule); r.StatusCode != http.StatusUnauthorized {
		t.Fatalf("no token: %d", r.StatusCode)
	}
	if r := do(t, "POST", srv.URL+"/api/policies", "wrong", rule); r.StatusCode != http.StatusUnauthorized {
		t.Fatalf("wrong token: %d", r.StatusCode)
	}
	if r := do(t, "POST", srv.URL+"/api/policies", "s3cret", rule); r.StatusCode != http.StatusOK {
		t.Fatalf("valid token: %d", r.StatusCode)
	}
	if len(engine.Rules()) != 1 {
		t.Fatal("engine must reload after save")
	}
}

func TestWritesDisabledWithoutToken(t *testing.T) {
	srv, _, _ := newServer(t, "", false)
	if r := do(t, "POST", srv.URL+"/api/policies", "", rule); r.StatusCode != http.StatusForbidden {
		t.Fatalf("want 403, got %d", r.StatusCode)
	}
}

func TestPolicyLifecycle(t *testing.T) {
	srv, engine, _ := newServer(t, "", true)
	if r := do(t, "POST", srv.URL+"/api/policies", "", `{"id":"x","kind":"open","action":"kill"}`); r.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("rule without conditions: %d", r.StatusCode)
	}
	if r := do(t, "POST", srv.URL+"/api/policies", "", `{"id":"x","bogus":1}`); r.StatusCode != http.StatusBadRequest {
		t.Fatalf("unknown field: %d", r.StatusCode)
	}
	do(t, "POST", srv.URL+"/api/policies", "", rule)

	yamlBody := "rules:\n  - id: a\n    kind: exec\n    action: alert\n    denyComms: [nc]\n  - id: b\n    kind: connect\n    action: kill\n    denyPorts: [4444]\n"
	if r := do(t, "PUT", srv.URL+"/api/policies", "", yamlBody); r.StatusCode != http.StatusOK {
		t.Fatalf("yaml replace: %d", r.StatusCode)
	}
	if n := len(engine.Rules()); n != 2 {
		t.Fatalf("after replace: %d rules", n)
	}
	if r := do(t, "DELETE", srv.URL+"/api/policies/a", "", ""); r.StatusCode != http.StatusNoContent {
		t.Fatalf("delete: %d", r.StatusCode)
	}
	if r := do(t, "DELETE", srv.URL+"/api/policies/a", "", ""); r.StatusCode != http.StatusNotFound {
		t.Fatalf("delete missing: %d", r.StatusCode)
	}
	r := do(t, "GET", srv.URL+"/api/policies/export", "", "")
	if ct := r.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/yaml") {
		t.Fatalf("export content-type %q", ct)
	}
}

func TestAuditQuery(t *testing.T) {
	srv, _, mem := newServer(t, "", true)
	for _, k := range []model.Kind{model.KindOpen, model.KindExec, model.KindOpen} {
		_, _ = mem.SaveAudit(t.Context(), model.Verdict{Matched: true, Action: model.ActionAlert, Event: model.Event{Kind: k, ContainerName: "victim"}})
	}
	r := do(t, "GET", srv.URL+"/api/audit?kind=open&container=vic", "", "")
	var got []model.AuditEntry
	if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].ID != 3 {
		t.Fatalf("want 2 newest-first open entries, got %+v", got)
	}
	if r := do(t, "GET", srv.URL+"/api/audit?kind=read", "", ""); r.StatusCode != http.StatusBadRequest {
		t.Fatalf("bad kind: %d", r.StatusCode)
	}
}

func TestCORS(t *testing.T) {
	mem := store.NewMemory()
	srv := httptest.NewServer(Router(Deps{
		Engine: rules.New(nil), Policies: mem, Audit: mem, Buffer: mem, Stats: stats.New().Snapshot,
		AllowAnonymousWrites: true, AllowedOrigins: []string{"http://127.0.0.1:8765", "null"},
	}))
	t.Cleanup(srv.Close)

	get := func(origin string) *http.Response {
		req, _ := http.NewRequest(http.MethodGet, srv.URL+"/api/info", nil)
		if origin != "" {
			req.Header.Set("Origin", origin)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { resp.Body.Close() })
		return resp
	}
	if got := get("http://127.0.0.1:8765").Header.Get("Access-Control-Allow-Origin"); got != "http://127.0.0.1:8765" {
		t.Fatalf("allowed origin: got %q", got)
	}
	if got := get("null").Header.Get("Access-Control-Allow-Origin"); got != "null" {
		t.Fatalf("file origin: got %q", got)
	}
	if got := get("http://evil.example").Header.Get("Access-Control-Allow-Origin"); got != "" {
		t.Fatalf("unlisted origin must get no CORS header, got %q", got)
	}
	if got := get("").Header.Get("Access-Control-Allow-Origin"); got != "" {
		t.Fatalf("same-origin request must get no CORS header, got %q", got)
	}

	req, _ := http.NewRequest(http.MethodOptions, srv.URL+"/api/policies", nil)
	req.Header.Set("Origin", "http://127.0.0.1:8765")
	req.Header.Set("Access-Control-Request-Method", "PUT")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent || !strings.Contains(resp.Header.Get("Access-Control-Allow-Methods"), "PUT") {
		t.Fatalf("preflight: status %d methods %q", resp.StatusCode, resp.Header.Get("Access-Control-Allow-Methods"))
	}
	if resp.Header.Get("Access-Control-Allow-Headers") != "Authorization, Content-Type" {
		t.Fatalf("preflight headers: %q", resp.Header.Get("Access-Control-Allow-Headers"))
	}
}
