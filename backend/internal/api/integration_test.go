package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/integration"
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/rules"
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/stats"
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/store"
)

type blockProber struct{ gate chan struct{} }

func (p blockProber) Probe(context.Context, string) error { <-p.gate; return nil }

// 연동(11/06, Tier 1 — 시험 컨테이너 기동): GET 은 읽기, POST /test 는 쓰기 규칙(ADMIN_TOKEN) · 진행 중 409 · Prober 없으면 503
func TestIntegrationRoutes(t *testing.T) {
	const admin = "tok-admin"
	gate := make(chan struct{})
	svc := integration.New(integration.Options{Prober: blockProber{gate: gate}, Source: "mock", EnforceNames: []string{"sg-install-*"}})
	mem := store.NewMemory()
	srv := httptest.NewServer(Router(Deps{Engine: rules.New(nil), Policies: mem, Audit: mem, Buffer: mem, Stats: stats.New().Snapshot, AdminToken: admin, Integration: svc}))
	defer srv.Close()

	resp := do(t, http.MethodGet, srv.URL+"/api/integration", "", "")
	var st integration.Status
	if err := json.NewDecoder(resp.Body).Decode(&st); err != nil || resp.StatusCode != 200 {
		t.Fatalf("GET = %d %v", resp.StatusCode, err)
	}
	if st.Env.Source != "mock" || !st.Env.Testable || st.Env.LabelEnforce != "supplyguard.enforce" || st.Test != nil {
		t.Fatalf("status = %+v", st)
	}
	if code := do(t, http.MethodPost, srv.URL+"/api/integration/test", "", "").StatusCode; code != http.StatusUnauthorized {
		t.Fatalf("POST without token = %d, want 401", code)
	}
	if code := do(t, http.MethodPost, srv.URL+"/api/integration/test", admin, "").StatusCode; code != http.StatusAccepted {
		t.Fatalf("POST = %d, want 202", code)
	}
	if code := do(t, http.MethodPost, srv.URL+"/api/integration/test", admin, "").StatusCode; code != http.StatusConflict {
		t.Fatalf("POST while running = %d, want 409", code)
	}
	close(gate)
	svc.Wait()

	none := integration.New(integration.Options{})
	srv2 := httptest.NewServer(Router(Deps{Engine: rules.New(nil), Policies: mem, Audit: mem, Buffer: mem, Stats: stats.New().Snapshot, AdminToken: admin, Integration: none}))
	defer srv2.Close()
	if code := do(t, http.MethodPost, srv2.URL+"/api/integration/test", admin, "").StatusCode; code != http.StatusServiceUnavailable {
		t.Fatalf("POST without prober = %d, want 503", code)
	}
	srv3 := httptest.NewServer(Router(Deps{Engine: rules.New(nil), Policies: mem, Audit: mem, Buffer: mem, Stats: stats.New().Snapshot}))
	defer srv3.Close()
	if code := do(t, http.MethodGet, srv3.URL+"/api/integration", "", "").StatusCode; code != http.StatusNotFound {
		t.Fatalf("no integration service = %d, want 404", code)
	}
}
