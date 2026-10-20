package api

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/rules"
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/stats"
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/store"
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/summary"
)

// 종합(10/16): GET /api/summary?range= — 읽기 전용(토큰 불필요), 모르는 기간은 400
func TestSummaryHTTP(t *testing.T) {
	mem := store.NewMemory()
	srv := httptest.NewServer(Router(Deps{Engine: rules.New(nil), Policies: mem, Audit: mem, Buffer: mem, Stats: stats.New().Snapshot,
		AdminToken: "admin", Summary: summary.New(mem, mem, nil)}))
	defer srv.Close()
	r := do(t, "GET", srv.URL+"/api/summary", "", "")
	want(t, r, http.StatusOK, "default range")
	s := decode[summary.Summary](t, r)
	if s.Range != "24h" || len(s.Series) != 24 || s.TopRules == nil {
		t.Fatalf("summary: %+v", s)
	}
	want(t, do(t, "GET", srv.URL+"/api/summary?range=1h", "", ""), http.StatusOK, "1h")
	want(t, do(t, "GET", srv.URL+"/api/summary?range=2y", "", ""), http.StatusBadRequest, "bad range")
}
