package api

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/model"
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/store"
)

func TestEvidenceHandler(t *testing.T) {
	mem := store.NewMemory()
	cid := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	base := time.Date(2026, 10, 20, 9, 0, 0, 0, time.UTC)
	for i, id := range []string{"e1", "e2"} {
		_ = mem.SaveEvidence(t.Context(), model.Evidence{ID: id, ContainerID: cid, ContainerName: "sg-install-pip-1", Image: "python:3.12-slim",
			CollectedAt: base.Add(time.Duration(i) * time.Minute), Logs: "l", Partial: i == 1,
			Changes: []model.FileChange{{Kind: "A", Path: "/tmp/a"}}, Processes: []model.Proc{{PID: 1, User: "root", Cmd: "pip"}}})
	}
	mux := http.NewServeMux()
	mux.Handle("GET /api/evidence", EvidenceHandler(mem))
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	// container 없음 → 400
	want(t, do(t, "GET", srv.URL+"/api/evidence", "", ""), http.StatusBadRequest, "missing container")
	// 너무 긴 값 → 400
	want(t, do(t, "GET", srv.URL+"/api/evidence?container="+strings.Repeat("a", 300), "", ""), http.StatusBadRequest, "long container")

	// 이름으로 — 최근 것부터
	r := do(t, "GET", srv.URL+"/api/evidence?container="+url.QueryEscape("sg-install-pip-1"), "", "")
	want(t, r, http.StatusOK, "by name")
	got := decode[[]model.Evidence](t, r)
	if len(got) != 2 || got[0].ID != "e2" || got[1].ID != "e1" {
		t.Fatalf("%+v", got)
	}
	if got[0].Changes[0].Path != "/tmp/a" || got[0].Processes[0].Cmd != "pip" || !got[0].Partial {
		t.Fatalf("payload: %+v", got[0])
	}
	// 짧은 id 로
	r = do(t, "GET", srv.URL+"/api/evidence?container="+cid[:12], "", "")
	want(t, r, http.StatusOK, "by short id")
	if got := decode[[]model.Evidence](t, r); len(got) != 2 {
		t.Fatalf("by short id: %d", len(got))
	}
	// 모르는 컨테이너 → 200 빈 배열(null 아님)
	r = do(t, "GET", srv.URL+"/api/evidence?container=nope", "", "")
	want(t, r, http.StatusOK, "unknown")
	if got := decode[[]model.Evidence](t, r); got == nil || len(got) != 0 {
		t.Fatalf("unknown: %v", got)
	}
	if ct := r.Header.Get("Content-Type"); ct != "application/json" {
		t.Fatalf("content-type %q", ct)
	}
}
