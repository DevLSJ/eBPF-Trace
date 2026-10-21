package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/rules"
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/stats"
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/store"
)

// /api/info 의 dnsResolve: trace_dns 가 실제로 돌고 있으면 ok, 아니면 off (소스가 알려 주지 않으면 off)
func TestInfoDNSResolve(t *testing.T) {
	get := func(srv *httptest.Server) string {
		r := do(t, "GET", srv.URL+"/api/info", "", "")
		var m map[string]any
		if err := json.NewDecoder(r.Body).Decode(&m); err != nil || r.StatusCode != http.StatusOK {
			t.Fatalf("%d %v", r.StatusCode, err)
		}
		s, _ := m["dnsResolve"].(string)
		return s
	}
	srv, _, _ := newServer(t, "", true)
	if got := get(srv); got != "off" {
		t.Fatalf("no DNS reporter: want off, got %q", got)
	}
	traced := true
	mem := store.NewMemory()
	live := httptest.NewServer(Router(Deps{Engine: rules.New(nil), Policies: mem, Audit: mem, Buffer: mem,
		Stats: stats.New().Snapshot, DNSTraced: func() bool { return traced }}))
	t.Cleanup(live.Close)
	if got := get(live); got != "ok" {
		t.Fatalf("want ok, got %q", got)
	}
	traced = false // 가젯이 나중에 포기하면 off 로 바뀐다
	if got := get(live); got != "off" {
		t.Fatalf("want off after trace_dns gave up, got %q", got)
	}
}

// /api/info discovery(10/20): 실제로 쓰이는 컨테이너 발견 방식과, docker-events 일 때만 놓칠 수 있는 구간 안내
func TestInfoDiscovery(t *testing.T) {
	get := func(srv *httptest.Server) map[string]any {
		r := do(t, "GET", srv.URL+"/api/info", "", "")
		var m map[string]any
		if err := json.NewDecoder(r.Body).Decode(&m); err != nil || r.StatusCode != http.StatusOK {
			t.Fatalf("%d %v", r.StatusCode, err)
		}
		return m
	}
	srv, _, _ := newServer(t, "", true)
	m := get(srv)
	if d, ok := m["discovery"]; !ok || d != "" {
		t.Fatalf("no discovery reporter: want present empty, got %v (present %v)", d, ok)
	}
	if n, ok := m["discoveryNote"]; !ok || n != "" {
		t.Fatalf("no discovery reporter: want empty note, got %v (present %v)", n, ok)
	}

	active := "docker-events"
	mem := store.NewMemory()
	live := httptest.NewServer(Router(Deps{Engine: rules.New(nil), Policies: mem, Audit: mem, Buffer: mem,
		Stats: stats.New().Snapshot, Discovery: func() string { return active }}))
	t.Cleanup(live.Close)
	m = get(live)
	if m["discovery"] != "docker-events" || m["discoveryNote"] != "컨테이너 시작 직후 약 0.1초 안의 동작은 놓칠 수 있습니다" {
		t.Fatalf("docker-events: %v / %v", m["discovery"], m["discoveryNote"])
	}
	active = "fanotify"
	m = get(live)
	if m["discovery"] != "fanotify" || m["discoveryNote"] != "" {
		t.Fatalf("fanotify: %v / %v", m["discovery"], m["discoveryNote"])
	}
}
