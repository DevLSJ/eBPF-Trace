package api

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/model"
)

// GET /api/audit?kind=dns (10/30): dns 행만 돌려주고 qtype 이 실린다. 모르는 kind 는 400 과 허용 목록 문구
func TestAuditKindDNS(t *testing.T) {
	srv, _, mem := newServer(t, "", true)
	ts := time.Date(2026, 10, 30, 9, 0, 0, 0, time.UTC)
	for _, v := range []model.Verdict{
		{Matched: true, RuleID: "runtime-dns-exfil", Action: model.ActionAlert, Reason: "금지 질의 유형: data.exfil.example (TXT)",
			Event: model.Event{Kind: model.KindDNS, Timestamp: ts, ContainerName: "web-api", DstHost: "data.exfil.example", Qtype: "TXT", DstIP: "127.0.0.11", DstPort: 53}},
		{Matched: true, RuleID: "pipe-to-shell", Action: model.ActionKill, Event: model.Event{Kind: model.KindExec, Timestamp: ts, ContainerName: "web-api", Comm: "sh", Args: "sh -c x | sh"}},
	} {
		if _, err := mem.SaveAudit(t.Context(), v); err != nil {
			t.Fatal(err)
		}
	}
	r := do(t, "GET", srv.URL+"/api/audit?kind=dns", "", "")
	if r.StatusCode != http.StatusOK {
		t.Fatalf("status %d", r.StatusCode)
	}
	var rows []map[string]any
	if err := json.NewDecoder(r.Body).Decode(&rows); err != nil || len(rows) != 1 {
		t.Fatalf("rows=%d err=%v", len(rows), err)
	}
	ev, _ := rows[0]["event"].(map[string]any)
	if ev["kind"] != "dns" || ev["qtype"] != "TXT" || ev["dstHost"] != "data.exfil.example" {
		t.Fatalf("dns row: %v", ev)
	}
	if _, has := ev["dnsTraced"]; has {
		t.Fatalf("dns row must not carry dnsTraced: %v", ev)
	}
	r = do(t, "GET", srv.URL+"/api/audit?kind=read", "", "")
	var e map[string]string
	_ = json.NewDecoder(r.Body).Decode(&e)
	if r.StatusCode != http.StatusBadRequest || e["error"] != "kind: exec | open | connect | dns" {
		t.Fatalf("bad kind: %d %v", r.StatusCode, e)
	}
}
