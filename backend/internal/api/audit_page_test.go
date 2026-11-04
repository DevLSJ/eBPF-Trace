package api

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/model"
)

// GET /api/audit 쪽 번호(11/04): offset 이 있으면 {items, total, offset, limit} — total 은 필터 뒤 전체 건수.
// offset 이 없으면 예전과 같은 배열(커서 before 포함). offset 은 0 이상 정수, before 와 함께 쓸 수 없다
func TestAuditOffsetPaging(t *testing.T) {
	srv, _, mem := newServer(t, "", true)
	ts := time.Date(2026, 11, 4, 9, 0, 0, 0, time.UTC)
	for i := range 5 {
		v := model.Verdict{Matched: true, RuleID: "no-shell-download", Action: model.ActionKill,
			Event: model.Event{Kind: model.KindExec, Timestamp: ts.Add(time.Duration(i) * time.Second), ContainerName: "sg-install-demo-1", Comm: "wget"}}
		if i == 4 {
			v.RuleID, v.Action = "runtime-direct-ip", model.ActionAlert
			v.Event = model.Event{Kind: model.KindConnect, Timestamp: ts.Add(4 * time.Second), ContainerName: "web-api", DstIP: "203.0.113.7", DstPort: 80}
		}
		if _, err := mem.SaveAudit(t.Context(), v); err != nil {
			t.Fatal(err)
		}
	}
	type page struct {
		Items  []model.AuditEntry `json:"items"`
		Total  int                `json:"total"`
		Offset int                `json:"offset"`
		Limit  int                `json:"limit"`
	}
	get := func(q string) page {
		t.Helper()
		r := do(t, "GET", srv.URL+"/api/audit?"+q, "", "")
		defer r.Body.Close()
		if r.StatusCode != http.StatusOK {
			t.Fatalf("%s: status %d", q, r.StatusCode)
		}
		var p page
		if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
		return p
	}
	p := get("offset=0&limit=2")
	if p.Total != 5 || p.Offset != 0 || p.Limit != 2 || len(p.Items) != 2 || p.Items[0].ID != 5 || p.Items[1].ID != 4 {
		t.Fatalf("page 1: %+v", p)
	}
	if p = get("offset=4&limit=2"); p.Total != 5 || len(p.Items) != 1 || p.Items[0].ID != 1 {
		t.Fatalf("last page: %+v", p)
	}
	if p = get("offset=10&limit=2"); p.Total != 5 || len(p.Items) != 0 || p.Items == nil {
		t.Fatalf("past end must be an empty array: %+v", p)
	}
	if p = get("offset=0&rule=no-shell-download&limit=3"); p.Total != 4 || len(p.Items) != 3 {
		t.Fatalf("filtered total: %+v", p)
	}
	if p = get("offset=0"); p.Limit != 100 || p.Total != 5 || len(p.Items) != 5 {
		t.Fatalf("default limit: %+v", p)
	}
	if p = get("offset=0&limit=9999"); p.Limit != 500 {
		t.Fatalf("limit cap: %+v", p)
	}

	// 예전 방식 그대로: offset 이 없으면 배열, before 커서 동작
	r := do(t, "GET", srv.URL+"/api/audit?before=3&limit=5", "", "")
	var rows []model.AuditEntry
	if err := json.NewDecoder(r.Body).Decode(&rows); err != nil || len(rows) != 2 || rows[0].ID != 2 {
		t.Fatalf("legacy cursor: %v %+v", err, rows)
	}
	r.Body.Close()

	for q, want := range map[string]string{
		"offset=-1":         "offset: 0 이상 정수",
		"offset=abc":        "offset: 0 이상 정수",
		"offset=0&before=3": "before 와 offset 은 함께 쓸 수 없음",
	} {
		r := do(t, "GET", srv.URL+"/api/audit?"+q, "", "")
		var e map[string]string
		_ = json.NewDecoder(r.Body).Decode(&e)
		r.Body.Close()
		if r.StatusCode != http.StatusBadRequest || e["error"] != want {
			t.Errorf("%s: %d %v", q, r.StatusCode, e)
		}
	}
}
