package store

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/model"
)

// 감사 로그 쪽 번호(11/04): CountAudit = 필터(kind · action · rule · container · since · until) 뒤 전체 건수 — 커서 · 쪽 크기 · 건너뛰기는 무시.
// QueryAudit 의 Offset 은 최신순에서 그만큼 건너뛴다. 기존 커서(BeforeID)는 그대로 동작한다. Memory · Postgres 가 같은 계약
func auditPageContract(t *testing.T, s AuditStore) {
	t.Helper()
	ctx := t.Context()
	base := time.Date(2026, 11, 4, 9, 0, 0, 0, time.UTC)
	var ids []int64
	for i := range 7 {
		v := model.Verdict{Matched: true, RuleID: "no-shell-download", Action: model.ActionKill,
			Event: model.Event{Kind: model.KindExec, Timestamp: base.Add(time.Duration(i) * time.Minute), ContainerName: "sg-install-demo-1", Comm: "wget"}}
		if i >= 5 {
			v = model.Verdict{Matched: true, RuleID: "runtime-direct-ip", Action: model.ActionAlert,
				Event: model.Event{Kind: model.KindConnect, Timestamp: base.Add(time.Duration(i) * time.Minute), ContainerName: "web-api", DstIP: "203.0.113.7", DstPort: 80}}
		}
		id, err := s.SaveAudit(ctx, v)
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, id)
	}
	count := func(q AuditQuery) int {
		t.Helper()
		n, err := s.CountAudit(ctx, q)
		if err != nil {
			t.Fatal(err)
		}
		return n
	}
	for name, c := range map[string]struct {
		q    AuditQuery
		want int
	}{
		"all":       {AuditQuery{}, 7},
		"rule":      {AuditQuery{RuleID: "no-shell-download"}, 5},
		"kind":      {AuditQuery{Kind: model.KindConnect}, 2},
		"action":    {AuditQuery{Action: model.ActionAlert}, 2},
		"container": {AuditQuery{Container: "demo"}, 5},
		"since":     {AuditQuery{Since: base.Add(4 * time.Minute)}, 3},
		"until":     {AuditQuery{Until: base.Add(1 * time.Minute)}, 2},
		"none":      {AuditQuery{RuleID: "nope"}, 0},
		// 커서 · 쪽 크기 · 건너뛰기는 총 건수에 영향이 없다
		"paging ignored": {AuditQuery{BeforeID: ids[3], Limit: 1, Offset: 3}, 7},
	} {
		if got := count(c.q); got != c.want {
			t.Errorf("count %s: %d, want %d", name, got, c.want)
		}
	}
	page := func(q AuditQuery) []int64 {
		t.Helper()
		rows, err := s.QueryAudit(ctx, q)
		if err != nil {
			t.Fatal(err)
		}
		out := []int64{}
		for _, r := range rows {
			out = append(out, r.ID)
		}
		return out
	}
	eq := func(name string, got, want []int64) {
		t.Helper()
		if len(got) != len(want) {
			t.Errorf("%s: %v, want %v", name, got, want)
			return
		}
		for i := range got {
			if got[i] != want[i] {
				t.Errorf("%s: %v, want %v", name, got, want)
				return
			}
		}
	}
	eq("offset 0", page(AuditQuery{Limit: 2}), []int64{ids[6], ids[5]})
	eq("offset 2", page(AuditQuery{Limit: 2, Offset: 2}), []int64{ids[4], ids[3]})
	eq("offset 6", page(AuditQuery{Limit: 2, Offset: 6}), []int64{ids[0]})
	eq("offset past end", page(AuditQuery{Limit: 2, Offset: 7}), []int64{})
	eq("filter + offset", page(AuditQuery{RuleID: "no-shell-download", Limit: 2, Offset: 4}), []int64{ids[0]})
	eq("cursor unchanged", page(AuditQuery{BeforeID: ids[4], Limit: 2}), []int64{ids[3], ids[2]})
}

func TestMemoryAuditPage(t *testing.T) { auditPageContract(t, NewMemory()) }

// PG: SUPPLYGUARD_TEST_DATABASE_URL 이 있을 때만 (빈 테스트용 DB — audit_log 를 비운다)
func TestPostgresAuditPage(t *testing.T) {
	url := os.Getenv("SUPPLYGUARD_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("SUPPLYGUARD_TEST_DATABASE_URL not set")
	}
	p, err := NewPostgres(context.Background(), url)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)
	if _, err := p.pool.Exec(t.Context(), `TRUNCATE audit_log RESTART IDENTITY`); err != nil {
		t.Fatal(err)
	}
	auditPageContract(t, p)
}
