package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/model"
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/review"
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/rules"
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/stats"
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/store"
)

// GET /api/audit?decision=(11/10 사용자): 대시보드 「설치 검사 결과」 판정 줄(악성 · 오탐 · 대기)을 누르면
// 감사 로그를 그 판정으로 거른다. 판정은 건(case)에 있으므로 서버가 건 id 로 거른다 — 쪽 번호 · 총 건수가 맞게.
//
//	malicious · false_positive = 건의 판정, pending = 열린 건(대시보드 「대기」와 같은 셈). 건이 없는 기록은 어디에도 안 든다
func TestAuditDecisionFilter(t *testing.T) {
	mem := store.NewMemory()
	engine := rules.New(nil)
	rv := review.New(review.Options{Store: mem, Policies: mem, Audit: mem, Engine: engine, EnforceKill: true, ActorFrom: RequesterName})
	srv := httptest.NewServer(Router(Deps{Engine: engine, Policies: mem, Audit: mem, Buffer: mem, Stats: stats.New().Snapshot,
		AllowAnonymousWrites: true, Review: rv}))
	t.Cleanup(srv.Close)

	ts := time.Date(2026, 11, 10, 9, 0, 0, 0, time.UTC)
	save := func(ctr string, action model.Action, n int) *string {
		t.Helper()
		var id *string
		for i := range n {
			v := model.Verdict{Matched: true, RuleID: "no-shell-download", Action: action, Enforced: action == model.ActionKill,
				Event: model.Event{Kind: model.KindExec, Timestamp: ts.Add(time.Duration(i) * time.Second), ContainerName: ctr, ContainerID: ctr + "-id", Comm: "wget"}}
			rv.Observe(&v)
			if _, err := mem.SaveAudit(t.Context(), v); err != nil {
				t.Fatal(err)
			}
			id = v.CaseID
		}
		return id
	}
	mal := save("web-a", model.ActionKill, 3)
	fp := save("web-b", model.ActionKill, 2)
	pend := save("web-c", model.ActionKill, 4)
	save("web-d", model.ActionAlert, 1) // 건 없음
	if mal == nil || fp == nil || pend == nil {
		t.Fatalf("cases not opened: %v %v %v", mal, fp, pend)
	}
	if _, _, err := rv.Decide(t.Context(), *mal, model.DecisionMalicious, ""); err != nil {
		t.Fatal(err)
	}
	if _, _, err := rv.Decide(t.Context(), *fp, model.DecisionFalsePositive, ""); err != nil {
		t.Fatal(err)
	}

	get := func(q string) (int, AuditPage) {
		t.Helper()
		r := do(t, "GET", srv.URL+"/api/audit?"+q, "", "")
		var p AuditPage
		if r.StatusCode == http.StatusOK {
			if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
				t.Fatal(err)
			}
		}
		return r.StatusCode, p
	}
	for dec, want := range map[string]struct {
		total int
		ctr   string
	}{
		"malicious":      {3, "web-a"},
		"false_positive": {2, "web-b"},
		"pending":        {4, "web-c"},
	} {
		code, p := get("offset=0&limit=2&decision=" + dec)
		if code != http.StatusOK || p.Total != want.total || len(p.Items) != 2 {
			t.Fatalf("%s: code %d total %d items %d, want total %d", dec, code, p.Total, len(p.Items), want.total)
		}
		for _, a := range p.Items {
			if a.Event.ContainerName != want.ctr {
				t.Fatalf("%s: got row of %s", dec, a.Event.ContainerName)
			}
		}
	}
	// 다른 조건과 함께(AND) · 걸리는 건이 없으면 빈 쪽
	if _, p := get("offset=0&decision=malicious&container=web-b"); p.Total != 0 || p.Items == nil {
		t.Fatalf("and: %+v", p)
	}
	// 판정 조건이 없으면 예전 그대로 전체
	if _, p := get("offset=0"); p.Total != 10 {
		t.Fatalf("all: %d", p.Total)
	}
	if code, _ := get("offset=0&decision=maybe"); code != http.StatusBadRequest {
		t.Fatalf("bad decision: %d", code)
	}
}
