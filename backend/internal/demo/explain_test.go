package demo_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/api"
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/demo"
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/model"
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/osv"
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/review"
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/rules"
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/stats"
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/store"
)

func session(name string, vs ...model.Verdict) model.InstallSession {
	s := model.InstallSession{ID: "ins-1", Manager: "pip", Packages: []string{"./reqeusts"}, Container: name, Status: model.InstallRunning}
	for _, v := range vs {
		s.Violations = append(s.Violations, model.ViolationCount{Verdict: v, Count: 1})
	}
	return s
}

// 연쇄가 1단계에서 먼저 격리되면 판정 · 감사 로그 어디에도 sequence 가 없다 — explain.sequence 가 단계별 진행(1/3)과 먼저 막은 규칙을 준다
func TestExplainChainPreempted(t *testing.T) {
	eng := defaultEngine(t)
	const box = "sg-install-demo-1"
	v := eng.Observe(chainEvents(box)[0])
	v.Enforced = true
	ex := demo.BuildExplain(demo.Run{Scenario: "chain"}, session(box, v), eng.Rules())
	if ex == nil || ex.Sequence == nil {
		t.Fatalf("explain: %+v", ex)
	}
	sq := ex.Sequence
	if sq.RuleID != "chain-download-secrets" || sq.Action != model.ActionKill || !sq.DryRun || sq.WindowSeconds != 10 || sq.Completed || len(sq.Steps) != 3 {
		t.Fatalf("sequence: %+v", sq)
	}
	if s := sq.Steps[0]; !s.Matched || s.Event == nil || s.Event.Comm != "wget" || s.GapMs != nil || s.Kind != model.KindExec || s.Condition != "프로세스 curl · wget" {
		t.Fatalf("step 1: %+v", s)
	}
	for i, s := range sq.Steps[1:] {
		if s.Matched || s.Event != nil || s.GapMs != nil {
			t.Fatalf("step %d must be unmet: %+v", i+2, s)
		}
	}
	if sq.Steps[1].Condition != "내부망(10.0.0.0/8 · 172.16.0.0/12 · 192.168.0.0/16 · 127.0.0.0/8 · ::1) 밖 연결" || sq.Steps[2].Kind != model.KindOpen {
		t.Fatalf("step conditions: %q / %+v", sq.Steps[1].Condition, sq.Steps[2])
	}
	d := ex.DecidedBy
	if d == nil || d.RuleID != "no-shell-download" || d.Action != model.ActionKill || d.DryRun || !d.Enforced || d.Event.Comm != "wget" || d.Description == "" {
		t.Fatalf("decidedBy: %+v", d)
	}
}

// 연쇄가 완성되면(판정의 sequence) 그 단계 기록과 간격을 그대로 쓰고, 판정을 낸 규칙(여기선 sandbox-secrets)을 decidedBy 로
func TestExplainChainCompletedAnnotated(t *testing.T) {
	const box = "sg-install-demo-2"
	eng := withRule(t, map[string]func(*rules.Rule){"no-shell-download": dry, "sandbox-egress": dry})
	var vs []model.Verdict
	for _, ev := range chainEvents(box) {
		if v := eng.Observe(ev); v.Matched {
			vs = append(vs, v)
		}
	}
	vs[len(vs)-1].Enforced = true
	ex := demo.BuildExplain(demo.Run{Scenario: "chain"}, session(box, vs...), eng.Rules())
	sq := ex.Sequence
	if sq == nil || !sq.Completed || len(sq.Steps) != 3 {
		t.Fatalf("sequence: %+v", sq)
	}
	for i, s := range sq.Steps {
		if !s.Matched || s.Event == nil {
			t.Fatalf("step %d: %+v", i+1, s)
		}
	}
	if sq.Steps[1].GapMs == nil || *sq.Steps[1].GapMs != 1000 || *sq.Steps[2].GapMs != 1000 {
		t.Fatalf("gaps: %v %v", sq.Steps[1].GapMs, sq.Steps[2].GapMs)
	}
	if d := ex.DecidedBy; d == nil || d.RuleID != "sandbox-secrets" || !d.Enforced || d.Event.Path != "/root/.netrc" {
		t.Fatalf("decidedBy: %+v", d)
	}
}

// 연쇄가 아닌 시나리오: sequence 없음. 위반이 없으면(benign) decidedBy 도 null — 화면은 「통과」
func TestExplainOtherScenarios(t *testing.T) {
	eng := defaultEngine(t)
	if ex := demo.BuildExplain(demo.Run{Scenario: "benign"}, session("sg-install-demo-3"), eng.Rules()); ex == nil || ex.Sequence != nil || ex.DecidedBy != nil {
		t.Fatalf("benign explain: %+v", ex)
	}
	// 가장 강한 판정이 decidedBy: 경고(alert)보다 실제 격리(kill · enforced)
	alert := model.Verdict{Matched: true, RuleID: "runtime-dns-exfil", Action: model.ActionAlert, Event: model.Event{Kind: model.KindDNS, Timestamp: time.Unix(10, 0)}}
	kill := model.Verdict{Matched: true, RuleID: "sandbox-dns", Action: model.ActionKill, Enforced: true, Event: model.Event{Kind: model.KindDNS, Timestamp: time.Unix(11, 0)}}
	ex := demo.BuildExplain(demo.Run{Scenario: "dns-exfil"}, session("sg-install-demo-4", alert, kill), eng.Rules())
	if ex.Sequence != nil || ex.DecidedBy == nil || ex.DecidedBy.RuleID != "sandbox-dns" {
		t.Fatalf("dns-exfil explain: %+v", ex)
	}
}

// API — GET /api/demo 의 running · last 에 explain 이 붙는다(세션 기준). 거부(refused)는 없다. 기존 필드는 그대로
func TestDemoStatusExplainAPI(t *testing.T) {
	rs, err := rules.LoadFile("../../policies/default.yaml")
	if err != nil {
		t.Fatal(err)
	}
	mem := store.NewMemory()
	if err := mem.ReplacePolicies(t.Context(), rs); err != nil {
		t.Fatal(err)
	}
	eng := rules.New(rs)
	rv := review.New(review.Options{Store: mem, Policies: mem, Audit: mem, Engine: eng, EnforceKill: true, ActorFrom: api.RequesterName})
	if err := rv.Load(t.Context()); err != nil {
		t.Fatal(err)
	}
	sim := &gateSim{release: make(chan struct{})}
	svc := demo.New(demo.Options{Review: rv, Simulator: sim})
	srv := httptest.NewServer(api.Router(api.Deps{Engine: eng, Policies: mem, Audit: mem, Buffer: mem, Stats: stats.New().Snapshot,
		Review: rv, Demo: svc, OSV: &osv.Client{URL: "http://127.0.0.1:1"}, AllowAnonymousWrites: true}))
	t.Cleanup(srv.Close)
	get := func() map[string]any {
		resp, err := http.Get(srv.URL + "/api/demo")
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var m map[string]any
		if err := json.NewDecoder(resp.Body).Decode(&m); err != nil {
			t.Fatal(err)
		}
		return m
	}

	run, err := svc.Start(context.Background(), "chain")
	if err != nil {
		t.Fatal(err)
	}
	// 1단계 wget 실행이 no-shell-download 로 격리된 판정이 세션에 들어온다(파이프라인 대신 직접)
	ev := chainEvents(run.Container)[0]
	v := eng.Observe(ev)
	v.Enforced = true
	rv.Observe(&v)

	st := get()
	running, _ := st["running"].(map[string]any)
	for _, k := range []string{"id", "scenario", "container", "installId", "startedAt", "finishedAt", "status", "exitCode", "simulated"} {
		if _, ok := running[k]; !ok {
			t.Fatalf("existing field %q missing: %v", k, running)
		}
	}
	ex, _ := running["explain"].(map[string]any)
	sq, _ := ex["sequence"].(map[string]any)
	steps, _ := sq["steps"].([]any)
	dec, _ := ex["decidedBy"].(map[string]any)
	if sq["ruleId"] != "chain-download-secrets" || sq["completed"] != false || len(steps) != 3 || dec["ruleId"] != "no-shell-download" || dec["enforced"] != true {
		t.Fatalf("explain: %v", ex)
	}
	s0, _ := steps[0].(map[string]any)
	s1, _ := steps[1].(map[string]any)
	if s0["matched"] != true || s1["matched"] != false || s1["event"] != nil || s1["gapMs"] != nil {
		t.Fatalf("steps: %v", steps)
	}
	close(sim.release)
	svc.Wait()
	if last, _ := get()["last"].(map[string]any); last["explain"] == nil {
		t.Fatalf("last must carry explain: %v", last)
	}

	// 거부된 실행은 explain 이 없다
	h := newHarness(t, demo.Options{Simulator: &gateSim{release: make(chan struct{})}}, false, nil, "pip:sg-demo-benign")
	b := h.browser()
	if r := b.must(202, "POST", "/api/demo/run", `{"scenario":"benign"}`); str(r.body, "status") != "refused" {
		t.Fatalf("refused: %v", r.body)
	}
	if last, _ := b.must(200, "GET", "/api/demo", "").body["last"].(map[string]any); str(last, "status") != "refused" || last["explain"] != nil {
		t.Fatalf("refused last: %v", last)
	}
	// POST 202 본문(Run)에는 explain 이 없다
	raw, _ := json.Marshal(run)
	var m map[string]any
	_ = json.Unmarshal(raw, &m)
	if _, ok := m["explain"]; ok {
		t.Fatalf("POST body must not carry explain: %s", raw)
	}
}
