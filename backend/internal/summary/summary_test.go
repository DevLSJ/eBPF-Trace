package summary

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/model"
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/store"
)

type fakeReview struct {
	installs []model.InstallSession
	cases    []model.Case
	bl       model.Blocklist
}

func (f fakeReview) Installs() []model.InstallSession { return f.installs }
func (f fakeReview) Cases() []model.Case              { return f.cases }
func (f fakeReview) Blocklist() model.Blocklist       { return f.bl }

func ptr[T any](v T) *T { return &v }

// 종합(10/16): 저장된 기록으로 기간별 수집량 · 위반 · 상위 · 설치 검사 · 판정 · 차단 목록
func TestBuild(t *testing.T) {
	ctx := t.Context()
	now := time.Date(2026, 10, 16, 9, 30, 0, 0, time.UTC)
	mem := store.NewMemory()
	save := func(ago time.Duration, ctr, rule string, action model.Action, enforced bool, install *model.InstallRef) {
		t.Helper()
		v := model.Verdict{Matched: true, RuleID: rule, Action: action, Enforced: enforced, Install: install,
			Event: model.Event{Kind: model.KindOpen, ContainerName: ctr, Timestamp: now.Add(-ago)}}
		if _, err := mem.SaveAudit(ctx, v); err != nil {
			t.Fatal(err)
		}
	}
	save(10*time.Minute, "pkg-reqeusts", "sensitive-files", model.ActionKill, true, nil)
	save(9*time.Minute, "pkg-reqeusts", "sensitive-files", model.ActionKill, true, nil)
	save(3*time.Hour, "web-api", "egress-allowlist", model.ActionAlert, false, nil)
	save(5*time.Hour, "sg-install-pip-1", "pipe-to-shell", model.ActionKill, true, &model.InstallRef{ID: "ins-0001", Label: "pip ./reqeusts"})
	save(30*time.Hour, "old", "sensitive-files", model.ActionKill, true, nil) // 24시간 밖
	_ = mem.AddCollected(ctx, []model.MinuteCount{
		{Minute: now.Add(-2 * time.Minute).Truncate(time.Minute), Exec: 3, Open: 10, Connect: 2, DNS: 4}, // 10/30 dns
		{Minute: now.Add(-2 * time.Hour).Truncate(time.Minute), Open: 5},
		{Minute: now.Add(-30 * time.Hour).Truncate(time.Minute), Open: 999},
	})
	rv := fakeReview{
		installs: []model.InstallSession{
			{ID: "ins-0001", StartedAt: now.Add(-5 * time.Hour), Status: model.InstallIsolated},
			{ID: "ins-0002", StartedAt: now.Add(-1 * time.Hour), Status: model.InstallPassed},
			{ID: "ins-0003", StartedAt: now.Add(-1 * time.Hour), Status: model.InstallRefused},
			{ID: "ins-0000", StartedAt: now.Add(-40 * time.Hour), Status: model.InstallPassed},
		},
		cases: []model.Case{
			{ID: "case-0001", State: model.CaseClosed, Decision: model.DecisionMalicious, DecidedAt: ptr(now.Add(-4 * time.Hour))},
			{ID: "case-0002", State: model.CaseOpen, Decision: model.DecisionPending},
		},
		bl: model.Blocklist{Packages: []model.BlockEntry{{Value: "pip:reqeusts"}}, Images: []model.BlockEntry{}, Hosts: []model.BlockEntry{{Value: "a.test"}, {Value: "b.test"}}},
	}
	svc := New(mem, mem, rv)
	svc.now = func() time.Time { return now }

	s, err := svc.Build(ctx, "24h")
	if err != nil {
		t.Fatal(err)
	}
	if s.Range != "24h" || s.BucketSec != 3600 || len(s.Series) != 24 {
		t.Fatalf("buckets: %s %d %d", s.Range, s.BucketSec, len(s.Series))
	}
	if s.Collected.Total != 24 || s.Collected.ByKind.Exec != 3 || s.Collected.ByKind.Open != 15 || s.Collected.ByKind.Connect != 2 || s.Collected.ByKind.DNS != 4 { // 10/30 dns 포함
		t.Fatalf("collected: %+v", s.Collected)
	}
	if p := s.Series[len(s.Series)-1]; p.DNS != 4 || p.Exec != 3 { // 지금이 든 칸
		t.Fatalf("series dns: %+v", p)
	}
	if v := s.Violations; v.Total != 4 || v.Killed != 3 || v.Alert != 1 || v.Held != 0 {
		t.Fatalf("violations: %+v", v)
	}
	if s.IsolatedContainers != 2 {
		t.Fatalf("isolated: %d", s.IsolatedContainers)
	}
	if len(s.TopRules) != 3 || s.TopRules[0].RuleID != "sensitive-files" || s.TopRules[0].Count != 2 || s.TopRules[0].Level != model.LevelKilled {
		t.Fatalf("top rules: %+v", s.TopRules)
	}
	if s.TopContainers[0].Container != "pkg-reqeusts" || s.TopContainers[2].Container != "pip ./reqeusts" && s.TopContainers[1].Container != "pip ./reqeusts" {
		t.Fatalf("top containers (install label): %+v", s.TopContainers)
	}
	if i := s.Installs; i.Total != 3 || i.Isolated != 1 || i.Passed != 1 || i.Refused != 1 {
		t.Fatalf("installs: %+v", i)
	}
	if d := s.Decisions; d.Malicious != 1 || d.FalsePositive != 0 || d.Pending != 1 {
		t.Fatalf("decisions: %+v", d)
	}
	if b := s.Blocklist; b.Packages != 1 || b.Images != 0 || b.Hosts != 2 {
		t.Fatalf("blocklist: %+v", b)
	}
	var sum int64
	for _, p := range s.Series {
		sum += p.Killed + p.Alert
	}
	if sum != 4 {
		t.Fatalf("series violations %d", sum)
	}
	if s.Isolation.Count != 0 || s.Isolation.MedianMs != nil { // 10/30 isolation: 타임라인 없는 기록은 세지 않는다
		t.Fatalf("isolation without timelines: %+v", s.Isolation)
	}

	if h, _ := svc.Build(ctx, "1h"); len(h.Series) != 60 || h.BucketSec != 60 || h.Violations.Total != 2 {
		t.Fatalf("1h: %d %d %+v", len(h.Series), h.BucketSec, h.Violations)
	}
	if w, _ := svc.Build(ctx, "7d"); len(w.Series) != 28 || w.BucketSec != 21600 || w.Collected.Total != 1023 { // 10/30 dns 포함
		t.Fatalf("7d: %d %d %d", len(w.Series), w.BucketSec, w.Collected.Total)
	}
	if _, err := svc.Build(ctx, "2y"); err == nil {
		t.Fatal("bad range must fail")
	}
}

// 격리 지연 통계(10/30): 범위 안에서 killedAt 이 있는 행의 killedAt − detectedAt(ms) 로 count · 중앙값 · p95 · 최대. 없으면 count 0 · 나머지 null
func TestIsolationStats(t *testing.T) {
	ctx := t.Context()
	now := time.Date(2026, 10, 30, 9, 30, 0, 0, time.UTC)
	mem := store.NewMemory()
	save := func(ago time.Duration, killedAfter time.Duration, withKill bool) {
		t.Helper()
		det := now.Add(-ago)
		tl := &model.Timeline{DetectedAt: det, MatchedAt: det.Add(time.Millisecond)}
		if withKill {
			k := det.Add(killedAfter)
			tl.KilledAt = &k
		}
		v := model.Verdict{Matched: true, RuleID: "sensitive-files", Action: model.ActionKill, Enforced: withKill, Timeline: tl,
			Event: model.Event{Kind: model.KindOpen, ContainerName: "pkg-reqeusts", Timestamp: det, Path: "/etc/shadow"}}
		if _, err := mem.SaveAudit(ctx, v); err != nil {
			t.Fatal(err)
		}
	}
	save(10*time.Minute, 100*time.Millisecond, true)
	save(9*time.Minute, 300*time.Millisecond, true)
	save(2*time.Hour, 500*time.Millisecond, true)
	save(5*time.Hour, 900*time.Millisecond, true)
	save(4*time.Hour, 0, false)                   // kill 없음(dry-run) — 세지 않는다
	save(30*time.Hour, 50*time.Millisecond, true) // 24시간 밖
	if _, err := mem.SaveAudit(ctx, model.Verdict{Matched: true, RuleID: "old", Action: model.ActionKill, Enforced: true,
		Event: model.Event{Kind: model.KindOpen, ContainerName: "legacy", Timestamp: now.Add(-time.Hour)}}); err != nil { // 옛 기록: 타임라인 없음
		t.Fatal(err)
	}
	svc := New(mem, mem, fakeReview{})
	svc.now = func() time.Time { return now }
	s, err := svc.Build(ctx, "24h")
	if err != nil {
		t.Fatal(err)
	}
	iso := s.Isolation
	if iso.Count != 4 || iso.MedianMs == nil || *iso.MedianMs != 400 || iso.P95Ms == nil || *iso.P95Ms != 900 || iso.MaxMs == nil || *iso.MaxMs != 900 {
		t.Fatalf("isolation: %+v", iso)
	}
	b, _ := json.Marshal(s)
	if !strings.Contains(string(b), `"isolation":{"count":4,"medianMs":400,"p95Ms":900,"maxMs":900}`) {
		t.Fatalf("isolation json: %s", b)
	}
	h, _ := svc.Build(ctx, "1h")
	if h.Isolation.Count != 2 || *h.Isolation.MedianMs != 200 || *h.Isolation.P95Ms != 300 || *h.Isolation.MaxMs != 300 {
		t.Fatalf("1h isolation: %+v", h.Isolation)
	}
	empty := New(store.NewMemory(), store.NewMemory(), fakeReview{})
	empty.now = svc.now
	e, _ := empty.Build(ctx, "24h")
	if e.Isolation.Count != 0 || e.Isolation.MedianMs != nil || e.Isolation.P95Ms != nil || e.Isolation.MaxMs != nil {
		t.Fatalf("empty isolation: %+v", e.Isolation)
	}
	if b, _ := json.Marshal(e); !strings.Contains(string(b), `"isolation":{"count":0,"medianMs":null,"p95Ms":null,"maxMs":null}`) {
		t.Fatalf("empty isolation json: %s", b)
	}
}
