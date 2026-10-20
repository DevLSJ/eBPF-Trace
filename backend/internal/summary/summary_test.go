package summary

import (
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
		if err := mem.SaveAudit(ctx, v); err != nil {
			t.Fatal(err)
		}
	}
	save(10*time.Minute, "pkg-reqeusts", "sensitive-files", model.ActionKill, true, nil)
	save(9*time.Minute, "pkg-reqeusts", "sensitive-files", model.ActionKill, true, nil)
	save(3*time.Hour, "web-api", "egress-allowlist", model.ActionAlert, false, nil)
	save(5*time.Hour, "sg-install-pip-1", "pipe-to-shell", model.ActionKill, true, &model.InstallRef{ID: "ins-0001", Label: "pip ./reqeusts"})
	save(30*time.Hour, "old", "sensitive-files", model.ActionKill, true, nil) // 24시간 밖
	_ = mem.AddCollected(ctx, []model.MinuteCount{
		{Minute: now.Add(-2 * time.Minute).Truncate(time.Minute), Exec: 3, Open: 10, Connect: 2},
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
	if s.Collected.Total != 20 || s.Collected.ByKind.Exec != 3 || s.Collected.ByKind.Open != 15 || s.Collected.ByKind.Connect != 2 {
		t.Fatalf("collected: %+v", s.Collected)
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

	if h, _ := svc.Build(ctx, "1h"); len(h.Series) != 60 || h.BucketSec != 60 || h.Violations.Total != 2 {
		t.Fatalf("1h: %d %d %+v", len(h.Series), h.BucketSec, h.Violations)
	}
	if w, _ := svc.Build(ctx, "7d"); len(w.Series) != 28 || w.BucketSec != 21600 || w.Collected.Total != 1019 {
		t.Fatalf("7d: %d %d %d", len(w.Series), w.BucketSec, w.Collected.Total)
	}
	if _, err := svc.Build(ctx, "2y"); err == nil {
		t.Fatal("bad range must fail")
	}
}
