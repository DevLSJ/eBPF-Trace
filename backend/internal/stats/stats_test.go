package stats

import (
	"testing"
	"time"

	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/model"
)

func TestSnapshot(t *testing.T) {
	a := New()
	now := time.Unix(1_800_000_000, 0)
	a.now = func() time.Time { return now }

	for range 3 {
		a.Observe(model.Verdict{Event: model.Event{Kind: model.KindOpen, ContainerName: "web"}})
	}
	a.Observe(model.Verdict{Matched: true, Action: model.ActionKill, Enforced: true, Event: model.Event{Kind: model.KindExec, ContainerName: "victim"}})
	a.Observe(model.Verdict{Matched: true, Action: model.ActionAlert, Event: model.Event{Kind: model.KindConnect, ContainerName: "victim"}})

	now = now.Add(time.Second)
	s := a.Snapshot()
	if s.TotalEvents != 5 || s.TotalViolations != 2 {
		t.Fatalf("totals: %+v", s)
	}
	if s.EventsPerSec != 5 || s.EventsLastMinute != 5 {
		t.Fatalf("rates: perSec=%d lastMin=%d", s.EventsPerSec, s.EventsLastMinute)
	}
	if s.RiskScore != 25 {
		t.Fatalf("risk = %d, want 20+5", s.RiskScore)
	}
	if len(s.TopContainers) != 1 || s.TopContainers[0] != (ContainerCount{"victim", 2}) {
		t.Fatalf("top: %+v", s.TopContainers)
	}
	if len(s.Trend) < 60 {
		t.Fatalf("trend points = %d", len(s.Trend))
	}

	// 위험 점수는 5분 뒤 사라진다
	now = now.Add(6 * time.Minute)
	if s := a.Snapshot(); s.RiskScore != 0 || s.EventsLastMinute != 0 {
		t.Fatalf("after window: risk=%d lastMin=%d", s.RiskScore, s.EventsLastMinute)
	}
}
