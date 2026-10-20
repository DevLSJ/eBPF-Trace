package stats

import (
	"testing"
	"time"

	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/model"
)

// 종합(10/16): 수집량을 1분 단위로 모았다가 TakeMinutes 로 넘기고 비운다(저장소에 더해 쓰기)
func TestTakeMinutes(t *testing.T) {
	a := New()
	now := time.Date(2026, 10, 16, 9, 30, 10, 0, time.UTC)
	a.now = func() time.Time { return now }
	for _, k := range []model.Kind{model.KindExec, model.KindOpen, model.KindOpen, model.KindConnect} {
		a.Observe(model.Verdict{Event: model.Event{Kind: k}})
	}
	now = now.Add(time.Minute)
	a.Observe(model.Verdict{Event: model.Event{Kind: model.KindOpen}})

	got := a.TakeMinutes()
	if len(got) != 2 {
		t.Fatalf("minutes: %+v", got)
	}
	if m := got[0]; !m.Minute.Equal(time.Date(2026, 10, 16, 9, 30, 0, 0, time.UTC)) || m.Exec != 1 || m.Open != 2 || m.Connect != 1 {
		t.Fatalf("first minute: %+v", m)
	}
	if m := got[1]; m.Open != 1 || m.Exec != 0 {
		t.Fatalf("second minute: %+v", m)
	}
	if len(a.TakeMinutes()) != 0 {
		t.Fatal("TakeMinutes must clear")
	}
}
