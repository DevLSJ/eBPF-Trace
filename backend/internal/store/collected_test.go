package store

import (
	"testing"
	"time"

	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/model"
)

// 1분 단위 수집량: 같은 분은 더하고, 구간 [from, to) 만 돌려준다(시간순)
func TestMemoryCollected(t *testing.T) {
	m := NewMemory()
	ctx := t.Context()
	t0 := time.Date(2026, 10, 16, 9, 0, 0, 0, time.UTC)
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(m.AddCollected(ctx, []model.MinuteCount{{Minute: t0, Exec: 1, Open: 2}, {Minute: t0.Add(time.Minute), Connect: 3}}))
	must(m.AddCollected(ctx, []model.MinuteCount{{Minute: t0, Exec: 4}}))
	got, err := m.CollectedRange(ctx, t0, t0.Add(2*time.Minute))
	must(err)
	if len(got) != 2 || got[0].Exec != 5 || got[0].Open != 2 || got[1].Connect != 3 {
		t.Fatalf("range: %+v", got)
	}
	if got, _ := m.CollectedRange(ctx, t0.Add(time.Minute), t0.Add(time.Hour)); len(got) != 1 {
		t.Fatalf("from is inclusive, earlier minutes excluded: %+v", got)
	}
}
