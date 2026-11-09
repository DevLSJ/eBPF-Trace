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
	// 11/10: 같은 1분 안 같은 대상 반복은 1건이라 서로 다른 대상으로 센다
	for _, ev := range []model.Event{
		{Kind: model.KindExec, Args: "sh -c true"},
		{Kind: model.KindOpen, Path: "/etc/a"},
		{Kind: model.KindOpen, Path: "/etc/b"},
		{Kind: model.KindConnect, DstIP: "203.0.113.7", DstPort: 443},
	} {
		a.Observe(model.Verdict{Event: ev})
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

// DNS 질의(10/30)도 1분 단위 수집량 · 추이 · 초당 이벤트에 센다
func TestTakeMinutesDNS(t *testing.T) {
	a := New()
	now := time.Date(2026, 10, 30, 9, 30, 10, 0, time.UTC)
	a.now = func() time.Time { return now }
	for _, ev := range []model.Event{
		{Kind: model.KindDNS, DstHost: "a.example", Qtype: "A"},
		{Kind: model.KindDNS, DstHost: "b.example", Qtype: "A"},
		{Kind: model.KindConnect, DstIP: "203.0.113.7", DstPort: 443},
	} {
		a.Observe(model.Verdict{Event: ev})
	}
	a.Observe(model.Verdict{Matched: true, Action: model.ActionAlert, Event: model.Event{Kind: model.KindDNS, ContainerName: "web-api", DstHost: "a.example", Qtype: "A"}})
	now = now.Add(time.Second)
	s := a.Snapshot()
	if s.TotalEvents != 4 || s.TotalViolations != 1 || s.EventsPerSec != 4 || s.EventsLastMinute != 4 {
		t.Fatalf("snapshot must count dns: %+v", s)
	}
	var dns int
	for _, p := range s.Trend {
		dns += p.DNS
	}
	if dns != 3 {
		t.Fatalf("trend dns = %d, want 3", dns)
	}
	got := a.TakeMinutes()
	if len(got) != 1 || got[0].DNS != 3 || got[0].Connect != 1 || got[0].Exec != 0 {
		t.Fatalf("minutes: %+v", got)
	}
}
