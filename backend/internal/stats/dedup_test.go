package stats

import (
	"fmt"
	"testing"
	"time"

	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/model"
)

// 11/10: 수집량(1분 단위 저장)은 같은 1분 안에 같은 (컨테이너 · 종류 · 프로세스 · 대상) 반복을 1건으로 센다.
// 실시간 수(총계 · 초당 · 5분 추이)는 그대로 모든 이벤트를 센다.

func dedupAgg(at time.Time) (*Aggregator, *time.Time) {
	a := New()
	now := at
	a.now = func() time.Time { return now }
	return a, &now
}

func sumMinutes(ms []model.MinuteCount) (exec, open, connect, dns int64) {
	for _, m := range ms {
		exec += m.Exec
		open += m.Open
		connect += m.Connect
		dns += m.DNS
	}
	return
}

func TestCollectedSameKeyInMinuteCountsOnce(t *testing.T) {
	a, now := dedupAgg(time.Date(2026, 11, 10, 9, 0, 5, 0, time.UTC))
	ev := model.Event{Kind: model.KindOpen, ContainerID: "c1", ContainerName: "redis", Comm: "redis-server", Path: "/proc/self/stat"}
	for i := 0; i < 500; i++ {
		a.Observe(model.Verdict{Event: ev})
		if i%100 == 99 {
			*now = now.Add(5 * time.Second) // 같은 분 안에서 시간이 흐른다(9:00:05 → 9:00:30)
		}
	}
	_, open, _, _ := sumMinutes(a.TakeMinutes())
	if open != 1 {
		t.Fatalf("same key x500 in one minute: open = %d, want 1", open)
	}
	// 실시간 수는 그대로 전부
	if s := a.Snapshot(); s.TotalEvents != 500 {
		t.Fatalf("TotalEvents = %d, want 500 (live counts unchanged)", s.TotalEvents)
	}
}

// 중간 저장(TakeMinutes, 10초마다)이 끼어도 같은 분의 반복은 다시 세지 않는다
func TestCollectedDedupSurvivesFlushInSameMinute(t *testing.T) {
	a, now := dedupAgg(time.Date(2026, 11, 10, 9, 0, 5, 0, time.UTC))
	ev := model.Event{Kind: model.KindExec, ContainerID: "c1", Comm: "runc", Args: "/usr/bin/runc init"}
	a.Observe(model.Verdict{Event: ev})
	first := a.TakeMinutes()
	*now = now.Add(20 * time.Second)
	a.Observe(model.Verdict{Event: ev})
	second := a.TakeMinutes()
	e1, _, _, _ := sumMinutes(first)
	e2, _, _, _ := sumMinutes(second)
	if e1 != 1 || e2 != 0 {
		t.Fatalf("exec first flush = %d, second = %d, want 1 and 0", e1, e2)
	}
}

func TestCollectedDifferentKeysCountSeparately(t *testing.T) {
	a, _ := dedupAgg(time.Date(2026, 11, 10, 9, 0, 5, 0, time.UTC))
	base := model.Event{ContainerID: "c1", ContainerName: "web", Comm: "node"}
	evs := []model.Event{
		// open: path 가 다르면 따로
		{Kind: model.KindOpen, Path: "/a"},
		{Kind: model.KindOpen, Path: "/b"},
		{Kind: model.KindOpen, Path: "/a"}, // 반복
		// exec: 실행 파일 경로(인자 없이) 기준 — 인자만 다르면 같은 건
		{Kind: model.KindExec, Args: "/bin/sh -c one"},
		{Kind: model.KindExec, Args: "/bin/sh -c two"},
		{Kind: model.KindExec, Args: "/usr/bin/curl -s x"},
		// connect: 도메인 있으면 도메인:포트, 없으면 IP:포트
		{Kind: model.KindConnect, DstIP: "203.0.113.7", DstPort: 443},
		{Kind: model.KindConnect, DstIP: "203.0.113.7", DstPort: 80},
		{Kind: model.KindConnect, DstIP: "203.0.113.8", DstPort: 443, DstHost: "pkg.example"},
		{Kind: model.KindConnect, DstIP: "203.0.113.9", DstPort: 443, DstHost: "pkg.example"}, // 같은 도메인:포트
		// dns: 질의 이름 + qtype
		{Kind: model.KindDNS, DstHost: "pkg.example", Qtype: "A"},
		{Kind: model.KindDNS, DstHost: "pkg.example", Qtype: "AAAA"},
		{Kind: model.KindDNS, DstHost: "pkg.example", Qtype: "A"}, // 반복
	}
	for _, e := range evs {
		ev := base
		ev.Kind, ev.Path, ev.Args, ev.DstIP, ev.DstPort, ev.DstHost, ev.Qtype = e.Kind, e.Path, e.Args, e.DstIP, e.DstPort, e.DstHost, e.Qtype
		a.Observe(model.Verdict{Event: ev})
	}
	// 컨테이너 · 프로세스(comm)가 다르면 같은 대상이라도 따로
	a.Observe(model.Verdict{Event: model.Event{Kind: model.KindOpen, ContainerID: "c2", ContainerName: "db", Comm: "node", Path: "/a"}})
	a.Observe(model.Verdict{Event: model.Event{Kind: model.KindOpen, ContainerID: "c1", ContainerName: "web", Comm: "python3", Path: "/a"}})

	exec, open, connect, dns := sumMinutes(a.TakeMinutes())
	if exec != 2 || open != 4 || connect != 3 || dns != 2 {
		t.Fatalf("exec=%d open=%d connect=%d dns=%d, want 2 4 3 2", exec, open, connect, dns)
	}
}

func TestCollectedNewMinuteCountsAgain(t *testing.T) {
	a, now := dedupAgg(time.Date(2026, 11, 10, 9, 0, 50, 0, time.UTC))
	ev := model.Event{Kind: model.KindOpen, ContainerID: "c1", Comm: "redis-server", Path: "/proc/self/stat"}
	a.Observe(model.Verdict{Event: ev})
	a.Observe(model.Verdict{Event: ev})
	*now = now.Add(15 * time.Second) // 9:01:05
	a.Observe(model.Verdict{Event: ev})
	a.Observe(model.Verdict{Event: ev})
	got := a.TakeMinutes()
	if len(got) != 2 || got[0].Open != 1 || got[1].Open != 1 {
		t.Fatalf("minutes: %+v, want two minutes with open=1 each", got)
	}
}

// 한 분에 서로 다른 키가 상한(50,000)을 넘으면 그 뒤 새 키는 기억하지 않고 매번 센다(덜 줄어들 뿐 빠뜨리지 않음).
// 이미 기억한 키의 반복은 계속 1건이다.
func TestCollectedSeenCapOverflowCountsEverything(t *testing.T) {
	const capKeys = 50_000
	a, _ := dedupAgg(time.Date(2026, 11, 10, 9, 0, 5, 0, time.UTC))
	ev := func(i int) model.Verdict {
		return model.Verdict{Event: model.Event{Kind: model.KindOpen, ContainerID: "c1", Comm: "find", Path: fmt.Sprintf("/f/%d", i)}}
	}
	for i := 0; i < capKeys; i++ {
		a.Observe(ev(i))
	}
	a.Observe(ev(0)) // 기억한 키 반복 → 세지 않음
	a.Observe(ev(capKeys))
	a.Observe(ev(capKeys)) // 상한 밖 새 키 → 기억 못 하므로 두 번 다 센다
	_, open, _, _ := sumMinutes(a.TakeMinutes())
	if want := int64(capKeys + 2); open != want {
		t.Fatalf("open = %d, want %d", open, want)
	}
	if capKeys != maxSeenPerMinute || len(a.seen) > maxSeenPerMinute {
		t.Fatalf("seen set %d keys, cap %d (test assumes %d)", len(a.seen), maxSeenPerMinute, capKeys)
	}
}

// 이벤트 1건당 추가 비용: 반복 키(대부분의 경우)와 매번 새 키(상한까지)
func BenchmarkObserveRepeatedKey(b *testing.B) {
	a := New()
	v := model.Verdict{Event: model.Event{Kind: model.KindOpen, ContainerID: "c1", ContainerName: "redis", Comm: "redis-server", Path: "/proc/self/stat"}}
	b.ReportAllocs()
	for b.Loop() {
		a.Observe(v)
	}
}

func BenchmarkObserveDistinctKeys(b *testing.B) {
	a := New()
	paths := make([]string, 65536) // 상한(50,000)을 넘겨 기억 · 넘침 두 길을 모두 지난다
	for i := range paths {
		paths[i] = fmt.Sprintf("/f/%d", i)
	}
	v := model.Verdict{Event: model.Event{Kind: model.KindOpen, ContainerID: "c1", Comm: "find"}}
	b.ReportAllocs()
	i := 0
	for b.Loop() {
		v.Event.Path = paths[i&65535]
		i++
		a.Observe(v)
	}
}
