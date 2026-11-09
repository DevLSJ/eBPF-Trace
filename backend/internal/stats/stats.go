// Package stats aggregates KPIs, the syscall trend and the risk score shown on
// the dashboard. Every event is counted here, before WebSocket sampling. The
// per-minute collected counts (stored for the dashboard summary) count a
// repeated (container, kind, comm, target) once per minute.
package stats

import (
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/model"
)

const (
	window      = 300 // 초 — 추이 차트 5분
	trendStep   = 5   // 초 — 차트 한 점
	riskWindow  = 5 * time.Minute
	topN        = 5
	maxTracked  = 1000
	maxKilledUI = 20
	// maxSeenPerMinute: 수집량 중복 제거(11/10)가 한 분에 기억하는 키 수 상한. 키 하나는 문자열 머리 4개 + 포트 +
	// 맵 칸으로 약 150~250B(문자열 본문은 이벤트와 공유)라 꽉 차도 10MB 안팎이다. make dev 실측은 1,000건에
	// 81개(분당 수백 개)라 정상 운영에서는 닿지 않고, 파일을 훑는 프로세스 같은 폭주 때만 넘는다.
	// 넘으면 그 분의 새 키는 기억하지 않고 매번 센다(덜 줄어들 뿐 빠뜨리지 않음), 이미 기억한 키는 계속 1건.
	maxSeenPerMinute = 50_000
)

// seenKey: 수집량에서 「같은 이벤트」의 기준(11/10) — 컨테이너 · 종류 · 프로세스(comm) · 대상.
// 대상 = open 은 path, exec 는 실행 파일(인자 첫 토큰, 없으면 comm), connect 는 도메인(없으면 IP) + 포트,
// dns 는 질의 이름 + qtype(qtype 은 aux 칸).
type seenKey struct {
	container string
	kind      model.Kind
	comm      string
	target    string
	aux       string
	port      uint16
}

func keyOf(ev *model.Event) seenKey {
	k := seenKey{container: ev.ContainerID, kind: ev.Kind, comm: ev.Comm}
	if k.container == "" {
		k.container = ev.ContainerName
	}
	switch ev.Kind {
	case model.KindOpen:
		k.target = ev.Path
	case model.KindExec:
		k.target, _, _ = strings.Cut(ev.Args, " ")
		if k.target == "" {
			k.target = ev.Comm
		}
	case model.KindConnect:
		k.target, k.port = ev.DstHost, ev.DstPort
		if k.target == "" {
			k.target = ev.DstIP
		}
	case model.KindDNS:
		k.target, k.aux = ev.DstHost, ev.Qtype
	}
	return k
}

type bucket struct {
	sec        int64
	exec, open int
	connect    int
	dns        int
	violations int
}

type TrendPoint struct {
	T          time.Time `json:"t"`
	Exec       int       `json:"exec"`
	Open       int       `json:"open"`
	Connect    int       `json:"connect"`
	DNS        int       `json:"dns"` // DNS 질의(10/30)
	Violations int       `json:"violations"`
}

type ContainerCount struct {
	Name       string `json:"name"`
	Violations int    `json:"violations"`
}

type Killed struct {
	ID   string    `json:"id"`
	Name string    `json:"name"`
	At   time.Time `json:"at"`
}

type Snapshot struct {
	Timestamp        time.Time        `json:"timestamp"`
	TotalEvents      uint64           `json:"totalEvents"`
	EventsLastMinute int              `json:"eventsLastMinute"`
	EventsPerSec     int              `json:"eventsPerSec"`
	TotalViolations  uint64           `json:"totalViolations"`
	RiskScore        int              `json:"riskScore"`
	Killed           []Killed         `json:"killed"`
	KilledCount      int              `json:"killedCount"`
	TopContainers    []ContainerCount `json:"topContainers"`
	Trend            []TrendPoint     `json:"trend"`
	WSClients        int              `json:"wsClients"`
	Dropped          uint64           `json:"dropped"`
	EnforceKill      bool             `json:"enforceKill"`
	Source           string           `json:"source"`
}

type riskHit struct {
	at     time.Time
	weight int
}

type Aggregator struct {
	mu          sync.Mutex
	now         func() time.Time
	buckets     [window]bucket
	total       uint64
	violations  uint64
	byContainer map[string]int
	minutes     map[int64]*model.MinuteCount // 종합(10/16): 아직 저장하지 않은 1분 단위 수집량
	// 수집량 중복 제거(11/10): 지금 분(seenMin)에 이미 센 키. 분이 바뀌면 통째로 버린다.
	// TakeMinutes(10초마다 저장)와 따로 두어 같은 분 안 중간 저장 뒤에도 다시 세지 않는다.
	seenMin int64
	seen    map[seenKey]struct{}
	killed  []Killed
	risk    []riskHit
}

func New() *Aggregator {
	return &Aggregator{now: time.Now, byContainer: map[string]int{}}
}

func (a *Aggregator) slot(t time.Time) *bucket {
	sec := t.Unix()
	b := &a.buckets[sec%window]
	if b.sec != sec {
		*b = bucket{sec: sec}
	}
	return b
}

// Observe: 모든 판정(정상 포함)을 센다.
func (a *Aggregator) Observe(v model.Verdict) {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := a.now()
	b := a.slot(now)
	// 실시간 수(총계 · 초당 · 5분 추이)는 모든 이벤트를 센다
	switch v.Event.Kind {
	case model.KindExec:
		b.exec++
	case model.KindOpen:
		b.open++
	case model.KindConnect:
		b.connect++
	case model.KindDNS:
		b.dns++
	}
	a.total++
	a.countMinute(now, &v.Event)
	if !v.Matched {
		return
	}
	b.violations++
	a.violations++
	if _, ok := a.byContainer[v.Event.ContainerName]; ok || len(a.byContainer) < maxTracked {
		a.byContainer[v.Event.ContainerName]++
	}
	a.risk = append(a.risk, riskHit{at: now, weight: riskWeight(v)})
}

// countMinute: 1분 단위 수집량(저장 · 종합 화면)에 더한다. 같은 1분 안 같은 키 반복은 1건(11/10).
func (a *Aggregator) countMinute(now time.Time, ev *model.Event) {
	switch ev.Kind {
	case model.KindExec, model.KindOpen, model.KindConnect, model.KindDNS:
	default:
		return
	}
	mk := now.Unix() / 60
	if mk != a.seenMin || a.seen == nil {
		a.seenMin, a.seen = mk, map[seenKey]struct{}{}
	}
	k := keyOf(ev)
	if _, dup := a.seen[k]; dup {
		return
	}
	if len(a.seen) < maxSeenPerMinute {
		a.seen[k] = struct{}{}
	}
	m := a.minutes[mk]
	if m == nil {
		if a.minutes == nil {
			a.minutes = map[int64]*model.MinuteCount{}
		}
		m = &model.MinuteCount{Minute: time.Unix(mk*60, 0).UTC()}
		a.minutes[mk] = m
	}
	switch ev.Kind {
	case model.KindExec:
		m.Exec++
	case model.KindOpen:
		m.Open++
	case model.KindConnect:
		m.Connect++
	case model.KindDNS:
		m.DNS++
	}
}

// riskWeight: 최근 5분 위반 가중합이 위험 점수(0–100)가 된다.
// 실제 격리 20 · 격리 대상(dry-run/실패) 12 · 경고 5
func riskWeight(v model.Verdict) int {
	switch {
	case v.Action == model.ActionKill && v.Enforced:
		return 20
	case v.Action == model.ActionKill:
		return 12
	default:
		return 5
	}
}

// TakeMinutes: 쌓인 1분 단위 수집량을 시간순으로 넘기고 비운다 — 저장소에 「더해」 쓴다(재시작해도 종합이 남게)
func (a *Aggregator) TakeMinutes() []model.MinuteCount {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make([]model.MinuteCount, 0, len(a.minutes))
	for _, m := range a.minutes {
		out = append(out, *m)
	}
	a.minutes = nil
	sort.Slice(out, func(i, j int) bool { return out[i].Minute.Before(out[j].Minute) })
	return out
}

// Killed: 격리 성공한 컨테이너 기록
func (a *Aggregator) Killed(id, name string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.killed = append(a.killed, Killed{ID: id, Name: name, At: a.now()})
	if len(a.killed) > maxTracked {
		a.killed = a.killed[len(a.killed)-maxTracked:]
	}
}

func (a *Aggregator) Snapshot() Snapshot {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := a.now()
	nowSec := now.Unix()

	s := Snapshot{Timestamp: now, TotalEvents: a.total, TotalViolations: a.violations, KilledCount: len(a.killed)}

	// 5초 단위 추이 (오래된 것 → 최신)
	start := nowSec - window + 1
	start -= start % trendStep
	for t := start; t <= nowSec; t += trendStep {
		p := TrendPoint{T: time.Unix(t, 0).UTC()}
		for sec := t; sec < t+trendStep && sec <= nowSec; sec++ {
			b := a.buckets[((sec%window)+window)%window]
			if b.sec != sec {
				continue
			}
			p.Exec += b.exec
			p.Open += b.open
			p.Connect += b.connect
			p.DNS += b.dns
			p.Violations += b.violations
			if sec > nowSec-60 {
				s.EventsLastMinute += b.exec + b.open + b.connect + b.dns
			}
			if sec == nowSec-1 {
				s.EventsPerSec = b.exec + b.open + b.connect + b.dns
			}
		}
		s.Trend = append(s.Trend, p)
	}

	cut := now.Add(-riskWindow)
	i := sort.Search(len(a.risk), func(i int) bool { return a.risk[i].at.After(cut) })
	a.risk = a.risk[i:]
	for _, h := range a.risk {
		s.RiskScore += h.weight
	}
	s.RiskScore = min(s.RiskScore, 100)

	for name, n := range a.byContainer {
		s.TopContainers = append(s.TopContainers, ContainerCount{Name: name, Violations: n})
	}
	sort.Slice(s.TopContainers, func(i, j int) bool {
		if s.TopContainers[i].Violations != s.TopContainers[j].Violations {
			return s.TopContainers[i].Violations > s.TopContainers[j].Violations
		}
		return s.TopContainers[i].Name < s.TopContainers[j].Name
	})
	if len(s.TopContainers) > topN {
		s.TopContainers = s.TopContainers[:topN]
	}

	s.Killed = []Killed{}
	for j := len(a.killed) - 1; j >= 0 && len(s.Killed) < maxKilledUI; j-- {
		s.Killed = append(s.Killed, a.killed[j])
	}
	if s.TopContainers == nil {
		s.TopContainers = []ContainerCount{}
	}
	return s
}
