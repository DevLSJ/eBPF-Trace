// Package stats aggregates KPIs, the syscall trend and the risk score shown on
// the dashboard. Every event is counted here, before WebSocket sampling.
package stats

import (
	"sort"
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
)

type bucket struct {
	sec        int64
	exec, open int
	connect    int
	violations int
}

type TrendPoint struct {
	T          time.Time `json:"t"`
	Exec       int       `json:"exec"`
	Open       int       `json:"open"`
	Connect    int       `json:"connect"`
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
	killed      []Killed
	risk        []riskHit
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
	switch v.Event.Kind {
	case model.KindExec:
		b.exec++
	case model.KindOpen:
		b.open++
	case model.KindConnect:
		b.connect++
	}
	a.total++
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
			p.Violations += b.violations
			if sec > nowSec-60 {
				s.EventsLastMinute += b.exec + b.open + b.connect
			}
			if sec == nowSec-1 {
				s.EventsPerSec = b.exec + b.open + b.connect
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
