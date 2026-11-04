// Package summary: 대시보드 「eBPF 수집 종합」(10/16) — 저장된 기록(1분 단위 수집량 · 감사 로그 · 세션 · 건 · 차단 목록)을 기간별로 모은다.
// 재시작해도 남는 값만 쓴다(메모리 통계는 쓰지 않는다).
package summary

import (
	"cmp"
	"context"
	"fmt"
	"log/slog"
	"math"
	"slices"
	"time"

	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/model"
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/store"
)

// Review: 설치 세션 · 건 · 차단 목록 읽기(review.Service 를 감싼 것)
type Review interface {
	Installs() []model.InstallSession
	Cases() []model.Case
	Blocklist() model.Blocklist
}

type Service struct {
	audit     store.AuditStore
	collected store.CollectedStore
	review    Review
	now       func() time.Time
}

func New(audit store.AuditStore, collected store.CollectedStore, review Review) *Service {
	return &Service{audit: audit, collected: collected, review: review, now: time.Now}
}

// 기간 → 칸 수 · 칸 길이: 1시간 = 1분 × 60, 24시간 = 1시간 × 24, 7일 = 6시간 × 28
var ranges = map[string]struct {
	n    int
	step time.Duration
}{
	"1h":  {60, time.Minute},
	"24h": {24, time.Hour},
	"7d":  {28, 6 * time.Hour},
}

// auditScan: 위반 집계에 읽는 감사 로그 행 상한(오래된 쪽부터 잘린다)
const auditScan = 50000

type Kinds struct {
	Exec    int64 `json:"exec"`
	Open    int64 `json:"open"`
	Connect int64 `json:"connect"`
	DNS     int64 `json:"dns"` // DNS 질의(10/30) — 화면은 옛 백엔드 호환으로 선택 값으로 읽는다
}

type Point struct {
	T       time.Time `json:"t"`
	Exec    int64     `json:"exec"`
	Open    int64     `json:"open"`
	Connect int64     `json:"connect"`
	DNS     int64     `json:"dns"`
	Killed  int64     `json:"killed"` // 격리됨 · 격리 대상
	Alert   int64     `json:"alert"`
}

type Top struct {
	RuleID    string      `json:"ruleId,omitempty"`
	Container string      `json:"container,omitempty"`
	Count     int64       `json:"count"`
	Level     model.Level `json:"level"`
}

// Isolation: 격리 지연(10/30) — 범위 안에서 killedAt 이 있는 감사 로그 행의 killedAt − detectedAt(ms). 없으면 count 0 · 나머지 null
type Isolation struct {
	Count    int    `json:"count"`
	MedianMs *int64 `json:"medianMs"`
	P95Ms    *int64 `json:"p95Ms"`
	MaxMs    *int64 `json:"maxMs"`
}

type Summary struct {
	Range     string    `json:"range"`
	From      time.Time `json:"from"`
	To        time.Time `json:"to"`
	BucketSec int       `json:"bucketSec"`
	Collected struct {
		Total  int64 `json:"total"`
		ByKind Kinds `json:"byKind"`
	} `json:"collected"`
	Violations struct {
		Total  int64 `json:"total"`
		Killed int64 `json:"killed"`
		Alert  int64 `json:"alert"`
		Held   int64 `json:"held"`
	} `json:"violations"`
	IsolatedContainers int       `json:"isolatedContainers"`
	Isolation          Isolation `json:"isolation"`
	Series             []Point   `json:"series"`
	TopRules           []Top     `json:"topRules"`
	TopContainers      []Top     `json:"topContainers"`
	Installs           struct {
		Total    int `json:"total"`
		Passed   int `json:"passed"`
		Isolated int `json:"isolated"`
		Warned   int `json:"warned"`
		Refused  int `json:"refused"`
		Failed   int `json:"failed"` // 설치 실패 + 결과 미확인
		Running  int `json:"running"`
	} `json:"installs"`
	Decisions struct {
		Malicious     int `json:"malicious"`
		FalsePositive int `json:"falsePositive"`
		Pending       int `json:"pending"`
	} `json:"decisions"`
	Blocklist struct {
		Packages int `json:"packages"`
		Images   int `json:"images"`
		Hosts    int `json:"hosts"`
	} `json:"blocklist"`
	// Previous(R2 11/04): 바로 앞 같은 길이 기간 [from − 길이, from) 의 같은 숫자(KPI 증감 줄). 계산은 지금 기간과 같다.
	// 그 기간에 저장된 기록(수집량 · 감사 로그 · 설치 세션 · 판정)이 하나도 없으면 null(서버가 꺼져 있었거나 보관 밖 — 0 과 구별)
	Previous *Previous `json:"previous"`
}

// Previous: 직전 기간 숫자 — 이름은 Summary 필드와 같다(collected = collected.total, violations = violations.total,
// installs = installs.total, decided = decisions.malicious + falsePositive, isolationMedianMs = isolation.medianMs — 격리가 없으면 null)
type Previous struct {
	Collected          int64  `json:"collected"`
	Violations         int64  `json:"violations"`
	IsolatedContainers int    `json:"isolatedContainers"`
	Installs           int    `json:"installs"`
	Decided            int    `json:"decided"`
	IsolationMedianMs  *int64 `json:"isolationMedianMs"`
}

// ErrRange: 모르는 기간
type ErrRange struct{ Range string }

func (e ErrRange) Error() string {
	return fmt.Sprintf("range 는 1h | 24h | 7d (받은 값 %q)", e.Range)
}

func (s *Service) Build(ctx context.Context, rng string) (Summary, error) {
	if rng == "" {
		rng = "24h"
	}
	r, ok := ranges[rng]
	if !ok {
		return Summary{}, ErrRange{rng}
	}
	end := s.now().UTC().Truncate(r.step).Add(r.step) // 지금이 든 칸까지
	out, _, err := s.window(ctx, rng, r.n, r.step, end)
	if err != nil {
		return Summary{}, err
	}
	// 직전 기간 — 실패해도 지금 기간은 그대로 보낸다(증감 줄만 「이전 기간 정보 없음」)
	prev, has, err := s.window(ctx, rng, r.n, r.step, out.From)
	switch {
	case err != nil:
		slog.Warn("summary: previous window", "range", rng, "err", err)
	case has:
		out.Previous = &Previous{
			Collected:          prev.Collected.Total,
			Violations:         prev.Violations.Total,
			IsolatedContainers: prev.IsolatedContainers,
			Installs:           prev.Installs.Total,
			Decided:            prev.Decisions.Malicious + prev.Decisions.FalsePositive,
			IsolationMedianMs:  prev.Isolation.MedianMs,
		}
	}
	return out, nil
}

// window: [end − n×step, end) 한 기간의 종합. has = 그 기간에 저장된 기록이 하나라도 있는가(수집량 행 · 감사 로그 · 설치 세션 · 판정)
func (s *Service) window(ctx context.Context, rng string, n int, step time.Duration, end time.Time) (Summary, bool, error) {
	from := end.Add(-time.Duration(n) * step)
	out := Summary{Range: rng, From: from, To: end, BucketSec: int(step / time.Second), Series: make([]Point, n)}
	for i := range out.Series {
		out.Series[i].T = from.Add(time.Duration(i) * step)
	}
	slot := func(t time.Time) *Point {
		if t.Before(from) || !t.Before(end) {
			return nil
		}
		return &out.Series[int(t.Sub(from)/step)]
	}

	ms, err := s.collected.CollectedRange(ctx, from, end)
	if err != nil {
		return Summary{}, false, fmt.Errorf("collected: %w", err)
	}
	for _, m := range ms {
		if p := slot(m.Minute); p != nil {
			p.Exec += m.Exec
			p.Open += m.Open
			p.Connect += m.Connect
			p.DNS += m.DNS
		}
		out.Collected.ByKind.Exec += m.Exec
		out.Collected.ByKind.Open += m.Open
		out.Collected.ByKind.Connect += m.Connect
		out.Collected.ByKind.DNS += m.DNS
	}
	out.Collected.Total = out.Collected.ByKind.Exec + out.Collected.ByKind.Open + out.Collected.ByKind.Connect + out.Collected.ByKind.DNS

	if err := s.violations(ctx, &out, from, end, slot); err != nil {
		return Summary{}, false, err
	}
	reviewed := s.reviewParts(&out, from, end)
	return out, len(ms) > 0 || out.Violations.Total > 0 || reviewed, nil
}

func (s *Service) violations(ctx context.Context, out *Summary, from, end time.Time, slot func(time.Time) *Point) error {
	type acc struct {
		n     int64
		level model.Level
	}
	byRule, byCtr := map[string]*acc{}, map[string]*acc{}
	isolated := map[string]bool{}
	bump := func(m map[string]*acc, k string, l model.Level) {
		a := m[k]
		if a == nil {
			a = &acc{level: l}
			m[k] = a
		}
		a.n++
		if l.Rank() > a.level.Rank() {
			a.level = l
		}
	}
	q := store.AuditQuery{Since: from, Until: end, Limit: store.MaxAuditLimit}
	scanned := 0
	var isolationMs []int64
	for scanned < auditScan {
		rows, err := s.audit.QueryAudit(ctx, q)
		if err != nil {
			return fmt.Errorf("audit: %w", err)
		}
		for _, a := range rows {
			scanned++
			if !a.Event.Timestamp.Before(end) { // 끝 시각은 다음 기간(직전 기간의 끝 = 지금 기간의 시작)
				continue
			}
			l := model.LevelOf(a.Verdict)
			out.Violations.Total++
			switch l {
			case model.LevelKilled:
				out.Violations.Killed++
				isolated[a.Event.ContainerName] = true
			case model.LevelHeld:
				out.Violations.Held++
			default:
				out.Violations.Alert++
			}
			if p := slot(a.Event.Timestamp); p != nil {
				if l == model.LevelKilled || l == model.LevelHeld {
					p.Killed++
				} else {
					p.Alert++
				}
			}
			if a.Timeline != nil {
				if ms, ok := a.Timeline.IsolationMs(); ok {
					isolationMs = append(isolationMs, ms)
				}
			}
			if a.RuleID != "" {
				bump(byRule, a.RuleID, l)
			}
			name := a.Event.ContainerName
			if a.Install != nil && a.Install.Label != "" {
				name = a.Install.Label // 설치 검사는 패키지 이름으로
			}
			bump(byCtr, name, l)
		}
		if len(rows) < q.Limit {
			break
		}
		q.BeforeID = rows[len(rows)-1].ID
	}
	if scanned >= auditScan {
		slog.Warn("summary: audit scan capped", "rows", scanned)
	}
	out.IsolatedContainers = len(isolated)
	out.Isolation = isolationStats(isolationMs)
	top := func(m map[string]*acc, rule bool) []Top {
		xs := make([]Top, 0, len(m))
		for k, a := range m {
			t := Top{Count: a.n, Level: a.level}
			if rule {
				t.RuleID = k
			} else {
				t.Container = k
			}
			xs = append(xs, t)
		}
		slices.SortFunc(xs, func(x, y Top) int {
			return cmp.Or(cmp.Compare(y.Count, x.Count), cmp.Compare(x.RuleID+x.Container, y.RuleID+y.Container))
		})
		return xs[:min(len(xs), 10)]
	}
	out.TopRules, out.TopContainers = top(byRule, true), top(byCtr, false)
	return nil
}

// isolationStats: 중앙값(짝수면 가운데 둘의 평균) · p95(nearest-rank) · 최대
func isolationStats(ms []int64) Isolation {
	n := len(ms)
	if n == 0 {
		return Isolation{}
	}
	slices.Sort(ms)
	median := ms[n/2]
	if n%2 == 0 {
		median = (ms[n/2-1] + ms[n/2]) / 2
	}
	p95 := ms[min(n-1, max(0, int(math.Ceil(0.95*float64(n)))-1))]
	mx := ms[n-1]
	return Isolation{Count: n, MedianMs: &median, P95Ms: &p95, MaxMs: &mx}
}

// reviewParts: [from, end) 에 시작한 설치 세션 · 판정한 건(대기 · 차단 목록은 지금 값). 반환 = 그 기간에 세션 · 판정이 있었나
func (s *Service) reviewParts(out *Summary, from, end time.Time) bool {
	if s.review == nil {
		return false
	}
	decided := 0
	for _, x := range s.review.Installs() {
		if x.StartedAt.Before(from) || !x.StartedAt.Before(end) {
			continue
		}
		out.Installs.Total++
		switch x.Status {
		case model.InstallPassed:
			out.Installs.Passed++
		case model.InstallIsolated:
			out.Installs.Isolated++
		case model.InstallWarned:
			out.Installs.Warned++
		case model.InstallRefused:
			out.Installs.Refused++
		case model.InstallFailed, model.InstallUnknown:
			out.Installs.Failed++
		case model.InstallRunning:
			out.Installs.Running++
		}
	}
	for _, c := range s.review.Cases() {
		if c.State == model.CaseOpen {
			out.Decisions.Pending++
		}
		if c.DecidedAt == nil || c.DecidedAt.Before(from) || !c.DecidedAt.Before(end) {
			continue
		}
		decided++
		switch c.Decision {
		case model.DecisionMalicious:
			out.Decisions.Malicious++
		case model.DecisionFalsePositive:
			out.Decisions.FalsePositive++
		}
	}
	b := s.review.Blocklist()
	out.Blocklist.Packages, out.Blocklist.Images, out.Blocklist.Hosts = len(b.Packages), len(b.Images), len(b.Hosts)
	return out.Installs.Total > 0 || decided > 0
}
