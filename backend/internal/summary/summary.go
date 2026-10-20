// Package summary: 대시보드 「eBPF 수집 종합」(10/16) — 저장된 기록(1분 단위 수집량 · 감사 로그 · 세션 · 건 · 차단 목록)을 기간별로 모은다.
// 재시작해도 남는 값만 쓴다(메모리 통계는 쓰지 않는다).
package summary

import (
	"cmp"
	"context"
	"fmt"
	"log/slog"
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
}

type Point struct {
	T       time.Time `json:"t"`
	Exec    int64     `json:"exec"`
	Open    int64     `json:"open"`
	Connect int64     `json:"connect"`
	Killed  int64     `json:"killed"` // 격리됨 · 격리 대상
	Alert   int64     `json:"alert"`
}

type Top struct {
	RuleID    string      `json:"ruleId,omitempty"`
	Container string      `json:"container,omitempty"`
	Count     int64       `json:"count"`
	Level     model.Level `json:"level"`
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
	IsolatedContainers int     `json:"isolatedContainers"`
	Series             []Point `json:"series"`
	TopRules           []Top   `json:"topRules"`
	TopContainers      []Top   `json:"topContainers"`
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
	from := end.Add(-time.Duration(r.n) * r.step)
	out := Summary{Range: rng, From: from, To: end, BucketSec: int(r.step / time.Second), Series: make([]Point, r.n)}
	for i := range out.Series {
		out.Series[i].T = from.Add(time.Duration(i) * r.step)
	}
	slot := func(t time.Time) *Point {
		if t.Before(from) || !t.Before(end) {
			return nil
		}
		return &out.Series[int(t.Sub(from)/r.step)]
	}

	ms, err := s.collected.CollectedRange(ctx, from, end)
	if err != nil {
		return Summary{}, fmt.Errorf("collected: %w", err)
	}
	for _, m := range ms {
		if p := slot(m.Minute); p != nil {
			p.Exec += m.Exec
			p.Open += m.Open
			p.Connect += m.Connect
		}
		out.Collected.ByKind.Exec += m.Exec
		out.Collected.ByKind.Open += m.Open
		out.Collected.ByKind.Connect += m.Connect
	}
	out.Collected.Total = out.Collected.ByKind.Exec + out.Collected.ByKind.Open + out.Collected.ByKind.Connect

	if err := s.violations(ctx, &out, from, end, slot); err != nil {
		return Summary{}, err
	}
	s.reviewParts(&out, from)
	return out, nil
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
	for scanned < auditScan {
		rows, err := s.audit.QueryAudit(ctx, q)
		if err != nil {
			return fmt.Errorf("audit: %w", err)
		}
		for _, a := range rows {
			scanned++
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

func (s *Service) reviewParts(out *Summary, from time.Time) {
	if s.review == nil {
		return
	}
	for _, x := range s.review.Installs() {
		if x.StartedAt.Before(from) {
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
		if c.DecidedAt == nil || c.DecidedAt.Before(from) {
			continue
		}
		switch c.Decision {
		case model.DecisionMalicious:
			out.Decisions.Malicious++
		case model.DecisionFalsePositive:
			out.Decisions.FalsePositive++
		}
	}
	b := s.review.Blocklist()
	out.Blocklist.Packages, out.Blocklist.Images, out.Blocklist.Hosts = len(b.Packages), len(b.Images), len(b.Hosts)
}
