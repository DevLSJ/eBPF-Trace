// Package store persists policies and audit entries (PostgreSQL) and buffers
// recent verdicts (Redis). Memory implementations back local development.
package store

import (
	"context"
	"time"

	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/model"
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/rules"
)

type PolicyStore interface {
	ListPolicies(ctx context.Context) ([]rules.Rule, error)
	UpsertPolicy(ctx context.Context, r rules.Rule) error
	DeletePolicy(ctx context.Context, id string) (bool, error)
	// ReplacePolicies: YAML 일괄 적용. 기존 정책을 모두 교체한다.
	ReplacePolicies(ctx context.Context, rs []rules.Rule) error
}

type AuditQuery struct {
	Kind      model.Kind
	Action    model.Action
	RuleID    string
	Container string // 이름 부분 일치
	Since     time.Time
	Until     time.Time
	BeforeID  int64 // 페이지네이션: 이 id보다 작은 것
	Limit     int
	// Offset: 쪽 번호(11/04) — 최신순에서 이만큼 건너뛴다(0 = 첫 쪽). 커서(BeforeID)와 함께 쓰지 않는다(API 가 막는다)
	Offset int
	// ByCase · CaseIDs: 판정 필터(11/10) — ByCase 면 caseId 가 CaseIDs 안에 있는 행만(비어 있으면 0건). 건 id 는 API 가 review 에서 고른다
	ByCase  bool
	CaseIDs []string
}

type AuditStore interface {
	// SaveAudit: 위반 판정 한 건을 남기고 그 행 id 를 돌려준다 (설치 세션 · 건의 격리 타임라인이 auditId 로 가리킨다, 10/30)
	SaveAudit(ctx context.Context, v model.Verdict) (int64, error)
	QueryAudit(ctx context.Context, q AuditQuery) ([]model.AuditEntry, error)
	// CountAudit: 필터(kind · action · rule · container · since · until) 뒤 전체 건수(11/04 쪽 번호). BeforeID · Limit · Offset 은 보지 않는다
	CountAudit(ctx context.Context, q AuditQuery) (int, error)
}

// CollectedStore: 1분 단위 수집량(종합 대시보드, 10/16). Add 는 같은 분에 더한다. Range 는 [from, to) 시간순
type CollectedStore interface {
	AddCollected(ctx context.Context, ms []model.MinuteCount) error
	CollectedRange(ctx context.Context, from, to time.Time) ([]model.MinuteCount, error)
}

// Buffer: 새로 접속한 대시보드가 받을 최근 판정 (정상 포함)
type Buffer interface {
	Push(ctx context.Context, v model.Verdict) error
	Recent(ctx context.Context, n int) ([]model.Verdict, error)
}

const (
	DefaultAuditLimit = 100
	MaxAuditLimit     = 500
	RecentSize        = 1000
)

func (q *AuditQuery) normalize() {
	if q.Limit <= 0 {
		q.Limit = DefaultAuditLimit
	}
	if q.Limit > MaxAuditLimit {
		q.Limit = MaxAuditLimit
	}
	q.Offset = max(q.Offset, 0)
}

// NormalizeLimit: 저장소가 실제로 쓰는 쪽 크기(기본 100 · 상한 500) — 응답의 limit
func NormalizeLimit(n int) int {
	q := AuditQuery{Limit: n}
	q.normalize()
	return q.Limit
}
