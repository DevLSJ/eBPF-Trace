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
}

type AuditStore interface {
	SaveAudit(ctx context.Context, v model.Verdict) error
	QueryAudit(ctx context.Context, q AuditQuery) ([]model.AuditEntry, error)
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
}
