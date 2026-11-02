package store

import (
	"context"
	"slices"
	"strings"
	"sync"

	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/model"
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/rules"
)

// Memory: DATABASE_URL·REDIS_URL 없이 로컬 개발할 때 쓰는 휘발성 저장소
type Memory struct {
	mu       sync.RWMutex
	policies []rules.Rule
	audit    []model.AuditEntry
	nextID   int64
	recent   []model.Verdict
	review   memReview
	// collected: 1분 단위 수집량 (Unix 분 → 합)
	collected map[int64]model.MinuteCount
	scans     map[string]model.Scan
	// evidence: kill 전 증거(10/20) — 컨테이너당 최근 EvidenceKeep 개. 메서드는 evidence.go
	evidence []model.Evidence
}

const memoryAuditCap = 5000

func NewMemory() *Memory { return &Memory{nextID: 1} }

func (m *Memory) ListPolicies(context.Context) ([]rules.Rule, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return slices.Clone(m.policies), nil
}

func (m *Memory) UpsertPolicy(_ context.Context, r rules.Rule) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.upsertPolicyLocked(r)
	return nil
}

func (m *Memory) upsertPolicyLocked(r rules.Rule) {
	for i := range m.policies {
		if m.policies[i].ID == r.ID {
			m.policies[i] = r
			return
		}
	}
	m.policies = append(m.policies, r)
}

func (m *Memory) DeletePolicy(_ context.Context, id string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := len(m.policies)
	m.policies = slices.DeleteFunc(m.policies, func(r rules.Rule) bool { return r.ID == id })
	return len(m.policies) != n, nil
}

func (m *Memory) ReplacePolicies(_ context.Context, rs []rules.Rule) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.policies = slices.Clone(rs)
	return nil
}

func (m *Memory) SaveAudit(_ context.Context, v model.Verdict) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	v.Timeline = v.Timeline.Clone() // 저장 뒤 호출자가 타임라인을 더 채워도 기록은 그대로
	id := m.nextID
	m.audit = append(m.audit, model.AuditEntry{ID: id, Verdict: v})
	m.nextID++
	if len(m.audit) > memoryAuditCap {
		m.audit = m.audit[len(m.audit)-memoryAuditCap:]
	}
	return id, nil
}

func (m *Memory) QueryAudit(_ context.Context, q AuditQuery) ([]model.AuditEntry, error) {
	q.normalize()
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := []model.AuditEntry{}
	for i := len(m.audit) - 1; i >= 0 && len(out) < q.Limit; i-- {
		a := m.audit[i]
		if q.BeforeID > 0 && a.ID >= q.BeforeID {
			continue
		}
		if q.Kind != "" && a.Event.Kind != q.Kind {
			continue
		}
		if q.Action != "" && a.Action != q.Action {
			continue
		}
		if q.RuleID != "" && a.RuleID != q.RuleID {
			continue
		}
		if q.Container != "" && !strings.Contains(a.Event.ContainerName, q.Container) {
			continue
		}
		if !q.Since.IsZero() && a.Event.Timestamp.Before(q.Since) {
			continue
		}
		if !q.Until.IsZero() && a.Event.Timestamp.After(q.Until) {
			continue
		}
		out = append(out, a)
	}
	return out, nil
}

func (m *Memory) Push(_ context.Context, v model.Verdict) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.recent = append(m.recent, v)
	if len(m.recent) > RecentSize {
		m.recent = m.recent[len(m.recent)-RecentSize:]
	}
	return nil
}

// Recent: 최신순
func (m *Memory) Recent(_ context.Context, n int) ([]model.Verdict, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if n <= 0 || n > len(m.recent) {
		n = len(m.recent)
	}
	out := make([]model.Verdict, 0, n)
	for i := len(m.recent) - 1; i >= 0 && len(out) < n; i-- {
		out = append(out, m.recent[i])
	}
	return out, nil
}
