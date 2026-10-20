package store

import (
	"context"
	"slices"

	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/model"
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/rules"
)

// ReviewSnapshot: 시작할 때 불러오는 설치 세션 · 건 · 제안 · 차단 목록 · 변경 이력 전체
type ReviewSnapshot struct {
	Installs  []model.InstallSession
	Cases     []model.CaseRecord
	Proposals []model.Proposal
	Blocklist []model.BlockEntry
	Changes   []model.Change
}

// ReviewCommit: 한 번에(모두 되거나 모두 안 됨) 쓰는 변경 묶음. 같은 id 는 덮어쓴다(upsert).
// Policies 는 정책 upsert — 제안 적용이 차단 목록 · 건 · 변경 이력과 같은 트랜잭션에서 규칙을 바꾸도록 여기 둔다.
type ReviewCommit struct {
	Installs    []model.InstallSession
	Cases       []model.CaseRecord
	Proposals   []model.Proposal
	BlockAdd    []model.BlockEntry
	BlockRemove []model.BlockRef
	Policies    []rules.Rule
	Changes     []model.Change
}

func (c ReviewCommit) Empty() bool {
	return len(c.Installs)+len(c.Cases)+len(c.Proposals)+len(c.BlockAdd)+len(c.BlockRemove)+len(c.Policies)+len(c.Changes) == 0
}

type ReviewStore interface {
	LoadReview(ctx context.Context) (ReviewSnapshot, error)
	CommitReview(ctx context.Context, c ReviewCommit) error
}

// ── Memory ─────────────────────────────────────────────

type memReview struct {
	installs  []model.InstallSession
	cases     []model.CaseRecord
	proposals []model.Proposal
	blocklist []model.BlockEntry
	changes   []model.Change
}

func (m *Memory) LoadReview(context.Context) (ReviewSnapshot, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	r := &m.review
	s := ReviewSnapshot{Blocklist: slices.Clone(r.blocklist), Changes: slices.Clone(r.changes)}
	for _, x := range r.installs {
		s.Installs = append(s.Installs, x.Clone())
	}
	for _, x := range r.cases {
		s.Cases = append(s.Cases, x.Clone())
	}
	for _, x := range r.proposals {
		s.Proposals = append(s.Proposals, x.Clone())
	}
	return s, nil
}

func (m *Memory) CommitReview(_ context.Context, c ReviewCommit) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	r := &m.review
	for _, x := range c.Installs {
		r.installs = upsertBy(r.installs, x.Clone(), func(a model.InstallSession) string { return a.ID })
	}
	for _, x := range c.Cases {
		r.cases = upsertBy(r.cases, x.Clone(), func(a model.CaseRecord) string { return a.Case.ID })
	}
	for _, x := range c.Proposals {
		r.proposals = upsertBy(r.proposals, x.Clone(), func(a model.Proposal) string { return a.ID })
	}
	for _, x := range c.BlockAdd {
		r.blocklist = upsertBy(r.blocklist, x, func(a model.BlockEntry) string { return a.List + "\x00" + a.Value })
	}
	for _, k := range c.BlockRemove {
		r.blocklist = slices.DeleteFunc(r.blocklist, func(a model.BlockEntry) bool { return a.List == k.List && a.Value == k.Value })
	}
	for _, p := range c.Policies {
		m.upsertPolicyLocked(p)
	}
	for _, x := range c.Changes {
		r.changes = upsertBy(r.changes, x, func(a model.Change) string { return a.ID })
	}
	return nil
}

func upsertBy[T any](xs []T, x T, key func(T) string) []T {
	k := key(x)
	for i := range xs {
		if key(xs[i]) == k {
			xs[i] = x
			return xs
		}
	}
	return append(xs, x)
}
