package store

import (
	"testing"

	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/model"
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/rules"
)

func TestMemoryReviewCommit(t *testing.T) {
	m := NewMemory()
	ctx := t.Context()
	in := model.InstallSession{ID: "ins-0001", Packages: []string{"a"}}
	if err := m.CommitReview(ctx, ReviewCommit{
		Installs: []model.InstallSession{in},
		BlockAdd: []model.BlockEntry{{List: model.ListHosts, Value: "x.test"}},
		Policies: []rules.Rule{{ID: "r1", Kind: model.KindExec, Action: model.ActionAlert, DenyComms: []string{"nc"}}},
	}); err != nil {
		t.Fatal(err)
	}
	in.Packages[0] = "mutated" // 저장소는 사본을 가진다
	s, _ := m.LoadReview(ctx)
	if len(s.Installs) != 1 || s.Installs[0].Packages[0] != "a" || len(s.Blocklist) != 1 {
		t.Fatalf("snapshot: %+v", s)
	}
	if ps, _ := m.ListPolicies(ctx); len(ps) != 1 {
		t.Fatal("policy upsert in the same commit")
	}
	_ = m.CommitReview(ctx, ReviewCommit{BlockRemove: []model.BlockRef{{List: model.ListHosts, Value: "x.test"}}})
	if s, _ := m.LoadReview(ctx); len(s.Blocklist) != 0 {
		t.Fatal("remove")
	}
	if !(ReviewCommit{}).Empty() {
		t.Fatal("empty commit")
	}
}
