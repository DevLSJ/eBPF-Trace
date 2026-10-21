package store

import (
	"testing"
	"time"

	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/model"
)

// W15: 변경 이력의 사유(reason)는 changes.doc(jsonb)에 함께 저장된다 — 스키마 변경 없음.
// 사유 필드가 없던 옛 행은 reason "" 로 읽힌다.
func TestPostgresChangeReason(t *testing.T) {
	p := testPG(t)
	ctx := t.Context()
	at := time.Date(2026, 10, 20, 9, 0, 0, 0, time.UTC)
	cid, pid := "case-0001", "prop-0001"
	if err := p.CommitReview(ctx, ReviewCommit{Changes: []model.Change{
		{ID: "chg-0001", At: at, By: "보안 담당자", Kind: model.ChangeProposalDiscarded, CaseID: &cid, ProposalID: &pid, Summary: "제안 버림", Reason: "사내 미러 패키지"},
	}}); err != nil {
		t.Fatal(err)
	}
	if _, err := p.pool.Exec(ctx, `INSERT INTO changes (id, at, doc) VALUES ('chg-0002', $1, '{"id":"chg-0002","kind":"policy_edit","summary":"옛 행"}')`, at.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	s, err := p.LoadReview(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Changes) != 2 || s.Changes[0].Reason != "사내 미러 패키지" || s.Changes[0].Kind != model.ChangeProposalDiscarded || s.Changes[1].Reason != "" {
		t.Fatalf("changes: %+v", s.Changes)
	}
}

func TestMemoryChangeReason(t *testing.T) {
	m := NewMemory()
	ctx := t.Context()
	if err := m.CommitReview(ctx, ReviewCommit{Changes: []model.Change{{ID: "chg-0001", At: time.Now().UTC(), Kind: model.ChangeBlocklistRemove, Reason: "오탐 재확인"}}}); err != nil {
		t.Fatal(err)
	}
	s, err := m.LoadReview(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Changes) != 1 || s.Changes[0].Reason != "오탐 재확인" {
		t.Fatalf("changes: %+v", s.Changes)
	}
}
