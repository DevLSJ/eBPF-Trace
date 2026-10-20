package store

import (
	"os"
	"testing"
	"time"

	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/model"
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/rules"
)

// SUPPLYGUARD_TEST_DATABASE_URL 이 있을 때만 돈다 (빈 테스트용 DB — 테이블을 지운다).
func testPG(t *testing.T) *Postgres {
	t.Helper()
	url := os.Getenv("SUPPLYGUARD_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("SUPPLYGUARD_TEST_DATABASE_URL not set")
	}
	p, err := NewPostgres(t.Context(), url)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)
	if _, err := p.pool.Exec(t.Context(), `TRUNCATE install_sessions, review_cases, proposals, blocklist, changes, policies`); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestPostgresReviewRoundTrip(t *testing.T) {
	p := testPG(t)
	ctx := t.Context()
	// 스키마는 멱등 — 두 번 열어도 된다
	p2, err := NewPostgres(ctx, os.Getenv("SUPPLYGUARD_TEST_DATABASE_URL"))
	if err != nil {
		t.Fatal(err)
	}
	p2.Close()

	at := time.Date(2026, 10, 15, 9, 0, 0, 0, time.UTC)
	cid := "case-0001"
	c := ReviewCommit{
		Installs:  []model.InstallSession{{ID: "ins-0001", Manager: "pip", Packages: []string{"./reqeusts"}, Container: "sg-install-pip-1", StartedAt: at, Status: model.InstallIsolated, Violations: []model.ViolationCount{}, Activity: model.Activity{Kinds: map[model.Kind]int{"exec": 1}}}},
		Cases:     []model.CaseRecord{{Case: model.Case{ID: cid, Source: model.CaseInstall, OpenedAt: at, State: model.CaseClosed, Decision: model.DecisionMalicious, RuleIDs: []string{"x"}}}},
		Proposals: []model.Proposal{{ID: "prop-0001", CaseID: cid, State: model.ProposalApplied, CreatedAt: at}},
		BlockAdd:  []model.BlockEntry{{List: model.ListPackages, Value: "pip:reqeusts", CaseID: &cid, At: at, By: "보안 담당자"}},
		Policies:  []rules.Rule{{ID: "egress", Kind: model.KindConnect, Action: model.ActionAlert, AllowHosts: []string{"github.com"}}},
		Changes:   []model.Change{{ID: "chg-0001", At: at, By: "보안 담당자", Kind: model.ChangeProposalApplied, CaseID: &cid, Summary: "패키지 pip:reqeusts 차단"}},
	}
	if err := p.CommitReview(ctx, c); err != nil {
		t.Fatal(err)
	}
	// upsert: 같은 id 를 다시 쓰면 바뀐다
	c.Installs[0].Status = model.InstallPassed
	if err := p.CommitReview(ctx, ReviewCommit{Installs: c.Installs}); err != nil {
		t.Fatal(err)
	}
	s, err := p.LoadReview(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Installs) != 1 || s.Installs[0].Status != model.InstallPassed || s.Installs[0].Activity.Kinds["exec"] != 1 {
		t.Fatalf("installs: %+v", s.Installs)
	}
	if len(s.Cases) != 1 || s.Cases[0].Case.Decision != model.DecisionMalicious || len(s.Proposals) != 1 || len(s.Changes) != 1 {
		t.Fatalf("snapshot: %+v", s)
	}
	if len(s.Blocklist) != 1 || s.Blocklist[0].List != model.ListPackages || *s.Blocklist[0].CaseID != cid {
		t.Fatalf("blocklist: %+v", s.Blocklist)
	}
	pols, _ := p.ListPolicies(ctx)
	if len(pols) != 1 || pols[0].AllowHosts[0] != "github.com" {
		t.Fatalf("policies: %+v", pols)
	}
	if err := p.CommitReview(ctx, ReviewCommit{BlockRemove: []model.BlockRef{{List: model.ListPackages, Value: "pip:reqeusts"}}}); err != nil {
		t.Fatal(err)
	}
	if s, _ := p.LoadReview(ctx); len(s.Blocklist) != 0 {
		t.Fatal("block remove")
	}
}

// 커밋 중간에 실패하면 앞서 쓴 행까지 모두 롤백된다.
func TestPostgresCommitRollsBack(t *testing.T) {
	p := testPG(t)
	ctx := t.Context()
	at := time.Now().UTC()
	err := p.CommitReview(ctx, ReviewCommit{
		Installs: []model.InstallSession{{ID: "ins-0001", Manager: "pip", StartedAt: at}},
		BlockAdd: []model.BlockEntry{{List: model.ListHosts, Value: "bad\x00value", At: at}}, // text 에 NUL → 오류
		Changes:  []model.Change{{ID: "chg-0001", At: at}},
	})
	if err == nil {
		t.Fatal("NUL in text must fail")
	}
	s, err := p.LoadReview(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Installs)+len(s.Blocklist)+len(s.Changes) != 0 {
		t.Fatalf("nothing may remain after a failed commit: %+v", s)
	}
}
