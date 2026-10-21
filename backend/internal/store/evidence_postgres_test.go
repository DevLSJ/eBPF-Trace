package store

import (
	"fmt"
	"os"
	"testing"
	"time"
)

// SUPPLYGUARD_TEST_DATABASE_URL 이 있을 때만 돈다 (빈 테스트용 DB — evidence 테이블을 비운다).
func testPGEvidence(t *testing.T) *Postgres {
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
	// 멱등 — 두 번 불러도 된다
	for i := 0; i < 2; i++ {
		if err := p.EnsureEvidenceSchema(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := p.pool.Exec(t.Context(), `TRUNCATE evidence`); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestPostgresEvidence(t *testing.T) {
	p := testPGEvidence(t)
	ctx := t.Context()
	base := time.Now().UTC().Truncate(time.Second).Add(-time.Hour) // 7일 정리 단계에서 지워지지 않게 최근 시각
	for i := 0; i < 5; i++ {
		if err := p.SaveEvidence(ctx, ev(fmt.Sprintf("e%d", i), evCID, base.Add(time.Duration(i)*time.Minute))); err != nil {
			t.Fatal(err)
		}
	}
	other := "ffffffffffff0000000000000000000000000000000000000000000000000000"
	if err := p.SaveEvidence(ctx, ev("o1", other, base)); err != nil {
		t.Fatal(err)
	}
	got, err := p.EvidenceByContainer(ctx, evCID)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 || got[0].ID != "e4" || got[2].ID != "e2" {
		t.Fatalf("keep 3 newest first: %+v", got)
	}
	if got[0].Changes[0].Path != "/tmp/a" || got[0].Processes[0].Cmd != "pip" || got[0].Image != "python:3.12-slim" {
		t.Fatalf("doc round trip: %+v", got[0])
	}
	if byName, _ := p.EvidenceByContainer(ctx, "sg-install-pip-1"); len(byName) != 4 {
		t.Fatalf("by name: %d", len(byName))
	}
	if short, _ := p.EvidenceByContainer(ctx, evCID[:12]); len(short) != 3 {
		t.Fatalf("by short id: %d", len(short))
	}
	if none, _ := p.EvidenceByContainer(ctx, "%"); len(none) != 0 {
		t.Fatalf("LIKE wildcard must be escaped: %d", len(none))
	}
	// 7일 정리
	_ = p.SaveEvidence(ctx, ev("old", other, time.Now().Add(-8*24*time.Hour)))
	n, err := p.PruneEvidence(ctx, time.Now().Add(-7*24*time.Hour))
	if err != nil || n != 1 {
		t.Fatalf("pruned=%d err=%v", n, err)
	}
}
