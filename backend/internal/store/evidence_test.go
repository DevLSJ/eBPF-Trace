package store

import (
	"fmt"
	"testing"
	"time"

	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/model"
)

const evCID = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func ev(id string, cid string, at time.Time) model.Evidence {
	return model.Evidence{ID: id, ContainerID: cid, ContainerName: "sg-install-pip-1", Image: "python:3.12-slim", CollectedAt: at,
		Logs: "x", Changes: []model.FileChange{{Kind: "A", Path: "/tmp/a"}}, Processes: []model.Proc{{PID: 1, User: "root", Cmd: "pip"}}}
}

func TestMemoryEvidenceKeepsThreePerContainer(t *testing.T) {
	m := NewMemory()
	ctx := t.Context()
	base := time.Date(2026, 10, 20, 9, 0, 0, 0, time.UTC)
	for i := 0; i < 5; i++ {
		if err := m.SaveEvidence(ctx, ev(fmt.Sprintf("e%d", i), evCID, base.Add(time.Duration(i)*time.Minute))); err != nil {
			t.Fatal(err)
		}
	}
	other := "ffffffffffff0000000000000000000000000000000000000000000000000000"
	if err := m.SaveEvidence(ctx, ev("o1", other, base)); err != nil {
		t.Fatal(err)
	}

	got, err := m.EvidenceByContainer(ctx, evCID)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("keep 3 per container, got %d", len(got))
	}
	if got[0].ID != "e4" || got[1].ID != "e3" || got[2].ID != "e2" {
		t.Fatalf("newest first: %s %s %s", got[0].ID, got[1].ID, got[2].ID)
	}
	// 다른 컨테이너는 영향 없음
	if o, _ := m.EvidenceByContainer(ctx, other); len(o) != 1 {
		t.Fatalf("other container: %d", len(o))
	}
	// 이름 · 짧은 id(12자) 로도 찾는다
	if byName, _ := m.EvidenceByContainer(ctx, "sg-install-pip-1"); len(byName) != 4 {
		t.Fatalf("by name (both containers share the name): %d", len(byName))
	}
	if short, _ := m.EvidenceByContainer(ctx, evCID[:12]); len(short) != 3 {
		t.Fatalf("by short id: %d", len(short))
	}
	if none, err := m.EvidenceByContainer(ctx, "nope"); err != nil || none == nil || len(none) != 0 {
		t.Fatalf("unknown: %v %v", none, err)
	}
	// 반환값을 고쳐도 저장된 것은 안 바뀐다
	got[0].Changes[0].Path = "/mutated"
	again, _ := m.EvidenceByContainer(ctx, evCID)
	if again[0].Changes[0].Path != "/tmp/a" {
		t.Fatal("returned slices must be copies")
	}
}

func TestMemoryEvidencePrune(t *testing.T) {
	m := NewMemory()
	ctx := t.Context()
	now := time.Now()
	_ = m.SaveEvidence(ctx, ev("old", evCID, now.Add(-8*24*time.Hour)))
	_ = m.SaveEvidence(ctx, ev("edge", evCID, now.Add(-6*24*time.Hour)))
	_ = m.SaveEvidence(ctx, ev("new", evCID, now))
	n, err := m.PruneEvidence(ctx, now.Add(-7*24*time.Hour))
	if err != nil || n != 1 {
		t.Fatalf("pruned=%d err=%v", n, err)
	}
	got, _ := m.EvidenceByContainer(ctx, evCID)
	if len(got) != 2 || got[0].ID != "new" || got[1].ID != "edge" {
		t.Fatalf("%+v", got)
	}
}
