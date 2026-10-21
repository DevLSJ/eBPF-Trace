package store

import (
	"context"
	"slices"
	"strings"
	"time"

	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/model"
)

// kill 전 증거(10/20) — 컨테이너(id)당 최근 EvidenceKeep 개, 보존 7일(정리는 evidence.RunPrune 이 PruneEvidence 를 부른다).

const (
	// EvidenceKeep: 같은 컨테이너 id 로 남기는 최근 증거 수
	EvidenceKeep = 3
	// EvidenceQueryLimit: 한 번에 돌려주는 최대 수 (이름은 재사용되므로 여러 컨테이너가 걸릴 수 있다)
	EvidenceQueryLimit = 50
	// memoryEvidenceCap: 메모리 저장소 전체 상한
	memoryEvidenceCap = 300
)

// matchEvidence: 전체 id · 이름 · 짧은 id(12자 이상 접두)
func matchEvidence(e model.Evidence, q string) bool {
	return e.ContainerID == q || e.ContainerName == q || (len(q) >= 12 && strings.HasPrefix(e.ContainerID, q))
}

func (m *Memory) SaveEvidence(_ context.Context, e model.Evidence) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.evidence = append(m.evidence, e.Clone())
	// 같은 컨테이너는 최근 EvidenceKeep 개만
	same := []int{}
	for i, x := range m.evidence {
		if x.ContainerID == e.ContainerID {
			same = append(same, i)
		}
	}
	if len(same) > EvidenceKeep {
		slices.SortFunc(same, func(a, b int) int {
			return m.evidence[b].CollectedAt.Compare(m.evidence[a].CollectedAt) // 최신 먼저
		})
		drop := map[string]bool{}
		for _, i := range same[EvidenceKeep:] {
			drop[m.evidence[i].ID] = true
		}
		m.evidence = slices.DeleteFunc(m.evidence, func(x model.Evidence) bool { return drop[x.ID] })
	}
	if len(m.evidence) > memoryEvidenceCap {
		m.evidence = m.evidence[len(m.evidence)-memoryEvidenceCap:]
	}
	return nil
}

// EvidenceByContainer: 최근 것부터
func (m *Memory) EvidenceByContainer(_ context.Context, q string) ([]model.Evidence, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := []model.Evidence{}
	for _, x := range m.evidence {
		if matchEvidence(x, q) {
			out = append(out, x.Clone())
		}
	}
	slices.SortFunc(out, func(a, b model.Evidence) int {
		if c := b.CollectedAt.Compare(a.CollectedAt); c != 0 {
			return c
		}
		return strings.Compare(b.ID, a.ID)
	})
	if len(out) > EvidenceQueryLimit {
		out = out[:EvidenceQueryLimit]
	}
	return out, nil
}

func (m *Memory) PruneEvidence(_ context.Context, before time.Time) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := len(m.evidence)
	m.evidence = slices.DeleteFunc(m.evidence, func(x model.Evidence) bool { return x.CollectedAt.Before(before) })
	return n - len(m.evidence), nil
}
