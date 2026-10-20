package store

import (
	"context"
	"encoding/json"
	"slices"
	"time"

	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/model"
)

// 공급망 검사 결과(10/16) — 30일 보관(위협이 나온 파일 코드 포함). 원본 파일은 저장하지 않는다

const scanKeep = 30 * 24 * time.Hour

func (m *Memory) SaveScan(_ context.Context, s model.Scan) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.scans == nil {
		m.scans = map[string]model.Scan{}
	}
	m.scans[s.ID] = s
	for id, x := range m.scans {
		if time.Since(x.StartedAt) > scanKeep {
			delete(m.scans, id)
		}
	}
	return nil
}

func (m *Memory) ListScans(context.Context) ([]model.Scan, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]model.Scan, 0, len(m.scans))
	for _, x := range m.scans {
		out = append(out, x)
	}
	slices.SortFunc(out, func(a, b model.Scan) int { return b.StartedAt.Compare(a.StartedAt) })
	return out, nil
}

func (p *Postgres) SaveScan(ctx context.Context, s model.Scan) error {
	doc, err := json.Marshal(s)
	if err != nil {
		return err
	}
	if _, err := p.pool.Exec(ctx, `INSERT INTO scans (id, started_at, doc) VALUES ($1, $2, $3)
ON CONFLICT (id) DO UPDATE SET doc = EXCLUDED.doc`, s.ID, s.StartedAt, doc); err != nil {
		return err
	}
	_, err = p.pool.Exec(ctx, `DELETE FROM scans WHERE started_at < $1`, time.Now().Add(-scanKeep))
	return err
}

func (p *Postgres) ListScans(ctx context.Context) ([]model.Scan, error) {
	rows, err := p.pool.Query(ctx, `SELECT doc FROM scans WHERE started_at >= $1 ORDER BY started_at DESC`, time.Now().Add(-scanKeep))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.Scan{}
	for rows.Next() {
		var b []byte
		if err := rows.Scan(&b); err != nil {
			return nil, err
		}
		var s model.Scan
		if err := json.Unmarshal(b, &s); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}
