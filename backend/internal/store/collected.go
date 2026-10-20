package store

import (
	"context"
	"slices"
	"time"

	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/model"
)

// 1분 단위 수집량 — eBPF 수집 종합(10/16). 같은 분은 더한다(여러 번 나눠 써도 합이 맞게)

const collectedKeep = 8 * 24 * time.Hour // 메모리 저장소는 최근 8일만 (종합 최대 기간 7일)

func (m *Memory) AddCollected(_ context.Context, ms []model.MinuteCount) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.collected == nil {
		m.collected = map[int64]model.MinuteCount{}
	}
	for _, x := range ms {
		k := x.Minute.Unix() / 60
		c := m.collected[k]
		c.Minute = time.Unix(k*60, 0).UTC()
		c.Exec += x.Exec
		c.Open += x.Open
		c.Connect += x.Connect
		m.collected[k] = c
	}
	cut := time.Now().Add(-collectedKeep).Unix() / 60
	for k := range m.collected {
		if k < cut {
			delete(m.collected, k)
		}
	}
	return nil
}

func (m *Memory) CollectedRange(_ context.Context, from, to time.Time) ([]model.MinuteCount, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := []model.MinuteCount{}
	for _, c := range m.collected {
		if !c.Minute.Before(from) && c.Minute.Before(to) {
			out = append(out, c)
		}
	}
	slices.SortFunc(out, func(x, y model.MinuteCount) int { return x.Minute.Compare(y.Minute) })
	return out, nil
}

func (p *Postgres) AddCollected(ctx context.Context, ms []model.MinuteCount) error {
	for _, x := range ms {
		_, err := p.pool.Exec(ctx, `INSERT INTO collected_minutes (minute, exec, open, connect) VALUES ($1, $2, $3, $4)
ON CONFLICT (minute) DO UPDATE SET exec = collected_minutes.exec + EXCLUDED.exec, open = collected_minutes.open + EXCLUDED.open, connect = collected_minutes.connect + EXCLUDED.connect`,
			x.Minute.UTC().Truncate(time.Minute), x.Exec, x.Open, x.Connect)
		if err != nil {
			return err
		}
	}
	return nil
}

func (p *Postgres) CollectedRange(ctx context.Context, from, to time.Time) ([]model.MinuteCount, error) {
	rows, err := p.pool.Query(ctx, `SELECT minute, exec, open, connect FROM collected_minutes WHERE minute >= $1 AND minute < $2 ORDER BY minute`, from.UTC(), to.UTC())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.MinuteCount{}
	for rows.Next() {
		var c model.MinuteCount
		if err := rows.Scan(&c.Minute, &c.Exec, &c.Open, &c.Connect); err != nil {
			return nil, err
		}
		c.Minute = c.Minute.UTC()
		out = append(out, c)
	}
	return out, rows.Err()
}
