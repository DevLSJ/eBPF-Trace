package store

import (
	"context"
	"encoding/json"

	"github.com/jackc/pgx/v5"

	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/model"
)

// reviewSchema: 설치 세션 · 건 · 제안 · 차단 목록 · 변경 이력. 추가만 한다(기존 테이블은 건드리지 않음, 멱등).
// 문서 하나를 jsonb 로 두고, 정렬 · 조회에 쓰는 값만 열로 뺀다.
const reviewSchema = `
CREATE TABLE IF NOT EXISTS install_sessions (
	id         text PRIMARY KEY,
	started_at timestamptz NOT NULL,
	container  text NOT NULL DEFAULT '',
	doc        jsonb NOT NULL,
	updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS review_cases (
	id         text PRIMARY KEY,
	opened_at  timestamptz NOT NULL,
	doc        jsonb NOT NULL,
	updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS proposals (
	id         text PRIMARY KEY,
	created_at timestamptz NOT NULL,
	doc        jsonb NOT NULL,
	updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS blocklist (
	list  text NOT NULL,
	value text NOT NULL,
	doc   jsonb NOT NULL,
	PRIMARY KEY (list, value)
);
CREATE TABLE IF NOT EXISTS changes (
	id  text PRIMARY KEY,
	at  timestamptz NOT NULL,
	doc jsonb NOT NULL
);
`

func (p *Postgres) LoadReview(ctx context.Context) (ReviewSnapshot, error) {
	var s ReviewSnapshot
	if err := loadDocs(ctx, p, `SELECT doc FROM install_sessions ORDER BY started_at, id`, &s.Installs); err != nil {
		return s, err
	}
	if err := loadDocs(ctx, p, `SELECT doc FROM review_cases ORDER BY opened_at, id`, &s.Cases); err != nil {
		return s, err
	}
	if err := loadDocs(ctx, p, `SELECT doc FROM proposals ORDER BY created_at, id`, &s.Proposals); err != nil {
		return s, err
	}
	rows, err := p.pool.Query(ctx, `SELECT list, doc FROM blocklist ORDER BY list, value`)
	if err != nil {
		return s, err
	}
	for rows.Next() {
		var list string
		var b []byte
		if err := rows.Scan(&list, &b); err != nil {
			rows.Close()
			return s, err
		}
		var e model.BlockEntry
		if err := json.Unmarshal(b, &e); err != nil {
			rows.Close()
			return s, err
		}
		e.List = list
		s.Blocklist = append(s.Blocklist, e)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return s, err
	}
	err = loadDocs(ctx, p, `SELECT doc FROM changes ORDER BY at, id`, &s.Changes)
	return s, err
}

func loadDocs[T any](ctx context.Context, p *Postgres, sql string, out *[]T) error {
	rows, err := p.pool.Query(ctx, sql)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var b []byte
		if err := rows.Scan(&b); err != nil {
			return err
		}
		var v T
		if err := json.Unmarshal(b, &v); err != nil {
			return err
		}
		*out = append(*out, v)
	}
	return rows.Err()
}

// CommitReview: 트랜잭션 하나 — 중간에 실패하면 전부 롤백된다.
func (p *Postgres) CommitReview(ctx context.Context, c ReviewCommit) error {
	if c.Empty() {
		return nil
	}
	return pgx.BeginFunc(ctx, p.pool, func(tx pgx.Tx) error {
		for _, x := range c.Installs {
			b, err := json.Marshal(x)
			if err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `
				INSERT INTO install_sessions (id, started_at, container, doc) VALUES ($1, $2, $3, $4)
				ON CONFLICT (id) DO UPDATE SET doc = EXCLUDED.doc, container = EXCLUDED.container, updated_at = now()`,
				x.ID, x.StartedAt, x.Container, b); err != nil {
				return err
			}
		}
		for _, x := range c.Cases {
			b, err := json.Marshal(x)
			if err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `
				INSERT INTO review_cases (id, opened_at, doc) VALUES ($1, $2, $3)
				ON CONFLICT (id) DO UPDATE SET doc = EXCLUDED.doc, updated_at = now()`,
				x.Case.ID, x.Case.OpenedAt, b); err != nil {
				return err
			}
		}
		for _, x := range c.Proposals {
			b, err := json.Marshal(x)
			if err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `
				INSERT INTO proposals (id, created_at, doc) VALUES ($1, $2, $3)
				ON CONFLICT (id) DO UPDATE SET doc = EXCLUDED.doc, updated_at = now()`,
				x.ID, x.CreatedAt, b); err != nil {
				return err
			}
		}
		for _, x := range c.BlockAdd {
			b, err := json.Marshal(x)
			if err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `
				INSERT INTO blocklist (list, value, doc) VALUES ($1, $2, $3)
				ON CONFLICT (list, value) DO UPDATE SET doc = EXCLUDED.doc`, x.List, x.Value, b); err != nil {
				return err
			}
		}
		for _, k := range c.BlockRemove {
			if _, err := tx.Exec(ctx, `DELETE FROM blocklist WHERE list = $1 AND value = $2`, k.List, k.Value); err != nil {
				return err
			}
		}
		for _, r := range c.Policies {
			b, err := json.Marshal(r)
			if err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, upsertPolicySQL, r.ID, b); err != nil {
				return err
			}
		}
		for _, x := range c.Changes {
			b, err := json.Marshal(x)
			if err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `
				INSERT INTO changes (id, at, doc) VALUES ($1, $2, $3)
				ON CONFLICT (id) DO UPDATE SET doc = EXCLUDED.doc`, x.ID, x.At, b); err != nil {
				return err
			}
		}
		return nil
	})
}
