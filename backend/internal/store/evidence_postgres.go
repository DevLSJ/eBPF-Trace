package store

import (
	"context"
	"encoding/json"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/model"
)

// evidenceSchema: kill 전 증거(10/20). 문서 하나를 jsonb 로 두고 조회 · 정리에 쓰는 값만 열로 뺀다. 멱등.
const evidenceSchema = `
CREATE TABLE IF NOT EXISTS evidence (
	id             text PRIMARY KEY,
	container_id   text NOT NULL,
	container_name text NOT NULL DEFAULT '',
	collected_at   timestamptz NOT NULL,
	doc            jsonb NOT NULL
);
CREATE INDEX IF NOT EXISTS evidence_container_idx ON evidence (container_id, collected_at DESC);
CREATE INDEX IF NOT EXISTS evidence_name_idx ON evidence (container_name, collected_at DESC);
CREATE INDEX IF NOT EXISTS evidence_collected_idx ON evidence (collected_at);
`

// EnsureEvidenceSchema: 증거 테이블을 만든다(멱등). main 이 NewPostgres 뒤에 한 번 부른다
func (p *Postgres) EnsureEvidenceSchema(ctx context.Context) error {
	_, err := p.pool.Exec(ctx, evidenceSchema)
	return err
}

// SaveEvidence: 넣고, 같은 컨테이너 id 의 오래된 것은 EvidenceKeep 개만 남기고 지운다 (한 트랜잭션)
func (p *Postgres) SaveEvidence(ctx context.Context, e model.Evidence) error {
	doc, err := json.Marshal(e)
	if err != nil {
		return err
	}
	return pgx.BeginFunc(ctx, p.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `
			INSERT INTO evidence (id, container_id, container_name, collected_at, doc) VALUES ($1, $2, $3, $4, $5)
			ON CONFLICT (id) DO UPDATE SET doc = EXCLUDED.doc`,
			e.ID, e.ContainerID, e.ContainerName, e.CollectedAt, doc); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `
			DELETE FROM evidence WHERE container_id = $1 AND id NOT IN (
				SELECT id FROM evidence WHERE container_id = $1 ORDER BY collected_at DESC, id DESC LIMIT $2)`,
			e.ContainerID, EvidenceKeep)
		return err
	})
}

// EvidenceByContainer: 전체 id · 이름 · 짧은 id(12자 이상 접두)로, 최근 것부터
func (p *Postgres) EvidenceByContainer(ctx context.Context, q string) ([]model.Evidence, error) {
	rows, err := p.pool.Query(ctx, `
		SELECT doc FROM evidence
		WHERE container_id = $1 OR container_name = $1 OR (length($1) >= 12 AND container_id LIKE $2)
		ORDER BY collected_at DESC, id DESC LIMIT $3`,
		q, escapeLike(q)+"%", EvidenceQueryLimit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.Evidence{}
	for rows.Next() {
		var b []byte
		if err := rows.Scan(&b); err != nil {
			return nil, err
		}
		var e model.Evidence
		if err := json.Unmarshal(b, &e); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

func (p *Postgres) PruneEvidence(ctx context.Context, before time.Time) (int, error) {
	tag, err := p.pool.Exec(ctx, `DELETE FROM evidence WHERE collected_at < $1`, before)
	return int(tag.RowsAffected()), err
}
