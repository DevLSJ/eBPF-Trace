package store

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/model"
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/rules"
)

// Postgres: 정책(policies)·감사로그(audit_log) 영속 저장소
type Postgres struct{ pool *pgxpool.Pool }

const schema = `
CREATE TABLE IF NOT EXISTS policies (
	id         text PRIMARY KEY,
	position   integer NOT NULL DEFAULT 0,
	spec       jsonb NOT NULL,
	updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS audit_log (
	id             bigserial PRIMARY KEY,
	ts             timestamptz NOT NULL,
	kind           text NOT NULL,
	action         text NOT NULL,
	rule_id        text NOT NULL,
	dry_run        boolean NOT NULL DEFAULT false,
	enforced       boolean NOT NULL DEFAULT false,
	container_id   text NOT NULL DEFAULT '',
	container_name text NOT NULL DEFAULT '',
	image_name     text NOT NULL DEFAULT '',
	comm           text NOT NULL DEFAULT '',
	pid            bigint NOT NULL DEFAULT 0,
	detail         text NOT NULL DEFAULT '',
	reason         text NOT NULL DEFAULT '',
	verdict        jsonb NOT NULL
);
CREATE INDEX IF NOT EXISTS audit_log_ts_idx ON audit_log (ts DESC);
CREATE INDEX IF NOT EXISTS audit_log_container_idx ON audit_log (container_name);
CREATE TABLE IF NOT EXISTS scans (
	id         text PRIMARY KEY,
	started_at timestamptz NOT NULL,
	doc        jsonb NOT NULL
);
CREATE TABLE IF NOT EXISTS collected_minutes (
	minute  timestamptz PRIMARY KEY,
	exec    bigint NOT NULL DEFAULT 0,
	open    bigint NOT NULL DEFAULT 0,
	connect bigint NOT NULL DEFAULT 0,
	dns     bigint NOT NULL DEFAULT 0
);
ALTER TABLE collected_minutes ADD COLUMN IF NOT EXISTS dns bigint NOT NULL DEFAULT 0;
ALTER TABLE audit_log ADD COLUMN IF NOT EXISTS timeline jsonb;
`

func NewPostgres(ctx context.Context, url string) (*Postgres, error) {
	pool, err := pgxpool.New(ctx, url)
	if err != nil {
		return nil, err
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("postgres ping: %w", err)
	}
	if _, err := pool.Exec(ctx, schema+reviewSchema); err != nil {
		pool.Close()
		return nil, fmt.Errorf("postgres migrate: %w", err)
	}
	return &Postgres{pool: pool}, nil
}

func (p *Postgres) Close() { p.pool.Close() }

func (p *Postgres) Ping(ctx context.Context) error { return p.pool.Ping(ctx) }

func (p *Postgres) ListPolicies(ctx context.Context) ([]rules.Rule, error) {
	rows, err := p.pool.Query(ctx, `SELECT spec FROM policies ORDER BY position, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []rules.Rule{}
	for rows.Next() {
		var b []byte
		if err := rows.Scan(&b); err != nil {
			return nil, err
		}
		var r rules.Rule
		if err := json.Unmarshal(b, &r); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (p *Postgres) UpsertPolicy(ctx context.Context, r rules.Rule) error {
	b, err := json.Marshal(r)
	if err != nil {
		return err
	}
	_, err = p.pool.Exec(ctx, upsertPolicySQL, r.ID, b)
	return err
}

// upsertPolicySQL: 새 정책은 목록 끝에 붙이고, 기존 정책은 위치를 유지한다
const upsertPolicySQL = `
		INSERT INTO policies (id, position, spec)
		VALUES ($1, (SELECT COALESCE(MAX(position), -1) + 1 FROM policies), $2)
		ON CONFLICT (id) DO UPDATE SET spec = EXCLUDED.spec, updated_at = now()`

func (p *Postgres) DeletePolicy(ctx context.Context, id string) (bool, error) {
	tag, err := p.pool.Exec(ctx, `DELETE FROM policies WHERE id = $1`, id)
	return tag.RowsAffected() > 0, err
}

func (p *Postgres) ReplacePolicies(ctx context.Context, rs []rules.Rule) error {
	return pgx.BeginFunc(ctx, p.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `DELETE FROM policies`); err != nil {
			return err
		}
		for i, r := range rs {
			b, err := json.Marshal(r)
			if err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `INSERT INTO policies (id, position, spec) VALUES ($1, $2, $3)`, r.ID, i, b); err != nil {
				return err
			}
		}
		return nil
	})
}

func (p *Postgres) SaveAudit(ctx context.Context, v model.Verdict) (int64, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return 0, err
	}
	// timeline 열(10/30): verdict jsonb 안에도 있지만 격리 지연 조회용으로 따로 둔다. 없으면 NULL
	var tl []byte
	if v.Timeline != nil {
		if tl, err = json.Marshal(v.Timeline); err != nil {
			return 0, err
		}
	}
	e := v.Event
	var id int64
	err = p.pool.QueryRow(ctx, `
		INSERT INTO audit_log (ts, kind, action, rule_id, dry_run, enforced,
			container_id, container_name, image_name, comm, pid, detail, reason, verdict, timeline)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15) RETURNING id`,
		e.Timestamp, e.Kind, v.Action, v.RuleID, v.DryRun, v.Enforced,
		e.ContainerID, e.ContainerName, e.ImageName, e.Comm, int64(e.Pid), e.Detail(), v.Reason, b, tl).Scan(&id)
	return id, err
}

func (p *Postgres) QueryAudit(ctx context.Context, q AuditQuery) ([]model.AuditEntry, error) {
	q.normalize()
	var where []string
	var args []any
	add := func(cond string, v any) {
		args = append(args, v)
		where = append(where, fmt.Sprintf(cond, len(args)))
	}
	if q.Kind != "" {
		add("kind = $%d", q.Kind)
	}
	if q.Action != "" {
		add("action = $%d", q.Action)
	}
	if q.RuleID != "" {
		add("rule_id = $%d", q.RuleID)
	}
	if q.Container != "" {
		add("container_name ILIKE '%%' || $%d || '%%'", escapeLike(q.Container))
	}
	if !q.Since.IsZero() {
		add("ts >= $%d", q.Since)
	}
	if !q.Until.IsZero() {
		add("ts <= $%d", q.Until)
	}
	if q.BeforeID > 0 {
		add("id < $%d", q.BeforeID)
	}
	sql := `SELECT id, verdict FROM audit_log`
	if len(where) > 0 {
		sql += " WHERE " + strings.Join(where, " AND ")
	}
	args = append(args, q.Limit)
	sql += fmt.Sprintf(" ORDER BY id DESC LIMIT $%d", len(args))

	rows, err := p.pool.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.AuditEntry{}
	for rows.Next() {
		var a model.AuditEntry
		var b []byte
		if err := rows.Scan(&a.ID, &b); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(b, &a.Verdict); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

func escapeLike(s string) string {
	return strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(s)
}
