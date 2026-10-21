package store

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/model"
)

// AuthSchema: 계정 · 세션 · 라이선스 · 인증 감사. 멱등이라 시작할 때마다 실행해도 된다.
// NewPostgres 의 schema+reviewSchema 뒤에 붙이거나 MigrateAuth 로 따로 실행한다.
const AuthSchema = `
CREATE TABLE IF NOT EXISTS users (
	id              text PRIMARY KEY,
	username        text NOT NULL,
	display_name    text NOT NULL DEFAULT '',
	role            text NOT NULL,
	pw_hash         text NOT NULL,
	must_change_pw  boolean NOT NULL DEFAULT false,
	otp_secret      text NOT NULL DEFAULT '',
	otp_enabled     boolean NOT NULL DEFAULT false,
	otp_last_step   bigint NOT NULL DEFAULT 0,
	recovery_hashes jsonb NOT NULL DEFAULT '[]'::jsonb,
	failed_count    integer NOT NULL DEFAULT 0,
	locked_until    timestamptz,
	disabled        boolean NOT NULL DEFAULT false,
	created_at      timestamptz NOT NULL DEFAULT now(),
	last_login_at   timestamptz
);
CREATE UNIQUE INDEX IF NOT EXISTS users_username_lower_idx ON users (lower(username));
CREATE TABLE IF NOT EXISTS sessions (
	hash         text PRIMARY KEY,
	user_id      text NOT NULL REFERENCES users(id) ON DELETE CASCADE,
	state        text NOT NULL,
	created_at   timestamptz NOT NULL,
	last_seen    timestamptz NOT NULL,
	ip           text NOT NULL DEFAULT '',
	ua           text NOT NULL DEFAULT '',
	otp_pending  text NOT NULL DEFAULT '',
	otp_failures integer NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS sessions_user_idx ON sessions (user_id);
CREATE TABLE IF NOT EXISTS license (
	id            integer PRIMARY KEY CHECK (id = 1),
	key_masked    text NOT NULL,
	kind          text NOT NULL,
	issued_at     timestamptz NOT NULL,
	expires_at    timestamptz NOT NULL,
	registered_by text NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS auth_audit (
	id     bigserial PRIMARY KEY,
	at     timestamptz NOT NULL,
	actor  text NOT NULL DEFAULT '',
	action text NOT NULL,
	target text NOT NULL DEFAULT '',
	ip     text NOT NULL DEFAULT '',
	ok     boolean NOT NULL,
	detail text NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS auth_audit_at_idx ON auth_audit (at DESC);
`

// MigrateAuth: 인증 테이블을 만든다 (멱등)
func (p *Postgres) MigrateAuth(ctx context.Context) error {
	_, err := p.pool.Exec(ctx, AuthSchema)
	return err
}

const userCols = `id, username, display_name, role, pw_hash, must_change_pw, otp_secret, otp_enabled,
	otp_last_step, recovery_hashes, failed_count, locked_until, disabled, created_at, last_login_at`

func scanUser(row pgx.Row) (model.User, error) {
	var u model.User
	var rec []byte
	var locked *time.Time
	err := row.Scan(&u.ID, &u.Username, &u.DisplayName, &u.Role, &u.PwHash, &u.MustChangePW, &u.OTPSecret, &u.OTPEnabled,
		&u.OTPLastStep, &rec, &u.FailedCount, &locked, &u.Disabled, &u.CreatedAt, &u.LastLoginAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return u, ErrAuthNotFound
	}
	if err != nil {
		return u, err
	}
	if locked != nil {
		u.LockedUntil = *locked
	}
	if err := json.Unmarshal(rec, &u.RecoveryHashes); err != nil {
		return u, err
	}
	return u, nil
}

func recJSON(hs []string) []byte {
	if hs == nil {
		hs = []string{}
	}
	b, _ := json.Marshal(hs)
	return b
}

func nullTime(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	return &t
}

func isUnique(err error) bool {
	var pe *pgconn.PgError
	return errors.As(err, &pe) && pe.Code == "23505"
}

func (p *Postgres) CountUsers(ctx context.Context) (int, error) {
	var n int
	err := p.pool.QueryRow(ctx, `SELECT count(*) FROM users`).Scan(&n)
	return n, err
}

func (p *Postgres) CreateUser(ctx context.Context, u model.User) error {
	_, err := p.pool.Exec(ctx, `INSERT INTO users (`+userCols+`)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)`,
		u.ID, u.Username, u.DisplayName, u.Role, u.PwHash, u.MustChangePW, u.OTPSecret, u.OTPEnabled,
		u.OTPLastStep, recJSON(u.RecoveryHashes), u.FailedCount, nullTime(u.LockedUntil), u.Disabled, u.CreatedAt, u.LastLoginAt)
	if isUnique(err) {
		return ErrAuthConflict
	}
	return err
}

func (p *Postgres) GetUser(ctx context.Context, id string) (model.User, error) {
	return scanUser(p.pool.QueryRow(ctx, `SELECT `+userCols+` FROM users WHERE id = $1`, id))
}

func (p *Postgres) GetUserByName(ctx context.Context, username string) (model.User, error) {
	return scanUser(p.pool.QueryRow(ctx, `SELECT `+userCols+` FROM users WHERE lower(username) = lower($1)`, username))
}

func (p *Postgres) ListUsers(ctx context.Context) ([]model.User, error) {
	rows, err := p.pool.Query(ctx, `SELECT `+userCols+` FROM users ORDER BY created_at, username`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.User{}
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

func execOne(tag pgconn.CommandTag, err error) error {
	if err == nil && tag.RowsAffected() == 0 {
		return ErrAuthNotFound
	}
	return err
}

func (p *Postgres) UpdateProfile(ctx context.Context, id, displayName string, role model.Role, disabled bool) error {
	return execOne(p.pool.Exec(ctx, `UPDATE users SET display_name=$2, role=$3, disabled=$4 WHERE id=$1`, id, displayName, role, disabled))
}

func (p *Postgres) SetPassword(ctx context.Context, id, pwHash string, mustChange bool) error {
	return execOne(p.pool.Exec(ctx, `UPDATE users SET pw_hash=$2, must_change_pw=$3, failed_count=0, locked_until=NULL WHERE id=$1`,
		id, pwHash, mustChange))
}

func (p *Postgres) SetOTP(ctx context.Context, id, secret string, enabled bool, lastStep int64, recoveryHashes []string) error {
	return execOne(p.pool.Exec(ctx, `UPDATE users SET otp_secret=$2, otp_enabled=$3, otp_last_step=$4, recovery_hashes=$5 WHERE id=$1`,
		id, secret, enabled, lastStep, recJSON(recoveryHashes)))
}

// RegisterFailure: 한 문장 안에서 올리고 · 잠그고 · 되돌린다 (동시 실패도 빠짐없이 센다)
func (p *Postgres) RegisterFailure(ctx context.Context, id string, max int, lockUntil time.Time) (bool, error) {
	var locked bool
	err := p.pool.QueryRow(ctx, `UPDATE users SET
			failed_count = CASE WHEN failed_count + 1 >= $2 THEN 0 ELSE failed_count + 1 END,
			locked_until = CASE WHEN failed_count + 1 >= $2 THEN $3 ELSE locked_until END
		WHERE id = $1 RETURNING failed_count = 0`, id, max, lockUntil).Scan(&locked)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, ErrAuthNotFound
	}
	return locked, err
}

func (p *Postgres) LoginSucceeded(ctx context.Context, id string, at time.Time) error {
	_, err := p.pool.Exec(ctx, `UPDATE users SET failed_count = 0, last_login_at = $2 WHERE id = $1`, id, at)
	return err
}

// AdvanceOTPStep: 조건부 UPDATE — 같은 코드로 동시에 두 번 들어와도 하나만 통과한다
func (p *Postgres) AdvanceOTPStep(ctx context.Context, id string, step int64) (bool, error) {
	tag, err := p.pool.Exec(ctx, `UPDATE users SET otp_last_step = $2 WHERE id = $1 AND otp_last_step < $2`, id, step)
	return err == nil && tag.RowsAffected() == 1, err
}

// UseRecoveryHash: jsonb 배열에 있을 때만 지운다 (원자적 1회용)
func (p *Postgres) UseRecoveryHash(ctx context.Context, id, hash string) (bool, error) {
	tag, err := p.pool.Exec(ctx, `UPDATE users SET recovery_hashes = recovery_hashes - $2::text
		WHERE id = $1 AND recovery_hashes ? $2::text`, id, hash)
	return err == nil && tag.RowsAffected() == 1, err
}

func (p *Postgres) CreateSession(ctx context.Context, s model.Session) error {
	_, err := p.pool.Exec(ctx, `INSERT INTO sessions (hash, user_id, state, created_at, last_seen, ip, ua, otp_pending, otp_failures)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`, s.Hash, s.UserID, s.State, s.CreatedAt, s.LastSeen, s.IP, s.UA, s.OTPPending, s.OTPFailures)
	if isUnique(err) {
		return ErrAuthConflict
	}
	return err
}

func (p *Postgres) GetSession(ctx context.Context, hash string) (model.Session, error) {
	var s model.Session
	err := p.pool.QueryRow(ctx, `SELECT hash, user_id, state, created_at, last_seen, ip, ua, otp_pending, otp_failures
		FROM sessions WHERE hash = $1`, hash).
		Scan(&s.Hash, &s.UserID, &s.State, &s.CreatedAt, &s.LastSeen, &s.IP, &s.UA, &s.OTPPending, &s.OTPFailures)
	if errors.Is(err, pgx.ErrNoRows) {
		return s, ErrAuthNotFound
	}
	return s, err
}

func (p *Postgres) UpdateSession(ctx context.Context, s model.Session) error {
	return execOne(p.pool.Exec(ctx, `UPDATE sessions SET state=$2, otp_pending=$3, otp_failures=$4 WHERE hash=$1`,
		s.Hash, s.State, s.OTPPending, s.OTPFailures))
}

func (p *Postgres) TouchSession(ctx context.Context, hash string, at time.Time) error {
	return execOne(p.pool.Exec(ctx, `UPDATE sessions SET last_seen=$2 WHERE hash=$1`, hash, at))
}

func (p *Postgres) DeleteSession(ctx context.Context, hash string) error {
	_, err := p.pool.Exec(ctx, `DELETE FROM sessions WHERE hash = $1`, hash)
	return err
}

func (p *Postgres) DeleteUserSessions(ctx context.Context, userID string) error {
	_, err := p.pool.Exec(ctx, `DELETE FROM sessions WHERE user_id = $1`, userID)
	return err
}

func (p *Postgres) DeleteOtherSessions(ctx context.Context, userID, keepHash string) error {
	_, err := p.pool.Exec(ctx, `DELETE FROM sessions WHERE user_id = $1 AND hash <> $2`, userID, keepHash)
	return err
}

func (p *Postgres) PurgeSessions(ctx context.Context, idleBefore, createdBefore time.Time) (int64, error) {
	tag, err := p.pool.Exec(ctx, `DELETE FROM sessions WHERE last_seen < $1 OR created_at < $2`, idleBefore, createdBefore)
	return tag.RowsAffected(), err
}

func (p *Postgres) GetLicense(ctx context.Context) (*model.License, error) {
	var l model.License
	err := p.pool.QueryRow(ctx, `SELECT key_masked, kind, issued_at, expires_at, registered_by FROM license WHERE id = 1`).
		Scan(&l.KeyMasked, &l.Kind, &l.IssuedAt, &l.ExpiresAt, &l.RegisteredBy)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &l, nil
}

func (p *Postgres) SaveLicense(ctx context.Context, l model.License) error {
	_, err := p.pool.Exec(ctx, `INSERT INTO license (id, key_masked, kind, issued_at, expires_at, registered_by)
		VALUES (1, $1, $2, $3, $4, $5)
		ON CONFLICT (id) DO UPDATE SET key_masked = EXCLUDED.key_masked, kind = EXCLUDED.kind,
			issued_at = EXCLUDED.issued_at, expires_at = EXCLUDED.expires_at, registered_by = EXCLUDED.registered_by`,
		l.KeyMasked, l.Kind, l.IssuedAt, l.ExpiresAt, l.RegisteredBy)
	return err
}

func (p *Postgres) AddAuthAudit(ctx context.Context, e model.AuthAudit) error {
	_, err := p.pool.Exec(ctx, `INSERT INTO auth_audit (at, actor, action, target, ip, ok, detail) VALUES ($1,$2,$3,$4,$5,$6,$7)`,
		e.At, e.Actor, e.Action, e.Target, e.IP, e.OK, e.Detail)
	return err
}

func (p *Postgres) ListAuthAudit(ctx context.Context, limit int) ([]model.AuthAudit, error) {
	rows, err := p.pool.Query(ctx, `SELECT id, at, actor, action, target, ip, ok, detail FROM auth_audit ORDER BY id DESC LIMIT $1`, authAuditLimit(limit))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.AuthAudit{}
	for rows.Next() {
		var e model.AuthAudit
		if err := rows.Scan(&e.ID, &e.At, &e.Actor, &e.Action, &e.Target, &e.IP, &e.OK, &e.Detail); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}
