package store

import (
	"context"
	"errors"
	"time"

	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/model"
)

// AuthStore: 계정 · 세션 · 라이선스 · 인증 감사. 구현은 MemoryAuth(개발) · Postgres(운영).
// 동시성이 중요한 갱신(실패 횟수 · OTP 스텝 · 복구 코드)은 저장소 안에서 원자적으로 한다.
type AuthStore interface {
	CountUsers(ctx context.Context) (int, error)
	// CreateUser: 같은 username 이 있으면 ErrAuthConflict
	CreateUser(ctx context.Context, u model.User) error
	GetUser(ctx context.Context, id string) (model.User, error)
	GetUserByName(ctx context.Context, username string) (model.User, error)
	ListUsers(ctx context.Context) ([]model.User, error)
	// 행 전체를 덮어쓰지 않는다 — 동시에 바뀐 otp_last_step · failed_count 를 옛 값으로 되돌리지 않도록 필요한 칸만 쓴다.
	// UpdateProfile: 표시 이름 · 역할 · 비활성
	UpdateProfile(ctx context.Context, id, displayName string, role model.Role, disabled bool) error
	// SetPassword: 비밀번호 해시 · 변경 필수 여부. 실패 횟수 · 잠금도 푼다
	SetPassword(ctx context.Context, id, pwHash string, mustChange bool) error
	// SetOTP: OTP 비밀값 · 사용 여부 · 마지막 스텝 · 복구 코드 해시를 한 번에 바꾼다 (등록 확인 · 초기화)
	SetOTP(ctx context.Context, id, secret string, enabled bool, lastStep int64, recoveryHashes []string) error

	// RegisterFailure: failed_count 를 1 올리고, max 에 닿으면 0 으로 되돌리며 lockUntil 까지 잠근다. 잠갔으면 true
	RegisterFailure(ctx context.Context, id string, max int, lockUntil time.Time) (bool, error)
	// LoginSucceeded: 실패 횟수 초기화 · 마지막 로그인 시각
	LoginSucceeded(ctx context.Context, id string, at time.Time) error
	// AdvanceOTPStep: 저장된 스텝보다 클 때만 바꾸고 true (같은 스텝 재사용 · 동시 사용을 막는다)
	AdvanceOTPStep(ctx context.Context, id string, step int64) (bool, error)
	// UseRecoveryHash: 남은 복구 코드 해시에 있으면 지우고 true (1회용)
	UseRecoveryHash(ctx context.Context, id, hash string) (bool, error)

	CreateSession(ctx context.Context, s model.Session) error
	GetSession(ctx context.Context, hash string) (model.Session, error)
	// UpdateSession: state · otp_pending · otp_failures 를 덮어쓴다 (last_seen 은 TouchSession)
	UpdateSession(ctx context.Context, s model.Session) error
	TouchSession(ctx context.Context, hash string, at time.Time) error
	DeleteSession(ctx context.Context, hash string) error
	DeleteUserSessions(ctx context.Context, userID string) error
	// DeleteOtherSessions: 그 계정의 세션 중 keepHash 하나만 남기고 지운다 (비밀번호 변경)
	DeleteOtherSessions(ctx context.Context, userID, keepHash string) error
	// PurgeSessions: last_seen 이 idleBefore 이전이거나 created_at 이 createdBefore 이전인 세션을 지운다
	PurgeSessions(ctx context.Context, idleBefore, createdBefore time.Time) (int64, error)

	// GetLicense: 없으면 (nil, nil)
	GetLicense(ctx context.Context) (*model.License, error)
	SaveLicense(ctx context.Context, l model.License) error

	AddAuthAudit(ctx context.Context, e model.AuthAudit) error
	// ListAuthAudit: 최신순(id 내림차순), q 의 조건을 모두 만족하는 것만
	ListAuthAudit(ctx context.Context, q AuthAuditQuery) ([]model.AuthAudit, error)
}

// AuthAuditQuery: 인증 감사 조회 조건. 0 · 빈 값은 그 조건을 쓰지 않는다
type AuthAuditQuery struct {
	Limit      int    // 0 이하면 기본, 상한 MaxAuthAuditLimit
	BeforeID   int64  // 커서: 이 id 보다 작은 것 (화면의 「더 보기」가 마지막 행 id 를 넘긴다)
	Action     string // 이 action 하나만
	FailedOnly bool   // ok=false 인 것만
}

var (
	ErrAuthNotFound = errors.New("없음")
	ErrAuthConflict = errors.New("이미 있음")
)

var (
	_ AuthStore = (*MemoryAuth)(nil)
	_ AuthStore = (*Postgres)(nil)
)

const (
	DefaultAuthAuditLimit = 100
	MaxAuthAuditLimit     = 1000
)

func authAuditLimit(n int) int {
	if n <= 0 {
		return DefaultAuthAuditLimit
	}
	return min(n, MaxAuthAuditLimit)
}
