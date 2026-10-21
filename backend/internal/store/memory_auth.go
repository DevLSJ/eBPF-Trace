package store

import (
	"context"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/model"
)

// MemoryAuth: DATABASE_URL 없이 쓰는 휘발성 계정 저장소 (재시작하면 초기 관리자부터 다시)
type MemoryAuth struct {
	mu       sync.Mutex
	users    map[string]model.User
	sessions map[string]model.Session
	license  *model.License
	audit    []model.AuthAudit
	nextID   int64
}

const memoryAuthAuditCap = 5000

func NewMemoryAuth() *MemoryAuth {
	return &MemoryAuth{users: map[string]model.User{}, sessions: map[string]model.Session{}, nextID: 1}
}

func cloneUser(u model.User) model.User {
	u.RecoveryHashes = slices.Clone(u.RecoveryHashes)
	if u.LastLoginAt != nil {
		t := *u.LastLoginAt
		u.LastLoginAt = &t
	}
	return u
}

func (m *MemoryAuth) CountUsers(context.Context) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.users), nil
}

func (m *MemoryAuth) CreateUser(_ context.Context, u model.User) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.users[u.ID]; ok {
		return ErrAuthConflict
	}
	for _, x := range m.users {
		if strings.EqualFold(x.Username, u.Username) {
			return ErrAuthConflict
		}
	}
	m.users[u.ID] = cloneUser(u)
	return nil
}

func (m *MemoryAuth) GetUser(_ context.Context, id string) (model.User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	u, ok := m.users[id]
	if !ok {
		return model.User{}, ErrAuthNotFound
	}
	return cloneUser(u), nil
}

func (m *MemoryAuth) GetUserByName(_ context.Context, username string) (model.User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, u := range m.users {
		if strings.EqualFold(u.Username, username) {
			return cloneUser(u), nil
		}
	}
	return model.User{}, ErrAuthNotFound
}

func (m *MemoryAuth) ListUsers(context.Context) ([]model.User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]model.User, 0, len(m.users))
	for _, u := range m.users {
		out = append(out, cloneUser(u))
	}
	slices.SortFunc(out, func(a, b model.User) int {
		if c := a.CreatedAt.Compare(b.CreatedAt); c != 0 {
			return c
		}
		return strings.Compare(a.Username, b.Username)
	})
	return out, nil
}

// updateUser: 있으면 f 로 고쳐 넣는다
func (m *MemoryAuth) updateUser(id string, f func(*model.User)) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	u, ok := m.users[id]
	if !ok {
		return ErrAuthNotFound
	}
	f(&u)
	m.users[id] = cloneUser(u)
	return nil
}

func (m *MemoryAuth) UpdateProfile(_ context.Context, id, displayName string, role model.Role, disabled bool) error {
	return m.updateUser(id, func(u *model.User) { u.DisplayName, u.Role, u.Disabled = displayName, role, disabled })
}

func (m *MemoryAuth) SetPassword(_ context.Context, id, pwHash string, mustChange bool) error {
	return m.updateUser(id, func(u *model.User) {
		u.PwHash, u.MustChangePW, u.FailedCount, u.LockedUntil = pwHash, mustChange, 0, time.Time{}
	})
}

func (m *MemoryAuth) SetOTP(_ context.Context, id, secret string, enabled bool, lastStep int64, recoveryHashes []string) error {
	return m.updateUser(id, func(u *model.User) {
		u.OTPSecret, u.OTPEnabled, u.OTPLastStep, u.RecoveryHashes = secret, enabled, lastStep, slices.Clone(recoveryHashes)
	})
}

func (m *MemoryAuth) RegisterFailure(_ context.Context, id string, max int, lockUntil time.Time) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	u, ok := m.users[id]
	if !ok {
		return false, ErrAuthNotFound
	}
	u.FailedCount++
	locked := u.FailedCount >= max
	if locked {
		u.FailedCount, u.LockedUntil = 0, lockUntil
	}
	m.users[id] = u
	return locked, nil
}

func (m *MemoryAuth) LoginSucceeded(_ context.Context, id string, at time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	u, ok := m.users[id]
	if !ok {
		return ErrAuthNotFound
	}
	u.FailedCount, u.LastLoginAt = 0, &at
	m.users[id] = u
	return nil
}

func (m *MemoryAuth) AdvanceOTPStep(_ context.Context, id string, step int64) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	u, ok := m.users[id]
	if !ok {
		return false, ErrAuthNotFound
	}
	if step <= u.OTPLastStep {
		return false, nil
	}
	u.OTPLastStep = step
	m.users[id] = u
	return true, nil
}

func (m *MemoryAuth) UseRecoveryHash(_ context.Context, id, hash string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	u, ok := m.users[id]
	if !ok {
		return false, ErrAuthNotFound
	}
	i := slices.Index(u.RecoveryHashes, hash)
	if i < 0 {
		return false, nil
	}
	u.RecoveryHashes = slices.Delete(slices.Clone(u.RecoveryHashes), i, i+1)
	m.users[id] = u
	return true, nil
}

func (m *MemoryAuth) CreateSession(_ context.Context, s model.Session) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.sessions[s.Hash]; ok {
		return ErrAuthConflict
	}
	m.sessions[s.Hash] = s
	return nil
}

func (m *MemoryAuth) GetSession(_ context.Context, hash string) (model.Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.sessions[hash]
	if !ok {
		return model.Session{}, ErrAuthNotFound
	}
	return s, nil
}

func (m *MemoryAuth) UpdateSession(_ context.Context, s model.Session) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	old, ok := m.sessions[s.Hash]
	if !ok {
		return ErrAuthNotFound
	}
	old.State, old.OTPPending, old.OTPFailures = s.State, s.OTPPending, s.OTPFailures
	m.sessions[s.Hash] = old
	return nil
}

func (m *MemoryAuth) TouchSession(_ context.Context, hash string, at time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.sessions[hash]
	if !ok {
		return ErrAuthNotFound
	}
	s.LastSeen = at
	m.sessions[hash] = s
	return nil
}

func (m *MemoryAuth) DeleteSession(_ context.Context, hash string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.sessions, hash)
	return nil
}

func (m *MemoryAuth) DeleteUserSessions(_ context.Context, userID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for h, s := range m.sessions {
		if s.UserID == userID {
			delete(m.sessions, h)
		}
	}
	return nil
}

func (m *MemoryAuth) DeleteOtherSessions(_ context.Context, userID, keepHash string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for h, s := range m.sessions {
		if s.UserID == userID && h != keepHash {
			delete(m.sessions, h)
		}
	}
	return nil
}

func (m *MemoryAuth) PurgeSessions(_ context.Context, idleBefore, createdBefore time.Time) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var n int64
	for h, s := range m.sessions {
		if s.LastSeen.Before(idleBefore) || s.CreatedAt.Before(createdBefore) {
			delete(m.sessions, h)
			n++
		}
	}
	return n, nil
}

func (m *MemoryAuth) GetLicense(context.Context) (*model.License, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.license == nil {
		return nil, nil
	}
	l := *m.license
	return &l, nil
}

func (m *MemoryAuth) SaveLicense(_ context.Context, l model.License) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.license = &l
	return nil
}

func (m *MemoryAuth) AddAuthAudit(_ context.Context, e model.AuthAudit) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	e.ID = m.nextID
	m.nextID++
	m.audit = append(m.audit, e)
	if len(m.audit) > memoryAuthAuditCap {
		m.audit = m.audit[len(m.audit)-memoryAuthAuditCap:]
	}
	return nil
}

func (m *MemoryAuth) ListAuthAudit(_ context.Context, limit int) ([]model.AuthAudit, error) {
	limit = authAuditLimit(limit)
	m.mu.Lock()
	defer m.mu.Unlock()
	out := []model.AuthAudit{}
	for i := len(m.audit) - 1; i >= 0 && len(out) < limit; i-- {
		out = append(out, m.audit[i])
	}
	return out, nil
}
