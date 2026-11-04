// Package auth: 로그인 계정 · 세션 · 라이선스 · TOTP(RFC 6238) · 미들웨어.
//
// 로그인 단계(세션 상태): need_password → need_license → need_otp_enroll | need_otp → active.
// active 가 아닌 세션은 /api/auth/* 단계 요청만 할 수 있다.
package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/auth/license"
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/model"
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/store"
)

const (
	DefaultIdleTimeout = 60 * time.Minute
	DefaultMaxAge      = 12 * time.Hour

	maxFailures    = 5               // 계정별 연속 실패 → 잠금
	lockFor        = 5 * time.Minute // 잠금 시간
	ipMaxFailures  = 20              // IP 별 실패 상한
	ipWindow       = time.Minute     // IP 상한 창
	maxOTPFailures = 5               // 한 세션의 OTP 실패 → 세션 끊기
	touchEvery     = time.Minute     // last_seen 갱신 간격 (DB 쓰기 줄이기)
)

const (
	msgLogin        = "로그인이 필요합니다"
	msgExpired      = "세션이 만료되었습니다. 다시 로그인하세요"
	msgBadCreds     = "아이디 또는 비밀번호가 올바르지 않습니다. 5번 연속 틀리면 5분 동안 로그인할 수 없습니다"
	msgTooMany      = "시도가 너무 많습니다. 1분 뒤 다시 시도하세요"
	msgAdminOnly    = "관리자 권한이 필요합니다"
	msgViewerNoLic  = "관리자가 먼저 라이선스를 등록해야 합니다"
	msgWrongStep    = "지금 로그인 단계에서 할 수 없는 요청입니다"
	msgBadOTP       = "OTP 코드가 올바르지 않습니다"
	msgBadRecovery  = "복구 코드가 올바르지 않거나 이미 사용되었습니다"
	msgOTPRestart   = "OTP 를 여러 번 틀려 로그인을 처음부터 다시 해야 합니다"
	msgFinishLogin  = "로그인 단계를 마쳐야 합니다"
	msgViewerWrite  = "조회자는 읽기만 할 수 있습니다"
	msgBadOrigin    = "요청 출처(Origin)가 허용되지 않습니다"
	msgBadToken     = "토큰이 올바르지 않습니다"
	msgNoUser       = "계정이 없습니다"
	msgSelfDisable  = "자기 자신은 비활성화할 수 없습니다"
	msgLastAdmin    = "마지막 관리자는 강등하거나 비활성화할 수 없습니다"
	msgDupUser      = "이미 있는 아이디입니다"
	msgEnrollFirst  = "먼저 OTP 등록을 시작하세요"
	msgPWLockedOut  = "현재 비밀번호를 5번 틀려 5분 동안 잠겼습니다. 다시 로그인하세요"
	msgBadCurrentPW = "현재 비밀번호가 올바르지 않습니다"
	msgSamePW       = "새 비밀번호는 지금 비밀번호와 달라야 합니다"
)

// Error: HTTP 상태와 화면에 보일 메시지. State 는 세션이 살아 있을 때 지금 단계
type Error struct {
	Status int
	Msg    string
	State  model.SessionState
}

func (e *Error) Error() string { return e.Msg }

func fail(status int, msg string) *Error { return &Error{Status: status, Msg: msg} }

type Options struct {
	Store store.AuthStore
	// OTPRequired: AUTH_OTP_REQUIRED (기본 true). false 면 OTP 단계를 건너뛴다(개발 · e2e)
	OTPRequired bool
	// SecretKey: AUTH_SECRET_KEY. 있으면 OTP 비밀값을 AES-GCM 으로 암호화해 저장
	SecretKey string
	// CookieSecure: AUTH_COOKIE_SECURE (HTTPS 에서 켠다)
	CookieSecure bool
	// DevMode: AUTH_DEV_MODE (11/04, 로컬 개발 전용). 시드 관리자에 「아이디와 다름」을 보지 않고(길이 검사는 유지)
	// 첫 로그인 비밀번호 변경 없이 만들며, 라이선스 단계를 통과한 것으로 본다. OTP 는 OTPRequired 가 따로 정한다
	DevMode bool
	// TrustProxy: X-Real-IP / X-Forwarded-For 를 믿는다 (nginx 뒤, 백엔드 포트가 바깥에 없을 때만)
	TrustProxy  bool
	BcryptCost  int           // 0 → 12
	IdleTimeout time.Duration // 0 → 60분
	MaxAge      time.Duration // 0 → 12시간
	Now         func() time.Time
}

type Service struct {
	o      Options
	seal   sealer
	ipl    *ipLimiter
	userMu sync.Mutex // 계정 변경(마지막 관리자 검사 → 변경)을 한 줄로 세운다

	dummyOnce sync.Once
	dummy     string
}

func New(o Options) *Service {
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.BcryptCost == 0 {
		o.BcryptCost = DefaultBcryptCost
	}
	if o.IdleTimeout == 0 {
		o.IdleTimeout = DefaultIdleTimeout
	}
	if o.MaxAge == 0 {
		o.MaxAge = DefaultMaxAge
	}
	return &Service{o: o, seal: newSealer(o.SecretKey), ipl: newIPLimiter(ipMaxFailures, ipWindow)}
}

func (s *Service) now() time.Time { return s.o.Now().UTC() }

// OTPRequired: 화면이 단계 안내에 쓴다
func (s *Service) OTPRequired() bool { return s.o.OTPRequired }

// ClientIP: Options.TrustProxy 에 맞춰 요청 IP
func (s *Service) ClientIP(r *http.Request) string { return ClientIP(r, s.o.TrustProxy) }

// dummyHash: 없는 아이디에도 bcrypt 를 한 번 돌려 응답 시간으로 존재 여부가 드러나지 않게 한다
func (s *Service) dummyHash() string {
	s.dummyOnce.Do(func() {
		s.dummy, _ = HashPassword("supplyguard-timing-equalizer", s.o.BcryptCost)
	})
	return s.dummy
}

// ---------- 토큰 · 감사 ----------

// newToken: 32바이트 난수(쿠키 값)와 그 SHA-256(hex, DB 키). DB 가 새어도 쿠키를 만들 수 없다
func newToken() (token, hash string, err error) {
	b := make([]byte, 32)
	if _, err = rand.Read(b); err != nil {
		return "", "", err
	}
	token = base64.RawURLEncoding.EncodeToString(b)
	return token, HashToken(token), nil
}

func HashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func newUserID() (string, error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "u_" + hex.EncodeToString(b), nil
}

// clip: 감사에 남길 사용자 입력(아이디 칸)을 줄인다 — 비밀번호를 아이디 칸에 잘못 넣은 경우를 줄이려 64자
func clip(s string) string {
	s = strings.TrimSpace(s)
	if utf8.RuneCountInString(s) > 64 {
		return string([]rune(s)[:64])
	}
	return s
}

// AuditActions: 이 서비스가 감사에 남기는 action 값 전부 (GET /api/auth/audit?action= 허용 목록).
// audit_actions_test.go 가 아래 s.audit · s.otpFail 호출의 문자열과 같은지 확인한다
var AuditActions = []string{
	"login", "login_lock", "logout", "password_change",
	"license_register", "license_renew",
	"otp_enroll", "otp_verify", "otp_recovery",
	"user_create", "user_update", "user_reset_password", "user_reset_otp",
}

// ValidAuditAction: AuditActions 안의 값인지 (대소문자 구분)
func ValidAuditAction(a string) bool { return slices.Contains(AuditActions, a) }

func (s *Service) audit(ctx context.Context, actor, action, target, ip string, ok bool, detail string) {
	e := model.AuthAudit{At: s.now(), Actor: clip(actor), Action: action, Target: clip(target), IP: ip, OK: ok, Detail: detail}
	if err := s.o.Store.AddAuthAudit(context.WithoutCancel(ctx), e); err != nil {
		slog.Error("auth audit", "action", action, "err", err)
	}
}

// ---------- 단계 ----------

var stepRank = map[model.SessionState]int{
	"": 0, model.StateNeedPassword: 1, model.StateNeedLicense: 2,
	model.StateNeedOTPEnroll: 3, model.StateNeedOTP: 3, model.StateActive: 4,
}

// next: from 단계 다음에 남은 첫 단계. 조회자가 라이선스 단계에 닿으면 403
func (s *Service) next(u model.User, from model.SessionState, licensed bool) (model.SessionState, error) {
	r := stepRank[from]
	if r < 1 && u.MustChangePW {
		return model.StateNeedPassword, nil
	}
	if r < 2 && !licensed {
		if u.Role != model.RoleAdmin {
			return "", fail(http.StatusForbidden, msgViewerNoLic)
		}
		return model.StateNeedLicense, nil
	}
	if r < 3 && s.o.OTPRequired {
		if u.OTPEnabled {
			return model.StateNeedOTP, nil
		}
		return model.StateNeedOTPEnroll, nil
	}
	return model.StateActive, nil
}

// licensed: 등록된 라이선스가 있고 기간 안
func (s *Service) licensed(ctx context.Context) (bool, error) {
	l, err := s.o.Store.GetLicense(ctx)
	if err != nil {
		return false, err
	}
	return l != nil && s.now().Before(l.ExpiresAt), nil
}

// licenseOK: 로그인 단계를 정할 때의 라이선스 조건. AUTH_DEV_MODE 면 등록 없이 통과(라이선스를 만들어 저장하지 않는다).
// RegisterLicense 는 실제 등록 여부가 필요해 licensed 를 그대로 쓴다
func (s *Service) licenseOK(ctx context.Context) (bool, error) {
	if s.o.DevMode {
		return true, nil
	}
	return s.licensed(ctx)
}

// ---------- 초기 관리자 ----------

// SeedAdmin: 계정이 하나도 없을 때만 관리자 1명을 만든다(첫 로그인에서 비밀번호 변경 필수 — DevMode 는 제외). 만들었으면 true
func (s *Service) SeedAdmin(ctx context.Context, username, password string) (bool, error) {
	n, err := s.o.Store.CountUsers(ctx)
	if err != nil || n > 0 {
		return false, err
	}
	username = strings.TrimSpace(username)
	if username == "" {
		username = "admin"
	}
	if password == "" {
		return false, errors.New("계정이 없어 초기 관리자를 만들어야 하는데 ADMIN_INITIAL_PASSWORD 가 비어 있음")
	}
	pwErr := ValidatePassword(username, password)
	if s.o.DevMode { // 개발 전용: admin/admin 을 받는다 — 길이(5자 · 72바이트)만 본다
		pwErr = validatePasswordSize(password)
	}
	if pwErr != nil {
		return false, fmt.Errorf("ADMIN_INITIAL_PASSWORD: %w", pwErr)
	}
	if !validUsername(username) {
		return false, fmt.Errorf("ADMIN_USER: %q (영문 · 숫자 · . _ - 3~32자)", username)
	}
	u, err := s.newUser(username, username, model.RoleAdmin, password)
	if err != nil {
		return false, err
	}
	u.MustChangePW = !s.o.DevMode // 개발 전용: 첫 로그인 비밀번호 변경 단계 없이 시작
	if err := s.o.Store.CreateUser(ctx, u); err != nil {
		if errors.Is(err, store.ErrAuthConflict) {
			return false, nil // 다른 인스턴스가 먼저 만들었다
		}
		return false, err
	}
	s.audit(ctx, "system", "user_create", username, "", true, "초기 관리자")
	return true, nil
}

var usernameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{2,31}$`)

func validUsername(u string) bool { return usernameRe.MatchString(u) }

func (s *Service) newUser(username, display string, role model.Role, password string) (model.User, error) {
	id, err := newUserID()
	if err != nil {
		return model.User{}, err
	}
	h, err := HashPassword(password, s.o.BcryptCost)
	if err != nil {
		return model.User{}, err
	}
	return model.User{ID: id, Username: username, DisplayName: display, Role: role, PwHash: h,
		MustChangePW: true, CreatedAt: s.now()}, nil
}

// ---------- 로그인 ----------

type LoginInput struct {
	Username, Password, IP, UA string
	// OldToken: 브라우저에 남아 있던 세션 — 새로 로그인하면 지운다
	OldToken string
}

type LoginResult struct {
	Token string
	State model.SessionState
	User  model.User
}

// Login: 아이디 · 비밀번호 확인 → 다음 단계 세션. 실패 응답은 아이디가 있든 없든 · 잠겼든 같은 메시지(401)
func (s *Service) Login(ctx context.Context, in LoginInput) (LoginResult, error) {
	now := s.now()
	if !s.ipl.Allow(in.IP, now) { // IP 별 1분 20회 실패 → 429 (비밀번호를 보지도 않는다)
		s.audit(ctx, in.Username, "login", "", in.IP, false, "IP 시도 상한")
		return LoginResult{}, fail(http.StatusTooManyRequests, msgTooMany)
	}
	u, err := s.o.Store.GetUserByName(ctx, strings.TrimSpace(in.Username))
	if err != nil && !errors.Is(err, store.ErrAuthNotFound) {
		return LoginResult{}, err
	}
	found := err == nil
	hash := s.dummyHash()
	if found {
		hash = u.PwHash
	}
	pwOK := CheckPassword(hash, in.Password) && found // 없는 아이디도 bcrypt 한 번 — 응답 시간을 맞춘다
	bad := func(detail string) (LoginResult, error) {
		s.ipl.Fail(in.IP, now)
		s.audit(ctx, in.Username, "login", "", in.IP, false, detail)
		return LoginResult{}, fail(http.StatusUnauthorized, msgBadCreds)
	}
	switch {
	case !found:
		return bad("없는 아이디")
	case u.Disabled:
		return bad("비활성 계정")
	case now.Before(u.LockedUntil): // 잠긴 동안은 맞는 비밀번호도 거절 (실패 횟수는 더 세지 않는다)
		return bad("잠긴 계정")
	case !pwOK:
		locked, err := s.o.Store.RegisterFailure(ctx, u.ID, maxFailures, now.Add(lockFor))
		if err != nil {
			return LoginResult{}, err
		}
		if locked {
			s.audit(ctx, u.Username, "login_lock", u.Username, in.IP, false, "5회 연속 실패 — 5분 잠금")
		}
		return bad("비밀번호 틀림")
	}
	lic, err := s.licenseOK(ctx)
	if err != nil {
		return LoginResult{}, err
	}
	if !lic && u.Role != model.RoleAdmin { // 조회자는 라이선스 등록 전에 들어올 수 없다
		s.audit(ctx, u.Username, "login", "", in.IP, false, "라이선스 없음(조회자)")
		return LoginResult{}, fail(http.StatusForbidden, msgViewerNoLic)
	}
	state, err := s.next(u, "", lic)
	if err != nil {
		return LoginResult{}, err
	}
	if err := s.o.Store.LoginSucceeded(ctx, u.ID, now); err != nil {
		return LoginResult{}, err
	}
	token, h, err := newToken()
	if err != nil {
		return LoginResult{}, err
	}
	if in.OldToken != "" {
		_ = s.o.Store.DeleteSession(ctx, HashToken(in.OldToken))
	}
	sess := model.Session{Hash: h, UserID: u.ID, State: state, CreatedAt: now, LastSeen: now, IP: in.IP, UA: clipUA(in.UA)}
	if err := s.o.Store.CreateSession(ctx, sess); err != nil {
		return LoginResult{}, err
	}
	s.audit(ctx, u.Username, "login", "", in.IP, true, "다음 단계: "+string(state))
	return LoginResult{Token: token, State: state, User: u}, nil
}

func clipUA(ua string) string {
	if len(ua) > 256 {
		return ua[:256]
	}
	return ua
}

// Session: 토큰 → 세션 · 계정. 유휴 60분 · 절대 12시간이 지났거나 계정이 비활성이면 지우고 401.
// 단계(state)는 보지 않는다 — 부르는 쪽이 확인한다.
func (s *Service) Session(ctx context.Context, token string) (model.Session, model.User, error) {
	if token == "" {
		return model.Session{}, model.User{}, fail(http.StatusUnauthorized, msgLogin)
	}
	sess, err := s.o.Store.GetSession(ctx, HashToken(token))
	if errors.Is(err, store.ErrAuthNotFound) {
		return sess, model.User{}, fail(http.StatusUnauthorized, msgLogin)
	}
	if err != nil {
		return sess, model.User{}, err
	}
	now := s.now()
	if now.Sub(sess.LastSeen) > s.o.IdleTimeout || now.Sub(sess.CreatedAt) > s.o.MaxAge {
		_ = s.o.Store.DeleteSession(ctx, sess.Hash)
		return sess, model.User{}, fail(http.StatusUnauthorized, msgExpired)
	}
	u, err := s.o.Store.GetUser(ctx, sess.UserID)
	if errors.Is(err, store.ErrAuthNotFound) || (err == nil && u.Disabled) {
		_ = s.o.Store.DeleteUserSessions(ctx, sess.UserID)
		return sess, u, fail(http.StatusUnauthorized, msgLogin)
	}
	if err != nil {
		return sess, u, err
	}
	if now.Sub(sess.LastSeen) >= touchEvery { // last_seen 만 바꾼다 — 동시에 바뀐 단계를 덮지 않는다
		if err := s.o.Store.TouchSession(ctx, sess.Hash, now); err != nil {
			return sess, u, err
		}
		sess.LastSeen = now
	}
	return sess, u, nil
}

// stepSession: 세션을 찾고 지금 단계가 allowed 중 하나인지 본다 (아니면 409 + 지금 단계)
func (s *Service) stepSession(ctx context.Context, token string, allowed ...model.SessionState) (model.Session, model.User, error) {
	sess, u, err := s.Session(ctx, token)
	if err != nil {
		return sess, u, err
	}
	for _, a := range allowed {
		if sess.State == a {
			return sess, u, nil
		}
	}
	return sess, u, &Error{Status: http.StatusConflict, Msg: msgWrongStep, State: sess.State}
}

func (s *Service) setState(ctx context.Context, sess *model.Session, st model.SessionState) error {
	sess.State, sess.OTPPending, sess.OTPFailures = st, "", 0
	return s.o.Store.UpdateSession(ctx, *sess)
}

// ---------- 비밀번호 ----------

// ChangePassword: need_password 또는 active 에서. 현재 비밀번호 확인 → 정책 → 저장 → 다음 단계
func (s *Service) ChangePassword(ctx context.Context, token, current, next, ip string) (model.SessionState, error) {
	sess, u, err := s.stepSession(ctx, token, model.StateNeedPassword, model.StateActive)
	if err != nil {
		return "", err
	}
	now := s.now()
	if !s.ipl.Allow(ip, now) {
		return sess.State, &Error{Status: http.StatusTooManyRequests, Msg: msgTooMany, State: sess.State}
	}
	if !CheckPassword(u.PwHash, current) {
		s.ipl.Fail(ip, now)
		s.audit(ctx, u.Username, "password_change", u.Username, ip, false, "현재 비밀번호 틀림")
		locked, err := s.o.Store.RegisterFailure(ctx, u.ID, maxFailures, now.Add(lockFor))
		if err != nil {
			return "", err
		}
		if locked { // 세션을 쥔 채 현재 비밀번호를 추측하는 것도 잠금에 넣는다
			_ = s.o.Store.DeleteUserSessions(ctx, u.ID)
			s.audit(ctx, u.Username, "login_lock", u.Username, ip, false, "비밀번호 변경 5회 실패 — 5분 잠금")
			return "", fail(http.StatusUnauthorized, msgPWLockedOut)
		}
		return sess.State, &Error{Status: http.StatusBadRequest, Msg: msgBadCurrentPW, State: sess.State}
	}
	if err := ValidatePassword(u.Username, next); err != nil {
		return sess.State, &Error{Status: http.StatusBadRequest, Msg: err.Error(), State: sess.State}
	}
	if next == current {
		return sess.State, &Error{Status: http.StatusBadRequest, Msg: msgSamePW, State: sess.State}
	}
	h, err := HashPassword(next, s.o.BcryptCost)
	if err != nil {
		return "", err
	}
	if err := s.o.Store.SetPassword(ctx, u.ID, h, false); err != nil {
		return "", err
	}
	// 바꾼 이 세션만 남기고 같은 계정의 다른 기기 로그인은 끝낸다(10/20)
	if err := s.o.Store.DeleteOtherSessions(ctx, u.ID, sess.Hash); err != nil {
		return "", err
	}
	u.MustChangePW = false
	st := sess.State
	if st == model.StateNeedPassword {
		lic, err := s.licenseOK(ctx)
		if err != nil {
			return "", err
		}
		if st, err = s.next(u, model.StateNeedPassword, lic); err != nil {
			_ = s.o.Store.DeleteSession(ctx, sess.Hash) // 조회자인데 라이선스가 사라졌다
			return "", err
		}
		if err := s.setState(ctx, &sess, st); err != nil {
			return "", err
		}
	}
	s.audit(ctx, u.Username, "password_change", u.Username, ip, true, "")
	return st, nil
}

// ---------- 라이선스 ----------

// RegisterLicense: need_license(관리자)에서. 형식만 맞으면 1년 평가판으로 저장 → 다음 단계
func (s *Service) RegisterLicense(ctx context.Context, token, key, ip string) (model.SessionState, model.License, error) {
	sess, u, err := s.stepSession(ctx, token, model.StateNeedLicense)
	if err != nil {
		return "", model.License{}, err
	}
	if u.Role != model.RoleAdmin {
		return sess.State, model.License{}, &Error{Status: http.StatusForbidden, Msg: msgViewerNoLic, State: sess.State}
	}
	lic, err := license.ValidateAt(key, s.now())
	if err != nil {
		s.audit(ctx, u.Username, "license_register", "", ip, false, "형식 오류")
		return sess.State, model.License{}, &Error{Status: http.StatusBadRequest, Msg: err.Error(), State: sess.State}
	}
	ok, err := s.licensed(ctx)
	if err != nil {
		return "", model.License{}, err
	}
	if ok { // 그 사이 다른 관리자가 등록했다 — 덮어쓰지 않고 다음 단계로
		cur, err := s.o.Store.GetLicense(ctx)
		if err != nil {
			return "", model.License{}, err
		}
		lic = *cur
	} else {
		lic.RegisteredBy = u.Username
		if err := s.o.Store.SaveLicense(ctx, lic); err != nil {
			return "", model.License{}, err
		}
		s.audit(ctx, u.Username, "license_register", lic.KeyMasked, ip, true, lic.Kind+" ~"+lic.ExpiresAt.Format("2006-01-02"))
	}
	st, err := s.next(u, model.StateNeedLicense, true)
	if err != nil {
		return "", model.License{}, err
	}
	if err := s.setState(ctx, &sess, st); err != nil {
		return "", model.License{}, err
	}
	return st, lic, nil
}

// RenewLicense: 설정 › 라이선스 「새 키 등록」(PUT /api/license). 관리자만, 활성 세션(또는 CLI Bearer)에서.
// 만료 여부와 상관없이 기존 라이선스(단일 행)를 새 키로 바꾸고 만료일을 지금부터 다시 계산한다.
// 감사 · 로그에는 키 원문을 남기지 않는다 — 성공은 가린 키, 실패는 대상 없이 「형식 오류」만.
func (s *Service) RenewLicense(ctx context.Context, by Actor, key, ip string) (model.License, error) {
	if !by.IsAdmin() {
		s.audit(ctx, by.Username, "license_renew", "", ip, false, "권한 없음")
		return model.License{}, fail(http.StatusForbidden, msgAdminOnly)
	}
	lic, err := license.ValidateAt(key, s.now())
	if err != nil {
		s.audit(ctx, by.Username, "license_renew", "", ip, false, "형식 오류")
		return model.License{}, fail(http.StatusBadRequest, err.Error())
	}
	prev, err := s.o.Store.GetLicense(ctx)
	if err != nil {
		return model.License{}, err
	}
	lic.RegisteredBy = by.Username
	if err := s.o.Store.SaveLicense(ctx, lic); err != nil {
		return model.License{}, err
	}
	detail := lic.Kind + " ~" + lic.ExpiresAt.Format("2006-01-02")
	if prev != nil {
		detail += " (이전 " + prev.KeyMasked + " ~" + prev.ExpiresAt.Format("2006-01-02") + ")"
	}
	s.audit(ctx, by.Username, "license_renew", lic.KeyMasked, ip, true, detail)
	return lic, nil
}

// Expired: 라이선스 기간이 지났는지 (지나면 관리자 로그인 때 다시 라이선스 단계)
func (s *Service) Expired(l model.License) bool { return !s.now().Before(l.ExpiresAt) }

// License: 등록된 라이선스 (없으면 nil)
func (s *Service) License(ctx context.Context) (*model.License, error) {
	return s.o.Store.GetLicense(ctx)
}

// ---------- OTP ----------

// OTPEnroll: need_otp_enroll 에서 비밀값 발급. 같은 세션에서 다시 부르면 같은 값(확인 전까지 세션에만 둔다)
func (s *Service) OTPEnroll(ctx context.Context, token string) (secret, uri string, err error) {
	sess, u, err := s.stepSession(ctx, token, model.StateNeedOTPEnroll)
	if err != nil {
		return "", "", err
	}
	if sess.OTPPending != "" {
		if secret, err = s.seal.open(u.ID, sess.OTPPending); err != nil {
			return "", "", err
		}
		return secret, OTPAuthURI(u.Username, secret), nil
	}
	if secret, err = NewOTPSecret(); err != nil {
		return "", "", err
	}
	if sess.OTPPending, err = s.seal.seal(u.ID, secret); err != nil {
		return "", "", err
	}
	if err := s.o.Store.UpdateSession(ctx, sess); err != nil {
		return "", "", err
	}
	return secret, OTPAuthURI(u.Username, secret), nil
}

// OTPEnrollConfirm: 인증 앱 코드가 맞으면 비밀값 · 복구 코드(해시)를 계정에 저장하고 active. 복구 코드 원문은 여기서 한 번만 돌려준다
func (s *Service) OTPEnrollConfirm(ctx context.Context, token, code, ip string) ([]string, error) {
	sess, u, err := s.stepSession(ctx, token, model.StateNeedOTPEnroll)
	if err != nil {
		return nil, err
	}
	if sess.OTPPending == "" {
		return nil, &Error{Status: http.StatusConflict, Msg: msgEnrollFirst, State: sess.State}
	}
	if err := s.otpGate(ctx, &sess, u, ip); err != nil {
		return nil, err
	}
	secret, err := s.seal.open(u.ID, sess.OTPPending)
	if err != nil {
		return nil, err
	}
	raw, err := DecodeSecret(secret)
	if err != nil {
		return nil, err
	}
	step, ok := VerifyTOTP(raw, strings.TrimSpace(code), s.now(), 0)
	if !ok {
		return nil, s.otpFail(ctx, &sess, u, ip, "otp_enroll", msgBadOTP)
	}
	codes, err := NewRecoveryCodes()
	if err != nil {
		return nil, err
	}
	hashes := make([]string, len(codes))
	for i, c := range codes {
		hashes[i] = RecoveryHash(u.ID, c)
	}
	// 확인에 쓴 스텝을 마지막 스텝으로 — 같은 코드로 곧바로 다시 로그인할 수 없다
	if err := s.o.Store.SetOTP(ctx, u.ID, sess.OTPPending, true, step, hashes); err != nil {
		return nil, err
	}
	if err := s.o.Store.LoginSucceeded(ctx, u.ID, s.now()); err != nil {
		return nil, err
	}
	if err := s.setState(ctx, &sess, model.StateActive); err != nil {
		return nil, err
	}
	s.audit(ctx, u.Username, "otp_enroll", u.Username, ip, true, "")
	return codes, nil
}

// OTPVerify: need_otp 에서 인증 앱 코드 또는 복구 코드(1회용)
func (s *Service) OTPVerify(ctx context.Context, token, code, recovery, ip string) error {
	sess, u, err := s.stepSession(ctx, token, model.StateNeedOTP)
	if err != nil {
		return err
	}
	if err := s.otpGate(ctx, &sess, u, ip); err != nil {
		return err
	}
	if strings.TrimSpace(recovery) != "" {
		ok, err := s.o.Store.UseRecoveryHash(ctx, u.ID, RecoveryHash(u.ID, recovery)) // 있으면 지우고 true (원자적)
		if err != nil {
			return err
		}
		if !ok {
			return s.otpFail(ctx, &sess, u, ip, "otp_recovery", msgBadRecovery)
		}
		s.audit(ctx, u.Username, "otp_recovery", u.Username, ip, true, "복구 코드 사용")
	} else {
		secret, err := s.seal.open(u.ID, u.OTPSecret)
		if err != nil {
			return err
		}
		raw, err := DecodeSecret(secret)
		if err != nil {
			return err
		}
		step, ok := VerifyTOTP(raw, strings.TrimSpace(code), s.now(), u.OTPLastStep) // 마지막 스텝 이하는 건너뜀
		if ok {
			// 조건부 갱신: 같은 코드로 동시에 두 요청이 와도 저장된 스텝보다 큰 첫 요청만 통과
			if ok, err = s.o.Store.AdvanceOTPStep(ctx, u.ID, step); err != nil {
				return err
			}
		}
		if !ok {
			return s.otpFail(ctx, &sess, u, ip, "otp_verify", msgBadOTP)
		}
		s.audit(ctx, u.Username, "otp_verify", u.Username, ip, true, "")
	}
	if err := s.o.Store.LoginSucceeded(ctx, u.ID, s.now()); err != nil {
		return err
	}
	return s.setState(ctx, &sess, model.StateActive)
}

// otpGate: 계정이 잠겼으면 세션을 끊고, IP 상한이면 429
func (s *Service) otpGate(ctx context.Context, sess *model.Session, u model.User, ip string) error {
	now := s.now()
	if now.Before(u.LockedUntil) {
		_ = s.o.Store.DeleteSession(ctx, sess.Hash)
		return fail(http.StatusUnauthorized, msgOTPRestart)
	}
	if !s.ipl.Allow(ip, now) {
		return &Error{Status: http.StatusTooManyRequests, Msg: msgTooMany, State: sess.State}
	}
	return nil
}

// otpFail: OTP · 복구 코드 실패 — IP 실패 · 계정 실패(5회면 잠금) · 세션 실패(5회면 세션 끊기)
func (s *Service) otpFail(ctx context.Context, sess *model.Session, u model.User, ip, action, msg string) error {
	now := s.now()
	s.ipl.Fail(ip, now)
	s.audit(ctx, u.Username, action, u.Username, ip, false, "")
	locked, err := s.o.Store.RegisterFailure(ctx, u.ID, maxFailures, now.Add(lockFor))
	if err != nil {
		return err
	}
	sess.OTPFailures++
	if locked || sess.OTPFailures >= maxOTPFailures {
		if locked {
			s.audit(ctx, u.Username, "login_lock", u.Username, ip, false, "OTP 5회 실패 — 5분 잠금")
		}
		_ = s.o.Store.DeleteSession(ctx, sess.Hash)
		return fail(http.StatusUnauthorized, msgOTPRestart)
	}
	if err := s.o.Store.UpdateSession(ctx, *sess); err != nil {
		return err
	}
	return &Error{Status: http.StatusBadRequest, Msg: msg, State: sess.State}
}

// ---------- 로그아웃 · 나 ----------

func (s *Service) Logout(ctx context.Context, token, ip string) error {
	if token == "" {
		return nil
	}
	h := HashToken(token)
	sess, err := s.o.Store.GetSession(ctx, h)
	if errors.Is(err, store.ErrAuthNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	if err := s.o.Store.DeleteSession(ctx, h); err != nil {
		return err
	}
	name := sess.UserID
	if u, err := s.o.Store.GetUser(ctx, sess.UserID); err == nil {
		name = u.Username
	}
	s.audit(ctx, name, "logout", name, ip, true, "")
	return nil
}

type Me struct {
	State       model.SessionState
	User        model.User
	License     *model.License
	OTPRequired bool
}

func (s *Service) Me(ctx context.Context, token string) (Me, error) {
	sess, u, err := s.Session(ctx, token)
	if err != nil {
		return Me{}, err
	}
	l, err := s.o.Store.GetLicense(ctx)
	if err != nil {
		return Me{}, err
	}
	return Me{State: sess.State, User: u, License: l, OTPRequired: s.o.OTPRequired}, nil
}

// Locked: 계정이 지금 잠겨 있는지 (계정 목록 표시용)
func (s *Service) Locked(u model.User) bool { return s.now().Before(u.LockedUntil) }

// Purge: 만료 세션 정리 (주기적으로 부른다)
func (s *Service) Purge(ctx context.Context) (int64, error) {
	now := s.now()
	return s.o.Store.PurgeSessions(ctx, now.Add(-s.o.IdleTimeout), now.Add(-s.o.MaxAge))
}

func (s *Service) AuthAudit(ctx context.Context, q store.AuthAuditQuery) ([]model.AuthAudit, error) {
	return s.o.Store.ListAuthAudit(ctx, q)
}

// ---------- 계정 관리(관리자) ----------

func (s *Service) ListUsers(ctx context.Context) ([]model.User, error) {
	return s.o.Store.ListUsers(ctx)
}

type NewUser struct {
	Username    string     `json:"username"`
	DisplayName string     `json:"displayName"`
	Role        model.Role `json:"role"`
}

// CreateUser: 임시 비밀번호(1회 표시)로 만든다 — 첫 로그인에서 바꿔야 한다
func (s *Service) CreateUser(ctx context.Context, by Actor, in NewUser, ip string) (model.User, string, error) {
	in.Username, in.DisplayName = strings.TrimSpace(in.Username), strings.TrimSpace(in.DisplayName)
	if !validUsername(in.Username) {
		return model.User{}, "", fail(http.StatusBadRequest, "아이디는 영문 · 숫자 · . _ - 로 3~32자입니다")
	}
	if !in.Role.Valid() {
		return model.User{}, "", fail(http.StatusBadRequest, "role: admin | viewer")
	}
	if utf8.RuneCountInString(in.DisplayName) > 64 {
		return model.User{}, "", fail(http.StatusBadRequest, "표시 이름은 64자 이하입니다")
	}
	if in.DisplayName == "" {
		in.DisplayName = in.Username
	}
	temp, err := TempPassword()
	if err != nil {
		return model.User{}, "", err
	}
	u, err := s.newUser(in.Username, in.DisplayName, in.Role, temp)
	if err != nil {
		return model.User{}, "", err
	}
	if err := s.o.Store.CreateUser(ctx, u); err != nil {
		if errors.Is(err, store.ErrAuthConflict) {
			return model.User{}, "", fail(http.StatusConflict, msgDupUser)
		}
		return model.User{}, "", err
	}
	s.audit(ctx, by.Username, "user_create", u.Username, ip, true, "역할 "+string(u.Role))
	return u, temp, nil
}

type UserPatch struct {
	Role        *model.Role `json:"role"`
	Disabled    *bool       `json:"disabled"`
	DisplayName *string     `json:"displayName"`
}

// UpdateUser: 역할 · 비활성 · 표시 이름. 자기 비활성화 금지, 남은 활성 관리자가 0명이 되는 변경 금지.
// 비활성화하면 그 계정의 세션을 모두 끊는다. 역할은 요청마다 계정에서 읽으므로 바로 반영된다.
func (s *Service) UpdateUser(ctx context.Context, by Actor, id string, p UserPatch, ip string) (model.User, error) {
	s.userMu.Lock() // 「다른 관리자 수 확인 → 변경」 사이에 다른 변경이 끼지 않게
	defer s.userMu.Unlock()
	u, err := s.o.Store.GetUser(ctx, id)
	if errors.Is(err, store.ErrAuthNotFound) {
		return u, fail(http.StatusNotFound, msgNoUser)
	}
	if err != nil {
		return u, err
	}
	role, disabled, display := u.Role, u.Disabled, u.DisplayName
	if p.Role != nil {
		if !p.Role.Valid() {
			return u, fail(http.StatusBadRequest, "role: admin | viewer")
		}
		role = *p.Role
	}
	if p.Disabled != nil {
		disabled = *p.Disabled
	}
	if p.DisplayName != nil {
		display = strings.TrimSpace(*p.DisplayName)
		if display == "" || utf8.RuneCountInString(display) > 64 {
			return u, fail(http.StatusBadRequest, "표시 이름은 1~64자입니다")
		}
	}
	if disabled && !u.Disabled && id == by.ID {
		return u, fail(http.StatusBadRequest, msgSelfDisable)
	}
	wasActiveAdmin := u.Role == model.RoleAdmin && !u.Disabled
	staysActiveAdmin := role == model.RoleAdmin && !disabled
	if wasActiveAdmin && !staysActiveAdmin {
		others, err := s.otherActiveAdmins(ctx, id)
		if err != nil {
			return u, err
		}
		if others == 0 {
			s.audit(ctx, by.Username, "user_update", u.Username, ip, false, "마지막 관리자")
			return u, fail(http.StatusConflict, msgLastAdmin)
		}
	}
	if err := s.o.Store.UpdateProfile(ctx, id, display, role, disabled); err != nil {
		return u, err
	}
	if disabled && !u.Disabled {
		if err := s.o.Store.DeleteUserSessions(ctx, id); err != nil {
			return u, err
		}
	}
	s.audit(ctx, by.Username, "user_update", u.Username, ip, true,
		fmt.Sprintf("역할 %s→%s, 비활성 %v→%v", u.Role, role, u.Disabled, disabled))
	u.Role, u.Disabled, u.DisplayName = role, disabled, display
	return u, nil
}

func (s *Service) otherActiveAdmins(ctx context.Context, exceptID string) (int, error) {
	us, err := s.o.Store.ListUsers(ctx)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, x := range us {
		if x.ID != exceptID && x.Role == model.RoleAdmin && !x.Disabled {
			n++
		}
	}
	return n, nil
}

// ResetPassword: 임시 비밀번호(1회 표시) · 변경 필수 · 잠금 해제 · 세션 끊기
func (s *Service) ResetPassword(ctx context.Context, by Actor, id, ip string) (string, error) {
	u, err := s.o.Store.GetUser(ctx, id)
	if errors.Is(err, store.ErrAuthNotFound) {
		return "", fail(http.StatusNotFound, msgNoUser)
	}
	if err != nil {
		return "", err
	}
	temp, err := TempPassword()
	if err != nil {
		return "", err
	}
	h, err := HashPassword(temp, s.o.BcryptCost)
	if err != nil {
		return "", err
	}
	if err := s.o.Store.SetPassword(ctx, id, h, true); err != nil {
		return "", err
	}
	if err := s.o.Store.DeleteUserSessions(ctx, id); err != nil {
		return "", err
	}
	s.audit(ctx, by.Username, "user_reset_password", u.Username, ip, true, "")
	return temp, nil
}

// ResetOTP: 다음 로그인에서 OTP 를 다시 등록하게 한다 (휴대폰 분실 · 복구 코드 소진). 세션 끊기
func (s *Service) ResetOTP(ctx context.Context, by Actor, id, ip string) error {
	u, err := s.o.Store.GetUser(ctx, id)
	if errors.Is(err, store.ErrAuthNotFound) {
		return fail(http.StatusNotFound, msgNoUser)
	}
	if err != nil {
		return err
	}
	if err := s.o.Store.SetOTP(ctx, id, "", false, 0, nil); err != nil {
		return err
	}
	if err := s.o.Store.DeleteUserSessions(ctx, id); err != nil {
		return err
	}
	s.audit(ctx, by.Username, "user_reset_otp", u.Username, ip, true, "")
	return nil
}
