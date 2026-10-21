package auth

import (
	"errors"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/model"
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/store"
)

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) Add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

const (
	adminPW = "initial-pass-1"
	newPW   = "brand-new-pass-1"
	licKey  = "1234-5678-9012-3456"
)

func newTestService(t *testing.T, otp bool, key string) (*Service, *store.MemoryAuth, *clock) {
	t.Helper()
	st := store.NewMemoryAuth()
	c := &clock{t: time.Date(2026, 10, 20, 9, 0, 0, 0, time.UTC)}
	s := New(Options{Store: st, OTPRequired: otp, SecretKey: key, BcryptCost: 4, Now: c.Now})
	if created, err := s.SeedAdmin(t.Context(), "admin", adminPW); err != nil || !created {
		t.Fatalf("seed: %v %v", created, err)
	}
	return s, st, c
}

func status(err error) int {
	var e *Error
	if errors.As(err, &e) {
		return e.Status
	}
	if err == nil {
		return 0
	}
	return -1
}

func login(t *testing.T, s *Service, user, pw, ip string) (LoginResult, error) {
	t.Helper()
	return s.Login(t.Context(), LoginInput{Username: user, Password: pw, IP: ip, UA: "test"})
}

// activate: 초기 관리자 첫 로그인 → 비밀번호 → 라이선스 → OTP 등록 → active. 토큰 · 비밀값 · 복구 코드
func activate(t *testing.T, s *Service, c *clock) (string, []byte, []string) {
	t.Helper()
	ctx := t.Context()
	r, err := login(t, s, "admin", adminPW, "10.0.0.1")
	if err != nil || r.State != model.StateNeedPassword {
		t.Fatalf("login: %v %v", r.State, err)
	}
	st, err := s.ChangePassword(ctx, r.Token, adminPW, newPW, "10.0.0.1")
	if err != nil || st != model.StateNeedLicense {
		t.Fatalf("password: %v %v", st, err)
	}
	st, _, err = s.RegisterLicense(ctx, r.Token, licKey, "10.0.0.1")
	if err != nil || st != model.StateNeedOTPEnroll {
		t.Fatalf("license: %v %v", st, err)
	}
	sec, _, err := s.OTPEnroll(ctx, r.Token)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := DecodeSecret(sec)
	codes, err := s.OTPEnrollConfirm(ctx, r.Token, TOTP(raw, Step(c.Now())), "10.0.0.1")
	if err != nil || len(codes) != 10 {
		t.Fatalf("confirm: %v %d", err, len(codes))
	}
	if sess, _, err := s.Session(ctx, r.Token); err != nil || sess.State != model.StateActive {
		t.Fatalf("active: %v %v", sess.State, err)
	}
	return r.Token, raw, codes
}

func TestSeedAdminOnce(t *testing.T) {
	s, st, _ := newTestService(t, true, "")
	if created, err := s.SeedAdmin(t.Context(), "other", "another-pass-1"); err != nil || created {
		t.Fatalf("계정이 있으면 무시: %v %v", created, err)
	}
	u, err := st.GetUserByName(t.Context(), "admin")
	if err != nil || u.Role != model.RoleAdmin || !u.MustChangePW || u.PwHash == adminPW {
		t.Fatalf("초기 관리자: %+v %v", u, err)
	}
	if _, err := New(Options{Store: store.NewMemoryAuth(), BcryptCost: 4}).SeedAdmin(t.Context(), "admin", ""); err == nil {
		t.Fatal("빈 초기 비밀번호는 오류")
	}
}

// Tier 1 — 연속 5번 틀리면 5분 잠금. 잠긴 동안은 맞는 비밀번호도 거절, 5분 뒤 풀린다. 메시지는 아이디 존재 여부를 드러내지 않는다.
func TestLockoutAfterFiveFailures(t *testing.T) {
	s, _, c := newTestService(t, true, "")
	var wrongMsg string
	for i := range 5 {
		_, err := login(t, s, "admin", "wrong-password-x", "10.0.0."+string(rune('1'+i)))
		if status(err) != http.StatusUnauthorized {
			t.Fatalf("시도 %d: %v", i+1, err)
		}
		wrongMsg = err.Error()
	}
	if _, err := login(t, s, "admin", adminPW, "10.0.0.9"); status(err) != http.StatusUnauthorized || err.Error() != wrongMsg {
		t.Fatalf("잠금 중 맞는 비밀번호: %v", err)
	}
	if _, err := login(t, s, "nobody", "whatever-pass", "10.0.0.9"); err == nil || err.Error() != wrongMsg {
		t.Fatalf("없는 아이디도 같은 메시지: %v", err)
	}
	c.Add(5*time.Minute + time.Second)
	if _, err := login(t, s, "admin", adminPW, "10.0.0.9"); err != nil {
		t.Fatalf("5분 뒤: %v", err)
	}
	ev, _ := s.AuthAudit(t.Context(), 50)
	if !hasAction(ev, "login_lock", false) {
		t.Fatalf("잠금 감사 기록: %+v", ev)
	}
}

// 4번 틀리고 맞히면 실패 횟수가 초기화된다.
func TestFailureCountResetsOnSuccess(t *testing.T) {
	s, _, _ := newTestService(t, true, "")
	for range 4 {
		_, _ = login(t, s, "admin", "wrong-password-x", "10.0.0.1")
	}
	if _, err := login(t, s, "admin", adminPW, "10.0.0.1"); err != nil {
		t.Fatal(err)
	}
	for range 4 {
		_, _ = login(t, s, "admin", "wrong-password-x", "10.0.0.1")
	}
	if _, err := login(t, s, "admin", adminPW, "10.0.0.1"); err != nil {
		t.Fatalf("다시 4번은 잠기지 않음: %v", err)
	}
}

// IP 별 1분 20회 실패면 그 IP 는 1분 동안 429.
func TestIPRateLimit(t *testing.T) {
	s, _, c := newTestService(t, true, "")
	for i := range 20 {
		if _, err := login(t, s, "ghost"+string(rune('a'+i)), "x-password-1", "10.9.9.9"); status(err) != http.StatusUnauthorized {
			t.Fatalf("%d: %v", i, err)
		}
	}
	if _, err := login(t, s, "admin", adminPW, "10.9.9.9"); status(err) != http.StatusTooManyRequests {
		t.Fatalf("21번째: %v", err)
	}
	if _, err := login(t, s, "admin", adminPW, "10.9.9.8"); err != nil {
		t.Fatalf("다른 IP: %v", err)
	}
	c.Add(time.Minute)
	if _, err := login(t, s, "admin", adminPW, "10.9.9.9"); err != nil {
		t.Fatalf("1분 뒤: %v", err)
	}
}

func TestPasswordChangeRules(t *testing.T) {
	s, _, _ := newTestService(t, true, "")
	r, _ := login(t, s, "admin", adminPW, "10.0.0.1")
	ctx := t.Context()
	if _, err := s.ChangePassword(ctx, r.Token, "wrong-current-1", newPW, "10.0.0.1"); status(err) != http.StatusBadRequest {
		t.Fatalf("현재 비밀번호 틀림: %v", err)
	}
	if _, err := s.ChangePassword(ctx, r.Token, adminPW, "abcd", "10.0.0.1"); status(err) != http.StatusBadRequest {
		t.Fatalf("짧음: %v", err)
	}
	if _, err := s.ChangePassword(ctx, r.Token, adminPW, "ADMIN", "10.0.0.1"); status(err) != http.StatusBadRequest {
		t.Fatalf("아이디와 같음: %v", err)
	}
	if _, err := s.ChangePassword(ctx, r.Token, adminPW, adminPW, "10.0.0.1"); status(err) != http.StatusBadRequest {
		t.Fatalf("지금과 같음: %v", err)
	}
	// 비밀번호 단계 전에는 다른 단계 요청 불가
	if _, _, err := s.RegisterLicense(ctx, r.Token, licKey, "10.0.0.1"); status(err) != http.StatusConflict {
		t.Fatalf("단계 건너뛰기: %v", err)
	}
}

// 비밀번호를 바꾸면 바꾼 세션만 남고 같은 계정의 다른 세션은 끝난다(10/20 결정)
func TestPasswordChangeEndsOtherSessions(t *testing.T) {
	s, _, c := newTestService(t, true, "")
	ctx := t.Context()
	a, raw, _ := activate(t, s, c)
	c.Add(30 * time.Second)
	r, err := login(t, s, "admin", newPW, "10.0.0.2")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.OTPVerify(ctx, r.Token, TOTP(raw, Step(c.Now())), "", "10.0.0.2"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ChangePassword(ctx, a, newPW, "another-strong-pw-2", "10.0.0.1"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Session(ctx, a); err != nil {
		t.Fatalf("바꾼 세션은 남아야 함: %v", err)
	}
	if _, _, err := s.Session(ctx, r.Token); err == nil {
		t.Fatal("다른 기기 세션이 남아 있음")
	}
}

// 전체 상태 전이: 첫 로그인 → 비밀번호 → 라이선스 → OTP 등록 → active, 두 번째 로그인 → OTP → active.
// 등록에 쓴 코드는 같은 스텝 안에서 다시 쓸 수 없다.
func TestStateFlowAndOTPReuse(t *testing.T) {
	s, _, c := newTestService(t, true, "")
	ctx := t.Context()
	tok, raw, _ := activate(t, s, c)
	if err := s.Logout(ctx, tok, "10.0.0.1"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Session(ctx, tok); status(err) != http.StatusUnauthorized {
		t.Fatalf("로그아웃 뒤 세션: %v", err)
	}
	r, err := login(t, s, "admin", newPW, "10.0.0.1")
	if err != nil || r.State != model.StateNeedOTP {
		t.Fatalf("두 번째 로그인: %v %v", r.State, err)
	}
	if err := s.OTPVerify(ctx, r.Token, TOTP(raw, Step(c.Now())), "", "10.0.0.1"); status(err) != http.StatusBadRequest {
		t.Fatalf("등록에 쓴 스텝 재사용: %v", err)
	}
	c.Add(30 * time.Second)
	if err := s.OTPVerify(ctx, r.Token, TOTP(raw, Step(c.Now())), "", "10.0.0.1"); err != nil {
		t.Fatalf("다음 스텝: %v", err)
	}
	if sess, _, _ := s.Session(ctx, r.Token); sess.State != model.StateActive {
		t.Fatalf("active: %v", sess.State)
	}
	// 같은 코드로 또 다른 세션 — 거절
	r2, _ := login(t, s, "admin", newPW, "10.0.0.1")
	if err := s.OTPVerify(ctx, r2.Token, TOTP(raw, Step(c.Now())), "", "10.0.0.1"); err == nil {
		t.Fatal("다른 세션에서도 같은 스텝 재사용 거절")
	}
}

func TestOTPEnrollSameSecretInSession(t *testing.T) {
	s, _, _ := newTestService(t, true, "")
	ctx := t.Context()
	r, _ := login(t, s, "admin", adminPW, "10.0.0.1")
	_, _ = s.ChangePassword(ctx, r.Token, adminPW, newPW, "10.0.0.1")
	_, _, _ = s.RegisterLicense(ctx, r.Token, licKey, "10.0.0.1")
	a, uri, err := s.OTPEnroll(ctx, r.Token)
	b, _, _ := s.OTPEnroll(ctx, r.Token)
	if err != nil || a != b || !strings.Contains(uri, "secret="+a) {
		t.Fatalf("같은 세션 같은 비밀값: %q %q %v", a, b, err)
	}
	r2, _ := login(t, s, "admin", newPW, "10.0.0.1")
	if c, _, _ := s.OTPEnroll(ctx, r2.Token); c == a {
		t.Fatal("다른 세션은 새 비밀값")
	}
}

// 복구 코드는 1회용이다.
func TestRecoveryCodeOneTime(t *testing.T) {
	s, _, c := newTestService(t, true, "")
	ctx := t.Context()
	_, _, codes := activate(t, s, c)
	r, _ := login(t, s, "admin", newPW, "10.0.0.1")
	if err := s.OTPVerify(ctx, r.Token, "", strings.ToLower(codes[3]), "10.0.0.1"); err != nil {
		t.Fatalf("복구 코드: %v", err)
	}
	r2, _ := login(t, s, "admin", newPW, "10.0.0.1")
	if err := s.OTPVerify(ctx, r2.Token, "", codes[3], "10.0.0.1"); status(err) != http.StatusBadRequest {
		t.Fatalf("두 번째 사용: %v", err)
	}
	if err := s.OTPVerify(ctx, r2.Token, "", codes[4], "10.0.0.1"); err != nil {
		t.Fatalf("다른 코드: %v", err)
	}
	ev, _ := s.AuthAudit(ctx, 100)
	if !hasAction(ev, "otp_recovery", true) || !hasAction(ev, "otp_recovery", false) {
		t.Fatal("복구 코드 감사")
	}
}

// OTP 를 5번 틀리면 세션을 끊는다(계정도 5분 잠금).
func TestOTPFailuresEndSession(t *testing.T) {
	s, _, c := newTestService(t, true, "")
	ctx := t.Context()
	activate(t, s, c)
	r, _ := login(t, s, "admin", newPW, "10.0.0.1")
	for i := range 4 {
		if err := s.OTPVerify(ctx, r.Token, "000000", "", "10.0.0.1"); status(err) != http.StatusBadRequest {
			t.Fatalf("%d: %v", i, err)
		}
	}
	if err := s.OTPVerify(ctx, r.Token, "000000", "", "10.0.0.1"); status(err) != http.StatusUnauthorized {
		t.Fatalf("5번째: %v", err)
	}
	if _, _, err := s.Session(ctx, r.Token); err == nil {
		t.Fatal("세션이 끊겨야 함")
	}
}

// Tier 1 — 유휴 60분 · 절대 12시간 만료.
func TestSessionExpiry(t *testing.T) {
	s, _, c := newTestService(t, false, "")
	ctx := t.Context()
	r, _ := login(t, s, "admin", adminPW, "10.0.0.1")
	c.Add(59 * time.Minute)
	if _, _, err := s.Session(ctx, r.Token); err != nil {
		t.Fatalf("59분: %v", err)
	}
	c.Add(60*time.Minute + time.Second)
	if _, _, err := s.Session(ctx, r.Token); status(err) != http.StatusUnauthorized {
		t.Fatalf("유휴 60분 초과: %v", err)
	}
	r2, _ := login(t, s, "admin", adminPW, "10.0.0.1")
	for range 14 { // 50분마다 쓰면 유휴로는 안 끊기지만 12시간에서 끊긴다
		c.Add(50 * time.Minute)
		if _, _, err := s.Session(ctx, r2.Token); err != nil {
			t.Fatalf("12시간 전: %v", err)
		}
	}
	c.Add(50 * time.Minute) // 12h30m
	if _, _, err := s.Session(ctx, r2.Token); status(err) != http.StatusUnauthorized {
		t.Fatalf("절대 12시간: %v", err)
	}
}

// 라이선스가 없으면 조회자는 로그인할 수 없다(403). OTP 필수가 꺼져 있으면 라이선스 뒤 바로 active.
func TestViewerNeedsLicenseAndOTPOptional(t *testing.T) {
	s, _, _ := newTestService(t, false, "")
	ctx := t.Context()
	cli := CLIActor
	v, temp, err := s.CreateUser(ctx, cli, NewUser{Username: "viewer1", Role: model.RoleViewer}, "10.0.0.1")
	if err != nil || !v.MustChangePW || ValidatePassword("viewer1", temp) != nil {
		t.Fatalf("create: %+v %v", v, err)
	}
	if _, err := login(t, s, "viewer1", temp, "10.0.0.1"); status(err) != http.StatusForbidden || !strings.Contains(err.Error(), "라이선스") {
		t.Fatalf("라이선스 없이 조회자: %v", err)
	}
	r, _ := login(t, s, "admin", adminPW, "10.0.0.1")
	_, _ = s.ChangePassword(ctx, r.Token, adminPW, newPW, "10.0.0.1")
	if _, _, err := s.RegisterLicense(ctx, r.Token, "1234-5678", "10.0.0.1"); status(err) != http.StatusBadRequest {
		t.Fatalf("형식 오류 키: %v", err)
	}
	st, l, err := s.RegisterLicense(ctx, r.Token, licKey, "10.0.0.1")
	if err != nil || st != model.StateActive || l.Kind != "trial" || l.RegisteredBy != "admin" {
		t.Fatalf("OTP 끔 → active: %v %+v %v", st, l, err)
	}
	vr, err := login(t, s, "viewer1", temp, "10.0.0.1")
	if err != nil || vr.State != model.StateNeedPassword {
		t.Fatalf("조회자 첫 로그인: %v %v", vr.State, err)
	}
	if st, err := s.ChangePassword(ctx, vr.Token, temp, "viewer-pass-1", "10.0.0.1"); err != nil || st != model.StateActive {
		t.Fatalf("조회자 비밀번호 → active(라이선스 있음): %v %v", st, err)
	}
}

// Tier 1 — 자기 자신 비활성화 · 마지막 관리자 강등/비활성화 금지.
func TestLastAdminProtection(t *testing.T) {
	s, st, _ := newTestService(t, false, "")
	ctx := t.Context()
	admin, _ := st.GetUserByName(ctx, "admin")
	me := actorOf(admin)
	viewer, viewerRole, adminRole, yes := model.RoleViewer, model.RoleViewer, model.RoleAdmin, true
	_ = viewer
	if _, err := s.UpdateUser(ctx, me, admin.ID, UserPatch{Disabled: &yes}, ""); status(err) != http.StatusBadRequest {
		t.Fatalf("자기 비활성화: %v", err)
	}
	if _, err := s.UpdateUser(ctx, me, admin.ID, UserPatch{Role: &viewerRole}, ""); status(err) != http.StatusConflict {
		t.Fatalf("마지막 관리자 강등: %v", err)
	}
	if _, err := s.UpdateUser(ctx, CLIActor, admin.ID, UserPatch{Disabled: &yes}, ""); status(err) != http.StatusConflict {
		t.Fatalf("마지막 관리자 비활성화(CLI): %v", err)
	}
	second, _, err := s.CreateUser(ctx, me, NewUser{Username: "admin2", Role: adminRole}, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.CreateUser(ctx, me, NewUser{Username: "ADMIN2", Role: adminRole}, ""); status(err) != http.StatusConflict {
		t.Fatalf("중복 아이디: %v", err)
	}
	if u, err := s.UpdateUser(ctx, me, admin.ID, UserPatch{Role: &viewerRole}, ""); err != nil || u.Role != model.RoleViewer {
		t.Fatalf("관리자가 둘이면 강등 가능: %v", err)
	}
	if _, err := s.UpdateUser(ctx, CLIActor, second.ID, UserPatch{Disabled: &yes}, ""); status(err) != http.StatusConflict {
		t.Fatalf("이제 admin2 가 마지막: %v", err)
	}
	ev, _ := s.AuthAudit(ctx, 100)
	if !hasAction(ev, "user_update", true) || !hasAction(ev, "user_create", true) {
		t.Fatal("계정 변경 감사")
	}
}

// 비활성화 · 비밀번호 초기화 · OTP 초기화는 그 계정의 세션을 끊는다.
func TestAdminResetsEndSessions(t *testing.T) {
	s, _, _ := newTestService(t, false, "")
	ctx := t.Context()
	r, _ := login(t, s, "admin", adminPW, "10.0.0.1")
	_, _ = s.ChangePassword(ctx, r.Token, adminPW, newPW, "10.0.0.1")
	_, _, _ = s.RegisterLicense(ctx, r.Token, licKey, "10.0.0.1")
	v, temp, _ := s.CreateUser(ctx, CLIActor, NewUser{Username: "viewer1", Role: model.RoleViewer}, "")
	vr, _ := login(t, s, "viewer1", temp, "10.0.0.1")
	temp2, err := s.ResetPassword(ctx, CLIActor, v.ID, "")
	if err != nil || temp2 == temp {
		t.Fatal(err)
	}
	if _, _, err := s.Session(ctx, vr.Token); err == nil {
		t.Fatal("비밀번호 초기화 → 세션 끊김")
	}
	if _, err := login(t, s, "viewer1", temp, "10.0.0.1"); err == nil {
		t.Fatal("옛 임시 비밀번호 거절")
	}
	vr, _ = login(t, s, "viewer1", temp2, "10.0.0.1")
	yes := true
	if _, err := s.UpdateUser(ctx, CLIActor, v.ID, UserPatch{Disabled: &yes}, ""); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Session(ctx, vr.Token); err == nil {
		t.Fatal("비활성화 → 세션 끊김")
	}
	if _, err := login(t, s, "viewer1", temp2, "10.0.0.1"); status(err) != http.StatusUnauthorized {
		t.Fatalf("비활성 계정 로그인: %v", err)
	}
}

// AUTH_SECRET_KEY 가 있으면 저장된 OTP 비밀값은 암호문이고, 로그인은 그대로 된다.
func TestOTPSecretEncryptedAtRest(t *testing.T) {
	s, st, c := newTestService(t, true, "server-side-key")
	activate(t, s, c)
	u, _ := st.GetUserByName(t.Context(), "admin")
	if !strings.HasPrefix(u.OTPSecret, "v1:") || !u.OTPEnabled || len(u.RecoveryHashes) != 10 {
		t.Fatalf("저장 형식: %q %v %d", u.OTPSecret, u.OTPEnabled, len(u.RecoveryHashes))
	}
	sec, err := s.seal.open(u.ID, u.OTPSecret)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := DecodeSecret(sec)
	c.Add(30 * time.Second)
	r, _ := login(t, s, "admin", newPW, "10.0.0.1")
	if err := s.OTPVerify(t.Context(), r.Token, TOTP(raw, Step(c.Now())), "", "10.0.0.1"); err != nil {
		t.Fatal(err)
	}
}

func hasAction(ev []model.AuthAudit, action string, ok bool) bool {
	for _, e := range ev {
		if e.Action == action && e.OK == ok {
			return true
		}
	}
	return false
}
