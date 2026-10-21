package store

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/model"
)

// authStoreContract: MemoryAuth · Postgres 가 같이 지켜야 할 동작
func authStoreContract(t *testing.T, st AuthStore) {
	ctx := t.Context()
	at := time.Date(2026, 10, 20, 9, 0, 0, 0, time.UTC)
	u := model.User{ID: "u_1", Username: "Admin", DisplayName: "관리자", Role: model.RoleAdmin, PwHash: "h", MustChangePW: true, CreatedAt: at}
	if err := st.CreateUser(ctx, u); err != nil {
		t.Fatal(err)
	}
	if err := st.CreateUser(ctx, model.User{ID: "u_2", Username: "admin", Role: model.RoleViewer, PwHash: "h", CreatedAt: at}); !errors.Is(err, ErrAuthConflict) {
		t.Fatalf("아이디 대소문자 무시 중복: %v", err)
	}
	if n, _ := st.CountUsers(ctx); n != 1 {
		t.Fatalf("count %d", n)
	}
	got, err := st.GetUserByName(ctx, "ADMIN")
	if err != nil || got.ID != "u_1" || !got.MustChangePW {
		t.Fatalf("by name: %+v %v", got, err)
	}
	if _, err := st.GetUser(ctx, "u_x"); !errors.Is(err, ErrAuthNotFound) {
		t.Fatalf("없음: %v", err)
	}

	// 실패 5번째에 잠그고 횟수는 0 으로
	lock := at.Add(5 * time.Minute)
	for i := 1; i <= 5; i++ {
		locked, err := st.RegisterFailure(ctx, "u_1", 5, lock)
		if err != nil || locked != (i == 5) {
			t.Fatalf("실패 %d: locked=%v %v", i, locked, err)
		}
	}
	got, _ = st.GetUser(ctx, "u_1")
	if got.FailedCount != 0 || !got.LockedUntil.Equal(lock) {
		t.Fatalf("잠금: %d %v", got.FailedCount, got.LockedUntil)
	}
	_, _ = st.RegisterFailure(ctx, "u_1", 5, lock)
	if err := st.LoginSucceeded(ctx, "u_1", at); err != nil {
		t.Fatal(err)
	}
	if got, _ = st.GetUser(ctx, "u_1"); got.FailedCount != 0 || got.LastLoginAt == nil || !got.LastLoginAt.Equal(at) {
		t.Fatalf("성공: %+v", got)
	}
	if err := st.SetPassword(ctx, "u_1", "h2", false); err != nil {
		t.Fatal(err)
	}
	if got, _ = st.GetUser(ctx, "u_1"); got.PwHash != "h2" || got.MustChangePW || !got.LockedUntil.IsZero() {
		t.Fatalf("비밀번호: %+v", got)
	}

	// OTP: 스텝은 커질 때만, 동시에 같은 스텝은 하나만
	if err := st.SetOTP(ctx, "u_1", "SECRET", true, 100, []string{"a", "b"}); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		step int64
		ok   bool
	}{{100, false}, {99, false}, {101, true}, {101, false}} {
		if ok, err := st.AdvanceOTPStep(ctx, "u_1", c.step); err != nil || ok != c.ok {
			t.Fatalf("step %d: %v %v", c.step, ok, err)
		}
	}
	var wins atomic.Int32
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if ok, _ := st.AdvanceOTPStep(ctx, "u_1", 102); ok {
				wins.Add(1)
			}
		}()
	}
	wg.Wait()
	if wins.Load() != 1 {
		t.Fatalf("동시 같은 스텝 통과 수 %d, want 1", wins.Load())
	}
	// 복구 코드 1회용
	if ok, _ := st.UseRecoveryHash(ctx, "u_1", "a"); !ok {
		t.Fatal("첫 사용")
	}
	if ok, _ := st.UseRecoveryHash(ctx, "u_1", "a"); ok {
		t.Fatal("두 번째 사용")
	}
	if got, _ = st.GetUser(ctx, "u_1"); len(got.RecoveryHashes) != 1 || got.RecoveryHashes[0] != "b" || got.OTPSecret != "SECRET" || !got.OTPEnabled {
		t.Fatalf("otp: %+v", got)
	}
	if err := st.UpdateProfile(ctx, "u_1", "새 이름", model.RoleViewer, true); err != nil {
		t.Fatal(err)
	}
	if got, _ = st.GetUser(ctx, "u_1"); got.Role != model.RoleViewer || !got.Disabled || got.DisplayName != "새 이름" || got.OTPLastStep != 102 {
		t.Fatalf("profile: %+v", got)
	}
	if err := st.UpdateProfile(ctx, "u_x", "", model.RoleViewer, false); !errors.Is(err, ErrAuthNotFound) {
		t.Fatalf("없는 계정: %v", err)
	}

	// 세션
	s := model.Session{Hash: "h1", UserID: "u_1", State: model.StateNeedOTP, CreatedAt: at, LastSeen: at, IP: "10.0.0.1", UA: "ua"}
	if err := st.CreateSession(ctx, s); err != nil {
		t.Fatal(err)
	}
	s.State, s.OTPPending, s.OTPFailures = model.StateActive, "p", 2
	if err := st.UpdateSession(ctx, s); err != nil {
		t.Fatal(err)
	}
	if err := st.TouchSession(ctx, "h1", at.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	gs, err := st.GetSession(ctx, "h1")
	if err != nil || gs.State != model.StateActive || gs.OTPPending != "p" || gs.OTPFailures != 2 || !gs.LastSeen.Equal(at.Add(time.Minute)) {
		t.Fatalf("session: %+v %v", gs, err)
	}
	_ = st.CreateSession(ctx, model.Session{Hash: "h2", UserID: "u_1", State: model.StateActive, CreatedAt: at, LastSeen: at})
	if n, _ := st.PurgeSessions(ctx, at.Add(30*time.Second), at.Add(-time.Hour)); n != 1 {
		t.Fatalf("purge %d", n)
	}
	if err := st.DeleteUserSessions(ctx, "u_1"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.GetSession(ctx, "h1"); !errors.Is(err, ErrAuthNotFound) {
		t.Fatalf("세션 삭제: %v", err)
	}

	// 라이선스 단일 행
	if l, err := st.GetLicense(ctx); err != nil || l != nil {
		t.Fatalf("빈 라이선스: %v %v", l, err)
	}
	for _, m := range []string{"****-****-****-1111", "****-****-****-2222"} {
		if err := st.SaveLicense(ctx, model.License{KeyMasked: m, Kind: "trial", IssuedAt: at, ExpiresAt: at.AddDate(1, 0, 0), RegisteredBy: "admin"}); err != nil {
			t.Fatal(err)
		}
	}
	if l, _ := st.GetLicense(ctx); l == nil || l.KeyMasked != "****-****-****-2222" || !l.ExpiresAt.Equal(at.AddDate(1, 0, 0)) {
		t.Fatalf("license: %+v", l)
	}

	// 감사: 최신순 · limit
	for i, a := range []string{"login", "logout", "login"} {
		_ = st.AddAuthAudit(ctx, model.AuthAudit{At: at.Add(time.Duration(i) * time.Second), Actor: "admin", Action: a, OK: i != 1})
	}
	ev, err := st.ListAuthAudit(ctx, AuthAuditQuery{Limit: 2})
	if err != nil || len(ev) != 2 || ev[0].Action != "login" || ev[1].Action != "logout" || ev[1].OK || ev[0].ID <= ev[1].ID {
		t.Fatalf("audit: %+v %v", ev, err)
	}
}

func TestMemoryAuthContract(t *testing.T) { authStoreContract(t, NewMemoryAuth()) }

// authAuditFilterContract: 감사 필터(action · failed · before 커서 · limit) — 빈 감사 테이블에서 시작한다.
// e1~e6 을 차례로 넣고, 조건마다 걸러진 기록과 최신순(id 내림차순)을 detail 표식으로 확인한다.
func authAuditFilterContract(t *testing.T, st AuthStore) {
	ctx := t.Context()
	at := time.Date(2026, 10, 21, 9, 0, 0, 0, time.UTC)
	rows := []struct {
		action string
		ok     bool
	}{
		{"login", true}, {"login", false}, {"logout", true}, {"login", false}, {"otp_verify", false}, {"login", true},
	}
	for i, r := range rows {
		if err := st.AddAuthAudit(ctx, model.AuthAudit{At: at.Add(time.Duration(i) * time.Second), Actor: "admin", Action: r.action, OK: r.ok, Detail: fmt.Sprintf("e%d", i+1)}); err != nil {
			t.Fatal(err)
		}
	}
	all, err := st.ListAuthAudit(ctx, AuthAuditQuery{})
	if err != nil || len(all) != 6 {
		t.Fatalf("all: %+v %v", all, err)
	}
	id := map[string]int64{} // 표식 → id
	for _, e := range all {
		id[e.Detail] = e.ID
	}
	marks := func(q AuthAuditQuery) string {
		t.Helper()
		ev, err := st.ListAuthAudit(ctx, q)
		if err != nil {
			t.Fatalf("%+v: %v", q, err)
		}
		if ev == nil {
			t.Fatalf("%+v: nil (빈 결과도 [] 여야 JSON 이 null 이 아님)", q)
		}
		out := make([]string, 0, len(ev))
		for i, e := range ev {
			if i > 0 && e.ID >= ev[i-1].ID {
				t.Fatalf("%+v: 최신순 아님 %+v", q, ev)
			}
			out = append(out, e.Detail)
		}
		return strings.Join(out, ",")
	}
	cases := []struct {
		name string
		q    AuthAuditQuery
		want string
	}{
		{"조건 없음", AuthAuditQuery{}, "e6,e5,e4,e3,e2,e1"},
		{"action", AuthAuditQuery{Action: "login"}, "e6,e4,e2,e1"},
		{"failed", AuthAuditQuery{FailedOnly: true}, "e5,e4,e2"},
		{"action+failed", AuthAuditQuery{Action: "login", FailedOnly: true}, "e4,e2"},
		{"before", AuthAuditQuery{BeforeID: id["e4"]}, "e3,e2,e1"},
		{"before+action", AuthAuditQuery{BeforeID: id["e6"], Action: "login"}, "e4,e2,e1"},
		{"before+failed", AuthAuditQuery{BeforeID: id["e5"], FailedOnly: true}, "e4,e2"},
		{"셋 다", AuthAuditQuery{BeforeID: id["e4"], Action: "login", FailedOnly: true}, "e2"},
		{"limit 1쪽", AuthAuditQuery{Action: "login", Limit: 2}, "e6,e4"},
		{"limit 2쪽(마지막 행 id 를 before 로)", AuthAuditQuery{Action: "login", Limit: 2, BeforeID: id["e4"]}, "e2,e1"},
		{"끝 다음 쪽", AuthAuditQuery{BeforeID: id["e1"]}, ""},
		{"맞는 action 없음", AuthAuditQuery{Action: "user_create"}, ""},
	}
	for _, c := range cases {
		if got := marks(c.q); got != c.want {
			t.Errorf("%s: got %q want %q", c.name, got, c.want)
		}
	}
}

func TestMemoryAuthAuditFilter(t *testing.T) { authAuditFilterContract(t, NewMemoryAuth()) }
