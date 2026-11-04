package auth

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/model"
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/store"
)

// devService: AUTH_DEV_MODE(11/04) 서비스 — make dev 와 같게 OTP 끔
func devService(t *testing.T, dev, otp bool) (*Service, *store.MemoryAuth) {
	t.Helper()
	st := store.NewMemoryAuth()
	c := &clock{t: time.Date(2026, 11, 4, 9, 0, 0, 0, time.UTC)}
	return New(Options{Store: st, DevMode: dev, OTPRequired: otp, BcryptCost: 4, Now: c.Now}), st
}

// Tier 1 — 개발 모드: 시드 admin/admin → 로그인 바로 active(비밀번호 변경 · 라이선스 단계 없음). 라이선스를 저장하지 않는다
func TestDevModeAdminAdminLogin(t *testing.T) {
	s, st := devService(t, true, false)
	ctx := t.Context()
	if created, err := s.SeedAdmin(ctx, "admin", "admin"); err != nil || !created {
		t.Fatalf("개발 모드는 admin/admin 시드 허용: %v %v", created, err)
	}
	u, err := st.GetUserByName(ctx, "admin")
	if err != nil || u.MustChangePW || u.Role != model.RoleAdmin || u.PwHash == "admin" {
		t.Fatalf("시드 계정: MustChangePW=%v role=%v %v", u.MustChangePW, u.Role, err)
	}
	r, err := login(t, s, "admin", "admin", "10.0.0.1")
	if err != nil || r.State != model.StateActive {
		t.Fatalf("로그인 → active: %v %v", r.State, err)
	}
	m, err := s.Me(ctx, r.Token)
	if err != nil || m.State != model.StateActive || m.User.MustChangePW {
		t.Fatalf("me: %+v %v", m, err)
	}
	if l, err := st.GetLicense(ctx); err != nil || l != nil {
		t.Fatalf("개발 모드는 라이선스를 만들어 저장하지 않는다: %+v %v", l, err)
	}
	// 조회자도 라이선스 없이 들어온다(라이선스 단계를 통과한 것으로 본다)
	by := actorOf(u)
	_, temp, err := s.CreateUser(ctx, by, NewUser{Username: "viewer1", DisplayName: "조회", Role: model.RoleViewer}, "10.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	r2, err := login(t, s, "viewer1", temp, "10.0.0.2")
	if err != nil || r2.State != model.StateNeedPassword {
		t.Fatalf("관리자가 만든 계정은 지금처럼 첫 비밀번호 변경: %v %v", r2.State, err)
	}
	if st2, err := s.ChangePassword(ctx, r2.Token, temp, "viewer-pass-1", "10.0.0.2"); err != nil || st2 != model.StateActive {
		t.Fatalf("조회자 비밀번호 변경 → active(라이선스 통과): %v %v", st2, err)
	}
}

// Tier 1 — 개발 모드에서도 길이 검사(5자 · 72바이트)는 그대로, 화면의 비밀번호 변경 규칙(ValidatePassword)도 그대로
func TestDevModeKeepsLengthAndChangeRules(t *testing.T) {
	for _, pw := range []string{"", "adm", strings.Repeat("a", 73)} {
		s, _ := devService(t, true, false)
		if _, err := s.SeedAdmin(t.Context(), "admin", pw); err == nil {
			t.Fatalf("개발 모드도 길이 %d 는 거부", len(pw))
		}
	}
	s, _ := devService(t, true, false)
	ctx := t.Context()
	if _, err := s.SeedAdmin(ctx, "admin", "admin"); err != nil {
		t.Fatal(err)
	}
	r, err := login(t, s, "admin", "admin", "10.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.ChangePassword(ctx, r.Token, "admin", "Admin", "10.0.0.1"); status(err) != http.StatusBadRequest {
		t.Fatalf("화면에서 아이디와 같은 비밀번호로 바꾸기는 막는다: %v", err)
	}
	if st, err := s.ChangePassword(ctx, r.Token, "admin", "dev-pass-2", "10.0.0.1"); err != nil || st != model.StateActive {
		t.Fatalf("다른 비밀번호로는 바뀐다: %v %v", st, err)
	}
}

// 개발 모드는 OTP 를 건드리지 않는다 — OTP 필수면 라이선스만 건너뛰고 OTP 등록 단계
func TestDevModeLeavesOTP(t *testing.T) {
	s, _ := devService(t, true, true)
	if _, err := s.SeedAdmin(t.Context(), "admin", "admin"); err != nil {
		t.Fatal(err)
	}
	if r, err := login(t, s, "admin", "admin", "10.0.0.1"); err != nil || r.State != model.StateNeedOTPEnroll {
		t.Fatalf("OTP 필수 → need_otp_enroll: %v %v", r.State, err)
	}
}

// Tier 1 — 개발 모드 끔(기본 · 실제 서버): admin/admin 시드 거부, 첫 로그인은 비밀번호 변경 → 라이선스 그대로
func TestDevModeOffKeepsRules(t *testing.T) {
	s, st := devService(t, false, false)
	ctx := t.Context()
	if _, err := s.SeedAdmin(ctx, "admin", "admin"); err == nil || !strings.Contains(err.Error(), "아이디와 달라야") {
		t.Fatalf("개발 모드가 아니면 admin/admin 거부: %v", err)
	}
	if created, err := s.SeedAdmin(ctx, "admin", adminPW); err != nil || !created {
		t.Fatal(created, err)
	}
	if u, _ := st.GetUserByName(ctx, "admin"); !u.MustChangePW {
		t.Fatal("시드 관리자는 첫 로그인에서 비밀번호 변경 필수")
	}
	r, err := login(t, s, "admin", adminPW, "10.0.0.1")
	if err != nil || r.State != model.StateNeedPassword {
		t.Fatalf("need_password: %v %v", r.State, err)
	}
	if st, err := s.ChangePassword(ctx, r.Token, adminPW, newPW, "10.0.0.1"); err != nil || st != model.StateNeedLicense {
		t.Fatalf("need_license: %v %v", st, err)
	}
}
