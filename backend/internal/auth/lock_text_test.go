package auth

import (
	"fmt"
	"testing"

	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/store"
)

// 잠금 감사의 「내용」(설정 › 인증 감사 표에 그대로 보임, 11/09 「— 표기 없앰」): 원인 + 「로 5분 잠금」
func TestLockAuditDetailText(t *testing.T) {
	lockDetail := func(t *testing.T, s *Service) string {
		t.Helper()
		ev, err := s.AuthAudit(t.Context(), store.AuthAuditQuery{Limit: 100})
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range ev {
			if e.Action == "login_lock" {
				return e.Detail
			}
		}
		t.Fatalf("no login_lock audit: %+v", ev)
		return ""
	}

	t.Run("login", func(t *testing.T) {
		s, _, _ := newTestService(t, true, "")
		for i := range 5 {
			_, _ = login(t, s, "admin", "wrong-password-x", fmt.Sprintf("10.0.1.%d", i+1))
		}
		if got, want := lockDetail(t, s), "5회 연속 실패로 5분 잠금"; got != want {
			t.Fatalf("detail %q, want %q", got, want)
		}
	})

	t.Run("password change", func(t *testing.T) {
		s, _, _ := newTestService(t, true, "")
		r, err := login(t, s, "admin", adminPW, "10.0.2.1")
		if err != nil {
			t.Fatal(err)
		}
		for i := range 5 {
			_, _ = s.ChangePassword(t.Context(), r.Token, "wrong-current-x", newPW, fmt.Sprintf("10.0.2.%d", i+2))
		}
		if got, want := lockDetail(t, s), "비밀번호 변경 5회 실패로 5분 잠금"; got != want {
			t.Fatalf("detail %q, want %q", got, want)
		}
	})

	t.Run("otp", func(t *testing.T) {
		s, _, c := newTestService(t, true, "")
		activate(t, s, c)
		r, err := login(t, s, "admin", newPW, "10.0.3.1")
		if err != nil {
			t.Fatal(err)
		}
		for i := range 5 {
			_ = s.OTPVerify(t.Context(), r.Token, "000000", "", fmt.Sprintf("10.0.3.%d", i+2))
		}
		if got, want := lockDetail(t, s), "OTP 5회 실패로 5분 잠금"; got != want {
			t.Fatalf("detail %q, want %q", got, want)
		}
	})
}
