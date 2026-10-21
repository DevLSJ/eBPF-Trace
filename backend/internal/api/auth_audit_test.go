package api

import (
	"strconv"
	"testing"
)

// Tier 1 — GET /api/auth/audit 필터: action · failed · before(최신순 커서) · limit.
// 기대값은 전체 목록을 테스트에서 같은 조건으로 거른 것과 비교한다. 잘못된 값은 400.
func TestAuthAuditFilterHTTP(t *testing.T) {
	e := newAuthEnv(t, false)
	admin := e.browser(t)
	activateAdmin(t, e, admin, false) // login 성공 · password_change · license_register 실패/성공

	// 로그인 실패 3건 (잠금 5회 미만)
	other := e.browser(t)
	other.must(401, "POST", "/api/auth/login", `{"username":"admin","password":"wrong-pass-1"}`)
	other.must(401, "POST", "/api/auth/login", `{"username":"nobody","password":"wrong-pass-1"}`)
	other.must(401, "POST", "/api/auth/login", `{"username":"admin","password":"wrong-pass-2"}`)

	all := admin.list("/api/auth/audit?limit=1000")
	pick := func(keep func(map[string]any) bool) []string {
		out := []string{}
		for _, x := range all {
			if keep(x) {
				out = append(out, idOf(x))
			}
		}
		return out
	}
	ids := func(path string) []string {
		t.Helper()
		out := []string{}
		for _, x := range admin.list(path) {
			out = append(out, idOf(x))
		}
		return out
	}
	failedLogin := func(x map[string]any) bool { return str(x, "action") == "login" && x["ok"] == false }

	want := pick(failedLogin)
	if len(want) != 3 {
		t.Fatalf("준비: 실패 로그인 %d건 %v", len(want), all)
	}
	if got := ids("/api/auth/audit?failed=1&action=login"); !same(got, want) {
		t.Fatalf("failed=1&action=login: %v want %v", got, want)
	}
	if got := ids("/api/auth/audit?failed=true&action=login"); !same(got, want) {
		t.Fatalf("failed=true: %v want %v", got, want)
	}
	// before = 가장 최근 실패 로그인 id → 나머지 2건
	if got := ids("/api/auth/audit?failed=1&action=login&before=" + want[0]); !same(got, want[1:]) {
		t.Fatalf("before: %v want %v", got, want[1:])
	}
	// 「더 보기」: limit=1 로 한 장씩, 마지막 행 id 를 before 로
	if got := ids("/api/auth/audit?failed=1&action=login&limit=1&before=" + want[0]); !same(got, want[1:2]) {
		t.Fatalf("limit+before: %v want %v", got, want[1:2])
	}
	// failed 만: ok=false 전부 (license_register 실패 포함)
	if got, w := ids("/api/auth/audit?failed=1"), pick(func(x map[string]any) bool { return x["ok"] == false }); !same(got, w) || len(w) != 4 {
		t.Fatalf("failed=1: %v want %v", got, w)
	}
	// action 만
	if got, w := ids("/api/auth/audit?action=license_register"), pick(func(x map[string]any) bool { return str(x, "action") == "license_register" }); !same(got, w) || len(w) != 2 {
		t.Fatalf("action=license_register: %v want %v", got, w)
	}
	// failed=0 · false · 빈 값은 거르지 않음
	for _, v := range []string{"0", "false", ""} {
		if got := ids("/api/auth/audit?limit=1000&failed=" + v); !same(got, pick(func(map[string]any) bool { return true })) {
			t.Fatalf("failed=%q: %v", v, got)
		}
	}

	// 잘못된 값 400
	for _, q := range []string{
		"before=abc", "before=0", "before=-3", "before=1.5",
		"action=nope", "action=LOGIN", "action=login,logout",
		"failed=yes", "failed=2",
	} {
		admin.must(400, "GET", "/api/auth/audit?"+q, "")
	}
}

func idOf(x map[string]any) string {
	f, _ := x["id"].(float64)
	return strconv.FormatInt(int64(f), 10)
}

func same(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
