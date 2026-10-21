package api

import (
	"strings"
	"testing"
	"time"
)

const renewLicense = "9876-5432-1098-7654"

// Tier 1 — PUT /api/license: 관리자(쿠키) 200 · 조회자 403 · 형식 오류 400 · 익명 401 · Bearer ADMIN 200.
// 응답은 GET /api/license 와 같은 모양, 감사에 키 원문이 없다.
func TestRenewLicenseHTTP(t *testing.T) {
	e := newAuthEnv(t, false)
	admin := e.browser(t)
	activateAdmin(t, e, admin, false)
	before := admin.must(200, "GET", "/api/license", "")

	// 익명 401
	anon := e.browser(t)
	anon.must(401, "PUT", "/api/license", `{"key":"`+renewLicense+`"}`)

	// 관리자: 30분 뒤 갱신 → 만료일이 30분 늘고 가린 키가 바뀐다
	e.clock.Add(30 * time.Minute)
	r := admin.must(200, "PUT", "/api/license", `{"key":"`+renewLicense+`"}`)
	got := admin.must(200, "GET", "/api/license", "")
	for _, k := range []string{"keyMasked", "kind", "issuedAt", "expiresAt", "registeredBy"} {
		if str(r.body, k) == "" || str(r.body, k) != str(got.body, k) {
			t.Fatalf("응답 %s: PUT %v / GET %v", k, r.body, got.body)
		}
	}
	if r.body["expired"] != false || got.body["expired"] != false {
		t.Fatalf("expired: %v", r.body)
	}
	if str(r.body, "keyMasked") != "****-****-****-7654" {
		t.Fatalf("keyMasked: %v", r.body)
	}
	b4, _ := time.Parse(time.RFC3339, str(before.body, "expiresAt"))
	af, _ := time.Parse(time.RFC3339, str(r.body, "expiresAt"))
	if af.Sub(b4) != 30*time.Minute {
		t.Fatalf("만료일 새로 계산: %v → %v", b4, af)
	}
	if m := admin.must(200, "GET", "/api/auth/me", ""); str(m.body["license"].(map[string]any), "keyMasked") != "****-****-****-7654" {
		t.Fatalf("me: %v", m.body)
	}

	// 형식 오류 400 — 로그인 단계와 같은 문구
	if r := admin.must(400, "PUT", "/api/license", `{"key":"1234-5678"}`); !strings.Contains(str(r.body, "error"), "숫자 16자리") {
		t.Fatalf("형식 오류: %v", r.body)
	}

	// 조회자 403
	c := admin.must(201, "POST", "/api/users", `{"username":"viewer1","role":"viewer"}`)
	temp := str(c.body, "tempPassword")
	v := e.browser(t)
	v.must(200, "POST", "/api/auth/login", `{"username":"viewer1","password":"`+temp+`"}`)
	v.must(200, "POST", "/api/auth/password", `{"current":"`+temp+`","next":"viewer-pass-1"}`)
	v.must(403, "PUT", "/api/license", `{"key":"`+renewLicense+`"}`)

	// Bearer ADMIN(CLI) 200, 틀린 Bearer 401
	cli := e.browser(t)
	cli.origin = ""
	if r := cli.call("PUT", "/api/license", `{"key":"1111-2222-3333-4444"}`, "Authorization", "Bearer "+flowAdminTok); r.code != 200 || str(r.body, "registeredBy") != "cli" {
		t.Fatalf("bearer: %d %v", r.code, r.body)
	}
	if r := cli.call("PUT", "/api/license", `{"key":"1111-2222-3333-4444"}`, "Authorization", "Bearer wrong"); r.code != 401 {
		t.Fatalf("틀린 bearer: %d", r.code)
	}

	// 감사: license_renew 성공 · 실패, 키 원문 없음
	ev := admin.list("/api/auth/audit?limit=100")
	ok, bad := false, false
	for _, x := range ev {
		if str(x, "action") == "license_renew" {
			if x["ok"] == true {
				ok = true
			} else {
				bad = true
			}
		}
		for _, f := range []string{"target", "detail", "actor"} {
			for _, k := range []string{renewLicense, "9876543210987654", "1111-2222-3333-4444", "1111222233334444", "1234-5678"} {
				if strings.Contains(str(x, f), k) {
					t.Fatalf("감사 %s 에 키 원문: %v", f, x)
				}
			}
		}
	}
	if !ok || !bad {
		t.Fatalf("license_renew 감사 ok=%v fail=%v", ok, bad)
	}
}
