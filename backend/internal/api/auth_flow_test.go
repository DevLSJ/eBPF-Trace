package api

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/auth"
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/store"
)

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *fakeClock) Add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

const (
	flowAdminPW  = "initial-pass-1"
	flowNewPW    = "brand-new-pass-1"
	flowLicense  = "1234-5678-9012-3456"
	flowAdminTok = "admin-tok"
	devOrigin    = "http://localhost:5173"
)

type authEnv struct {
	srv   *httptest.Server
	svc   *auth.Service
	clock *fakeClock
}

// newAuthEnv: RegisterAuth + 보호 대상 더미 경로를 미들웨어로 감싼다 (main.go 가 할 조립과 같은 모양).
func newAuthEnv(t *testing.T, otp bool) *authEnv {
	t.Helper()
	c := &fakeClock{t: time.Date(2026, 10, 20, 9, 0, 0, 0, time.UTC)}
	svc := auth.New(auth.Options{Store: store.NewMemoryAuth(), OTPRequired: otp, BcryptCost: 4, Now: c.Now})
	if _, err := svc.SeedAdmin(t.Context(), "admin", flowAdminPW); err != nil {
		t.Fatal(err)
	}
	ok := func(code int) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			a, _ := auth.ActorFrom(r.Context())
			writeJSON(w, code, map[string]string{"actor": a.Name, "role": string(a.Role)})
		}
	}
	mux := http.NewServeMux()
	RegisterAuth(mux, AuthDeps{Auth: svc})
	mux.HandleFunc("GET /health", ok(200))
	mux.HandleFunc("GET /api/things", ok(200))
	mux.HandleFunc("POST /api/things", auth.RequireAdmin(ok(200)))
	mux.HandleFunc("DELETE /api/unwrapped", ok(200)) // 라우터가 RequireAdmin 을 빠뜨린 쓰기 — 미들웨어가 막아야 한다
	mux.HandleFunc("POST /api/proposals/{id}/preview", ok(200))
	mux.HandleFunc("POST /api/installs", ok(201)) // 실제로는 sandboxAuth — 미들웨어는 건너뛰기만 확인
	mux.HandleFunc("GET /ws/events", ok(200))
	h := auth.Middleware(mux, auth.MiddlewareOptions{
		Service: svc, AdminToken: flowAdminTok, AllowedOrigins: []string{devOrigin},
		Bypass: auth.Routes(SandboxPatterns...), ViewerWrites: auth.Routes(ViewerWritePatterns...),
	})
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return &authEnv{srv: srv, svc: svc, clock: c}
}

type browser struct {
	t      *testing.T
	env    *authEnv
	c      *http.Client
	origin string // 상태 변경 요청에 붙일 Origin ("" 이면 안 붙임)
}

func (e *authEnv) browser(t *testing.T) *browser {
	jar, _ := cookiejar.New(nil)
	return &browser{t: t, env: e, c: &http.Client{Jar: jar}, origin: e.srv.URL}
}

type reply struct {
	code int
	body map[string]any
	hdr  http.Header
}

func (b *browser) call(method, path, body string, hdr ...string) reply {
	b.t.Helper()
	req, _ := http.NewRequest(method, b.env.srv.URL+path, strings.NewReader(body))
	if method != "GET" && b.origin != "" {
		req.Header.Set("Origin", b.origin)
	}
	for i := 0; i+1 < len(hdr); i += 2 {
		req.Header.Set(hdr[i], hdr[i+1])
	}
	resp, err := b.c.Do(req)
	if err != nil {
		b.t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	r := reply{code: resp.StatusCode, hdr: resp.Header}
	_ = json.Unmarshal(raw, &r.body)
	return r
}

func (b *browser) must(want int, method, path, body string) reply {
	b.t.Helper()
	r := b.call(method, path, body)
	if r.code != want {
		b.t.Fatalf("%s %s: %d %v, want %d", method, path, r.code, r.body, want)
	}
	return r
}

func str(m map[string]any, k string) string { s, _ := m[k].(string); return s }

// activateAdmin: 초기 관리자 첫 로그인 → 비밀번호 → 라이선스 → (OTP 등록) → active. OTP 비밀값을 돌려준다
func activateAdmin(t *testing.T, e *authEnv, b *browser, otp bool) []byte {
	t.Helper()
	r := b.must(200, "POST", "/api/auth/login", `{"username":"admin","password":"`+flowAdminPW+`"}`)
	if str(r.body, "state") != "need_password" {
		t.Fatalf("첫 로그인: %v", r.body)
	}
	r = b.must(200, "POST", "/api/auth/password", `{"current":"`+flowAdminPW+`","next":"`+flowNewPW+`"}`)
	if str(r.body, "state") != "need_license" {
		t.Fatalf("비밀번호 뒤: %v", r.body)
	}
	b.must(400, "POST", "/api/auth/license", `{"key":"1234-5678-9012-345X"}`)
	r = b.must(200, "POST", "/api/auth/license", `{"key":"`+flowLicense+`"}`)
	if !otp {
		if str(r.body, "state") != "active" {
			t.Fatalf("OTP 끔: %v", r.body)
		}
		return nil
	}
	if str(r.body, "state") != "need_otp_enroll" {
		t.Fatalf("라이선스 뒤: %v", r.body)
	}
	r = b.must(200, "POST", "/api/auth/otp/enroll", "")
	secret := str(r.body, "secret")
	if !strings.HasPrefix(str(r.body, "uri"), "otpauth://totp/SupplyGuard:admin?") {
		t.Fatalf("uri: %v", r.body)
	}
	if r2 := b.must(200, "POST", "/api/auth/otp/enroll", ""); str(r2.body, "secret") != secret {
		t.Fatal("같은 세션 같은 비밀값")
	}
	raw, _ := auth.DecodeSecret(secret)
	b.must(400, "POST", "/api/auth/otp/enroll/confirm", `{"code":"000000"}`)
	r = b.must(200, "POST", "/api/auth/otp/enroll/confirm", `{"code":"`+auth.TOTP(raw, auth.Step(e.clock.Now()))+`"}`)
	if codes, _ := r.body["recoveryCodes"].([]any); len(codes) != 10 || str(r.body, "state") != "active" {
		t.Fatalf("복구 코드: %v", r.body)
	}
	return raw
}

// Tier 1 — 전체 흐름: 단계마다 다른 API 는 401(단계 표시), 마친 뒤에만 열린다. 두 번째 로그인은 OTP 만.
func TestAuthFlowHTTP(t *testing.T) {
	e := newAuthEnv(t, true)
	b := e.browser(t)
	b.must(200, "GET", "/health", "")
	b.must(401, "GET", "/api/things", "")
	b.must(401, "GET", "/ws/events", "")
	b.must(401, "GET", "/api/auth/me", "")

	r := b.must(200, "POST", "/api/auth/login", `{"username":"admin","password":"`+flowAdminPW+`"}`)
	ck := r.hdr.Get("Set-Cookie")
	for _, want := range []string{"sg_session=", "HttpOnly", "SameSite=Strict", "Path=/"} {
		if !strings.Contains(ck, want) {
			t.Fatalf("쿠키 %q 없음: %s", want, ck)
		}
	}
	if u, _ := r.body["user"].(map[string]any); str(u, "username") != "admin" || str(u, "role") != "admin" {
		t.Fatalf("user: %v", r.body)
	}
	if r := b.must(401, "GET", "/api/things", ""); str(r.body, "state") != "need_password" {
		t.Fatalf("단계 중 보호 API: %v", r.body)
	}
	b.must(409, "POST", "/api/auth/otp/enroll", "") // 단계 건너뛰기
	b.call("POST", "/api/auth/logout", "")

	b = e.browser(t)
	raw := activateAdmin(t, e, b, true)
	b.must(200, "GET", "/api/things", "")
	b.must(200, "GET", "/ws/events", "")
	if r := b.must(200, "GET", "/api/license", ""); str(r.body, "kind") != "trial" || str(r.body, "keyMasked") != "****-****-****-3456" {
		t.Fatalf("license: %v", r.body)
	}
	if r := b.must(200, "GET", "/api/auth/me", ""); str(r.body, "state") != "active" || r.body["license"] == nil {
		t.Fatalf("me: %v", r.body)
	}
	b.must(204, "POST", "/api/auth/logout", "")
	b.must(401, "GET", "/api/things", "")

	r = b.must(200, "POST", "/api/auth/login", `{"username":"admin","password":"`+flowNewPW+`"}`)
	if str(r.body, "state") != "need_otp" {
		t.Fatalf("두 번째 로그인: %v", r.body)
	}
	b.must(400, "POST", "/api/auth/otp", `{"code":"`+auth.TOTP(raw, auth.Step(e.clock.Now()))+`"}`) // 등록에 쓴 스텝 재사용
	e.clock.Add(30 * time.Second)
	if r := b.must(200, "POST", "/api/auth/otp", `{"code":"`+auth.TOTP(raw, auth.Step(e.clock.Now()))+`"}`); str(r.body, "state") != "active" {
		t.Fatalf("otp: %v", r.body)
	}
	b.must(200, "GET", "/api/things", "")
	ev := b.list("/api/auth/audit?limit=50")
	seen := map[string]bool{}
	for _, x := range ev {
		seen[str(x, "action")+":"+strconv.FormatBool(x["ok"] == true)] = true
	}
	for _, want := range []string{"login:true", "password_change:true", "license_register:true", "otp_enroll:true", "otp_enroll:false", "otp_verify:true", "otp_verify:false", "logout:true"} {
		if !seen[want] {
			t.Errorf("인증 감사에 %s 없음: %v", want, seen)
		}
	}
}

// Tier 1 — 조회자는 GET 만. 쓰기는 403(미리보기 같은 허용 경로 제외), 관리자 전용 API 도 403.
func TestViewerIsReadOnly(t *testing.T) {
	e := newAuthEnv(t, false)
	admin := e.browser(t)
	activateAdmin(t, e, admin, false)
	r := admin.must(201, "POST", "/api/users", `{"username":"viewer1","displayName":"조회 담당","role":"viewer"}`)
	temp := str(r.body, "tempPassword")
	if u, _ := r.body["user"].(map[string]any); str(u, "role") != "viewer" || u["mustChangePassword"] != true || temp == "" {
		t.Fatalf("create: %v", r.body)
	}
	v := e.browser(t)
	if r := v.must(200, "POST", "/api/auth/login", `{"username":"viewer1","password":"`+temp+`"}`); str(r.body, "state") != "need_password" {
		t.Fatalf("조회자 첫 로그인: %v", r.body)
	}
	v.must(200, "POST", "/api/auth/password", `{"current":"`+temp+`","next":"viewer-pass-1"}`)
	if r := v.must(200, "GET", "/api/things", ""); str(r.body, "role") != "viewer" || str(r.body, "actor") != "조회 담당" {
		t.Fatalf("actor: %v", r.body)
	}
	v.must(403, "POST", "/api/things", "")
	v.must(403, "DELETE", "/api/unwrapped", "")
	v.must(200, "POST", "/api/proposals/p1/preview", "")
	v.must(403, "GET", "/api/users", "")
	v.must(403, "GET", "/api/auth/audit", "")
	v.must(403, "POST", "/api/users", `{"username":"x1x","role":"admin"}`)
	admin.must(200, "POST", "/api/things", "")
	admin.must(200, "DELETE", "/api/unwrapped", "")
	// 관리자가 역할을 바꾸면 바로 반영된다 (요청마다 계정에서 읽음)
	id := ""
	for _, u := range admin.list("/api/users") {
		if str(u, "username") == "viewer1" {
			id = str(u, "id")
		}
	}
	admin.must(200, "PATCH", "/api/users/"+id, `{"role":"admin"}`)
	v.must(200, "POST", "/api/things", "")
}

func (b *browser) list(path string) []map[string]any {
	b.t.Helper()
	req, _ := http.NewRequest("GET", b.env.srv.URL+path, nil)
	resp, err := b.c.Do(req)
	if err != nil {
		b.t.Fatal(err)
	}
	defer resp.Body.Close()
	var out []map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return out
}

// Tier 1 — Bearer ADMIN_TOKEN 은 세션 없이 관리자. 틀린 Bearer 는 401. SANDBOX 경로는 미들웨어를 건너뛴다.
func TestBearerAdminToken(t *testing.T) {
	e := newAuthEnv(t, true)
	b := e.browser(t)
	b.origin = "http://evil.example" // Bearer 는 CSRF 검사 대상이 아니다
	if r := b.call("POST", "/api/things", "", "Authorization", "Bearer "+flowAdminTok); r.code != 200 || str(r.body, "actor") != "cli" {
		t.Fatalf("bearer: %d %v", r.code, r.body)
	}
	if r := b.call("GET", "/api/users", "", "Authorization", "Bearer "+flowAdminTok); r.code != 200 {
		t.Fatalf("bearer admin api: %d", r.code)
	}
	for _, bad := range []string{"Bearer wrong", "Bearer ", "Basic YWRtaW46eA=="} {
		if r := b.call("GET", "/api/things", "", "Authorization", bad); r.code != 401 {
			t.Fatalf("%q: %d", bad, r.code)
		}
	}
	b.origin = ""
	b.must(201, "POST", "/api/installs", "{}")
}

// 토큰을 정하지 않았으면 빈 Bearer 도 통과시키지 않는다.
func TestEmptyAdminTokenRejectsBearer(t *testing.T) {
	c := &fakeClock{t: time.Now()}
	svc := auth.New(auth.Options{Store: store.NewMemoryAuth(), BcryptCost: 4, Now: c.Now})
	h := auth.Middleware(http.NotFoundHandler(), auth.MiddlewareOptions{Service: svc})
	for _, v := range []string{"Bearer ", "Bearer x"} {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("GET", "/api/things", nil)
		r.Header.Set("Authorization", v)
		h.ServeHTTP(w, r)
		if w.Code != 401 {
			t.Fatalf("%q: %d", v, w.Code)
		}
	}
}

// Tier 1 — 쿠키 세션의 상태 변경은 Origin 이 허용 목록이거나 같은 호스트여야 한다. 없거나 null 이면 403.
func TestCSRFOriginCheck(t *testing.T) {
	e := newAuthEnv(t, false)
	b := e.browser(t)
	activateAdmin(t, e, b, false)
	for origin, want := range map[string]int{
		"http://evil.example": 403,
		"null":                403,
		"":                    403, // 쿠키는 있는데 Origin 이 없다
		devOrigin:             200,
		e.srv.URL:             200, // 같은 호스트
	} {
		b.origin = origin
		if r := b.call("POST", "/api/things", ""); r.code != want {
			t.Errorf("Origin %q: %d, want %d", origin, r.code, want)
		}
	}
	b.origin = "http://evil.example"
	b.must(200, "GET", "/api/things", "") // GET 은 검사하지 않는다
	b.must(403, "POST", "/api/auth/logout", "")
	// 로그인도 다른 출처면 거절 (login CSRF)
	n := e.browser(t)
	n.origin = "http://evil.example"
	n.must(403, "POST", "/api/auth/login", `{"username":"admin","password":"`+flowNewPW+`"}`)
	n.origin = ""
	n.must(200, "POST", "/api/auth/login", `{"username":"admin","password":"`+flowNewPW+`"}`) // 쿠키 없는 curl 로그인
}

// Tier 1 — 마지막 관리자 강등 · 자기 비활성화 금지 (HTTP).
func TestLastAdminHTTP(t *testing.T) {
	e := newAuthEnv(t, false)
	b := e.browser(t)
	activateAdmin(t, e, b, false)
	id := str(b.list("/api/users")[0], "id")
	b.must(409, "PATCH", "/api/users/"+id, `{"role":"viewer"}`)
	b.must(400, "PATCH", "/api/users/"+id, `{"disabled":true}`)
	b.must(400, "PATCH", "/api/users/"+id, `{"role":"root"}`)
	b.must(404, "PATCH", "/api/users/u_missing", `{"role":"viewer"}`)
	b.must(400, "PATCH", "/api/users/"+id, `{"unknown":1}`)
}

// 유휴 60분이 지나면 401 — 다시 로그인해야 한다.
func TestIdleExpiryHTTP(t *testing.T) {
	e := newAuthEnv(t, false)
	b := e.browser(t)
	activateAdmin(t, e, b, false)
	e.clock.Add(59 * time.Minute)
	b.must(200, "GET", "/api/things", "")
	e.clock.Add(61 * time.Minute)
	if r := b.must(401, "GET", "/api/things", ""); !strings.Contains(str(r.body, "error"), "만료") {
		t.Fatalf("만료 메시지: %v", r.body)
	}
}

// 조회자는 라이선스 등록 전에 로그인할 수 없다(403). 관리자 비밀번호 초기화 · OTP 초기화.
func TestViewerBeforeLicenseAndResets(t *testing.T) {
	e := newAuthEnv(t, true)
	cli := e.browser(t)
	cli.origin = ""
	bearer := []string{"Authorization", "Bearer " + flowAdminTok}
	r := cli.call("POST", "/api/users", `{"username":"viewer1","role":"viewer"}`, bearer...)
	if r.code != 201 {
		t.Fatalf("create: %d %v", r.code, r.body)
	}
	id, _ := r.body["user"].(map[string]any)["id"].(string)
	temp := str(r.body, "tempPassword")
	v := e.browser(t)
	if r := v.must(403, "POST", "/api/auth/login", `{"username":"viewer1","password":"`+temp+`"}`); !strings.Contains(str(r.body, "error"), "라이선스") {
		t.Fatalf("msg: %v", r.body)
	}
	r = cli.call("POST", "/api/users/"+id+"/reset-password", "", bearer...)
	if r.code != 200 || str(r.body, "tempPassword") == "" || str(r.body, "tempPassword") == temp {
		t.Fatalf("reset-password: %d %v", r.code, r.body)
	}
	if r := cli.call("POST", "/api/users/"+id+"/reset-otp", "", bearer...); r.code != 204 {
		t.Fatalf("reset-otp: %d", r.code)
	}
	r = cli.call("GET", "/api/auth/audit?limit=100", "", bearer...)
	if r.code != 200 {
		t.Fatalf("audit: %d", r.code)
	}
}

// 로그인 실패 메시지는 아이디가 있든 없든 같다.
func TestLoginFailureMessageUniform(t *testing.T) {
	e := newAuthEnv(t, true)
	b := e.browser(t)
	a := b.must(401, "POST", "/api/auth/login", `{"username":"admin","password":"wrong-pass-123"}`)
	n := b.must(401, "POST", "/api/auth/login", `{"username":"nobody","password":"wrong-pass-123"}`)
	if str(a.body, "error") != str(n.body, "error") {
		t.Fatalf("%v vs %v", a.body, n.body)
	}
	b.must(400, "POST", "/api/auth/login", `{"username":"admin"`)
}
