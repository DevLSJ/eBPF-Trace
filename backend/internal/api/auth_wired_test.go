package api

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/auth"
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/chat"
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/model"
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/osv"
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/review"
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/rules"
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/stats"
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/store"
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/ws"
)

const wiredSandboxTok = "sandbox-tok"

type wiredEnv struct {
	*authEnv
	rv     *review.Service
	engine *rules.Engine
	mem    *store.Memory
}

// newWiredEnv: main.go 와 같은 조립 — 바깥 mux(/ws/events + Router) 전체를 Secure 로 감싼다.
// 라우터는 실제 것(Review · Chat · Auth)이고, 리뷰 처리자는 RequesterName 으로 요청자를 읽는다.
func newWiredEnv(t *testing.T) *wiredEnv {
	t.Helper()
	c := &fakeClock{t: time.Date(2026, 10, 20, 9, 0, 0, 0, time.UTC)}
	mem := store.NewMemory()
	if err := mem.ReplacePolicies(t.Context(), seedRules); err != nil {
		t.Fatal(err)
	}
	engine := rules.New(seedRules)
	rv := review.New(review.Options{Store: mem, Policies: mem, Audit: mem, Engine: engine, EnforceKill: true, ActorFrom: RequesterName})
	if err := rv.Load(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := rv.Reload(t.Context()); err != nil {
		t.Fatal(err)
	}
	svc := auth.New(auth.Options{Store: store.NewMemoryAuth(), OTPRequired: false, BcryptCost: 4, Now: c.Now, TrustProxy: true})
	if _, err := svc.SeedAdmin(t.Context(), "admin", flowAdminPW); err != nil {
		t.Fatal(err)
	}
	chatSvc, err := chat.New(chat.Options{OllamaURL: chatOllama(t, nil).URL, Timeout: 5 * time.Second, Review: chatCases{}})
	if err != nil {
		t.Fatal(err)
	}
	hub := ws.NewHub([]string{devOrigin})
	t.Cleanup(hub.Close)

	mux := http.NewServeMux()
	mux.HandleFunc("GET /ws/events", hub.HandleWS)
	mux.Handle("/", Router(Deps{
		Engine: engine, Policies: mem, Audit: mem, Buffer: mem, Stats: stats.New().Snapshot,
		AdminToken: flowAdminTok, SandboxToken: wiredSandboxTok,
		Review: rv, Chat: chatSvc, Auth: svc, OSV: &osv.Client{URL: "http://127.0.0.1:1"},
		AllowedOrigins: []string{devOrigin},
	}))
	srv := httptest.NewServer(Secure(mux, SecureOptions{Auth: svc, AdminToken: flowAdminTok, AllowedOrigins: []string{devOrigin}}))
	t.Cleanup(srv.Close)
	return &wiredEnv{authEnv: &authEnv{srv: srv, svc: svc, clock: c}, rv: rv, engine: engine, mem: mem}
}

// bearer: 쿠키 없는 CLI 요청
func (e *wiredEnv) bearer(t *testing.T, tok, method, path, body string) reply {
	t.Helper()
	b := &browser{t: t, env: e.authEnv, c: &http.Client{}}
	if tok == "" {
		return b.call(method, path, body)
	}
	return b.call(method, path, body, "Authorization", "Bearer "+tok)
}

func wsDial(t *testing.T, e *wiredEnv, b *browser) (*http.Response, error) {
	t.Helper()
	u, _ := url.Parse(e.srv.URL)
	hdr := http.Header{"Origin": {devOrigin}}
	if b != nil {
		var parts []string
		for _, c := range b.c.Jar.Cookies(u) {
			parts = append(parts, c.Name+"="+c.Value)
		}
		hdr.Set("Cookie", strings.Join(parts, "; "))
	}
	conn, resp, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(e.srv.URL, "http")+"/ws/events", hdr)
	if conn != nil {
		conn.Close()
	}
	return resp, err
}

// Tier 1 — main 수준 조립: /health 만 공개, 나머지는 로그인(쿠키) · ADMIN_TOKEN(Bearer) · SANDBOX_TOKEN(sg-install 경로)
func TestWiredAuth(t *testing.T) {
	e := newWiredEnv(t)

	// 1. 익명: /health 만 열린다 (읽기 · 쓰기 · WebSocket 모두 401)
	anon := e.browser(t)
	anon.must(200, "GET", "/health", "")
	anon.must(401, "GET", "/api/info", "")
	anon.must(401, "GET", "/api/events/recent", "")
	anon.must(401, "GET", "/api/cases", "")
	anon.must(401, "POST", "/api/policies", rule)
	if resp, err := wsDial(t, e, nil); err == nil || resp == nil || resp.StatusCode != 401 {
		t.Fatalf("익명 /ws/events: %v %v", resp, err)
	}

	// 2. 쿠키 관리자: 로그인 → 비밀번호 → 라이선스 → active (OTP 끔)
	admin := e.browser(t)
	activateAdmin(t, e.authEnv, admin, false)
	if r := admin.must(200, "GET", "/api/info", ""); r.body["authRequired"] != true {
		t.Fatalf("info: %v", r.body)
	}
	admin.must(200, "GET", "/api/events/recent", "")
	if resp, err := wsDial(t, e, admin); err != nil {
		t.Fatalf("로그인한 /ws/events: %v %v", resp, err)
	}
	admin.must(200, "POST", "/api/policies", rule)
	if ch := e.rv.ListChanges(1)[0]; ch.By != "admin" {
		t.Fatalf("정책 저장 처리자: %+v", ch)
	}

	// 표시 이름을 바꾸면 처리자도 그 이름
	var adminID string
	admin.must(200, "GET", "/api/users", "")
	users, _ := e.svc.ListUsers(t.Context())
	for _, u := range users {
		if u.Username == "admin" {
			adminID = u.ID
		}
	}
	admin.must(200, "PATCH", "/api/users/"+adminID, `{"displayName":"홍길동"}`)

	// 3. SANDBOX_TOKEN: sg-install 경로만 (미들웨어를 건너뛰고 sandboxAuth 가 확인)
	if r := e.bearer(t, "", "POST", "/api/installs", installBody); r.code != 401 {
		t.Fatalf("토큰 없는 설치 보고: %d", r.code)
	}
	if r := e.bearer(t, flowAdminTok, "POST", "/api/installs", installBody); r.code != 401 {
		t.Fatalf("ADMIN_TOKEN 으로 설치 보고: %d", r.code)
	}
	if r := e.bearer(t, wiredSandboxTok, "POST", "/api/installs", installBody); r.code != 201 {
		t.Fatalf("설치 보고: %d %v", r.code, r.body)
	}
	if r := e.bearer(t, wiredSandboxTok, "GET", "/api/blocklist/check?manager=pip&package=requests", ""); r.code != 200 {
		t.Fatalf("차단 확인: %d %v", r.code, r.body)
	}
	if r := e.bearer(t, wiredSandboxTok, "GET", "/api/info", ""); r.code != 401 {
		t.Fatalf("SANDBOX_TOKEN 으로 일반 API: %d", r.code)
	}

	// 4. 쿠키 관리자 판정 → 처리자 = 계정 표시 이름
	v := e.engine.Evaluate(model.Event{Kind: model.KindConnect, ContainerID: strings.Repeat("a", 64), ContainerName: "sg-install-pip-1-1",
		ImageName: "python:3.12-slim", DstIP: "203.0.113.7", DstPort: 8081, DstHost: "cdn.reqeusts-update.test"})
	v.Enforced = true
	e.rv.Observe(&v)
	if v.CaseID == nil {
		t.Fatal("violation must open a case")
	}
	r := admin.must(200, "POST", "/api/cases/"+*v.CaseID+"/decide", `{"decision":"malicious"}`)
	cs, _ := r.body["case"].(map[string]any)
	prop, _ := r.body["proposal"].(map[string]any)
	if str(cs, "decidedBy") != "홍길동" || str(prop, "createdBy") != "홍길동" {
		t.Fatalf("판정 처리자: %v", r.body)
	}

	// 5. Bearer ADMIN_TOKEN(CLI) → 관리자, 처리자 「cli」
	if r := e.bearer(t, "wrong", "GET", "/api/info", ""); r.code != 401 {
		t.Fatalf("틀린 Bearer: %d", r.code)
	}
	if r := e.bearer(t, flowAdminTok, "GET", "/api/info", ""); r.code != 200 {
		t.Fatalf("CLI 읽기: %d", r.code)
	}
	r = e.bearer(t, flowAdminTok, "POST", "/api/proposals/"+str(prop, "id")+"/apply", "")
	if r.code != 200 {
		t.Fatalf("CLI 적용: %d %v", r.code, r.body)
	}
	if p, _ := r.body["proposal"].(map[string]any); str(p, "appliedBy") != "cli" {
		t.Fatalf("적용 처리자: %v", r.body)
	}
	if ch := e.rv.ListChanges(1)[0]; ch.By != "cli" {
		t.Fatalf("적용 변경 이력: %+v", ch)
	}
	bl := e.rv.Blocklist()
	if len(bl.Packages) == 0 || bl.Packages[0].By != "cli" {
		t.Fatalf("차단 항목 처리자: %+v", bl)
	}
	admin.must(204, "DELETE", "/api/blocklist/"+bl.Packages[0].List+"/"+bl.Packages[0].Value, "")
	if ch := e.rv.ListChanges(1)[0]; ch.By != "홍길동" {
		t.Fatalf("차단 해제 처리자: %+v", ch)
	}

	// 6. 조회자: 읽기 · 미리보기 · AI 도우미만, 쓰기는 403
	r = admin.must(201, "POST", "/api/users", `{"username":"viewer1","displayName":"김조회","role":"viewer"}`)
	temp := str(r.body, "tempPassword")
	viewer := e.browser(t)
	if r := viewer.must(200, "POST", "/api/auth/login", `{"username":"viewer1","password":"`+temp+`"}`); str(r.body, "state") != "need_password" {
		t.Fatalf("조회자 첫 로그인: %v", r.body)
	}
	if r := viewer.must(200, "POST", "/api/auth/password", `{"current":"`+temp+`","next":"viewer-pass-12"}`); str(r.body, "state") != "active" {
		t.Fatalf("조회자 비밀번호 뒤: %v", r.body)
	}
	viewer.must(200, "GET", "/api/info", "")
	viewer.must(200, "GET", "/api/cases", "")
	viewer.must(403, "POST", "/api/policies", rule)
	viewer.must(403, "PUT", "/api/policies", "rules: []")
	viewer.must(403, "DELETE", "/api/policies/shadow", "")
	viewer.must(403, "GET", "/api/users", "") // 관리자 전용 읽기
	if r := viewer.call("POST", "/api/policies/preview", rule); r.code == 401 || r.code == 403 {
		t.Fatalf("조회자 정책 미리보기: %d %v", r.code, r.body)
	}
	if r := viewer.call("POST", "/api/chat", `{"question":"판정 대기 요약해 줘","page":"/","history":[]}`); r.code != 200 {
		t.Fatalf("조회자 AI 도우미: %d %v", r.code, r.body)
	}

	// 7. 다른 출처(Vite dev)의 쿠키 요청: preflight 에 PATCH · credentials
	req, _ := http.NewRequest("OPTIONS", e.srv.URL+"/api/users/x", nil)
	req.Header.Set("Origin", devOrigin)
	req.Header.Set("Access-Control-Request-Method", "PATCH")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 204 || resp.Header.Get("Access-Control-Allow-Credentials") != "true" ||
		!strings.Contains(resp.Header.Get("Access-Control-Allow-Methods"), "PATCH") {
		t.Fatalf("preflight: %d %v", resp.StatusCode, resp.Header)
	}
}
