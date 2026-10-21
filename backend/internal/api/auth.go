package api

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/auth"
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/model"
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/store"
)

// SandboxPatterns: SANDBOX_TOKEN 으로 sandboxAuth 가 직접 확인하는 sg-install 경로 — auth.Middleware 의 Bypass 로 넘긴다
var SandboxPatterns = []string{
	"POST /api/installs",
	"PUT /api/installs/{id}/finish",
	"POST /api/installs/refused",
	"GET /api/blocklist/check",
}

// ViewerWritePatterns: 조회자에게도 허용하는 POST (아무것도 바꾸지 않는 미리보기) — auth.Middleware 의 ViewerWrites
var ViewerWritePatterns = []string{
	"POST /api/proposals/{id}/preview",
	"POST /api/cases/{id}/preview", // 판정 미리보기(W15)
	"POST /api/policies/preview",
	ChatPattern, // AI 도우미 질문 — 읽기 전용
}

type AuthDeps struct {
	Auth *auth.Service
}

// RegisterAuth: 로그인 단계 · 라이선스 · 계정 관리 · 인증 감사 경로.
// /api/auth/* 단계 경로는 auth.PublicPatterns 라 미들웨어가 통과시키고, 핸들러가 세션 단계를 직접 확인한다.
// 나머지(/api/license · /api/users · /api/auth/audit)는 미들웨어의 active 세션(또는 ADMIN_TOKEN) 뒤에서만 열린다.
func RegisterAuth(mux *http.ServeMux, d AuthDeps) {
	a := &authHandlers{s: d.Auth}
	mux.HandleFunc("POST /api/auth/login", a.login)
	mux.HandleFunc("GET /api/auth/me", a.me)
	mux.HandleFunc("POST /api/auth/password", a.password)
	mux.HandleFunc("POST /api/auth/license", a.license)
	mux.HandleFunc("POST /api/auth/otp/enroll", a.otpEnroll)
	mux.HandleFunc("POST /api/auth/otp/enroll/confirm", a.otpConfirm)
	mux.HandleFunc("POST /api/auth/otp", a.otp)
	mux.HandleFunc("POST /api/auth/logout", a.logout)

	mux.HandleFunc("GET /api/license", requireActor(a.getLicense))
	mux.HandleFunc("PUT /api/license", auth.RequireAdmin(a.renewLicense)) // 갱신(W21): 관리자 · CLI Bearer 만
	mux.HandleFunc("GET /api/auth/audit", auth.RequireAdmin(a.audit))
	mux.HandleFunc("GET /api/users", auth.RequireAdmin(a.listUsers))
	mux.HandleFunc("POST /api/users", auth.RequireAdmin(a.createUser))
	mux.HandleFunc("PATCH /api/users/{id}", auth.RequireAdmin(a.patchUser))
	mux.HandleFunc("POST /api/users/{id}/reset-password", auth.RequireAdmin(a.resetPassword))
	mux.HandleFunc("POST /api/users/{id}/reset-otp", auth.RequireAdmin(a.resetOTP))
}

// requireActor: 미들웨어를 거친 요청만 (미들웨어 없이 조립됐을 때 열리지 않게 한 겹 더)
func requireActor(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if _, ok := auth.ActorFrom(r.Context()); !ok {
			writeErr(w, http.StatusUnauthorized, "로그인이 필요합니다")
			return
		}
		next(w, r)
	}
}

type authHandlers struct{ s *auth.Service }

type userBrief struct {
	ID          string     `json:"id"`
	Username    string     `json:"username"`
	DisplayName string     `json:"displayName"`
	Role        model.Role `json:"role"`
}

func brief(u model.User) userBrief {
	return userBrief{ID: u.ID, Username: u.Username, DisplayName: u.DisplayName, Role: u.Role}
}

type userView struct {
	userBrief
	Disabled           bool       `json:"disabled"`
	OTPEnabled         bool       `json:"otpEnabled"`
	MustChangePassword bool       `json:"mustChangePassword"`
	Locked             bool       `json:"locked"`
	CreatedAt          time.Time  `json:"createdAt"`
	LastLoginAt        *time.Time `json:"lastLoginAt"`
}

func (a *authHandlers) view(u model.User) userView {
	return userView{userBrief: brief(u), Disabled: u.Disabled, OTPEnabled: u.OTPEnabled,
		MustChangePassword: u.MustChangePW, Locked: a.s.Locked(u), CreatedAt: u.CreatedAt, LastLoginAt: u.LastLoginAt}
}

type licenseView struct {
	model.License
	Expired bool `json:"expired"`
}

func (a *authHandlers) licView(l *model.License) *licenseView {
	if l == nil {
		return nil
	}
	return &licenseView{License: *l, Expired: a.s.Expired(*l)}
}

func (a *authHandlers) login(w http.ResponseWriter, r *http.Request) {
	var in struct{ Username, Password string }
	if !decodeJSON(w, r, &in) {
		return
	}
	res, err := a.s.Login(r.Context(), auth.LoginInput{Username: in.Username, Password: in.Password,
		IP: a.s.ClientIP(r), UA: r.UserAgent(), OldToken: auth.TokenFrom(r)})
	if err != nil {
		auth.WriteError(w, err)
		return
	}
	a.s.SetCookie(w, res.Token)
	writeJSON(w, http.StatusOK, map[string]any{"state": res.State, "user": brief(res.User)})
}

func (a *authHandlers) me(w http.ResponseWriter, r *http.Request) {
	m, err := a.s.Me(r.Context(), auth.TokenFrom(r))
	if err != nil {
		auth.WriteError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"state": m.State, "user": brief(m.User), "mustChangePassword": m.User.MustChangePW,
		"license": a.licView(m.License), "otpRequired": m.OTPRequired,
	})
}

func (a *authHandlers) password(w http.ResponseWriter, r *http.Request) {
	var in struct{ Current, Next string }
	if !decodeJSON(w, r, &in) {
		return
	}
	st, err := a.s.ChangePassword(r.Context(), auth.TokenFrom(r), in.Current, in.Next, a.s.ClientIP(r))
	if err != nil {
		auth.WriteError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"state": st})
}

func (a *authHandlers) license(w http.ResponseWriter, r *http.Request) {
	var in struct{ Key string }
	if !decodeJSON(w, r, &in) {
		return
	}
	st, l, err := a.s.RegisterLicense(r.Context(), auth.TokenFrom(r), in.Key, a.s.ClientIP(r))
	if err != nil {
		auth.WriteError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"state": st, "license": a.licView(&l)})
}

func (a *authHandlers) otpEnroll(w http.ResponseWriter, r *http.Request) {
	secret, uri, err := a.s.OTPEnroll(r.Context(), auth.TokenFrom(r))
	if err != nil {
		auth.WriteError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"secret": secret, "uri": uri})
}

func (a *authHandlers) otpConfirm(w http.ResponseWriter, r *http.Request) {
	var in struct{ Code string }
	if !decodeJSON(w, r, &in) {
		return
	}
	codes, err := a.s.OTPEnrollConfirm(r.Context(), auth.TokenFrom(r), in.Code, a.s.ClientIP(r))
	if err != nil {
		auth.WriteError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"state": model.StateActive, "recoveryCodes": codes})
}

func (a *authHandlers) otp(w http.ResponseWriter, r *http.Request) {
	var in struct{ Code, Recovery string }
	if !decodeJSON(w, r, &in) {
		return
	}
	if err := a.s.OTPVerify(r.Context(), auth.TokenFrom(r), in.Code, in.Recovery, a.s.ClientIP(r)); err != nil {
		auth.WriteError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"state": model.StateActive})
}

func (a *authHandlers) logout(w http.ResponseWriter, r *http.Request) {
	if err := a.s.Logout(r.Context(), auth.TokenFrom(r), a.s.ClientIP(r)); err != nil {
		auth.WriteError(w, err)
		return
	}
	a.s.ClearCookie(w)
	w.WriteHeader(http.StatusNoContent)
}

func (a *authHandlers) getLicense(w http.ResponseWriter, r *http.Request) {
	l, err := a.s.License(r.Context())
	if err != nil {
		serverErr(w, "license", err)
		return
	}
	if l == nil {
		writeErr(w, http.StatusNotFound, "등록된 라이선스가 없습니다")
		return
	}
	writeJSON(w, http.StatusOK, a.licView(l))
}

// renewLicense: 새 키로 바꾼다. 응답은 GET /api/license 와 같은 모양
func (a *authHandlers) renewLicense(w http.ResponseWriter, r *http.Request) {
	var in struct{ Key string }
	if !decodeJSON(w, r, &in) {
		return
	}
	by, _ := auth.ActorFrom(r.Context())
	l, err := a.s.RenewLicense(r.Context(), by, in.Key, a.s.ClientIP(r))
	if err != nil {
		auth.WriteError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, a.licView(&l))
}

// audit: GET /api/auth/audit?action=&failed=1&before=<id>&limit= — 최신순. 응답 모양은 그대로(기록 배열).
// 「더 보기」는 화면이 마지막 행 id 를 before 로 보낸다. 잘못된 action · failed · before 는 400, limit 은 예전처럼 관대하게
func (a *authHandlers) audit(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	aq := store.AuthAuditQuery{Action: q.Get("action")}
	aq.Limit, _ = strconv.Atoi(q.Get("limit"))
	if aq.Action != "" && !auth.ValidAuditAction(aq.Action) {
		writeErr(w, http.StatusBadRequest, "action: "+strings.Join(auth.AuditActions, " | "))
		return
	}
	switch q.Get("failed") {
	case "", "0", "false":
	case "1", "true":
		aq.FailedOnly = true
	default:
		writeErr(w, http.StatusBadRequest, "failed: 1 | true")
		return
	}
	if s := q.Get("before"); s != "" {
		n, err := strconv.ParseInt(s, 10, 64)
		if err != nil || n <= 0 {
			writeErr(w, http.StatusBadRequest, "before: 양의 정수(기록 id)")
			return
		}
		aq.BeforeID = n
	}
	ev, err := a.s.AuthAudit(r.Context(), aq)
	if err != nil {
		serverErr(w, "auth audit", err)
		return
	}
	writeJSON(w, http.StatusOK, ev)
}

func (a *authHandlers) listUsers(w http.ResponseWriter, r *http.Request) {
	us, err := a.s.ListUsers(r.Context())
	if err != nil {
		serverErr(w, "list users", err)
		return
	}
	out := make([]userView, 0, len(us))
	for _, u := range us {
		out = append(out, a.view(u))
	}
	writeJSON(w, http.StatusOK, out)
}

func (a *authHandlers) createUser(w http.ResponseWriter, r *http.Request) {
	var in auth.NewUser
	if !decodeJSON(w, r, &in) {
		return
	}
	by, _ := auth.ActorFrom(r.Context())
	u, temp, err := a.s.CreateUser(r.Context(), by, in, a.s.ClientIP(r))
	if err != nil {
		auth.WriteError(w, err)
		return
	}
	// 임시 비밀번호는 이 응답에서 한 번만 보여 준다 (저장은 해시만)
	writeJSON(w, http.StatusCreated, map[string]any{"user": a.view(u), "tempPassword": temp})
}

func (a *authHandlers) patchUser(w http.ResponseWriter, r *http.Request) {
	var in auth.UserPatch
	if !decodeJSON(w, r, &in) {
		return
	}
	by, _ := auth.ActorFrom(r.Context())
	u, err := a.s.UpdateUser(r.Context(), by, r.PathValue("id"), in, a.s.ClientIP(r))
	if err != nil {
		auth.WriteError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, a.view(u))
}

func (a *authHandlers) resetPassword(w http.ResponseWriter, r *http.Request) {
	by, _ := auth.ActorFrom(r.Context())
	temp, err := a.s.ResetPassword(r.Context(), by, r.PathValue("id"), a.s.ClientIP(r))
	if err != nil {
		auth.WriteError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"tempPassword": temp})
}

func (a *authHandlers) resetOTP(w http.ResponseWriter, r *http.Request) {
	by, _ := auth.ActorFrom(r.Context())
	if err := a.s.ResetOTP(r.Context(), by, r.PathValue("id"), a.s.ClientIP(r)); err != nil {
		auth.WriteError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
