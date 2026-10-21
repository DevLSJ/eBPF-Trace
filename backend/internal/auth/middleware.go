package auth

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
)

// CookieName: 세션 쿠키 (HttpOnly · SameSite=Strict · Path=/ · AUTH_COOKIE_SECURE 면 Secure)
const CookieName = "sg_session"

// PublicPatterns: 세션 없이(또는 active 전 단계에서) 부를 수 있는 경로. 단계 확인은 각 핸들러가 Service 로 한다.
var PublicPatterns = []string{
	"GET /health",
	"POST /api/auth/login",
	"GET /api/auth/me",
	"POST /api/auth/password",
	"POST /api/auth/license",
	"POST /api/auth/otp/enroll",
	"POST /api/auth/otp/enroll/confirm",
	"POST /api/auth/otp",
	"POST /api/auth/logout",
}

type MiddlewareOptions struct {
	Service *Service
	// AdminToken: CLI · 자동화용 Bearer — 관리자(CLIActor)로 통과. 비어 있으면 Bearer 는 모두 401
	AdminToken string
	// AllowedOrigins: 쿠키 세션의 상태 변경 요청에서 받을 Origin (ALLOWED_ORIGINS). 같은 호스트는 따로 허용
	AllowedOrigins []string
	// Public: nil 이면 Routes(PublicPatterns...)
	Public func(*http.Request) bool
	// Bypass: 미들웨어를 건너뛰고 핸들러가 직접 인증하는 경로 (SANDBOX_TOKEN 의 sg-install 보고 · 차단 확인)
	Bypass func(*http.Request) bool
	// ViewerWrites: 조회자에게도 허용할 상태 변경 메서드 경로 (바꾸지 않는 POST — 미리보기 등). nil 이면 없음
	ViewerWrites func(*http.Request) bool
}

// Middleware: /health 와 로그인 단계 경로를 뺀 전부를 보호한다.
//
//  1. Bypass 경로 → 그대로 넘김 (핸들러의 sandboxAuth 가 SANDBOX_TOKEN 확인)
//  2. Authorization: Bearer → ADMIN_TOKEN 과 상수 시간 비교, 맞으면 CLIActor(관리자), 틀리면 401
//  3. 쿠키로 오는 상태 변경 요청(POST/PUT/PATCH/DELETE) → Origin 확인 (CSRF)
//  4. Public 경로 → 그대로 넘김
//  5. 세션 쿠키 → active 세션이어야 함, 계정 역할로 Actor. 조회자의 상태 변경은 403
func Middleware(next http.Handler, o MiddlewareOptions) http.Handler {
	if o.Public == nil {
		o.Public = Routes(PublicPatterns...)
	}
	never := func(*http.Request) bool { return false }
	if o.Bypass == nil {
		o.Bypass = never
	}
	if o.ViewerWrites == nil {
		o.ViewerWrites = never
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodOptions { // CORS preflight 는 쿠키 · 토큰 없이 온다 — 안쪽 cors 가 답한다
			next.ServeHTTP(w, r)
			return
		}
		if o.Bypass(r) {
			next.ServeHTTP(w, r)
			return
		}
		if authz := r.Header.Get("Authorization"); authz != "" {
			tok, isBearer := strings.CutPrefix(authz, "Bearer ")
			// 토큰이 설정돼 있고 값이 같을 때만 (빈 토큰끼리 같다고 보지 않는다)
			if isBearer && o.AdminToken != "" && subtle.ConstantTimeCompare([]byte(tok), []byte(o.AdminToken)) == 1 {
				next.ServeHTTP(w, r.WithContext(WithActor(r.Context(), CLIActor)))
				return
			}
			writeErr(w, http.StatusUnauthorized, msgBadToken, "")
			return
		}
		// 여기부터는 브라우저(쿠키) 요청 — Bearer 는 브라우저가 저절로 붙이지 않으므로 CSRF 검사 대상이 아니다
		if unsafeMethod(r.Method) && !o.originOK(r) {
			writeErr(w, http.StatusForbidden, msgBadOrigin, "")
			return
		}
		if o.Public(r) {
			next.ServeHTTP(w, r)
			return
		}
		sess, u, err := o.Service.Session(r.Context(), TokenFrom(r))
		if err != nil {
			writeServiceErr(w, err)
			return
		}
		if sess.State != "active" { // 비밀번호 · 라이선스 · OTP 단계를 마치기 전에는 단계 API 만
			writeErr(w, http.StatusUnauthorized, msgFinishLogin, string(sess.State))
			return
		}
		a := actorOf(u)
		if !a.IsAdmin() && unsafeMethod(r.Method) && !o.ViewerWrites(r) {
			writeErr(w, http.StatusForbidden, msgViewerWrite, "")
			return
		}
		next.ServeHTTP(w, r.WithContext(WithActor(r.Context(), a)))
	})
}

func unsafeMethod(m string) bool {
	return m != http.MethodGet && m != http.MethodHead && m != http.MethodOptions
}

// originOK: CSRF 방어(SameSite=Strict 위에 한 겹 더).
//   - Origin 이 있으면: 허용 목록에 있거나 요청 Host 와 같은 호스트여야 한다. "null"(샌드박스 iframe · file://)은 거절
//   - Origin 이 없으면: 세션 쿠키가 없을 때만 통과 (curl 로그인 등). 쿠키가 있는데 Origin 이 없으면 거절
func (o *MiddlewareOptions) originOK(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		_, err := r.Cookie(CookieName)
		return errors.Is(err, http.ErrNoCookie)
	}
	if origin == "null" {
		return false
	}
	if slices.Contains(o.AllowedOrigins, origin) {
		return true
	}
	u, err := url.Parse(origin)
	if err != nil || u.Host == "" {
		return false
	}
	if u.Host == r.Host {
		return true
	}
	// nginx 가 Host 를 $host(포트 없음)로 넘기므로, 요청 Host 에 포트가 없으면 호스트 이름만 비교
	if _, _, err := net.SplitHostPort(r.Host); err != nil {
		return strings.EqualFold(u.Hostname(), r.Host)
	}
	return false
}

// Routes: ServeMux 패턴("POST /api/x/{id}")과 같은 규칙으로 맞추는 판별 함수.
// 경로 정리(redirect)가 필요한 요청은 맞지 않는 것으로 본다 — 안쪽 mux 도 그 요청을 그대로 처리하지 않는다.
func Routes(patterns ...string) func(*http.Request) bool {
	mux := http.NewServeMux()
	for _, p := range patterns {
		mux.Handle(p, routeMark{})
	}
	return func(r *http.Request) bool {
		h, _ := mux.Handler(r)
		_, ok := h.(routeMark)
		return ok
	}
}

type routeMark struct{}

func (routeMark) ServeHTTP(http.ResponseWriter, *http.Request) {}

// TokenFrom: 세션 쿠키 값 (없으면 "")
func TokenFrom(r *http.Request) string {
	c, err := r.Cookie(CookieName)
	if err != nil {
		return ""
	}
	return c.Value
}

// SetCookie: 로그인 성공 시. 만료는 서버가 정한다(유휴 60분 · 절대 12시간) — 브라우저 쿠키는 세션 쿠키
func (s *Service) SetCookie(w http.ResponseWriter, token string) {
	http.SetCookie(w, &http.Cookie{Name: CookieName, Value: token, Path: "/", HttpOnly: true,
		Secure: s.o.CookieSecure, SameSite: http.SameSiteStrictMode})
}

func (s *Service) ClearCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{Name: CookieName, Value: "", Path: "/", MaxAge: -1, HttpOnly: true,
		Secure: s.o.CookieSecure, SameSite: http.SameSiteStrictMode})
}

// WriteError: Service 오류를 JSON 으로 — *Error 면 그 상태 · 메시지 · 단계, 아니면 500
func WriteError(w http.ResponseWriter, err error) { writeServiceErr(w, err) }

func writeServiceErr(w http.ResponseWriter, err error) {
	var e *Error
	if errors.As(err, &e) {
		writeErr(w, e.Status, e.Msg, string(e.State))
		return
	}
	slog.Error("auth", "err", err)
	writeErr(w, http.StatusInternalServerError, "서버 오류", "")
}

func writeErr(w http.ResponseWriter, code int, msg, state string) {
	body := map[string]string{"error": msg}
	if state != "" {
		body["state"] = state
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(body)
}
