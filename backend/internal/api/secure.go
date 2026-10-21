package api

import (
	"context"
	"net/http"

	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/auth"
)

// SecureOptions: main 이 바깥 mux 를 감쌀 때 쓰는 값. 테스트도 같은 함수로 조립한다(auth_wired_test)
type SecureOptions struct {
	Auth *auth.Service
	// AdminToken: CLI · 자동화의 Bearer — 관리자(처리자 「cli」)로 통과
	AdminToken string
	// AllowedOrigins: 쿠키 요청의 상태 변경 Origin 검사(CSRF) — CORS 허용 목록과 같은 값
	AllowedOrigins []string
}

// Secure: /health 와 로그인 단계 경로를 뺀 전부(읽기 API · /ws/events 포함)를 로그인 뒤로 둔다.
// sg-install 보고(SandboxPatterns)는 건너뛰고 핸들러의 sandboxAuth 가 SANDBOX_TOKEN 을 확인한다.
// 조회자에게는 바꾸지 않는 POST(ViewerWritePatterns: 미리보기 2개 · AI 도우미)만 허용한다.
func Secure(h http.Handler, o SecureOptions) http.Handler {
	return auth.Middleware(h, auth.MiddlewareOptions{
		Service: o.Auth, AdminToken: o.AdminToken, AllowedOrigins: o.AllowedOrigins,
		Bypass:       auth.Routes(SandboxPatterns...),
		ViewerWrites: auth.Routes(ViewerWritePatterns...),
	})
}

// RequesterName: 감사 처리자 이름 — 계정 표시 이름(없으면 아이디), Bearer ADMIN_TOKEN 이면 "cli".
// 요청자가 없으면(우회 경로 · 내부 작업) "" — review 가 ACTOR_NAME 으로 채운다. review.Options.ActorFrom 에 넣는다
func RequesterName(ctx context.Context) string {
	if a, ok := auth.ActorFrom(ctx); ok {
		return a.Name
	}
	return ""
}
