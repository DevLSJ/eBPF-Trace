package auth

import (
	"context"
	"net/http"

	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/model"
)

// Actor: 요청을 보낸 사람. 쿠키 세션이면 계정, ADMIN_TOKEN Bearer 면 CLIActor.
type Actor struct {
	ID       string `json:"id"`
	Username string `json:"username"`
	// Name: 화면 · 감사 처리자로 쓸 이름 (표시 이름, 없으면 아이디)
	Name string     `json:"name"`
	Role model.Role `json:"role"`
}

// CLIActor: CLI · 자동화(Authorization: Bearer ADMIN_TOKEN) — 관리자 권한
var CLIActor = Actor{ID: "cli", Username: "cli", Name: "cli", Role: model.RoleAdmin}

func (a Actor) IsAdmin() bool { return a.Role == model.RoleAdmin }

func actorOf(u model.User) Actor {
	name := u.DisplayName
	if name == "" {
		name = u.Username
	}
	return Actor{ID: u.ID, Username: u.Username, Name: name, Role: u.Role}
}

type actorKey struct{}

func WithActor(ctx context.Context, a Actor) context.Context {
	return context.WithValue(ctx, actorKey{}, a)
}

// ActorFrom: 미들웨어가 넣은 요청자. 공개 경로 · 우회 경로(SANDBOX_TOKEN)에서는 없다(ok=false)
func ActorFrom(ctx context.Context) (Actor, bool) {
	a, ok := ctx.Value(actorKey{}).(Actor)
	return a, ok
}

// RequireAdmin: 관리자만. 미들웨어 뒤에서 쓴다 — 요청자가 없으면 401, 조회자면 403
func RequireAdmin(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		a, ok := ActorFrom(r.Context())
		if !ok {
			writeErr(w, http.StatusUnauthorized, msgLogin, "")
			return
		}
		if !a.IsAdmin() {
			writeErr(w, http.StatusForbidden, msgAdminOnly, "")
			return
		}
		next(w, r)
	}
}
