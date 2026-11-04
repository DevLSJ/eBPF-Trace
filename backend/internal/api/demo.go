package api

import (
	"errors"
	"net/http"

	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/auth"
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/demo"
)

// 시연 실행(10/30): DEMO_ENABLED 일 때만 Router 가 등록한다(아니면 404).
// GET /api/demo 는 로그인 세션(조회자 포함), POST /api/demo/run 은 대시보드 관리자 세션만(Bearer ADMIN_TOKEN 도 403).

func (h *handlers) routeDemo(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/demo", h.demoStatus)
	mux.HandleFunc("POST /api/demo/run", h.demoAdmin(h.demoRun))
}

const msgDemoBrowserOnly = "시연은 대시보드의 관리자 로그인에서만 실행할 수 있습니다"

// demoAdmin: 컨테이너를 띄우는 쓰기 — 조회자 403(「조회자는 읽기만 할 수 있습니다」는 미들웨어가 먼저 낸다), CLI Bearer 403.
// 로그인이 꺼진 조립(테스트 · 옛 구성)에서는 다른 쓰기와 같은 ADMIN_TOKEN 규칙
func (h *handlers) demoAdmin(next http.HandlerFunc) http.HandlerFunc {
	if h.Deps.Auth == nil {
		return h.auth(next)
	}
	return func(w http.ResponseWriter, r *http.Request) {
		a, ok := auth.ActorFrom(r.Context())
		switch {
		case !ok:
			writeErr(w, http.StatusUnauthorized, "로그인이 필요합니다")
		case !a.IsAdmin():
			writeErr(w, http.StatusForbidden, "조회자는 읽기만 할 수 있습니다")
		case a.ID == auth.CLIActor.ID:
			writeErr(w, http.StatusForbidden, msgDemoBrowserOnly)
		default:
			next(w, r)
		}
	}
}

// demoStatus: GET /api/demo — running · last 에 explain(11/04)을 붙인다. 세션이 있고 거부가 아닐 때만(세션 · 지금 정책으로 읽을 때 계산)
func (h *handlers) demoStatus(w http.ResponseWriter, _ *http.Request) {
	st := h.Demo.Status()
	for _, run := range []*demo.Run{st.Running, st.Last} {
		if run == nil || run.InstallID == "" || run.Status == demo.StatusRefused || h.Review == nil {
			continue
		}
		if sess, err := h.Review.GetInstall(run.InstallID); err == nil {
			run.Explain = demo.BuildExplain(*run, sess, h.Engine.Rules())
		}
	}
	writeJSON(w, http.StatusOK, st)
}

// demoRun: 본문 {scenario} → 202 Run | 400 시나리오 | 409 실행 중(+running) | 503 Docker 불통
func (h *handlers) demoRun(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Scenario string `json:"scenario"`
	}
	if !decodeJSON(w, r, &in) {
		return
	}
	run, err := h.Demo.Start(r.Context(), in.Scenario)
	var running *demo.RunningError
	switch {
	case errors.Is(err, demo.ErrScenario):
		writeErr(w, http.StatusBadRequest, err.Error())
	case errors.As(err, &running):
		writeJSON(w, http.StatusConflict, map[string]any{"error": running.Error(), "running": running.Running})
	case errors.Is(err, demo.ErrDocker):
		writeErr(w, http.StatusServiceUnavailable, demo.ErrDocker.Error())
	case errors.Is(err, demo.ErrClosed):
		writeErr(w, http.StatusServiceUnavailable, demo.ErrClosed.Error())
	case err != nil:
		serverErr(w, "demo run", err)
	default:
		writeJSON(w, http.StatusAccepted, run)
	}
}
