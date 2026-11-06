package api

import (
	"errors"
	"net/http"

	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/integration"
)

// 연동(11/06): GET /api/integration 은 로그인 세션(조회자 포함), POST /api/integration/test 는 대시보드 관리자 세션만
// (시험 컨테이너를 띄운다 — CLI Bearer 도 403)

const msgProbeBrowserOnly = "연결 테스트는 대시보드의 관리자 로그인에서만 실행할 수 있습니다"

func (h *handlers) integrationStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, h.Integration.Status(r.Context()))
}

// integrationTest: 202 Test | 409 진행 중 | 503 이 서버에서 불가
func (h *handlers) integrationTest(w http.ResponseWriter, r *http.Request) {
	t, err := h.Integration.StartTest(r.Context())
	switch {
	case errors.Is(err, integration.ErrBusy):
		writeErr(w, http.StatusConflict, err.Error())
	case errors.Is(err, integration.ErrUnavailable):
		writeErr(w, http.StatusServiceUnavailable, err.Error())
	case err != nil:
		serverErr(w, "integration test", err)
	default:
		writeJSON(w, http.StatusAccepted, t)
	}
}
