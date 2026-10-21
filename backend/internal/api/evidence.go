package api

import (
	"context"
	"net/http"
	"strings"

	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/model"
)

// EvidenceReader: kill 전 증거(10/20) 조회. store.Memory · store.Postgres 가 구현한다
type EvidenceReader interface {
	EvidenceByContainer(ctx context.Context, nameOrID string) ([]model.Evidence, error)
}

// EvidenceHandler: GET /api/evidence?container=<name|id> → 최근 것부터 배열(없으면 빈 배열).
// 읽기라 토큰은 없다. 라우트 등록은 Router(Deps) 안에서 한다(CORS 를 타야 Vite · 목업에서 부를 수 있다).
func EvidenceHandler(rd EvidenceReader) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		q := strings.TrimSpace(r.URL.Query().Get("container"))
		if q == "" {
			writeErr(w, http.StatusBadRequest, "container(이름 또는 id)가 필요함")
			return
		}
		if len(q) > 128 {
			writeErr(w, http.StatusBadRequest, "container 가 너무 김")
			return
		}
		out, err := rd.EvidenceByContainer(r.Context(), q)
		if err != nil {
			serverErr(w, "evidence query", err)
			return
		}
		if out == nil {
			out = []model.Evidence{}
		}
		writeJSON(w, http.StatusOK, out)
	}
}
