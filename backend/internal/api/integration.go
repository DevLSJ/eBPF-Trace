package api

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/dockerapi"
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/integration"
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/pipeline"
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

// 감시 중 컨테이너 상세(11/10): GET /api/integration/containers/{id} — 읽기 전용(로그인 세션, 조회자 포함).
// 연동 목록(자기 스택 제외 · 파이프라인과 같은 감시 판정)에 있는 컨테이너만 연다 — 아무 id 로 Docker 를 들여다보지 않게.
// Docker inspect 에서는 상태 · 시작 시각 · 재시작 · 포트 · 라벨만 받는다. 환경 변수는 dockerapi 가 읽지도 않는다

const (
	msgContainerNotFound = "컨테이너를 찾을 수 없습니다. 이미 종료되었거나 감시 목록에 없는 컨테이너입니다"
	msgContainerDetail   = "Docker 에서 상세 정보를 읽지 못했습니다. 목록 값만 보입니다"
)

// ContainerInspector: dockerapi.Client.InspectDetail(테스트에서 대체)
type ContainerInspector interface {
	InspectDetail(ctx context.Context, id string) (dockerapi.Detail, error)
}

// ContainerDetail: 상세 시트 정보 탭
type ContainerDetail struct {
	ID           string            `json:"id"`
	Name         string            `json:"name"`
	Image        string            `json:"image"`
	ImageID      string            `json:"imageId,omitempty"`
	State        string            `json:"state"`
	StartedAt    *time.Time        `json:"startedAt,omitempty"`
	RestartCount int               `json:"restartCount"`
	Ports        []dockerapi.Port  `json:"ports"`
	Labels       map[string]string `json:"labels"`
	pipeline.Scope
	// DetailError: inspect 가 404 가 아닌 오류 — 목록 값만 보낸다(화면에 그대로 나가는 문장)
	DetailError string `json:"detailError,omitempty"`
}

// integrationContainer: 200 ContainerDetail | 404 목록에 없음 · 방금 종료
func (h *handlers) integrationContainer(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var found *integration.Container
	for _, c := range h.Integration.Status(r.Context()).Containers {
		if c.ID == id {
			found = &c
			break
		}
	}
	if id == "" || found == nil {
		writeErr(w, http.StatusNotFound, msgContainerNotFound)
		return
	}
	labels := found.Labels
	if labels == nil {
		labels = map[string]string{}
	}
	out := ContainerDetail{ID: found.ID, Name: found.Name, Image: found.Image, State: "running", Ports: []dockerapi.Port{}, Labels: labels, Scope: found.Scope}
	if h.Containers != nil {
		d, err := h.Containers.InspectDetail(r.Context(), found.ID)
		switch {
		case errors.Is(err, dockerapi.ErrNotFound):
			writeErr(w, http.StatusNotFound, msgContainerNotFound)
			return
		case errors.Is(err, context.Canceled):
			return
		case err != nil:
			slog.Warn("integration: container inspect", "container", found.Name, "err", err)
			out.DetailError = msgContainerDetail
		default:
			out.ImageID, out.State, out.StartedAt, out.RestartCount, out.Ports, out.Labels = d.ImageID, d.State, d.StartedAt, d.RestartCount, d.Ports, d.Labels
			if d.Image != "" {
				out.Image = d.Image
			}
		}
	}
	writeJSON(w, http.StatusOK, out)
}
