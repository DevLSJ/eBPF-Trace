package api

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/model"
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/osv"
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/review"
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/rules"
)

// routeReview: 「API 계약」 탭의 설치 세션 · 건 · 제안 · 차단 목록 · 변경 이력 · OSV.
// 읽기는 토큰 없음, 화면 쓰기는 ADMIN_TOKEN, CLI(세션 보고 · 차단 확인)는 SANDBOX_TOKEN.
func (h *handlers) routeReview(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/installs", h.sandboxAuth(h.startInstall))
	mux.HandleFunc("PUT /api/installs/{id}/finish", h.sandboxAuth(h.finishInstall))
	mux.HandleFunc("POST /api/installs/refused", h.sandboxAuth(h.refusedInstall))
	mux.HandleFunc("GET /api/blocklist/check", h.sandboxAuth(h.checkBlocklist))
	mux.HandleFunc("GET /api/installs", h.listInstalls)
	mux.HandleFunc("GET /api/installs/{id}", h.getInstall)

	mux.HandleFunc("GET /api/cases", h.listCases)
	mux.HandleFunc("GET /api/cases/{id}", h.getCase)
	mux.HandleFunc("POST /api/cases/{id}/decide", h.auth(h.decideCase))

	mux.HandleFunc("GET /api/proposals", h.listProposals)
	mux.HandleFunc("GET /api/proposals/{id}", h.getProposal)
	mux.HandleFunc("POST /api/proposals/{id}/preview", h.previewProposal)
	mux.HandleFunc("POST /api/policies/preview", h.previewPolicy)
	mux.HandleFunc("POST /api/proposals/{id}/apply", h.auth(h.applyProposal))
	mux.HandleFunc("POST /api/proposals/{id}/discard", h.auth(h.discardProposal))

	mux.HandleFunc("GET /api/blocklist", h.getBlocklist)
	mux.HandleFunc("DELETE /api/blocklist/{list}/{value...}", h.auth(h.removeBlock))
	mux.HandleFunc("GET /api/changes", h.listChanges)
	mux.HandleFunc("GET /api/osv", h.queryOSV)
}

// decodeJSON: 본문 크기 제한 · 모르는 필드 거부
func decodeJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBody))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		writeErr(w, http.StatusBadRequest, "JSON 형식 오류: "+err.Error())
		return false
	}
	return true
}

// reviewErr: review 오류 → 400 · 404 · 409, 나머지는 500
func reviewErr(w http.ResponseWriter, op string, err error) {
	switch review.ErrorKind(err) {
	case review.KindInvalid:
		writeErr(w, http.StatusBadRequest, err.Error())
	case review.KindNotFound:
		writeErr(w, http.StatusNotFound, err.Error())
	case review.KindConflict:
		writeErr(w, http.StatusConflict, err.Error())
	default:
		serverErr(w, op, err)
	}
}

func (h *handlers) startInstall(w http.ResponseWriter, r *http.Request) {
	var in review.StartInput
	if !decodeJSON(w, r, &in) {
		return
	}
	s, err := h.Review.StartInstall(r.Context(), in)
	if err != nil {
		reviewErr(w, "start install", err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]string{"id": s.ID})
}

func (h *handlers) finishInstall(w http.ResponseWriter, r *http.Request) {
	var in struct {
		ExitCode *int `json:"exitCode"`
	}
	if !decodeJSON(w, r, &in) {
		return
	}
	if in.ExitCode == nil {
		writeErr(w, http.StatusBadRequest, "exitCode 가 필요함")
		return
	}
	s, err := h.Review.FinishInstall(r.Context(), r.PathValue("id"), *in.ExitCode)
	if err != nil {
		reviewErr(w, "finish install", err)
		return
	}
	writeJSON(w, http.StatusOK, s)
}

func (h *handlers) refusedInstall(w http.ResponseWriter, r *http.Request) {
	var in review.RefusedInput
	if !decodeJSON(w, r, &in) {
		return
	}
	s, err := h.Review.RefusedInstall(r.Context(), in)
	if err != nil {
		reviewErr(w, "refused install", err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]string{"id": s.ID})
}

func (h *handlers) checkBlocklist(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	res, err := h.Review.CheckPackage(q.Get("manager"), q.Get("package"))
	if err != nil {
		reviewErr(w, "blocklist check", err)
		return
	}
	writeJSON(w, http.StatusOK, res)
}

func (h *handlers) listInstalls(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	iq := review.InstallQuery{Status: model.InstallStatus(q.Get("status")), Manager: q.Get("manager")}
	if iq.Status != "" && !iq.Status.Valid() {
		writeErr(w, http.StatusBadRequest, "status: running | passed | isolated | warned | failed | unknown | refused")
		return
	}
	if iq.Manager != "" && !model.ValidManager(iq.Manager) {
		writeErr(w, http.StatusBadRequest, "manager: pip | npm | cargo")
		return
	}
	if s := q.Get("limit"); s != "" {
		n, err := strconv.Atoi(s)
		if err != nil || n <= 0 {
			writeErr(w, http.StatusBadRequest, "limit: 양의 정수")
			return
		}
		iq.Limit = n
	}
	writeJSON(w, http.StatusOK, h.Review.ListInstalls(iq))
}

func (h *handlers) getInstall(w http.ResponseWriter, r *http.Request) {
	s, err := h.Review.GetInstall(r.PathValue("id"))
	if err != nil {
		reviewErr(w, "get install", err)
		return
	}
	writeJSON(w, http.StatusOK, s)
}

func (h *handlers) listCases(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	cq := review.CaseQuery{State: model.CaseState(q.Get("state")), Source: model.CaseSource(q.Get("source"))}
	switch cq.State {
	case "", model.CaseOpen, model.CaseDecided, model.CaseClosed:
	default:
		writeErr(w, http.StatusBadRequest, "state: open | decided | closed")
		return
	}
	switch cq.Source {
	case "", model.CaseInstall, model.CaseRuntime:
	default:
		writeErr(w, http.StatusBadRequest, "source: install | runtime")
		return
	}
	writeJSON(w, http.StatusOK, h.Review.ListCases(cq))
}

func (h *handlers) getCase(w http.ResponseWriter, r *http.Request) {
	c, err := h.Review.GetCase(r.PathValue("id"))
	if err != nil {
		reviewErr(w, "get case", err)
		return
	}
	writeJSON(w, http.StatusOK, c)
}

func (h *handlers) decideCase(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Decision model.Decision `json:"decision"`
		Note     string         `json:"note"`
	}
	if !decodeJSON(w, r, &in) {
		return
	}
	c, p, err := h.Review.Decide(r.Context(), r.PathValue("id"), in.Decision, in.Note)
	if err != nil {
		reviewErr(w, "decide", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"case": c, "proposal": p})
}

func (h *handlers) listProposals(w http.ResponseWriter, r *http.Request) {
	st := model.ProposalState(r.URL.Query().Get("state"))
	switch st {
	case "", model.ProposalDraft, model.ProposalApplied, model.ProposalDiscarded:
	default:
		writeErr(w, http.StatusBadRequest, "state: draft | applied | discarded")
		return
	}
	writeJSON(w, http.StatusOK, h.Review.ListProposals(st))
}

func (h *handlers) getProposal(w http.ResponseWriter, r *http.Request) {
	p, err := h.Review.GetProposal(r.PathValue("id"))
	if err != nil {
		reviewErr(w, "get proposal", err)
		return
	}
	writeJSON(w, http.StatusOK, p)
}

func (h *handlers) previewProposal(w http.ResponseWriter, r *http.Request) {
	pv, err := h.Review.Preview(r.Context(), r.PathValue("id"))
	if err != nil {
		reviewErr(w, "preview", err)
		return
	}
	writeJSON(w, http.StatusOK, pv)
}

// previewPolicy: 정책 저장 전 확인 — 바꾼 정책 하나로 감사 로그를 다시 평가(쓰기 없음, 토큰 불필요). 검사는 savePolicy 와 같다
func (h *handlers) previewPolicy(w http.ResponseWriter, r *http.Request) {
	var rule rules.Rule
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBody))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&rule); err != nil {
		writeErr(w, http.StatusBadRequest, "JSON 형식 오류: "+err.Error())
		return
	}
	if rules.IsSystemRule(rule.ID) {
		writeErr(w, http.StatusConflict, systemRuleMsg)
		return
	}
	if err := rule.Validate(); err != nil {
		writeErr(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	pv, err := h.Review.PreviewRule(r.Context(), rule)
	if err != nil {
		reviewErr(w, "policy preview", err)
		return
	}
	writeJSON(w, http.StatusOK, pv)
}

func (h *handlers) applyProposal(w http.ResponseWriter, r *http.Request) {
	p, c, err := h.Review.Apply(r.Context(), r.PathValue("id"))
	if err != nil {
		reviewErr(w, "apply", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"proposal": p, "case": c})
}

func (h *handlers) discardProposal(w http.ResponseWriter, r *http.Request) {
	p, c, err := h.Review.Discard(r.Context(), r.PathValue("id"))
	if err != nil {
		reviewErr(w, "discard", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"proposal": p, "case": c})
}

func (h *handlers) getBlocklist(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, h.Review.Blocklist())
}

func (h *handlers) removeBlock(w http.ResponseWriter, r *http.Request) {
	if err := h.Review.RemoveBlock(r.Context(), r.PathValue("list"), r.PathValue("value")); err != nil {
		reviewErr(w, "remove block", err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *handlers) listChanges(w http.ResponseWriter, r *http.Request) {
	n := 0
	if s := r.URL.Query().Get("limit"); s != "" {
		var err error
		if n, err = strconv.Atoi(s); err != nil || n <= 0 {
			writeErr(w, http.StatusBadRequest, "limit: 양의 정수")
			return
		}
	}
	writeJSON(w, http.StatusOK, h.Review.ListChanges(n))
}

func (h *handlers) queryOSV(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	eco, name := q.Get("ecosystem"), strings.TrimSpace(q.Get("name"))
	if !osv.ValidEcosystem(eco) {
		writeErr(w, http.StatusBadRequest, "ecosystem: PyPI | npm | crates.io")
		return
	}
	if name == "" || len(name) > 214 {
		writeErr(w, http.StatusBadRequest, "name: 1~214자")
		return
	}
	writeJSON(w, http.StatusOK, h.OSV.Query(r.Context(), eco, name))
}
