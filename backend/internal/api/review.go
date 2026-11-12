package api

import (
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
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
	// 판정 미리보기(W15): 쓰기 없음 — 조회자도 쓴다(ViewerWritePatterns)
	mux.HandleFunc("POST /api/cases/{id}/preview", h.previewDecision)

	mux.HandleFunc("GET /api/proposals", h.listProposals)
	mux.HandleFunc("GET /api/proposals/{id}", h.getProposal)
	mux.HandleFunc("POST /api/proposals/{id}/preview", h.previewProposal)
	mux.HandleFunc("POST /api/policies/preview", h.previewPolicy)
	mux.HandleFunc("POST /api/proposals/{id}/apply", h.auth(h.applyProposal))
	mux.HandleFunc("POST /api/proposals/{id}/discard", h.auth(h.discardProposal))

	mux.HandleFunc("GET /api/blocklist", h.getBlocklist)
	mux.HandleFunc("DELETE /api/blocklist/{list}/{value...}", h.auth(h.removeBlock))
	mux.HandleFunc("GET /api/changes", h.listChanges)
	mux.HandleFunc("POST /api/policies/{id}/revert", h.auth(h.revertPolicy)) // 정책 되돌리기(11/09) — 변경 이력이 있어야 해 Review 와 함께
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

// reasonBody: 적용 · 버림 · 차단 해제의 선택 본문 {reason} (W15). 본문이 없으면 사유 없음
type reasonBody struct {
	Reason string `json:"reason"`
}

// decodeOptionalJSON: decodeJSON 과 같되 빈 본문을 허용한다 (예전 호출 · CLI 는 본문 없이 부른다)
func decodeOptionalJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBody))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil && !errors.Is(err, io.EOF) {
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
	writeJSON(w, http.StatusOK, finishResult(h.installOut(s)))
}

// installView: 설치 세션 응답 — 세션 + 읽을 때 계산한 정적 검사 요약 scan(11/04 종합 판정, 설계 「API 계약」).
// scan 이 없으면(옛 세션 · 검사 기록 없음) 필드 없음. 저장 필드 scanSkip 은 scan.skip 으로만 내보낸다(바깥 필드가 가린다)
type installView struct {
	model.InstallSession
	ScanSkip string             `json:"scanSkip,omitempty"` // 항상 비움
	Scan     *model.InstallScan `json:"scan,omitempty"`
}

func (h *handlers) installOut(s model.InstallSession) installView {
	return installView{InstallSession: s, Scan: h.Scans.OfSession(s)} // Scans 가 nil 이어도 건너뜀은 계산한다
}

// finishResponse: 설치 세션 + sg-install 결과 출력용 요약(W14). CLI 는 SANDBOX_TOKEN 으로 이 응답만 읽는다
// (감사 로그 · 화면 API 는 로그인 뒤). 판정 = status, 위반 수 = violationCount, 건 = caseId
type finishResponse struct {
	installView
	// TopRules: 위반 수가 많은 규칙 순(같으면 규칙 id 순), 최대 5개. 위반이 없으면 []
	TopRules []ruleCount `json:"topRules"`
	// Link: 대시보드 「설치 검사」 경로 (알림과 같은 꼴, PUBLIC_URL 없이 경로만)
	Link string `json:"link"`
}

type ruleCount struct {
	RuleID string `json:"ruleId"`
	Count  int    `json:"count"`
}

const maxTopRules = 5

func finishResult(s installView) finishResponse {
	byRule := map[string]int{}
	for _, v := range s.Violations {
		byRule[v.RuleID] += v.Count
	}
	top := make([]ruleCount, 0, len(byRule))
	for id, n := range byRule {
		top = append(top, ruleCount{RuleID: id, Count: n})
	}
	slices.SortFunc(top, func(a, b ruleCount) int {
		if a.Count != b.Count {
			return b.Count - a.Count
		}
		return strings.Compare(a.RuleID, b.RuleID)
	})
	if len(top) > maxTopRules {
		top = top[:maxTopRules]
	}
	return finishResponse{installView: s, TopRules: top, Link: "/installs?id=" + url.QueryEscape(s.ID)}
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
	ss := h.Review.ListInstalls(iq)
	out := make([]installView, len(ss))
	for i, s := range ss {
		out[i] = h.installOut(s)
	}
	writeJSON(w, http.StatusOK, out)
}

func (h *handlers) getInstall(w http.ResponseWriter, r *http.Request) {
	s, err := h.Review.GetInstall(r.PathValue("id"))
	if err != nil {
		reviewErr(w, "get install", err)
		return
	}
	writeJSON(w, http.StatusOK, h.installOut(s))
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

// previewDecision: 판정하면 생길 제안의 변경 · 영향 요약 — 저장 없음. 판정 · 종결 건은 409
func (h *handlers) previewDecision(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Decision model.Decision `json:"decision"`
	}
	if !decodeJSON(w, r, &in) {
		return
	}
	pv, err := h.Review.PreviewDecision(r.Context(), r.PathValue("id"), in.Decision)
	if err != nil {
		reviewErr(w, "decision preview", err)
		return
	}
	writeJSON(w, http.StatusOK, pv)
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
	var in reasonBody
	if !decodeOptionalJSON(w, r, &in) {
		return
	}
	p, c, err := h.Review.Apply(r.Context(), r.PathValue("id"), in.Reason)
	if err != nil {
		reviewErr(w, "apply", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"proposal": p, "case": c})
}

func (h *handlers) discardProposal(w http.ResponseWriter, r *http.Request) {
	var in reasonBody
	if !decodeOptionalJSON(w, r, &in) {
		return
	}
	p, c, err := h.Review.Discard(r.Context(), r.PathValue("id"), in.Reason)
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
	var in reasonBody
	if !decodeOptionalJSON(w, r, &in) {
		return
	}
	if err := h.Review.RemoveBlock(r.Context(), r.PathValue("list"), r.PathValue("value"), in.Reason); err != nil {
		reviewErr(w, "remove block", err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// listChanges: GET /api/changes?rule=&kind=&offset=&limit= — 최신순, limit 기본 50 · 상한 500.
// rule = 그 정책을 다룬 기록만(before · after 도 그 정책 값만) · kind = 종류 완전 일치.
// offset 이 있으면 {items, total, offset, limit}(11/09 쪽 넘김), 없으면 예전처럼 배열
func (h *handlers) listChanges(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	cq := review.ChangeQuery{RuleID: q.Get("rule"), Kind: model.ChangeKind(q.Get("kind"))}
	if s := q.Get("limit"); s != "" {
		n, err := strconv.Atoi(s)
		if err != nil || n <= 0 {
			writeErr(w, http.StatusBadRequest, "limit: 양의 정수")
			return
		}
		cq.Limit = n
	}
	paged := q.Has("offset")
	if paged {
		n, err := strconv.Atoi(q.Get("offset"))
		if err != nil || n < 0 {
			writeErr(w, http.StatusBadRequest, "offset: 0 이상 정수")
			return
		}
		cq.Offset = n
	}
	items, total := h.Review.QueryChanges(cq)
	if !paged {
		writeJSON(w, http.StatusOK, items)
		return
	}
	writeJSON(w, http.StatusOK, ChangesPage{Items: items, Total: total, Offset: cq.Offset, Limit: review.ChangeLimit(cq.Limit)})
}

// ChangesPage: GET /api/changes?offset=… 응답(11/09) — AuditPage 와 같은 꼴, total 은 거른 뒤 전체 수
type ChangesPage struct {
	Items  []model.Change `json:"items"`
	Total  int            `json:"total"`
	Offset int            `json:"offset"`
	Limit  int            `json:"limit"`
}

// revertPolicy: POST /api/policies/{id}/revert {changeId, reason} — 관리자. 그 변경 직전 값으로 정책 하나 전체를 되돌린다(사유 필수).
// 200 = 되돌린 정책(updatedAt · updatedBy 포함) · 400 본문 · 사유 · changeId · 404 변경 기록 · 409 시스템 규칙 · 되돌릴 값 없음 · 이미 그 값
func (h *handlers) revertPolicy(w http.ResponseWriter, r *http.Request) {
	var in struct {
		ChangeID string `json:"changeId"`
		Reason   string `json:"reason"`
	}
	if !decodeJSON(w, r, &in) {
		return
	}
	id := r.PathValue("id")
	if rules.IsSystemRule(id) {
		writeErr(w, http.StatusConflict, systemRuleMsg)
		return
	}
	rule, err := h.Review.RevertPolicy(r.Context(), id, in.ChangeID, in.Reason)
	if err != nil {
		reviewErr(w, "revert policy", err)
		return
	}
	slog.Info("policy reverted", "id", id, "change", in.ChangeID)
	writeJSON(w, http.StatusOK, h.policyOut(rule))
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
