// Package api serves the REST endpoints behind nginx /api/ and /health.
package api

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/model"
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/rules"
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/stats"
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/store"
)

// Pinger: 헬스체크 대상 (Postgres·Redis)
type Pinger interface {
	Ping(ctx context.Context) error
}

type Deps struct {
	Engine   *rules.Engine
	Policies store.PolicyStore
	Audit    store.AuditStore
	Buffer   store.Buffer
	Stats    func() stats.Snapshot
	Checks   map[string]Pinger

	AdminToken string
	// AllowAnonymousWrites: ADMIN_TOKEN 없이 정책 변경 허용 (mock 소스 로컬 개발 전용)
	AllowAnonymousWrites bool
	// AllowedOrigins: 다른 출처(Vite dev, mock/ 목업)에서 REST 를 직접 부를 때 CORS 로 허용할 Origin.
	// nginx 뒤 동일 출처 요청에는 Origin 이 없거나 같은 호스트라 영향이 없다. 파일에서 연 페이지는 "null".
	AllowedOrigins []string
	Info           Info
}

// Info: 대시보드가 표시하는 런타임 설정
type Info struct {
	Source        string       `json:"source"`
	Gadgets       []model.Kind `json:"gadgets"`
	EnforceKill   bool         `json:"enforceKill"`
	AuthRequired  bool         `json:"authRequired"`
	GadgetVersion string       `json:"gadgetVersion"`
}

const maxBody = 64 << 10 // nginx client_max_body_size 64k와 맞춤

func Router(d Deps) http.Handler {
	d.Info.AuthRequired = !d.AllowAnonymousWrites
	h := &handlers{d}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", h.health)
	mux.HandleFunc("GET /api/info", h.info)
	mux.HandleFunc("GET /api/stats", h.stats)
	mux.HandleFunc("GET /api/events/recent", h.recent)
	mux.HandleFunc("GET /api/audit", h.audit)
	mux.HandleFunc("GET /api/policies", h.listPolicies)
	mux.HandleFunc("GET /api/policies/export", h.exportPolicies)
	mux.HandleFunc("POST /api/policies", h.auth(h.savePolicy))
	mux.HandleFunc("PUT /api/policies", h.auth(h.replacePolicies))
	mux.HandleFunc("DELETE /api/policies/{id}", h.auth(h.deletePolicy))
	return cors(d.AllowedOrigins, mux)
}

// cors: 허용 목록에 있는 Origin 에만 CORS 헤더를 붙이고 preflight(OPTIONS)에 204 로 답한다.
func cors(allowed []string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin != "" && slices.Contains(allowed, origin) {
			hd := w.Header()
			hd.Set("Access-Control-Allow-Origin", origin)
			hd.Add("Vary", "Origin")
			if r.Method == http.MethodOptions {
				hd.Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE")
				hd.Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
				hd.Set("Access-Control-Max-Age", "600")
				w.WriteHeader(http.StatusNoContent)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

type handlers struct{ Deps }

func (h *handlers) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if h.AdminToken == "" {
			if h.AllowAnonymousWrites {
				next(w, r)
				return
			}
			writeErr(w, http.StatusForbidden, "ADMIN_TOKEN이 설정되지 않아 정책 변경이 비활성화됨")
			return
		}
		got, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		if !ok || subtle.ConstantTimeCompare([]byte(got), []byte(h.AdminToken)) != 1 {
			writeErr(w, http.StatusUnauthorized, "관리자 토큰이 필요함")
			return
		}
		next(w, r)
	}
}

func (h *handlers) health(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	res := map[string]string{"status": "ok", "source": h.Info.Source}
	code := http.StatusOK
	for name, p := range h.Checks {
		if err := p.Ping(ctx); err != nil {
			res[name] = "error"
			res["status"] = "degraded"
			code = http.StatusServiceUnavailable
		} else {
			res[name] = "ok"
		}
	}
	writeJSON(w, code, res)
}

func (h *handlers) info(w http.ResponseWriter, _ *http.Request) { writeJSON(w, http.StatusOK, h.Info) }

func (h *handlers) stats(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, h.Stats())
}

func (h *handlers) recent(w http.ResponseWriter, r *http.Request) {
	n, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if n <= 0 || n > store.RecentSize {
		n = 500
	}
	vs, err := h.Buffer.Recent(r.Context(), n)
	if err != nil {
		serverErr(w, "recent", err)
		return
	}
	writeJSON(w, http.StatusOK, vs)
}

func (h *handlers) audit(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	aq := store.AuditQuery{
		Kind:      model.Kind(q.Get("kind")),
		Action:    model.Action(q.Get("action")),
		RuleID:    q.Get("rule"),
		Container: q.Get("container"),
	}
	if aq.Kind != "" && !aq.Kind.Valid() {
		writeErr(w, http.StatusBadRequest, "kind: exec | open | connect")
		return
	}
	if aq.Action != "" && !aq.Action.Valid() {
		writeErr(w, http.StatusBadRequest, "action: alert | kill")
		return
	}
	var err error
	if aq.Since, err = parseTime(q.Get("since")); err != nil {
		writeErr(w, http.StatusBadRequest, "since: RFC3339")
		return
	}
	if aq.Until, err = parseTime(q.Get("until")); err != nil {
		writeErr(w, http.StatusBadRequest, "until: RFC3339")
		return
	}
	aq.Limit, _ = strconv.Atoi(q.Get("limit"))
	aq.BeforeID, _ = strconv.ParseInt(q.Get("before"), 10, 64)
	entries, err := h.Audit.QueryAudit(r.Context(), aq)
	if err != nil {
		serverErr(w, "audit", err)
		return
	}
	writeJSON(w, http.StatusOK, entries)
}

func parseTime(s string) (time.Time, error) {
	if s == "" {
		return time.Time{}, nil
	}
	return time.Parse(time.RFC3339, s)
}

func (h *handlers) listPolicies(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, h.Engine.Rules())
}

func (h *handlers) exportPolicies(w http.ResponseWriter, _ *http.Request) {
	b, err := yaml.Marshal(map[string]any{"rules": h.Engine.Rules()})
	if err != nil {
		serverErr(w, "export", err)
		return
	}
	w.Header().Set("Content-Type", "application/yaml; charset=utf-8")
	_, _ = w.Write(b)
}

// savePolicy: 정책 1건 저장 후 엔진 리로드 ("저장 후 적용")
func (h *handlers) savePolicy(w http.ResponseWriter, r *http.Request) {
	var rule rules.Rule
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBody))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&rule); err != nil {
		writeErr(w, http.StatusBadRequest, "JSON 형식 오류: "+err.Error())
		return
	}
	if err := rule.Validate(); err != nil {
		writeErr(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	if err := h.Policies.UpsertPolicy(r.Context(), rule); err != nil {
		serverErr(w, "upsert policy", err)
		return
	}
	if err := h.reload(r.Context()); err != nil {
		serverErr(w, "reload", err)
		return
	}
	slog.Info("policy saved", "id", rule.ID, "kind", rule.Kind, "action", rule.Action, "dryRun", rule.DryRun)
	writeJSON(w, http.StatusOK, rule)
}

// replacePolicies: YAML 원클릭 적용 — 본문 전체(rules: [...])로 정책을 교체한다.
func (h *handlers) replacePolicies(w http.ResponseWriter, r *http.Request) {
	b, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBody))
	if err != nil {
		writeErr(w, http.StatusRequestEntityTooLarge, "본문이 너무 큼")
		return
	}
	rs, err := rules.ParseYAML(b)
	if err != nil {
		writeErr(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	if err := h.Policies.ReplacePolicies(r.Context(), rs); err != nil {
		serverErr(w, "replace policies", err)
		return
	}
	if err := h.reload(r.Context()); err != nil {
		serverErr(w, "reload", err)
		return
	}
	slog.Info("policies replaced", "count", len(rs))
	writeJSON(w, http.StatusOK, h.Engine.Rules())
}

func (h *handlers) deletePolicy(w http.ResponseWriter, r *http.Request) {
	ok, err := h.Policies.DeletePolicy(r.Context(), r.PathValue("id"))
	if err != nil {
		serverErr(w, "delete policy", err)
		return
	}
	if !ok {
		writeErr(w, http.StatusNotFound, "정책 없음")
		return
	}
	if err := h.reload(r.Context()); err != nil {
		serverErr(w, "reload", err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *handlers) reload(ctx context.Context) error {
	rs, err := h.Policies.ListPolicies(ctx)
	if err != nil {
		return err
	}
	h.Engine.Replace(rs)
	return nil
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

func serverErr(w http.ResponseWriter, op string, err error) {
	if errors.Is(err, context.Canceled) {
		return
	}
	slog.Error(op, "err", err)
	writeErr(w, http.StatusInternalServerError, "서버 오류")
}
