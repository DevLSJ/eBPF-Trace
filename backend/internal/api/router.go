// Package api serves the REST endpoints behind nginx /api/ and /health.
package api

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/auth"
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/chat"
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/demo"
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/integration"
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/model"
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/notify"
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/osv"
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/review"
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/rules"
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/scan"
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/stats"
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/store"
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/summary"
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
	// SandboxToken: sg-install CLI 의 세션 보고 · 차단 확인 전용 토큰 (ADMIN 엔드포인트에는 쓸 수 없다)
	SandboxToken string
	// SGInstallFile: 「사용 방법」 내려받기용 sg-install 스크립트 경로(SG_INSTALL_FILE, 이미지는 /tools/sg-install). 비거나 없으면 내려받기 없음
	SGInstallFile string
	// SGInstallAPI: 「사용 방법」의 SUPPLYGUARD_API(SG_INSTALL_API). 비면 추정 — compose(nginx 80) 는 http://127.0.0.1, mock 은 :8000
	SGInstallAPI string
	// AllowAnonymousWrites: EVENT_SOURCE=mock — 비어 있는 토큰의 쓰기를 토큰 없이 허용 (로컬 개발 전용)
	AllowAnonymousWrites bool
	// Review: 설치 세션 · 건 · 제안 · 차단 목록 · 변경 이력. nil 이면 해당 엔드포인트를 열지 않는다.
	Review *review.Service
	OSV    *osv.Client
	// AllowedOrigins: 다른 출처(Vite dev, mock/ 목업)에서 REST 를 직접 부를 때 CORS 로 허용할 Origin.
	// nginx 뒤 동일 출처 요청에는 Origin 이 없거나 같은 호스트라 영향이 없다. 파일에서 연 페이지는 "null".
	AllowedOrigins []string
	Info           Info
	// DNSTraced: 이벤트 소스가 지금 trace_dns 를 돌리고 있는지 (/api/info dnsResolve). nil 이면 off
	DNSTraced func() bool
	// Discovery: 가젯 소스가 실제로 쓰는 컨테이너 발견 방식(/api/info discovery). auto 는 시작 뒤에 정해지므로 요청마다 읽는다. nil 이면 빈 값
	Discovery func() string
	// Summary: 대시보드 eBPF 수집 종합(10/16). nil 이면 라우트 없음(「백엔드 미지원」)
	Summary *summary.Service
	// Scans: 공급망 검사(10/16). nil 이면 라우트 없음
	Scans *scan.Service
	// Notifier: 외부 알림(10/20). /api/info notify 를 요청마다 채우고 POST /api/notify/test 를 연다. nil 이면 둘 다 없음
	Notifier *notify.Service
	// Evidence: kill 직전에 모은 증거(10/20). nil 이면 라우트 없음
	Evidence EvidenceReader
	// PolicyFile: 기본 정책 파일(POLICY_FILE). 비면 GET /api/policies/defaults 를 열지 않는다
	PolicyFile string
	// Chat: AI 도우미(10/20). nil 이면 POST /api/chat 없음, /api/info chat=false
	Chat *chat.Service
	// Auth: 로그인(10/20). 있으면 /api/auth · /api/users · /api/license 를 열고, 화면 쓰기는 역할(admin)로 확인한다.
	// 세션 확인 자체는 바깥에서 Secure(auth.Middleware)가 한다(/ws/events 포함). nil 이면 예전처럼 ADMIN_TOKEN 만
	Auth *auth.Service
	// Demo: 시연 실행(10/30, DEMO_ENABLED). nil 이면 /api/demo 경로 없음 · /api/info demo=false
	Demo *demo.Service
	// Integration: 연동 화면(11/06) — 환경 점검 · 감시 중 컨테이너 · 연결 테스트. nil 이면 /api/integration 경로 없음
	Integration *integration.Service
	// EvalReportsDir: 평가 결과 JSON 디렉터리(EVAL_REPORTS_DIR, 11/04) — GET /api/evaluation 이 요청마다 읽는다. 비거나 파일이 없으면 404
	EvalReportsDir string
}

// Info: 대시보드가 표시하는 런타임 설정
type Info struct {
	Source        string       `json:"source"`
	Gadgets       []model.Kind `json:"gadgets"`
	EnforceKill   bool         `json:"enforceKill"`
	AuthRequired  bool         `json:"authRequired"`
	GadgetVersion string       `json:"gadgetVersion"`
	// 서버 설정 보기(10/16): 관찰 범위 — 화면은 보기만, 바꾸는 것은 서버 설정(WATCH_CONTAINERS · IGNORE_CONTAINERS)
	WatchContainers  []string `json:"watchContainers"`
	IgnoreContainers []string `json:"ignoreContainers"`
	// DNSResolve: "ok" = trace_dns 가 돌고 있어 도메인 · 직접 IP 연결을 판정한다 | "off" = 도메인 미확인 연결은 fail-open. 요청 때마다 Deps.DNSTraced 로 채운다
	DNSResolve string `json:"dnsResolve"`
	// Chat: AI 도우미 사용 가능(ANTHROPIC_API_KEY 또는 OLLAMA_URL) — 화면이 「AI 도우미」 탭을 보일지 정한다
	Chat bool `json:"chat"`
	// ChatEngine: 쓰는 모델(11/09) — 설정 화면이 「밖으로 나가는 데이터」를 provider 로 정해 보인다. 챗봇이 꺼져 있으면 생략
	ChatEngine *chat.Engine `json:"chatEngine,omitempty"`
	// Discovery: 실제로 쓰이는 컨테이너 발견 방식 "fanotify" | "docker-events" (mock · 가젯 시작 전은 빈 값). 요청 때마다 Deps.Discovery 로 채운다
	Discovery string `json:"discovery"`
	// DiscoveryNote: docker-events 일 때 놓칠 수 있는 구간 안내, 아니면 빈 값
	DiscoveryNote string `json:"discoveryNote"`
	// Notify: 외부 알림 채널 상태(호스트만 · 보낸/실패/버린 수). Deps.Notifier 가 없으면 생략
	Notify *notify.Status `json:"notify,omitempty"`
	// Demo: 시연 실행 API 가 열려 있는지(DEMO_ENABLED) — 화면이 관리자에게만 「시연」 카드를 보인다
	Demo bool `json:"demo"`
}

// dockerEventsNote: docker-events 는 컨테이너 start 이벤트를 받은 뒤에 추적을 붙여, 그 전의 첫 동작을 놓친다(sg-vm 실측 10/20)
const dockerEventsNote = "컨테이너 시작 직후 약 0.1초 안의 동작은 놓칠 수 있습니다"

const maxBody = 64 << 10 // nginx client_max_body_size 64k와 맞춤

func Router(d Deps) http.Handler {
	// 로그인이 켜져 있으면 늘 true (mock 이어도 쓰기는 관리자 계정만)
	d.Info.AuthRequired = d.Auth != nil || !(d.AllowAnonymousWrites && d.AdminToken == "")
	d.Info.Chat = d.Chat != nil
	if d.Chat != nil {
		e := d.Chat.Engine()
		d.Info.ChatEngine = &e
	}
	d.Info.Demo = d.Demo != nil
	if d.Info.WatchContainers == nil {
		d.Info.WatchContainers = []string{}
	}
	if d.Info.IgnoreContainers == nil {
		d.Info.IgnoreContainers = []string{}
	}
	if d.OSV == nil {
		d.OSV = osv.New()
	}
	h := &handlers{d}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", h.health)
	mux.HandleFunc("GET /api/info", h.info)
	mux.HandleFunc("GET /api/stats", h.stats)
	mux.HandleFunc("GET /api/events/recent", h.recent)
	mux.HandleFunc("GET /api/audit", h.audit)
	mux.HandleFunc("GET /api/policies", h.listPolicies)
	mux.HandleFunc("GET /api/policies/export", h.exportPolicies)
	mux.HandleFunc("GET /api/evaluation", h.evaluation)            // 평가 결과(11/04) — 읽기 전용, 로그인 뒤 모든 역할
	mux.HandleFunc("GET /api/sginstall/setup", h.sginstallSetup)   // 설치 검사 「사용 방법」(11/09) — 토큰은 관리자에게만
	mux.HandleFunc("GET /api/tools/sg-install", h.sginstallScript) // sg-install 내려받기(서버와 같은 판)
	if d.PolicyFile != "" {
		mux.HandleFunc("GET /api/policies/defaults", h.policyDefaults)
	}
	mux.HandleFunc("POST /api/policies", h.auth(h.savePolicy))
	mux.HandleFunc("PUT /api/policies", h.auth(h.replacePolicies))
	mux.HandleFunc("DELETE /api/policies/{id}", h.auth(h.deletePolicy))
	if d.Review != nil {
		h.routeReview(mux)
	}
	if d.Summary != nil {
		mux.HandleFunc("GET /api/summary", h.summary)
	}
	if d.Scans != nil {
		h.routeScans(mux)
	}
	if d.Notifier != nil {
		mux.HandleFunc("POST /api/notify/test", h.auth(h.notifyTest))
	}
	if d.Evidence != nil {
		mux.Handle("GET /api/evidence", EvidenceHandler(d.Evidence))
	}
	if d.Chat != nil {
		mux.Handle(ChatPattern, ChatHandler(d.Chat))
	}
	if d.Auth != nil {
		RegisterAuth(mux, AuthDeps{Auth: d.Auth})
	}
	if d.Demo != nil {
		h.routeDemo(mux)
	}
	if d.Integration != nil {
		mux.HandleFunc("GET /api/integration", h.integrationStatus)
		mux.HandleFunc("POST /api/integration/test", h.browserAdmin(msgProbeBrowserOnly, h.integrationTest))
	}
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
			hd.Set("Access-Control-Allow-Credentials", "true") // 다른 출처(Vite dev)에서 쿠키 세션 — fetch credentials: 'include'
			if r.Method == http.MethodOptions {
				hd.Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE") // PATCH: /api/users/{id}
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

// auth: 화면의 쓰기. 로그인이 켜져 있으면(Deps.Auth) Secure 가 넣은 요청자가 관리자여야 한다
// (쿠키 세션 admin 또는 Bearer ADMIN_TOKEN = CLIActor). 꺼져 있으면 예전처럼 ADMIN_TOKEN 만.
func (h *handlers) auth(next http.HandlerFunc) http.HandlerFunc {
	if h.Deps.Auth != nil {
		return auth.RequireAdmin(next)
	}
	return h.bearer(h.AdminToken, "ADMIN_TOKEN이 설정되지 않아 쓰기가 비활성화됨", "관리자 토큰이 필요함", next)
}

// sandboxAuth: sg-install CLI 의 세션 보고 · 차단 확인 — SANDBOX_TOKEN 만 받는다(ADMIN_TOKEN 으로는 안 됨).
func (h *handlers) sandboxAuth(next http.HandlerFunc) http.HandlerFunc {
	return h.bearer(h.SandboxToken, "SANDBOX_TOKEN이 설정되지 않아 설치 보고가 비활성화됨", "샌드박스 토큰이 필요함", next)
}

// bearer: 토큰이 비어 있으면 mock 소스만 통과(그 밖은 403), 있으면 Bearer 값을 상수 시간으로 비교(다르면 401).
func (h *handlers) bearer(token, disabledMsg, missingMsg string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if token == "" {
			if h.AllowAnonymousWrites {
				next(w, r)
				return
			}
			writeErr(w, http.StatusForbidden, disabledMsg)
			return
		}
		got, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		if !ok || subtle.ConstantTimeCompare([]byte(got), []byte(token)) != 1 {
			writeErr(w, http.StatusUnauthorized, missingMsg)
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

func (h *handlers) info(w http.ResponseWriter, _ *http.Request) {
	info := h.Info
	info.DNSResolve = "off"
	if h.DNSTraced != nil && h.DNSTraced() {
		info.DNSResolve = "ok"
	}
	info.Discovery, info.DiscoveryNote = "", ""
	if h.Discovery != nil {
		info.Discovery = h.Discovery()
	}
	if info.Discovery == "docker-events" {
		info.DiscoveryNote = dockerEventsNote
	}
	if h.Notifier != nil {
		st := h.Notifier.Status()
		info.Notify = &st
	}
	writeJSON(w, http.StatusOK, info)
}

// notifyTest: POST /api/notify/test — 관리자. 채널이 없으면 409, 있으면 202 와 지금 상태(발송은 비동기 —
// 화면은 1~2초 뒤 /api/info notify 의 sent · failed · lastError 를 다시 읽는다)
func (h *handlers) notifyTest(w http.ResponseWriter, r *http.Request) {
	if !h.Notifier.Enabled() {
		writeErr(w, http.StatusConflict, "알림 채널이 설정되지 않음 (NOTIFY_WEBHOOK_URL · NOTIFY_SLACK_URL)")
		return
	}
	h.Notifier.Notify(r.Context(), notify.TestMessage(time.Now()))
	writeJSON(w, http.StatusAccepted, h.Notifier.Status())
}

// summary: eBPF 수집 종합 — 읽기 전용, ?range=1h|24h|7d (기본 24h)
func (h *handlers) summary(w http.ResponseWriter, r *http.Request) {
	s, err := h.Summary.Build(r.Context(), r.URL.Query().Get("range"))
	var bad summary.ErrRange
	switch {
	case errors.As(err, &bad):
		writeErr(w, http.StatusBadRequest, err.Error())
	case err != nil:
		serverErr(w, "summary", err)
	default:
		writeJSON(w, http.StatusOK, s)
	}
}

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
		writeErr(w, http.StatusBadRequest, "kind: exec | open | connect | dns")
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
	// 쪽 번호(11/04): offset 이 있으면 {items, total, offset, limit}. 없으면 예전처럼 배열(커서 before)
	paged := q.Has("offset")
	if paged {
		if aq.Offset, err = strconv.Atoi(q.Get("offset")); err != nil || aq.Offset < 0 {
			writeErr(w, http.StatusBadRequest, "offset: 0 이상 정수")
			return
		}
		if q.Get("before") != "" {
			writeErr(w, http.StatusBadRequest, "before 와 offset 은 함께 쓸 수 없음")
			return
		}
	}
	entries, err := h.Audit.QueryAudit(r.Context(), aq)
	if err != nil {
		serverErr(w, "audit", err)
		return
	}
	if !paged {
		writeJSON(w, http.StatusOK, entries)
		return
	}
	total, err := h.Audit.CountAudit(r.Context(), aq)
	if err != nil {
		serverErr(w, "audit count", err)
		return
	}
	writeJSON(w, http.StatusOK, AuditPage{Items: entries, Total: total, Offset: aq.Offset, Limit: store.NormalizeLimit(aq.Limit)})
}

// AuditPage: GET /api/audit?offset=… 응답(11/04) — total 은 필터 뒤 전체 건수(쪽 번호 = ceil(total/limit))
type AuditPage struct {
	Items  []model.AuditEntry `json:"items"`
	Total  int                `json:"total"`
	Offset int                `json:"offset"`
	Limit  int                `json:"limit"`
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

// exportPolicies: 시스템 규칙(blocklist-hosts)은 빼고 내보낸다 — 내보낸 YAML 을 그대로 다시 적용(PUT)할 수 있게
func (h *handlers) exportPolicies(w http.ResponseWriter, _ *http.Request) {
	var rs []rules.Rule
	for _, r := range h.Engine.Rules() {
		if !rules.IsSystemRule(r.ID) {
			rs = append(rs, r)
		}
	}
	b, err := yaml.Marshal(map[string]any{"rules": rs})
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
	if rules.IsSystemRule(rule.ID) {
		writeErr(w, http.StatusConflict, systemRuleMsg)
		return
	}
	if err := rule.Validate(); err != nil {
		writeErr(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	err := h.policyWrite(r.Context(), model.ChangePolicyEdit, "정책 "+rule.ID+" 저장", []string{rule.ID}, func(ctx context.Context) error {
		return h.Policies.UpsertPolicy(ctx, rule)
	})
	if err != nil {
		serverErr(w, "save policy", err)
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
	for _, r := range rs {
		if rules.IsSystemRule(r.ID) {
			writeErr(w, http.StatusConflict, systemRuleMsg)
			return
		}
	}
	err = h.policyWrite(r.Context(), model.ChangePolicyReplace, fmt.Sprintf("YAML 로 정책 %d개 교체", len(rs)), nil, func(ctx context.Context) error {
		return h.Policies.ReplacePolicies(ctx, rs)
	})
	if err != nil {
		serverErr(w, "replace policies", err)
		return
	}
	slog.Info("policies replaced", "count", len(rs))
	writeJSON(w, http.StatusOK, h.Engine.Rules())
}

var errPolicyMissing = errors.New("정책 없음")

// systemRuleMsg: blocklist-hosts 는 차단 목록에서 만들어지므로 정책 API 로 다룰 수 없다
const systemRuleMsg = "blocklist-hosts 는 차단 목록에서 관리하는 시스템 규칙 — 차단 목록(/api/blocklist)에서 바꾼다"

func (h *handlers) deletePolicy(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if rules.IsSystemRule(id) {
		writeErr(w, http.StatusConflict, systemRuleMsg)
		return
	}
	err := h.policyWrite(r.Context(), model.ChangePolicyEdit, "정책 "+id+" 삭제", []string{id}, func(ctx context.Context) error {
		ok, err := h.Policies.DeletePolicy(ctx, id)
		if err == nil && !ok {
			return errPolicyMissing
		}
		return err
	})
	if errors.Is(err, errPolicyMissing) {
		writeErr(w, http.StatusNotFound, "정책 없음")
		return
	}
	if err != nil {
		serverErr(w, "delete policy", err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// policyWrite: 정책 저장 → 엔진 리로드 → 변경 이력. Review 가 있으면 제안 적용과 같은 잠금 안에서 한다.
// ids: 다루는 정책 id(저장 · 삭제), nil 이면 YAML 교체 — 변경 이력의 ruleIds · 변경 전 · 후 값(review.PolicyWrite)
func (h *handlers) policyWrite(ctx context.Context, kind model.ChangeKind, summary string, ids []string, write func(context.Context) error) error {
	if h.Review != nil {
		return h.Review.PolicyWrite(ctx, kind, summary, ids, write)
	}
	if err := write(ctx); err != nil {
		return err
	}
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
