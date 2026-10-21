package sginstall_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/api"
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/auth"
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/model"
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/osv"
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/review"
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/rules"
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/stats"
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/store"
)

// securedOpts: 설치 중 위반을 흉내 낼지, finish 보고를 실패시킬지
type securedOpts struct {
	violate    bool
	failFinish bool
}

// newSecuredHarness: main 과 같은 조립(로그인 켜짐, api.Secure). 감사 로그 · /api/info 는 로그인 뒤라 CLI 가 읽을 수 없다.
// 가짜 docker 는 컨테이너를 띄우지 않으므로, finish 보고가 오기 직전에 그 컨테이너의 위반을 파이프라인처럼 넣는다.
func newSecuredHarness(t *testing.T, o securedOpts) *harness {
	t.Helper()
	h := newHarness(t) // 도구 확인 · 가짜 docker (그 서버는 쓰지 않는다)
	mem := store.NewMemory()
	rs := []rules.Rule{{ID: "sandbox-egress", Kind: model.KindConnect, Action: model.ActionKill, Containers: []string{"sg-install-*"}, AllowHosts: []string{"pypi.org"}}}
	if err := mem.ReplacePolicies(t.Context(), rs); err != nil {
		t.Fatal(err)
	}
	engine := rules.New(rs)
	svc := review.New(review.Options{Store: mem, Policies: mem, Audit: mem, Engine: engine, EnforceKill: true, ActorFrom: api.RequesterName})
	if err := svc.Load(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := svc.Reload(t.Context()); err != nil {
		t.Fatal(err)
	}
	authSvc := auth.New(auth.Options{Store: store.NewMemoryAuth(), BcryptCost: 4})
	if _, err := authSvc.SeedAdmin(t.Context(), "admin", "initial-pass-1"); err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.Handle("/", api.Router(api.Deps{
		Engine: engine, Policies: mem, Audit: mem, Buffer: mem, Stats: stats.New().Snapshot,
		AdminToken: "admin-token", SandboxToken: sandboxToken, Review: svc, Auth: authSvc,
		OSV: &osv.Client{URL: "http://127.0.0.1:1"}, Info: api.Info{Source: "gadget"},
	}))
	secured := api.Secure(mux, api.SecureOptions{Auth: authSvc, AdminToken: "admin-token"})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut && strings.HasSuffix(r.URL.Path, "/finish") {
			if o.failFinish {
				http.Error(w, `{"error":"db down"}`, http.StatusInternalServerError)
				return
			}
			if o.violate {
				id := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/api/installs/"), "/finish")
				s, err := svc.GetInstall(id)
				if err != nil {
					t.Errorf("install %s: %v", id, err)
				}
				v := engine.Evaluate(model.Event{Kind: model.KindConnect, ContainerID: strings.Repeat("c", 64), ContainerName: s.Container,
					ImageName: s.Image, Comm: "python3", DstIP: "203.0.113.7", DstPort: 8081, DstHost: "cdn.reqeusts-update.test"})
				v.Enforced = true
				svc.Observe(&v)
				_ = mem.SaveAudit(r.Context(), v)
			}
		}
		secured.ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)
	h.svc, h.url = svc, srv.URL
	return h
}

// Tier 1 — 로그인 뒤에서도 위반을 숨기지 않는다: 결과는 SANDBOX_TOKEN 의 finish 응답에서 읽는다.
// 예전 스크립트는 감사 로그 조회가 401 이면 빈 목록으로 보고 「[OK] 위반 없음」 · 종료 코드 0 이었다.
func TestSecuredViolationIsReported(t *testing.T) {
	h := newSecuredHarness(t, securedOpts{violate: true})
	code, out := h.run(t, sandboxToken, "137", "pip", "./reqeusts")
	t.Logf("exit=%d\n%s", code, out)
	if code != 2 {
		t.Fatalf("exit code %d, want 2 (위반)\n%s", code, out)
	}
	for _, want := range []string{"[격리됨]", "sandbox-egress", "case-0001", "/installs?id=ins-0001"} {
		if !strings.Contains(out, want) {
			t.Errorf("출력에 %q 없음\n%s", want, out)
		}
	}
	if strings.Contains(out, "[OK]") || strings.Contains(out, "가젯 소스가 아닙니다") {
		t.Fatalf("거짓 OK · 거짓 경고\n%s", out)
	}
}

// Tier 1 — 결과를 받지 못하면 「결과 확인 불가」 + 0 이 아닌 종료 코드. 절대 「[OK] 위반 없음」으로 바꾸지 않는다.
func TestSecuredResultUnknownIsNotOK(t *testing.T) {
	h := newSecuredHarness(t, securedOpts{failFinish: true})
	code, out := h.run(t, sandboxToken, "0", "pip", "requests")
	t.Logf("exit=%d\n%s", code, out)
	if code == 0 || code == 2 {
		t.Fatalf("exit code %d, want non-zero 결과 확인 불가\n%s", code, out)
	}
	if !strings.Contains(out, "결과 확인 불가") || strings.Contains(out, "[OK]") {
		t.Fatalf("출력\n%s", out)
	}

	// 세션 시작 보고부터 실패해도(예: 백엔드가 세션을 못 남김) 같은 규칙
	h2 := newSecuredHarness(t, securedOpts{})
	code, out = h2.run(t, sandboxToken+"-x", "0", "pip", "requests")
	if code == 0 || strings.Contains(out, "[OK]") {
		t.Fatalf("틀린 토큰: exit %d\n%s", code, out)
	}
}

// 위반 없는 설치는 로그인 뒤에서도 [OK] · 0 (가젯 확인은 공개 /health 의 source)
func TestSecuredCleanInstall(t *testing.T) {
	h := newSecuredHarness(t, securedOpts{})
	code, out := h.run(t, sandboxToken, "0", "pip", "requests")
	if code != 0 || !strings.Contains(out, "[OK] 위반 없음") || strings.Contains(out, "가젯 소스가 아닙니다") {
		t.Fatalf("exit %d\n%s", code, out)
	}
}
