package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/auth"
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/dockerapi"
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/integration"
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/pipeline"
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/rules"
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/stats"
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/store"
)

type detailLister struct{ cs []integration.Container }

func (l detailLister) Containers(context.Context) ([]integration.Container, error) { return l.cs, nil }

type detailScoper struct{}

func (detailScoper) Scope(name string, l map[string]string) pipeline.Scope {
	if strings.HasPrefix(name, "supplyguard-") {
		return pipeline.Scope{Ignored: true}
	}
	if l[pipeline.LabelEnforce] == "true" {
		return pipeline.Scope{Watched: true, WatchBy: "all", Enforce: true, EnforceBy: "label"}
	}
	return pipeline.Scope{Watched: true, WatchBy: "all"}
}

// fakeDockerd: Docker Engine API 흉내 — inspect 에 환경 변수(비밀)를 담아 돌려준다. vanished 는 목록엔 있지만 inspect 는 404(방금 종료)
func fakeDockerd(t *testing.T) *dockerapi.Client {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/containers/c-shop/json":
			_, _ = w.Write([]byte(`{"Id":"c-shop","Name":"/shop-api","Image":"sha256:feed","RestartCount":1,
			 "State":{"Status":"running","Running":true,"StartedAt":"2026-11-10T01:02:03Z"},
			 "Config":{"Image":"node:22","Env":["API_SECRET=very-secret-value"],"Labels":{"supplyguard.enforce":"true","app":"shop"}},
			 "NetworkSettings":{"Ports":{"8080/tcp":[{"HostIp":"0.0.0.0","HostPort":"18080"}]}}}`))
		default:
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"message":"No such container"}`))
		}
	}))
	t.Cleanup(srv.Close)
	c, err := dockerapi.New("tcp://" + strings.TrimPrefix(srv.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func detailService() *integration.Service {
	return integration.New(integration.Options{Scoper: detailScoper{}, Lister: detailLister{cs: []integration.Container{
		{ID: "c-shop", Name: "shop-api", Image: "node:22", Labels: map[string]string{"supplyguard.enforce": "true", "app": "shop"}},
		{ID: "c-vanished", Name: "vanished", Image: "busybox", Labels: map[string]string{}},
		{ID: "c-self", Name: "supplyguard-backend-1", Image: "sg/backend", Labels: map[string]string{}},
	}}})
}

// 감시 중 컨테이너 상세(11/10, 읽기 전용): GET /api/integration/containers/{id}
//   - 목록(감시 판정 포함)에 있는 컨테이너만 — 자기 스택 · 모르는 id 는 404 + 서버 문장
//   - Docker inspect 로 상태 · 시작 시각 · 재시작 · 포트 · 라벨, 환경 변수는 응답 어디에도 없다
//   - 목록엔 있지만 inspect 가 404(방금 종료)면 404, inspect 가 없으면(mock) 목록 값만
func TestIntegrationContainerDetail(t *testing.T) {
	mem := store.NewMemory()
	srv := httptest.NewServer(Router(Deps{Engine: rules.New(nil), Policies: mem, Audit: mem, Buffer: mem, Stats: stats.New().Snapshot,
		Integration: detailService(), Containers: fakeDockerd(t)}))
	defer srv.Close()

	resp := do(t, http.MethodGet, srv.URL+"/api/integration/containers/c-shop", "", "")
	body := readBody(t, resp)
	if resp.StatusCode != 200 {
		t.Fatalf("GET = %d %s", resp.StatusCode, body)
	}
	for _, want := range []string{`"id":"c-shop"`, `"name":"shop-api"`, `"image":"node:22"`, `"state":"running"`, `"startedAt":"2026-11-10T01:02:03Z"`,
		`"restartCount":1`, `"port":"8080/tcp"`, `"hostPort":"18080"`, `"app":"shop"`, `"watched":true`, `"watchBy":"all"`, `"enforce":true`, `"enforceBy":"label"`} {
		if !strings.Contains(body, want) {
			t.Fatalf("응답에 %s 없음: %s", want, body)
		}
	}
	if strings.Contains(body, "very-secret-value") || strings.Contains(body, "API_SECRET") || strings.Contains(strings.ToLower(body), `"env"`) {
		t.Fatalf("환경 변수가 나갔다: %s", body)
	}

	for _, id := range []string{"nope", "c-self", "c-vanished"} {
		resp := do(t, http.MethodGet, srv.URL+"/api/integration/containers/"+id, "", "")
		b := readBody(t, resp)
		if resp.StatusCode != http.StatusNotFound || !strings.Contains(b, "컨테이너를 찾을 수 없습니다") {
			t.Fatalf("%s = %d %s, want 404 + 서버 문장", id, resp.StatusCode, b)
		}
	}

	// inspect 가 없는 서버(mock 소스): 목록 값만 — 상태는 실행 중, 시작 시각 없음
	srv2 := httptest.NewServer(Router(Deps{Engine: rules.New(nil), Policies: mem, Audit: mem, Buffer: mem, Stats: stats.New().Snapshot, Integration: detailService()}))
	defer srv2.Close()
	resp = do(t, http.MethodGet, srv2.URL+"/api/integration/containers/c-vanished", "", "")
	b := readBody(t, resp)
	if resp.StatusCode != 200 || !strings.Contains(b, `"state":"running"`) || strings.Contains(b, "startedAt") || !strings.Contains(b, `"labels":{}`) || !strings.Contains(b, `"ports":[]`) {
		t.Fatalf("목록 값만 = %d %s", resp.StatusCode, b)
	}
}

// 로그인 뒤에만(익명 401), 조회자도 읽는다(읽기 전용)
func TestIntegrationContainerDetailAuth(t *testing.T) {
	c := &fakeClock{t: time.Date(2026, 11, 10, 9, 0, 0, 0, time.UTC)}
	svc := auth.New(auth.Options{Store: store.NewMemoryAuth(), OTPRequired: false, BcryptCost: 4, Now: c.Now, TrustProxy: true})
	if _, err := svc.SeedAdmin(t.Context(), "admin", flowAdminPW); err != nil {
		t.Fatal(err)
	}
	mem := store.NewMemory()
	mux := http.NewServeMux()
	mux.Handle("/", Router(Deps{Engine: rules.New(nil), Policies: mem, Audit: mem, Buffer: mem, Stats: stats.New().Snapshot,
		AdminToken: flowAdminTok, Auth: svc, AllowedOrigins: []string{devOrigin}, Integration: detailService(), Containers: fakeDockerd(t)}))
	srv := httptest.NewServer(Secure(mux, SecureOptions{Auth: svc, AdminToken: flowAdminTok, AllowedOrigins: []string{devOrigin}}))
	defer srv.Close()
	e := &authEnv{srv: srv, svc: svc, clock: c}

	const path = "/api/integration/containers/c-shop"
	e.browser(t).must(401, "GET", path, "")

	admin := e.browser(t)
	activateAdmin(t, e, admin, false)
	if r := admin.must(200, "GET", path, ""); r.body["name"] != "shop-api" {
		t.Fatalf("admin: %v", r.body)
	}
	r := admin.must(201, "POST", "/api/users", `{"username":"viewer1","displayName":"김조회","role":"viewer"}`)
	temp := str(r.body, "tempPassword")
	viewer := e.browser(t)
	viewer.must(200, "POST", "/api/auth/login", `{"username":"viewer1","password":"`+temp+`"}`)
	viewer.must(200, "POST", "/api/auth/password", `{"current":"`+temp+`","next":"viewer-pass-12"}`)
	if r := viewer.must(200, "GET", path, ""); r.body["name"] != "shop-api" {
		t.Fatalf("viewer: %v", r.body)
	}
}
