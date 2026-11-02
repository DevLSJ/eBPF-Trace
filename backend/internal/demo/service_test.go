package demo_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/api"
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/auth"
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/demo"
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/dockerapi"
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/ingestion"
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/model"
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/osv"
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/review"
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/rules"
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/stats"
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/store"
)

const (
	adminTok = "admin-tok"
	adminPW  = "initial-pass-1"
	newPW    = "brand-new-pass-1"
	license  = "1234-5678-9012-3456"
)

var seedRules = []rules.Rule{
	{ID: "pipe-to-shell", Kind: model.KindExec, Action: model.ActionKill, DenyArgs: []string{"| sh"}},
	{ID: "sandbox-dns", Kind: model.KindDNS, Action: model.ActionKill, Containers: []string{"sg-install-*"}, AllowHosts: []string{"pypi.org", "pythonhosted.org"}},
}

// gateSim: 시연 재생을 흉내 내되 release 가 닫힐 때까지 끝나지 않는다 (동시 1개 · 상태 확인용)
type gateSim struct {
	mu      sync.Mutex
	calls   []string
	release chan struct{}
}

func (g *gateSim) PlayDemo(ctx context.Context, s model.InstallSession, scenario string) bool {
	g.mu.Lock()
	g.calls = append(g.calls, scenario+"|"+s.Container)
	g.mu.Unlock()
	select {
	case <-g.release:
	case <-ctx.Done():
	}
	return false
}

func (g *gateSim) count() int { g.mu.Lock(); defer g.mu.Unlock(); return len(g.calls) }

// fakeDocker: Docker API 호출 순서 · 인자를 기록한다. block 이면 wait 가 ctx 가 끝날 때까지 막힌다(타임아웃 경로)
type fakeDocker struct {
	mu          sync.Mutex
	calls       []string
	spec        dockerapi.CreateSpec
	archive     []byte
	archivePath string
	exit        int
	block       bool
	pingErr     error
	panicStart  bool // 시작 단계에서 panic (11/02 — 실행 고루틴 recover 확인)
}

func (f *fakeDocker) rec(s string) { f.mu.Lock(); f.calls = append(f.calls, s); f.mu.Unlock() }
func (f *fakeDocker) Ping(context.Context) error {
	f.rec("ping")
	return f.pingErr
}
func (f *fakeDocker) CreateContainer(_ context.Context, s dockerapi.CreateSpec) (string, error) {
	f.rec("create")
	f.mu.Lock()
	f.spec = s
	f.mu.Unlock()
	return "cid123", nil
}
func (f *fakeDocker) PutArchive(_ context.Context, id, path string, r io.Reader) error {
	b, _ := io.ReadAll(r)
	f.mu.Lock()
	f.archive, f.archivePath = b, path
	f.mu.Unlock()
	f.rec("archive:" + id)
	return nil
}
func (f *fakeDocker) StartContainer(_ context.Context, id string) error {
	f.rec("start:" + id)
	if f.panicStart {
		panic("docker client exploded")
	}
	return nil
}
func (f *fakeDocker) WaitContainer(ctx context.Context, id string) (int, error) {
	f.rec("wait:" + id)
	if f.block {
		<-ctx.Done()
		return -1, ctx.Err()
	}
	return f.exit, nil
}
func (f *fakeDocker) RemoveContainer(_ context.Context, id string, force bool) error {
	f.rec(fmt.Sprintf("remove:%s:%v", id, force))
	return nil
}
func (f *fakeDocker) list() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.calls...)
}

type harness struct {
	t    *testing.T
	srv  *httptest.Server
	rv   *review.Service
	mem  *store.Memory
	svc  *demo.Service
	auth *auth.Service
}

// newHarness: main 과 같은 조립. withAuth 면 로그인(쿠키 · Bearer) 미들웨어까지 감싼다. blocked 는 차단 목록 패키지 키
func newHarness(t *testing.T, o demo.Options, withAuth bool, onStart func(model.InstallSession), blocked ...string) *harness {
	t.Helper()
	mem := store.NewMemory()
	if err := mem.ReplacePolicies(t.Context(), seedRules); err != nil {
		t.Fatal(err)
	}
	var c store.ReviewCommit
	for _, v := range blocked {
		c.BlockAdd = append(c.BlockAdd, model.BlockEntry{List: model.ListPackages, Value: v, By: "보안 담당자"})
	}
	if err := mem.CommitReview(t.Context(), c); err != nil {
		t.Fatal(err)
	}
	engine := rules.New(seedRules)
	rv := review.New(review.Options{Store: mem, Policies: mem, Audit: mem, Engine: engine, EnforceKill: true, ActorFrom: api.RequesterName, OnInstallStart: onStart})
	if err := rv.Load(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := rv.Reload(t.Context()); err != nil {
		t.Fatal(err)
	}
	o.Review = rv
	svc := demo.New(o)
	h := &harness{t: t, rv: rv, mem: mem, svc: svc}
	deps := api.Deps{Engine: engine, Policies: mem, Audit: mem, Buffer: mem, Stats: stats.New().Snapshot,
		Review: rv, Demo: svc, OSV: &osv.Client{URL: "http://127.0.0.1:1"}, AllowAnonymousWrites: !withAuth}
	if !withAuth {
		h.srv = httptest.NewServer(api.Router(deps))
		t.Cleanup(h.srv.Close)
		return h
	}
	h.auth = auth.New(auth.Options{Store: store.NewMemoryAuth(), OTPRequired: false, BcryptCost: 4})
	if _, err := h.auth.SeedAdmin(t.Context(), "admin", adminPW); err != nil {
		t.Fatal(err)
	}
	deps.Auth, deps.AdminToken = h.auth, adminTok
	mux := http.NewServeMux()
	mux.Handle("/", api.Router(deps))
	h.srv = httptest.NewServer(api.Secure(mux, api.SecureOptions{Auth: h.auth, AdminToken: adminTok}))
	t.Cleanup(h.srv.Close)
	return h
}

type browser struct {
	h *harness
	c *http.Client
}

func (h *harness) browser() *browser {
	jar, _ := cookiejar.New(nil)
	return &browser{h: h, c: &http.Client{Jar: jar}}
}

type reply struct {
	code int
	body map[string]any
}

func (b *browser) call(method, path, body string, hdr ...string) reply {
	b.h.t.Helper()
	req, _ := http.NewRequest(method, b.h.srv.URL+path, strings.NewReader(body))
	if method != http.MethodGet {
		req.Header.Set("Origin", b.h.srv.URL) // 같은 호스트 — CSRF 검사 통과
	}
	for i := 0; i+1 < len(hdr); i += 2 {
		req.Header.Set(hdr[i], hdr[i+1])
	}
	resp, err := b.c.Do(req)
	if err != nil {
		b.h.t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	r := reply{code: resp.StatusCode}
	_ = json.Unmarshal(raw, &r.body)
	return r
}

func (b *browser) must(want int, method, path, body string) reply {
	b.h.t.Helper()
	r := b.call(method, path, body)
	if r.code != want {
		b.h.t.Fatalf("%s %s: %d %v, want %d", method, path, r.code, r.body, want)
	}
	return r
}

func str(m map[string]any, k string) string { s, _ := m[k].(string); return s }

// loginAdmin: 초기 관리자 첫 로그인 → 비밀번호 → 라이선스 → active (OTP 끔)
func (h *harness) loginAdmin() *browser {
	h.t.Helper()
	b := h.browser()
	b.must(200, "POST", "/api/auth/login", `{"username":"admin","password":"`+adminPW+`"}`)
	b.must(200, "POST", "/api/auth/password", `{"current":"`+adminPW+`","next":"`+newPW+`"}`)
	if r := b.must(200, "POST", "/api/auth/license", `{"key":"`+license+`"}`); str(r.body, "state") != "active" {
		h.t.Fatalf("admin activation: %v", r.body)
	}
	return b
}

// newViewer: 관리자가 조회자 계정을 만들고 그 계정으로 로그인한 브라우저
func (h *harness) newViewer(admin *browser) *browser {
	h.t.Helper()
	r := admin.must(201, "POST", "/api/users", `{"username":"viewer1","displayName":"김조회","role":"viewer"}`)
	temp := str(r.body, "tempPassword")
	v := h.browser()
	v.must(200, "POST", "/api/auth/login", `{"username":"viewer1","password":"`+temp+`"}`)
	if r := v.must(200, "POST", "/api/auth/password", `{"current":"`+temp+`","next":"viewer-pass-12"}`); str(r.body, "state") != "active" {
		h.t.Fatalf("viewer activation: %v", r.body)
	}
	return v
}

// Tier 1 — 시연 실행은 대시보드 관리자 세션만: 조회자 403 · Bearer ADMIN_TOKEN 403 · 관리자 쿠키 202. GET /api/demo 는 조회자도 읽는다
func TestDemoRunAdminOnly(t *testing.T) {
	sim := &gateSim{release: make(chan struct{})}
	h := newHarness(t, demo.Options{Simulator: sim}, true, nil)
	admin := h.loginAdmin()
	viewer := h.newViewer(admin)

	if r := viewer.must(200, "GET", "/api/demo", ""); r.body["enabled"] != true || r.body["running"] != nil {
		t.Fatalf("viewer GET /api/demo: %v", r.body)
	}
	if r := viewer.must(403, "POST", "/api/demo/run", `{"scenario":"shell"}`); str(r.body, "error") != "조회자는 읽기만 할 수 있습니다" {
		t.Fatalf("viewer run: %v", r.body)
	}
	cli := h.browser()
	if r := cli.call("POST", "/api/demo/run", `{"scenario":"shell"}`, "Authorization", "Bearer "+adminTok); r.code != 403 {
		t.Fatalf("Bearer ADMIN_TOKEN must not run the demo: %d %v", r.code, r.body)
	}
	if r := cli.call("POST", "/api/demo/run", `{"scenario":"shell"}`); r.code != 401 {
		t.Fatalf("anonymous: %d", r.code)
	}
	if sim.count() != 0 {
		t.Fatal("no run may have started")
	}
	r := admin.must(202, "POST", "/api/demo/run", `{"scenario":"shell"}`)
	if str(r.body, "status") != "running" || r.body["simulated"] != true || !strings.HasPrefix(str(r.body, "container"), "sg-install-demo-") || !strings.HasPrefix(str(r.body, "id"), "demo-") || str(r.body, "installId") == "" {
		t.Fatalf("run: %v", r.body)
	}
	if r.body["finishedAt"] != nil || r.body["exitCode"] != nil {
		t.Fatalf("running run must have null finishedAt · exitCode: %v", r.body)
	}
	if ch := h.rv.ListChanges(1); len(ch) != 1 || ch[0].Kind != model.ChangeDemoRun || ch[0].By != "admin" || ch[0].Summary != "시연 실행: shell" || ch[0].CaseID != nil {
		t.Fatalf("change: %+v", ch)
	}
	admin.must(400, "POST", "/api/demo/run", `{"scenario":"udp"}`)
	close(sim.release)
	h.svc.Wait()
	if r := admin.must(200, "GET", "/api/demo", ""); r.body["running"] != nil {
		t.Fatalf("after finish: %v", r.body)
	}
}

// 동시 1개: 실행 중에 또 부르면 409 와 진행 중인 Run. 끝나면 running 이 비고 last 가 남는다
func TestDemoRunConflict409(t *testing.T) {
	sim := &gateSim{release: make(chan struct{})}
	h := newHarness(t, demo.Options{Simulator: sim}, false, nil)
	b := h.browser()
	first := b.must(202, "POST", "/api/demo/run", `{"scenario":"all"}`)
	second := b.must(409, "POST", "/api/demo/run", `{"scenario":"shell"}`)
	running, _ := second.body["running"].(map[string]any)
	if str(second.body, "error") != "시연이 이미 실행 중입니다" || str(running, "id") != str(first.body, "id") {
		t.Fatalf("409 body: %v", second.body)
	}
	if r := b.must(200, "GET", "/api/demo", ""); r.body["running"] == nil || r.body["last"] != nil {
		t.Fatalf("status while running: %v", r.body)
	} else if sc, _ := r.body["scenarios"].([]any); len(sc) != 6 || sc[0] != "all" || sc[5] != "dns-exfil" {
		t.Fatalf("scenarios: %v", sc)
	}
	if sim.count() != 1 {
		t.Fatalf("exactly one play, got %d", sim.count())
	}
	close(sim.release)
	h.svc.Wait()
	r := b.must(200, "GET", "/api/demo", "")
	last, _ := r.body["last"].(map[string]any)
	if r.body["running"] != nil || str(last, "status") != "finished" || last["exitCode"] != float64(0) || last["finishedAt"] == nil {
		t.Fatalf("after finish: %v", r.body)
	}
	b.must(400, "POST", "/api/demo/run", `{"scenario":""}`)
	if r := b.must(400, "POST", "/api/demo/run", `{"scenario":"nope"}`); str(r.body, "error") != "scenario: all | shell | revshell | direct-ip | domain | dns-exfil" {
		t.Fatalf("bad scenario: %v", r.body)
	}
	b.must(202, "POST", "/api/demo/run", `{"scenario":"shell"}`) // 끝난 뒤에는 다시 실행할 수 있다(같은 초라도 컨테이너 이름이 겹치지 않는다)
	h.svc.Wait()
}

// DEMO_ENABLED 가 아니면(Deps.Demo 없음) 경로가 없고 /api/info.demo 는 false
func TestDemoRouteDisabledWithoutEnv(t *testing.T) {
	mem := store.NewMemory()
	off := httptest.NewServer(api.Router(api.Deps{Engine: rules.New(nil), Policies: mem, Audit: mem, Buffer: mem, Stats: stats.New().Snapshot, AllowAnonymousWrites: true}))
	t.Cleanup(off.Close)
	get := func(url string) (int, map[string]any) {
		resp, err := http.Get(url)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var m map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&m)
		return resp.StatusCode, m
	}
	if code, _ := get(off.URL + "/api/demo"); code != 404 {
		t.Fatalf("GET /api/demo without DEMO_ENABLED: %d", code)
	}
	if resp, _ := http.Post(off.URL+"/api/demo/run", "application/json", strings.NewReader(`{"scenario":"all"}`)); resp.StatusCode != 404 {
		t.Fatalf("POST /api/demo/run without DEMO_ENABLED: %d", resp.StatusCode)
	}
	if _, info := get(off.URL + "/api/info"); info["demo"] != false {
		t.Fatalf("info.demo must be false: %v", info)
	}
	h := newHarness(t, demo.Options{Simulator: &gateSim{release: make(chan struct{})}}, false, nil)
	if _, info := get(h.srv.URL + "/api/info"); info["demo"] != true {
		t.Fatalf("info.demo must be true when enabled: %v", info)
	}
	if code, st := get(h.srv.URL + "/api/demo"); code != 200 || st["enabled"] != true || st["running"] != nil || st["last"] != nil {
		t.Fatalf("GET /api/demo: %d %v", code, st)
	}
}

// 차단 목록에 pip:reqeusts 가 있으면 sg-install 처럼 거부 세션을 만들고 status refused 로 202. 컨테이너 · 재생은 없다
func TestDemoRefusedWhenBlocklisted(t *testing.T) {
	sim := &gateSim{release: make(chan struct{})}
	h := newHarness(t, demo.Options{Simulator: sim}, false, nil, "pip:reqeusts")
	b := h.browser()
	r := b.must(202, "POST", "/api/demo/run", `{"scenario":"all"}`)
	if str(r.body, "status") != "refused" || r.body["finishedAt"] == nil || str(r.body, "installId") == "" || r.body["simulated"] != true {
		t.Fatalf("refused run: %v", r.body)
	}
	s, err := h.rv.GetInstall(str(r.body, "installId"))
	if err != nil || s.Status != model.InstallRefused || s.RefusedBy == nil || s.RefusedBy.Value != "pip:reqeusts" || !s.Demo || s.Label() != "pip ./reqeusts" {
		t.Fatalf("refused session: %+v %v", s, err)
	}
	if sim.count() != 0 {
		t.Fatal("refused run must not play anything")
	}
	st := b.must(200, "GET", "/api/demo", "")
	last, _ := st.body["last"].(map[string]any)
	if st.body["running"] != nil || str(last, "status") != "refused" {
		t.Fatalf("status after refusal: %v", st.body)
	}
	if ch := h.rv.ListChanges(1); len(ch) != 1 || ch[0].Kind != model.ChangeDemoRun {
		t.Fatalf("refused run still records demo_run: %+v", ch)
	}
	// 차단 해제 뒤에는 실행된다
	if err := h.rv.RemoveBlock(t.Context(), model.ListPackages, "pip:reqeusts", ""); err != nil {
		t.Fatal(err)
	}
	if r := b.must(202, "POST", "/api/demo/run", `{"scenario":"shell"}`); str(r.body, "status") != "running" {
		t.Fatalf("after unblock: %v", r.body)
	}
	close(sim.release)
	h.svc.Wait()
}

// mock 소스(10/30): 컨테이너 없이 같은 세션(demo · pip ./reqeusts)에 시나리오 이벤트를 순서대로 재생한다(simulated). 첫 kill 에서 멈춘다
func TestDemoRunMockSimulated(t *testing.T) {
	m := ingestion.NewMock()
	m.Interval, m.AttackIn, m.RestartIn, m.Step = time.Hour, time.Hour, time.Hour, time.Millisecond
	out := make(chan model.Event, 4096)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go m.Run(ctx, out)
	for range 3 {
		<-out // 컨테이너 시작 3건
	}
	h := newHarness(t, demo.Options{Simulator: m}, false, m.SimulateInstall)

	run, err := h.svc.Start(context.Background(), "dns-exfil")
	if err != nil || run.Status != "running" || !run.Simulated || run.Scenario != "dns-exfil" {
		t.Fatalf("start: %+v %v", run, err)
	}
	s, err := h.rv.GetInstall(run.InstallID)
	if err != nil || !s.Demo || s.Manager != "pip" || s.Label() != "pip ./reqeusts" || s.Container != run.Container || s.Image != "python:3.12-slim" {
		t.Fatalf("session: %+v %v", s, err)
	}
	var kinds []string
	deadline := time.After(5 * time.Second)
loop:
	for {
		select {
		case ev := <-out:
			if ev.ContainerName != run.Container {
				continue
			}
			k := string(ev.Kind)
			switch ev.Kind {
			case model.KindExec:
				k += ":" + ev.Comm
			case model.KindConnect:
				k += ":" + ev.DstHost
			case model.KindDNS:
				k += ":" + ev.Qtype + ":" + ev.DstHost
			}
			kinds = append(kinds, k)
			if ev.Kind == model.KindExit {
				break loop
			}
		case <-deadline:
			t.Fatalf("timed out; events so far %v", kinds)
		}
	}
	want := []string{"start", "exec:pip", "connect:pypi.org", "connect:files.pythonhosted.org", "open", // pip 정상 설치 단계(setuptools 열기 포함)
		"dns:A:" + strings.Repeat("deadbeef", 6) + ".exfil.example", "dns:TXT:data.exfil.example", "exit"}
	if strings.Join(kinds, " ") != strings.Join(want, " ") {
		t.Fatalf("event order:\n got %v\nwant %v", kinds, want)
	}
	h.svc.Wait()
	st := h.svc.Status()
	if st.Running != nil || st.Last == nil || st.Last.Status != "finished" || st.Last.ExitCode == nil || *st.Last.ExitCode != 0 || !st.Last.Simulated {
		t.Fatalf("status: %+v", st)
	}
	if s, _ = h.rv.GetInstall(run.InstallID); s.FinishedAt == nil || s.ExitCode == nil || *s.ExitCode != 0 || s.Status != model.InstallPassed {
		t.Fatalf("finished session: %+v", s)
	}
	if ch := h.rv.ListChanges(1); len(ch) != 1 || ch[0].Kind != model.ChangeDemoRun || ch[0].Summary != "시연 실행: dns-exfil" {
		t.Fatalf("change: %+v", ch)
	}

	// all: 첫 kill(shell 의 sh) 에서 멈춘다 — 이후 시나리오 이벤트가 나오지 않고 종료 코드 137
	run2, err := h.svc.Start(context.Background(), "all")
	if err != nil {
		t.Fatal(err)
	}
	var after []string
	killedNow := false
	deadline = time.After(5 * time.Second)
loop2:
	for {
		select {
		case ev := <-out:
			if ev.ContainerName != run2.Container {
				continue
			}
			if !killedNow {
				if ev.Kind == model.KindExit {
					t.Fatal("the shell scenario's `sh` exec must come before the exit")
				}
				if ev.Kind == model.KindExec && ev.Comm == "sh" {
					if err := m.Kill(ctx, ev.ContainerID); err != nil {
						t.Fatal(err)
					}
					killedNow = true
				}
				continue
			}
			after = append(after, string(ev.Kind)+":"+ev.Comm)
			if ev.Kind == model.KindExit {
				break loop2
			}
		case <-deadline:
			t.Fatalf("timed out waiting for exit; %v", after)
		}
	}
	if len(after) != 1 || !strings.HasPrefix(after[0], "exit:") {
		t.Fatalf("after the kill only the exit event may follow, got %v", after)
	}
	h.svc.Wait()
	if st := h.svc.Status(); st.Last == nil || st.Last.ExitCode == nil || *st.Last.ExitCode != 137 || st.Last.Status != "finished" {
		t.Fatalf("killed run: %+v", st.Last)
	}
}

// Tier 1 — 가젯 소스: Docker API 순서(ping → create → archive → start → wait → remove) · 고정 인자 · 타임아웃 · Docker 불통 503
func TestDemoDockerFlow(t *testing.T) {
	fd := &fakeDocker{exit: 0}
	h := newHarness(t, demo.Options{Docker: fd, Image: "python:3.12-slim", Timeout: time.Second}, false, nil)
	run, err := h.svc.Start(context.Background(), "shell")
	if err != nil || run.Simulated || run.Status != "running" {
		t.Fatalf("start: %+v %v", run, err)
	}
	h.svc.Wait()
	calls := fd.list()
	want := []string{"ping", "create", "archive:cid123", "start:cid123", "wait:cid123", "remove:cid123:true"}
	if strings.Join(calls, " ") != strings.Join(want, " ") {
		t.Fatalf("docker calls:\n got %v\nwant %v", calls, want)
	}
	sp := fd.spec
	if sp.Name != run.Container || sp.Image != "python:3.12-slim" || strings.Join(sp.Cmd, " ") != "pip install --no-cache-dir --progress-bar off /pkg/reqeusts" {
		t.Fatalf("create spec: %+v", sp)
	}
	if strings.Join(sp.Env, ",") != "SG_DEMO_SCENARIOS=shell,PIP_DISABLE_PIP_VERSION_CHECK=1" || sp.Labels["supplyguard.demo"] != "install" {
		t.Fatalf("env · labels: %+v", sp)
	}
	if fd.archivePath != "/" || !strings.Contains(string(fd.archive), "pkg/reqeusts/setup.py") || !strings.Contains(string(fd.archive), "scn_dns_exfil") {
		t.Fatalf("archive: path=%q len=%d", fd.archivePath, len(fd.archive))
	}
	st := h.svc.Status()
	if st.Last == nil || st.Last.Status != "finished" || *st.Last.ExitCode != 0 {
		t.Fatalf("status: %+v", st.Last)
	}
	if s, _ := h.rv.GetInstall(run.InstallID); s.Status != model.InstallPassed || !s.Demo || s.Image != "python:3.12-slim" {
		t.Fatalf("session: %+v", s)
	}

	// 타임아웃: wait 가 안 끝나면 강제 제거하고 timeout 으로 끝낸다. 세션은 종료 코드 124 로 닫힌다
	slow := &fakeDocker{block: true}
	h2 := newHarness(t, demo.Options{Docker: slow, Timeout: 30 * time.Millisecond}, false, nil)
	run2, err := h2.svc.Start(context.Background(), "revshell")
	if err != nil {
		t.Fatal(err)
	}
	h2.svc.Wait()
	if st := h2.svc.Status(); st.Last == nil || st.Last.Status != "timeout" {
		t.Fatalf("timeout status: %+v", st.Last)
	}
	if calls := slow.list(); calls[len(calls)-1] != "remove:cid123:true" {
		t.Fatalf("timeout must force-remove: %v", calls)
	}
	if s, _ := h2.rv.GetInstall(run2.InstallID); s.FinishedAt == nil || s.ExitCode == nil || *s.ExitCode != 124 || s.Status != model.InstallFailed {
		t.Fatalf("timed-out session: %+v", s)
	}

	// Docker 불통: 세션을 만들기 전에 503 으로 끝낸다
	down := &fakeDocker{pingErr: errors.New("dial unix /var/run/docker.sock: connect: no such file")}
	h3 := newHarness(t, demo.Options{Docker: down}, false, nil)
	if _, err := h3.svc.Start(context.Background(), "shell"); !errors.Is(err, demo.ErrDocker) {
		t.Fatalf("want ErrDocker, got %v", err)
	}
	if n := len(h3.rv.ListInstalls(review.InstallQuery{})); n != 0 {
		t.Fatalf("no session when docker is down, got %d", n)
	}
	b := h3.browser()
	if r := b.must(503, "POST", "/api/demo/run", `{"scenario":"shell"}`); str(r.body, "error") != "Docker 에 연결할 수 없습니다" {
		t.Fatalf("503 body: %v", r.body)
	}
}

// 11/02: 실행 고루틴의 panic 은 서버를 죽이지 않고 — 컨테이너를 지우고 failed 로 끝내고, 다음 시연을 막지 않는다
func TestDemoPanicRecovered(t *testing.T) {
	fd := &fakeDocker{panicStart: true}
	h := newHarness(t, demo.Options{Docker: fd, Timeout: time.Second}, false, nil)
	run, err := h.svc.Start(context.Background(), "shell")
	if err != nil {
		t.Fatal(err)
	}
	h.svc.Wait()
	st := h.svc.Status()
	if st.Running != nil || st.Last == nil || st.Last.Status != "failed" || *st.Last.ExitCode != -1 {
		t.Fatalf("after panic: running=%+v last=%+v", st.Running, st.Last)
	}
	if calls := fd.list(); calls[len(calls)-1] != "remove:cid123:true" {
		t.Fatalf("panic must still force-remove: %v", calls)
	}
	if s, _ := h.rv.GetInstall(run.InstallID); s.FinishedAt == nil {
		t.Fatalf("session must be finished after panic: %+v", s)
	}
	fd.panicStart = false
	if _, err := h.svc.Start(context.Background(), "shell"); err != nil {
		t.Fatalf("next run must not be blocked: %v", err)
	}
	h.svc.Wait()
}

// 11/02: 서버 종료(Shutdown)는 대기 중인 시연을 곧바로 멈추고 컨테이너를 강제 제거한 뒤 돌아온다 — 고아 sg-install-demo-* 없음
func TestDemoShutdownRemovesContainer(t *testing.T) {
	fd := &fakeDocker{block: true}
	h := newHarness(t, demo.Options{Docker: fd, Timeout: time.Minute}, false, nil)
	if _, err := h.svc.Start(context.Background(), "shell"); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 200 && !strings.HasPrefix(strings.Join(fd.list(), " "), "ping create archive:cid123 start:cid123 wait:cid123"); i++ {
		time.Sleep(5 * time.Millisecond)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	t0 := time.Now()
	if err := h.svc.Shutdown(ctx); err != nil {
		t.Fatalf("shutdown: %v", err)
	}
	if d := time.Since(t0); d > time.Second {
		t.Fatalf("shutdown waited %v (must cancel the wait, not run out the 1m timeout)", d)
	}
	if calls := fd.list(); calls[len(calls)-1] != "remove:cid123:true" {
		t.Fatalf("shutdown must force-remove: %v", calls)
	}
	if st := h.svc.Status(); st.Running != nil || st.Last == nil || st.Last.Status != "failed" {
		t.Fatalf("after shutdown: %+v", st)
	}
	if _, err := h.svc.Start(context.Background(), "shell"); err == nil {
		t.Fatal("start after shutdown must be refused")
	}
}
