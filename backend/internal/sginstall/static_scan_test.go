package sginstall_test

// 종합 판정(11/04): sg-install 세션 보고(POST /api/installs)를 받으면 서버가 첫 패키지의 정적 검사를 스스로 시작한다.
// CLI 의 응답 시간 · 종료 코드는 그대로여야 한다(curl -m 5) — 검사는 보고 응답 뒤에서 돈다.

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/api"
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/dockerapi"
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/model"
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/osv"
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/review"
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/rules"
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/scan"
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/stats"
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/store"
)

// scanRunner: 검사기 컨테이너 대신 — GuardDog 는 위협 없음, OSV 는 빈 결과. hold 가 있으면 Ping 을 그때까지 붙잡는다
type scanRunner struct {
	hold chan struct{}
}

func (r *scanRunner) Ping(ctx context.Context) error {
	if r.hold == nil {
		return nil
	}
	select {
	case <-r.hold:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (r *scanRunner) Run(_ context.Context, s dockerapi.RunSpec) ([]byte, int, error) {
	switch {
	case s.Cmd[len(s.Cmd)-1] == "--version":
		return []byte("tool 1.0"), 0, nil
	case strings.Contains(s.Name, "-guarddog"):
		return []byte(`{"results":{},"risk_score":{"score":0,"label":"no_risks_detected"}}`), 0, nil
	}
	return []byte(`{"results":[]}`), 0, nil
}

// fakePyPI: requests 2.32.3 sdist 하나
func fakePyPI(t *testing.T) string {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	body := []byte("x = 1\n")
	_ = tw.WriteHeader(&tar.Header{Name: "requests-2.32.3/requests/__init__.py", Mode: 0o644, Size: int64(len(body)), Typeflag: tar.TypeReg})
	_, _ = tw.Write(body)
	tw.Close()
	gz.Close()
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasPrefix(r.URL.Path, "/pypi/requests/"):
			_, _ = w.Write([]byte(`{"info":{"version":"2.32.3"},"urls":[{"packagetype":"sdist","url":"` + srv.URL + `/files/requests-2.32.3.tar.gz"}]}`))
		case strings.HasSuffix(r.URL.Path, ".tar.gz"):
			_, _ = w.Write(buf.Bytes())
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

type scanHarness struct {
	*harness
	scans *scan.Service
}

// newScanHarness: newHarness 와 같되 review 의 OnInstallStart 에 자동 정적 검사(cmd/server 와 같은 합성)를 붙인다
func newScanHarness(t *testing.T, r *scanRunner) *scanHarness {
	t.Helper()
	base := newHarness(t) // 도구 확인 · 가짜 docker
	mem := store.NewMemory()
	engine := rules.New(nil)
	var svc *review.Service
	scans := scan.New(scan.Options{Docker: r, Dir: t.TempDir(), Volume: "v", Store: mem, PyPI: fakePyPI(t), NPM: "http://127.0.0.1:1"})
	svc = review.New(review.Options{Store: mem, Policies: mem, Audit: mem, Engine: engine,
		OnInstallStart: scan.AutoScan(func() *scan.Service { return scans }, func(ctx context.Context, id, scanID, skip string) error { return svc.AttachScan(ctx, id, scanID, skip) })})
	if err := svc.Load(t.Context()); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(api.Router(api.Deps{
		Engine: engine, Policies: mem, Audit: mem, Buffer: mem, Stats: stats.New().Snapshot,
		AdminToken: "admin-token", SandboxToken: sandboxToken, Review: svc, OSV: &osv.Client{URL: "http://127.0.0.1:1"},
		Scans: scans, Info: api.Info{Source: "gadget"},
	}))
	t.Cleanup(srv.Close)
	base.svc, base.url = svc, srv.URL
	return &scanHarness{harness: base, scans: scans}
}

func (h *scanHarness) session(t *testing.T) model.InstallSession {
	t.Helper()
	ss := h.svc.ListInstalls(review.InstallQuery{})
	if len(ss) != 1 {
		t.Fatalf("want one session, got %d", len(ss))
	}
	return ss[0]
}

func waitUntil(t *testing.T, what string, ok func() bool) {
	t.Helper()
	for i := 0; i < 1500; i++ {
		if ok() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timeout: %s", what)
}

func TestInstallStartsStaticScan(t *testing.T) {
	h := newScanHarness(t, &scanRunner{})
	code, out := h.run(t, sandboxToken, "0", "pip", "requests")
	if code != 0 {
		t.Fatalf("exit %d\n%s", code, out)
	}
	waitUntil(t, "scan attached", func() bool { return h.session(t).ScanID != nil })
	s := h.session(t)
	sc, ok := h.scans.Get(*s.ScanID)
	if !ok || sc.Trigger != model.ScanInstall || sc.InstallID == nil || *sc.InstallID != s.ID || sc.Target.Name != "requests" || sc.Target.Label != "pip requests" {
		t.Fatalf("scan record %+v", sc)
	}
	waitUntil(t, "scan done", func() bool { sc, _ := h.scans.Get(*s.ScanID); return sc.Status != "running" })
	// 화면이 읽는 응답(GET /api/installs/{id})에 정적 검사 요약
	res, err := http.Get(h.url + "/api/installs/" + s.ID)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	var got struct {
		Scan *model.InstallScan `json:"scan"`
	}
	if err := json.NewDecoder(res.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if got.Scan == nil || got.Scan.Status != "done" || got.Scan.Verdict != "clean" || got.Scan.Version != "2.32.3" || got.Scan.Reused {
		t.Fatalf("session scan %+v", got.Scan)
	}
}

func TestLocalInstallSkipsStaticScan(t *testing.T) {
	h := newScanHarness(t, &scanRunner{})
	dir := filepath.Join(t.TempDir(), "reqeusts")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if code, out := h.run(t, sandboxToken, "0", "pip", dir); code != 0 {
		t.Fatalf("exit %d\n%s", code, out)
	}
	waitUntil(t, "skip attached", func() bool { return h.session(t).ScanSkip != "" })
	if s := h.session(t); s.ScanSkip != scan.SkipLocal || s.ScanID != nil {
		t.Fatalf("local: %q %v", s.ScanSkip, s.ScanID)
	}
	if n := len(h.scans.List()); n != 0 {
		t.Fatalf("no scan for a local package, got %d", n)
	}
}

// 검사가 오래 걸려도(여기선 Docker Ping 이 끝나지 않는다) CLI 는 바로 끝나고 종료 코드는 설치 결과 그대로
func TestStaticScanDoesNotChangeExitCode(t *testing.T) {
	hold := make(chan struct{})
	t.Cleanup(func() { close(hold) })
	h := newScanHarness(t, &scanRunner{hold: hold})
	for _, c := range []struct {
		docker string
		want   int
	}{{"0", 0}, {"1", 1}} {
		code, out := h.run(t, sandboxToken, c.docker, "pip", "requests==2.32.3")
		if code != c.want {
			t.Fatalf("docker exit %s: sg-install exit %d, want %d\n%s", c.docker, code, c.want, out)
		}
	}
	// 세션 보고 응답 자체는 검사(Ping 3초 상한)를 기다리지 않는다 — sg-install 은 curl -m 5
	req, _ := http.NewRequest("POST", h.url+"/api/installs", strings.NewReader(`{"manager":"pip","packages":["requests"],"container":"sg-install-pip-9-9","image":"python:3.12-slim"}`))
	req.Header.Set("Authorization", "Bearer "+sandboxToken)
	req.Header.Set("Content-Type", "application/json")
	start := time.Now()
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if d := time.Since(start); res.StatusCode != http.StatusCreated || d > time.Second {
		t.Fatalf("report: HTTP %d in %v (must not wait for the scan)", res.StatusCode, d)
	}
	// 검사는 뒤에서 이어진다 — Ping 이 3초 상한에 걸려 off 로 붙는다(CLI 세션은 이미 끝나 있다)
	waitUntil(t, "off attached", func() bool {
		ss := h.svc.ListInstalls(review.InstallQuery{})
		return len(ss) == 3 && ss[0].ScanSkip == scan.SkipOff && ss[1].ScanSkip == scan.SkipOff && ss[2].ScanSkip == scan.SkipOff
	})
	for _, s := range h.svc.ListInstalls(review.InstallQuery{})[1:] {
		if s.FinishedAt == nil || s.ExitCode == nil {
			t.Fatalf("session finished by the CLI: %+v", s)
		}
	}
}
