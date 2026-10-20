// Package sginstall_test runs tools/sg-install against a real API router
// (httptest) with a fake `docker` on PATH — no container is ever started.
package sginstall_test

import (
	"errors"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/api"
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/model"
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/osv"
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/review"
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/rules"
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/stats"
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/store"
)

const sandboxToken = "sbx-test-token"

type harness struct {
	svc       *review.Service
	url       string
	dockerLog string
	bin       string
}

func newHarness(t *testing.T, blocked ...string) *harness {
	t.Helper()
	for _, tool := range []string{"bash", "curl", "python3"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s not found", tool)
		}
	}
	mem := store.NewMemory()
	var c store.ReviewCommit
	for _, v := range blocked {
		c.BlockAdd = append(c.BlockAdd, model.BlockEntry{List: model.ListPackages, Value: v, CaseID: ptr("case-0001"), By: "보안 담당자"})
	}
	if err := mem.CommitReview(t.Context(), c); err != nil {
		t.Fatal(err)
	}
	engine := rules.New(nil)
	svc := review.New(review.Options{Store: mem, Policies: mem, Audit: mem, Engine: engine})
	if err := svc.Load(t.Context()); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(api.Router(api.Deps{
		Engine: engine, Policies: mem, Audit: mem, Buffer: mem, Stats: stats.New().Snapshot,
		AdminToken: "admin-token", SandboxToken: sandboxToken, Review: svc, OSV: &osv.Client{URL: "http://127.0.0.1:1"},
		Info: api.Info{Source: "gadget"},
	}))
	t.Cleanup(srv.Close)

	h := &harness{svc: svc, url: srv.URL, bin: t.TempDir()}
	h.dockerLog = filepath.Join(h.bin, "docker.log")
	fake := "#!/usr/bin/env bash\necho \"$*\" >> \"$FAKE_DOCKER_LOG\"\nif [[ $1 == run ]]; then echo 'fake install output'; exit ${FAKE_DOCKER_EXIT:-0}; fi\n"
	if err := os.WriteFile(filepath.Join(h.bin, "docker"), []byte(fake), 0o755); err != nil {
		t.Fatal(err)
	}
	return h
}

func ptr(s string) *string { return &s }

// run: sg-install 을 돌려 종료 코드와 출력을 돌려준다.
func (h *harness) run(t *testing.T, token string, dockerExit string, args ...string) (int, string) {
	t.Helper()
	script, err := filepath.Abs("../../../tools/sg-install")
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("bash", append([]string{script}, args...)...)
	cmd.Env = append(os.Environ(),
		"PATH="+h.bin+string(os.PathListSeparator)+os.Getenv("PATH"),
		"SUPPLYGUARD_API="+h.url,
		"SUPPLYGUARD_SANDBOX_TOKEN="+token,
		"FAKE_DOCKER_LOG="+h.dockerLog,
		"FAKE_DOCKER_EXIT="+dockerExit,
	)
	out, err := cmd.CombinedOutput()
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee.ExitCode(), string(out)
	}
	if err != nil {
		t.Fatal(err)
	}
	return 0, string(out)
}

func (h *harness) dockerCalls() string {
	b, _ := os.ReadFile(h.dockerLog)
	return string(b)
}

// Tier 1 — 차단 목록의 패키지는 컨테이너를 띄우지 않고 refused 세션을 보고한 뒤 종료 코드 3.
func TestBlockedPackageRefusedWithoutContainer(t *testing.T) {
	h := newHarness(t, "pip:reqeusts")
	pkgDir := filepath.Join(t.TempDir(), "reqeusts")
	if err := os.Mkdir(pkgDir, 0o755); err != nil {
		t.Fatal(err)
	}
	code, out := h.run(t, sandboxToken, "0", "pip", pkgDir)
	if code != 3 {
		t.Fatalf("exit code %d, want 3\n%s", code, out)
	}
	if calls := h.dockerCalls(); calls != "" {
		t.Fatalf("docker must not be called for a blocked package, got:\n%s", calls)
	}
	ss := h.svc.ListInstalls(review.InstallQuery{})
	if len(ss) != 1 || ss[0].Status != model.InstallRefused || ss[0].RefusedBy == nil || ss[0].RefusedBy.Value != "pip:reqeusts" {
		t.Fatalf("want one refused session, got %+v", ss)
	}
	if ss[0].Container != "" || len(ss[0].Packages) != 1 || ss[0].Packages[0] != pkgDir {
		t.Fatalf("refused session must carry the raw package and no container: %+v", ss[0])
	}
	if !strings.Contains(out, "pip:reqeusts") {
		t.Fatalf("output must name the blocked value:\n%s", out)
	}
}

// 버전 표기를 붙여도 차단을 피하지 못한다.
func TestBlockedPackageWithVersion(t *testing.T) {
	h := newHarness(t, "pip:reqeusts")
	if code, out := h.run(t, sandboxToken, "0", "pip", "requests", "Reqeusts==1.0.2"); code != 3 {
		t.Fatalf("exit code %d, want 3\n%s", code, out)
	}
	if h.dockerCalls() != "" {
		t.Fatal("docker must not run when any package is blocked")
	}
}

// 차단되지 않은 패키지는 세션 시작 → 설치 → 끝(종료 코드)을 보고한다.
func TestAllowedPackageReportsSession(t *testing.T) {
	h := newHarness(t, "pip:reqeusts")
	code, out := h.run(t, sandboxToken, "0", "pip", "requests")
	if code != 0 {
		t.Fatalf("exit code %d\n%s", code, out)
	}
	if !strings.Contains(h.dockerCalls(), "run --name sg-install-pip-") {
		t.Fatalf("docker run expected, got %q", h.dockerCalls())
	}
	ss := h.svc.ListInstalls(review.InstallQuery{})
	if len(ss) != 1 || ss[0].Status != model.InstallPassed || ss[0].ExitCode == nil || *ss[0].ExitCode != 0 ||
		!strings.HasPrefix(ss[0].Container, "sg-install-pip-") || ss[0].Image != "python:3.12-slim" {
		t.Fatalf("want one passed session, got %+v", ss)
	}

	code, _ = h.run(t, sandboxToken, "1", "pip", "numpy==1.21.0")
	ss = h.svc.ListInstalls(review.InstallQuery{})
	if code != 1 || ss[0].Status != model.InstallFailed {
		t.Fatalf("failed install: exit %d, status %s", code, ss[0].Status)
	}
}

// Tier 1 — 차단 확인이 인증에 실패하면 설치하지 않는다(fail-closed).
func TestWrongTokenFailsClosed(t *testing.T) {
	h := newHarness(t)
	code, out := h.run(t, "wrong-token", "0", "pip", "requests")
	if code == 0 || code == 3 {
		t.Fatalf("exit code %d, want a non-zero auth failure\n%s", code, out)
	}
	if h.dockerCalls() != "" {
		t.Fatal("docker must not run when the blocklist check is rejected")
	}
	if n := len(h.svc.ListInstalls(review.InstallQuery{})); n != 0 {
		t.Fatalf("no session may be recorded with a wrong token, got %d", n)
	}
}
