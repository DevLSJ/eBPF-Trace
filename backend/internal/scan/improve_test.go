package scan

// 11/02 공급망 검사 보완 — ① PyPI 는 sdist(설치 스크립트 포함) 우선 ② 패키지 자기 이름 · 버전도 OSV 로 조회
// ③ 테스트 폴더는 위험 점수에서 뺀다(목록엔 「테스트 코드」) ④ 작업 폴더 · Docker 가 안 되면 503 안내

import (
	"archive/zip"
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/dockerapi"
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/model"
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/store"
)

// recRunner: 검사기 실행을 기록하고, 그 순간 작업 폴더에 보이는 파일 · 잠금 파일 내용을 함께 남긴다
type recRunner struct {
	dir     string
	mu      sync.Mutex
	gdSeen  map[string][]string // guarddog 대상 경로 → 그때 보인 파일
	osvSeen map[string]string   // osv 잠금 파일 경로 → 내용
	gd      func(target string, files []string) []byte
	osv     func(lockfile, content string) []byte
	pingErr error
}

func (r *recRunner) local(p string) string {
	return filepath.Join(r.dir, strings.TrimPrefix(p, "/work/"))
}
func (r *recRunner) Ping(context.Context) error { return r.pingErr }
func (r *recRunner) Run(_ context.Context, s dockerapi.RunSpec) ([]byte, int, error) {
	if len(s.Cmd) > 0 && s.Cmd[len(s.Cmd)-1] == "--version" {
		return []byte("tool 1.0"), 0, nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	switch {
	case strings.Contains(s.Name, "-guarddog"):
		target := s.Cmd[2]
		var files []string
		_ = filepath.WalkDir(r.local(target), func(p string, d os.DirEntry, err error) error {
			if err == nil && !d.IsDir() {
				rel, _ := filepath.Rel(r.local(target), p)
				files = append(files, filepath.ToSlash(rel))
			}
			return nil
		})
		if r.gdSeen == nil {
			r.gdSeen = map[string][]string{}
		}
		r.gdSeen[target] = files
		if r.gd == nil {
			return []byte(`{"results":{},"risk_score":{"score":0,"label":"no_risks_detected"}}`), 0, nil
		}
		return r.gd(target, files), 0, nil
	case strings.HasSuffix(s.Name, "-osv"):
		lock := ""
		for i, a := range s.Cmd {
			if a == "--lockfile" && i+1 < len(s.Cmd) {
				lock = s.Cmd[i+1]
			}
		}
		b, _ := os.ReadFile(r.local(lock))
		if r.osvSeen == nil {
			r.osvSeen = map[string]string{}
		}
		r.osvSeen[lock] = string(b)
		if r.osv == nil {
			return nil, 0, nil
		}
		return r.osv(lock, string(b)), 1, nil
	}
	return nil, 0, nil
}

func newRecSvc(t *testing.T, r *recRunner) *Service {
	t.Helper()
	r.dir = t.TempDir()
	s := New(Options{Docker: r, Dir: r.dir, Volume: "v", Store: store.NewMemory(), Blocker: &fakeBlocker{}})
	if err := s.Load(t.Context()); err != nil {
		t.Fatal(err)
	}
	return s
}

func fakeWheel(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for n, c := range files {
		w, err := zw.Create(n)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = w.Write([]byte(c))
	}
	zw.Close()
	return buf.Bytes()
}

// fakeRegistry: PyPI(휠이 sdist 보다 먼저 나열됨 — 실제 PyPI 순서) · npm 가짜 서버
func fakeRegistry(t *testing.T, name, version string) {
	t.Helper()
	sdist := fakeTarball(t, name+"-"+version, map[string]string{"setup.py": "from setuptools import setup\nsetup(name='" + name + "')\n", name + "/__init__.py": "x = 1\n"})
	wheel := fakeWheel(t, map[string]string{name + "/__init__.py": "x = 1\n"})
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasPrefix(r.URL.Path, "/pypi/"+name+"/"):
			_, _ = w.Write([]byte(`{"info":{"version":"` + version + `"},"urls":[` +
				`{"packagetype":"bdist_wheel","url":"` + srv.URL + `/files/` + name + `-` + version + `-py3-none-any.whl"},` +
				`{"packagetype":"sdist","url":"` + srv.URL + `/files/` + name + `-` + version + `.tar.gz"}]}`))
		case strings.HasSuffix(r.URL.Path, ".whl"):
			_, _ = w.Write(wheel)
		case strings.HasSuffix(r.URL.Path, ".tar.gz"):
			_, _ = w.Write(sdist)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	old := pypiBase
	pypiBase = srv.URL
	t.Cleanup(func() { pypiBase = old })
}

// ① PyPI 는 sdist 를 받는다 — 휠에는 setup.py(설치 때 도는 코드)가 없어 설치 훅 공격을 못 본다
func TestFetchPypiPrefersSdist(t *testing.T) {
	fakeRegistry(t, "foo", "1.0")
	dst := t.TempDir()
	v, err := fetchPackage(t.Context(), "pip", "foo", "", dst)
	if err != nil || v != "1.0" {
		t.Fatalf("fetch: %q %v", v, err)
	}
	if got := listFiles(t, dst); !strings.Contains(strings.Join(got, " "), "foo-1.0/setup.py") {
		t.Fatalf("sdist (setup.py) not fetched, got %v", got)
	}
}

// ② 패키지 검사도 자기 이름 · 버전을 OSV-Scanner 로 조회한다(잠금 파일을 만들어 넘긴다) — django 2.2.0 → 취약
func TestPackageScanQueriesOSVForOwnVersion(t *testing.T) {
	fakeRegistry(t, "django", "2.2.0")
	r := &recRunner{osv: func(lock, content string) []byte {
		if !strings.Contains(content, "django==2.2.0") {
			return []byte(`{"results":[]}`)
		}
		return []byte(`{"results":[{"source":{"path":"` + lock + `"},"packages":[{"package":{"name":"django","version":"2.2.0","ecosystem":"PyPI"},` +
			`"vulnerabilities":[{"id":"PYSEC-2019-10"},{"id":"GHSA-xxxx"}],"groups":[{"max_severity":"9.8"}]}]}]}`)
	}}
	s := newRecSvc(t, r)
	id, err := s.Start(t.Context(), Input{Kind: "package", Manager: "pip", Name: "django", Version: "2.2.0"})
	if err != nil {
		t.Fatal(err)
	}
	sc := waitDone(t, s, id)
	if sc.Status != "done" {
		t.Fatalf("status %s %q", sc.Status, sc.Error)
	}
	if len(r.osvSeen) != 1 {
		t.Fatalf("package scan must run OSV on its own version, osv runs: %v", r.osvSeen)
	}
	for lock, content := range r.osvSeen {
		if !strings.HasSuffix(lock, "/requirements.txt") || strings.TrimSpace(content) != "django==2.2.0" || strings.Contains(lock, "/src/") {
			t.Fatalf("lockfile %s %q (must be outside src so GuardDog does not read it)", lock, content)
		}
	}
	if sc.VulnCount != 2 || len(sc.Vulns) != 1 || sc.Vulns[0].Package != "django" || sc.Verdict != "vulnerable" || len(sc.Packages) != 0 {
		t.Fatalf("vulns %+v count %d verdict %s packages %v", sc.Vulns, sc.VulnCount, sc.Verdict, sc.Packages)
	}
	// npm 은 package-lock.json(v3) 로
	if b := ownLockfile("npm", "left-pad", "1.3.0"); !strings.Contains(string(b.content), `"node_modules/left-pad"`) || b.name != "package-lock.json" {
		t.Fatalf("npm lockfile %s %s", b.name, b.content)
	}
}

// ③ tests/ · test_*.py 등 테스트 코드는 위험 점수에서 뺀다 — 본체만으로 점수 · 판정, 테스트는 따로 돌려 목록에 「테스트 코드」로
func TestTestsExcludedFromScore(t *testing.T) {
	r := &recRunner{gd: func(target string, files []string) []byte {
		for _, f := range files {
			if strings.Contains(f, "/tests/") || strings.HasPrefix(f, "tests/") {
				return []byte(`{"results":{"threat-filesystem-read":[{"location":"` + target + `/pkg-1.0/tests/test_x.py:3","match":"/etc/passwd","message":"sensitive file"}]},"risk_score":{"score":6.1,"label":"suspicious"}}`)
			}
		}
		return []byte(`{"results":{"capability-process-spawn":[{"location":"` + target + `/pkg-1.0/setup.py:2","match":"os.system(","message":"spawn"}]},"risk_score":{"score":1.0,"label":"low"}}`)
	}}
	s := newRecSvc(t, r)
	tgz := fakeTarball(t, "pkg-1.0", map[string]string{"setup.py": "import os\nos.system('true')\n", "pkg/__init__.py": "x=1\n", "tests/test_x.py": "\n\nopen('/etc/passwd')\n"})
	id, err := s.Start(t.Context(), Input{Kind: "file", FileName: "pkg-1.0.tar.gz", File: bytes.NewReader(tgz)})
	if err != nil {
		t.Fatal(err)
	}
	sc := waitDone(t, s, id)
	if sc.Status != "done" {
		t.Fatalf("status %s %q", sc.Status, sc.Error)
	}
	main := r.gdSeen["/work/"+id+"/src"]
	if strings.Contains(strings.Join(main, " "), "tests/") || !strings.Contains(strings.Join(main, " "), "pkg-1.0/setup.py") {
		t.Fatalf("main GuardDog run must not see tests: %v", main)
	}
	if sc.Verdict == "malicious" || sc.Risk == nil || sc.Risk.Score != 1.0 {
		t.Fatalf("verdict %s risk %+v (score must come from the package body only)", sc.Verdict, sc.Risk)
	}
	var test *model.ScanFinding
	for i := range sc.Findings {
		if sc.Findings[i].File == "pkg-1.0/tests/test_x.py" {
			test = &sc.Findings[i]
		}
	}
	if test == nil || !test.Test || test.Line != 3 {
		t.Fatalf("test finding must be listed and marked: %+v", sc.Findings)
	}
	if sc.Threats != 0 || sc.Capabilities != 1 || sc.TestFindings != 1 {
		t.Fatalf("counts threats %d capabilities %d tests %d", sc.Threats, sc.Capabilities, sc.TestFindings)
	}
	for _, p := range []string{"tests/test_x.py", "pkg/tests/a.py", "test/a.js", "__tests__/a.test.js", "pkg/test_util.py", "pkg/util_test.py", "src/a.test.js", "src/a.spec.ts"} {
		if !isTestPath(p) {
			t.Errorf("%s must be test code", p)
		}
	}
	for _, p := range []string{"setup.py", "pkg/testing.py", "pkg/contest.py", "latest/a.py", "pkg/attestation.py"} {
		if isTestPath(p) {
			t.Errorf("%s must not be test code", p)
		}
	}
}

// ④ 작업 폴더를 만들 수 없거나(맥의 /scan) Docker 에 닿지 않으면 「서버 오류」 대신 503 + 원인 안내
func TestStartUnavailable503(t *testing.T) {
	status := func(err error) (int, string) {
		var se *Error
		if errors.As(err, &se) {
			return se.Status, se.Msg
		}
		return 0, ""
	}
	file := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(file, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	s := New(Options{Docker: &recRunner{}, Dir: file, Store: store.NewMemory()})
	if code, msg := status(func() error {
		_, err := s.Start(t.Context(), Input{Kind: "package", Manager: "pip", Name: "requests"})
		return err
	}()); code != 503 || !strings.Contains(msg, "작업 폴더") || !strings.Contains(msg, "SCAN_DIR") {
		t.Fatalf("unwritable dir: %d %q", code, msg)
	}
	r := &recRunner{pingErr: errors.New("dial unix /var/run/docker.sock: connect: no such file")}
	s2 := newRecSvc(t, r)
	if code, msg := status(func() error {
		_, err := s2.Start(t.Context(), Input{Kind: "package", Manager: "pip", Name: "requests"})
		return err
	}()); code != 503 || !strings.Contains(msg, "Docker") {
		t.Fatalf("docker down: %d %q", code, msg)
	}
	if n := len(s2.List()); n != 0 {
		t.Fatalf("no scan record when docker is down, got %d", n)
	}
}
