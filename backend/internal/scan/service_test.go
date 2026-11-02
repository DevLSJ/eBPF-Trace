package scan

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/dockerapi"
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/model"
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/store"
)

type fakeRunner struct{}

func (fakeRunner) Run(context.Context, dockerapi.RunSpec) ([]byte, int, error) {
	return []byte("tool 1.0"), 0, nil
}

type fakeBlocker struct {
	mu      sync.Mutex
	got     [][]model.ScanPackage
	reasons []string
	fail    error
}

func (b *fakeBlocker) FromScan(_ context.Context, sc model.Scan, pkgs []model.ScanPackage, reason string) (model.Case, model.Proposal, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.fail != nil {
		return model.Case{}, model.Proposal{}, b.fail
	}
	b.got = append(b.got, pkgs)
	b.reasons = append(b.reasons, reason)
	return model.Case{ID: "case-0001", ScanID: &sc.ID}, model.Proposal{ID: "prop-0001", CaseID: "case-0001"}, nil
}

func newSvc(t *testing.T, codeload string) (*Service, *fakeBlocker) {
	t.Helper()
	b := &fakeBlocker{}
	s := New(Options{Docker: fakeRunner{}, Dir: t.TempDir(), Volume: "v", Store: store.NewMemory(), Blocker: b, GitHub: codeload})
	if err := s.Load(t.Context()); err != nil {
		t.Fatal(err)
	}
	return s, b
}

func waitDone(t *testing.T, s *Service, id string) model.Scan {
	t.Helper()
	for i := 0; i < 200; i++ {
		if sc, ok := s.Get(id); ok && sc.Status != "running" {
			return sc
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("scan %s still running", id)
	return model.Scan{}
}

// Start: 저장소 주소 → Target 에 ref · subpath · 라벨, 404 는 안내 문구로 실패
func TestStartRepoTarget(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.NotFound(w, r) }))
	defer srv.Close()
	s, _ := newSvc(t, srv.URL)
	id, err := s.Start(t.Context(), Input{Kind: "repo", URL: "https://github.com/psf/requests/tree/v2.31.0/src/requests"})
	if err != nil {
		t.Fatal(err)
	}
	sc := waitDone(t, s, id)
	tg := sc.Target
	if tg.Kind != "repo" || tg.Name != "requests" || tg.Ref != "v2.31.0" || tg.Subpath != "src/requests" ||
		tg.URL != "https://github.com/psf/requests/tree/v2.31.0/src/requests" || tg.Label != "github.com/psf/requests@v2.31.0/src/requests" {
		t.Fatalf("target %+v", tg)
	}
	if sc.Status != "failed" || !strings.Contains(sc.Error, "공개 저장소") {
		t.Fatalf("status %s err %q", sc.Status, sc.Error)
	}
	if _, err := s.Start(t.Context(), Input{Kind: "repo", URL: "https://github.com/psf/requests/pull/1"}); err == nil || !strings.Contains(err.Error(), "tree/") {
		t.Fatalf("pull url must be rejected with a hint: %v", err)
	}
}

// BlockPackages: 패키지 검사는 그대로(선택 없음), 저장소 · 파일 검사는 결과의 패키지 중 고른 것만
func TestBlockPackages(t *testing.T) {
	s, b := newSvc(t, "")
	now := time.Now().UTC()
	pkgs := []model.ScanPackage{
		{Manager: "pip", Name: "urllib3", Version: "1.26.4", Ecosystem: "PyPI", Source: "requirements.txt", Vulns: 2},
		{Manager: "npm", Name: "lodash", Version: "4.17.20", Ecosystem: "npm", Source: "package-lock.json"},
		{Manager: "pip", Name: "lodash", Version: "0.1", Ecosystem: "PyPI", Source: "requirements.txt"}, // 같은 이름 · 다른 매니저
		{Manager: "", Name: "golang.org/x/text", Version: "0.3.0", Ecosystem: "Go", Source: "go.mod"},
	}
	s.scans = []*model.Scan{
		{ID: "scan-0001", Target: model.ScanTarget{Kind: "package", Manager: "pip", Name: "reqeusts", Label: "pip reqeusts"}, Status: "done", StartedAt: now},
		{ID: "scan-0002", Target: model.ScanTarget{Kind: "repo", Name: "r", Label: "github.com/o/r"}, Status: "done", StartedAt: now, Packages: pkgs},
		{ID: "scan-0003", Target: model.ScanTarget{Kind: "repo", Name: "r", Label: "github.com/o/r"}, Status: "running", StartedAt: now},
		{ID: "scan-0004", Target: model.ScanTarget{Kind: "file", FileName: "a.py", Label: "a.py"}, Status: "done", StartedAt: now},
	}
	ctx := t.Context()
	status := func(err error) int {
		var se *Error
		if errors.As(err, &se) {
			return se.Status
		}
		return 0
	}
	bad := []struct {
		name string
		id   string
		sel  []model.ScanPackage
		code int
		hint string
	}{
		{"unknown scan", "scan-9999", nil, 404, "없음"},
		{"running", "scan-0003", nil, 400, "마친"},
		{"package scan with selection", "scan-0001", []model.ScanPackage{{Name: "x"}}, 400, "패키지 이름"},
		{"repo without selection", "scan-0002", nil, 400, "고르세요"},
		{"wrong manager", "scan-0002", []model.ScanPackage{{Manager: "npm", Name: "urllib3"}}, 400, "없는 패키지"},
		{"invalid manager", "scan-0002", []model.ScanPackage{{Manager: "apt", Name: "urllib3"}}, 400, "manager"},
		{"unsupported ecosystem", "scan-0002", []model.ScanPackage{{Name: "golang.org/x/text"}}, 400, "pip · npm · cargo"},
		{"not in result", "scan-0002", []model.ScanPackage{{Name: "nope"}}, 400, "없는 패키지"},
		{"ambiguous name needs manager", "scan-0002", []model.ScanPackage{{Name: "lodash"}}, 400, "manager"},
		{"bad version", "scan-0002", []model.ScanPackage{{Name: "urllib3", Version: "1.0 x"}}, 400, "버전"},
		{"no package list", "scan-0004", []model.ScanPackage{{Name: "x"}}, 400, "패키지 목록이 없"},
	}
	for _, c := range bad {
		_, err := s.BlockPackages(ctx, c.id, c.sel, "")
		if status(err) != c.code || !strings.Contains(err.Error(), c.hint) {
			t.Errorf("%s: got %v (status %d), want %d with %q", c.name, err, status(err), c.code, c.hint)
		}
	}
	if len(b.got) != 0 {
		t.Fatalf("blocker must not be called on rejected input: %v", b.got)
	}

	// 패키지 검사: 선택 없이 그대로
	pid, err := s.BlockPackages(ctx, "scan-0001", nil, "")
	if err != nil || pid != "prop-0001" {
		t.Fatalf("package block: %v %q", err, pid)
	}
	if len(b.got) != 1 || len(b.got[0]) != 0 {
		t.Fatalf("package block passes no selection: %v", b.got)
	}
	if sc, _ := s.Get("scan-0001"); sc.CaseID == nil || *sc.CaseID != "case-0001" {
		t.Fatalf("caseId not set: %+v", sc.CaseID)
	}

	// 저장소 검사: 매니저 · 버전은 결과에서 채운다(대소문자 무시), 매니저를 주면 그대로
	pid, err = s.BlockPackages(ctx, "scan-0002", []model.ScanPackage{{Name: "URLLIB3"}, {Manager: "npm", Name: "lodash", Version: "9.9.9"}}, "")
	if err != nil || pid != "prop-0001" {
		t.Fatalf("repo block: %v %q", err, pid)
	}
	got := b.got[1]
	if len(got) != 2 || got[0] != (model.ScanPackage{Manager: "pip", Name: "urllib3", Version: "1.26.4", Ecosystem: "PyPI", Source: "requirements.txt", Vulns: 2}) ||
		got[1] != (model.ScanPackage{Manager: "npm", Name: "lodash", Version: "9.9.9", Ecosystem: "npm", Source: "package-lock.json"}) {
		t.Fatalf("resolved selection %+v", got)
	}
	// 너무 많이
	many := make([]model.ScanPackage, 51)
	for i := range many {
		many[i] = model.ScanPackage{Manager: "pip", Name: "urllib3"}
	}
	if _, err := s.BlockPackages(ctx, "scan-0002", many, ""); status(err) != 400 {
		t.Fatalf("51 packages: %v", err)
	}
}

// Block(기존): BlockPackages(nil) 과 같다 — 사유 없음
func TestBlockKeepsOldPath(t *testing.T) {
	s, b := newSvc(t, "")
	s.scans = []*model.Scan{{ID: "scan-0001", Target: model.ScanTarget{Kind: "package", Manager: "pip", Name: "x", Label: "pip x"}, Status: "done", StartedAt: time.Now()}}
	if _, err := s.Block(t.Context(), "scan-0001"); err != nil || len(b.got) != 1 || b.reasons[0] != "" {
		t.Fatal(err, b.got, b.reasons)
	}
}

// W18: 사유는 그대로 review(FromScan)로 넘긴다 — 검사(500자)는 review 가 한다
func TestBlockPackagesPassesReason(t *testing.T) {
	s, b := newSvc(t, "")
	s.scans = []*model.Scan{{ID: "scan-0001", Target: model.ScanTarget{Kind: "package", Manager: "pip", Name: "x", Label: "pip x"}, Status: "done", StartedAt: time.Now()}}
	if _, err := s.BlockPackages(t.Context(), "scan-0001", nil, "타이포스쿼팅"); err != nil {
		t.Fatal(err)
	}
	if len(b.reasons) != 1 || b.reasons[0] != "타이포스쿼팅" {
		t.Fatalf("reason not passed: %q", b.reasons)
	}
}

// OSV 결과에서 패키지 목록(차단 후보) — ecosystem → 매니저, 없으면 잠금 파일 이름으로
func TestParseOSVPackages(t *testing.T) {
	in := `{"results":[
	 {"source":{"path":"/work/scan-1/src/requirements.txt","type":"lockfile"},"packages":[
	   {"package":{"name":"urllib3","version":"1.26.4","ecosystem":"PyPI"},"vulnerabilities":[{"id":"GHSA-1"},{"id":"GHSA-2"}],"groups":[{"max_severity":"7.5"}]},
	   {"package":{"name":"six","version":"1.16.0","ecosystem":"PyPI"}}]},
	 {"source":{"path":"/work/scan-1/src/web/package-lock.json","type":"lockfile"},"packages":[
	   {"package":{"name":"lodash","version":"4.17.20","ecosystem":"npm"}}]},
	 {"source":{"path":"/work/scan-1/src/Cargo.lock","type":"lockfile"},"packages":[
	   {"package":{"name":"serde","version":"1.0.0"}}]},
	 {"source":{"path":"/work/scan-1/src/go.mod","type":"lockfile"},"packages":[
	   {"package":{"name":"golang.org/x/text","version":"0.3.0","ecosystem":"Go"}}]}
	]}`
	vulns, pkgs, err := parseOSV([]byte(in), "/work/scan-1/src", map[string]bool{"urllib3": true})
	if err != nil {
		t.Fatal(err)
	}
	if len(vulns) != 1 || vulns[0].Package != "urllib3" {
		t.Fatalf("vulns %+v", vulns)
	}
	want := []model.ScanPackage{
		{Manager: "pip", Name: "urllib3", Version: "1.26.4", Ecosystem: "PyPI", Source: "requirements.txt", Direct: true, Vulns: 2},
		{Manager: "pip", Name: "six", Version: "1.16.0", Ecosystem: "PyPI", Source: "requirements.txt"},
		{Manager: "npm", Name: "lodash", Version: "4.17.20", Ecosystem: "npm", Source: "web/package-lock.json"},
		{Manager: "cargo", Name: "serde", Version: "1.0.0", Source: "Cargo.lock"},
		{Manager: "", Name: "golang.org/x/text", Version: "0.3.0", Ecosystem: "Go", Source: "go.mod"},
	}
	if len(pkgs) != len(want) {
		t.Fatalf("packages %+v", pkgs)
	}
	for i := range want {
		if pkgs[i] != want[i] {
			t.Errorf("%d: got %+v want %+v", i, pkgs[i], want[i])
		}
	}
	if _, pkgs, err := parseOSV(nil, "", nil); err != nil || pkgs != nil {
		t.Fatalf("empty: %v %v", err, pkgs)
	}
}
