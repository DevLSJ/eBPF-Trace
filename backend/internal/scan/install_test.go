package scan

// 11/04 종합 판정 — sg-install 세션 보고 때 서버가 첫 패키지의 정적 검사를 스스로 시작한다(설계 2026-11-03 승인).
// 대상 해석 · 합류 · 재사용 · 건너뜀 · 동시 실행 상한 · 대기열 · 대기 시간 초과 · 메모리 부족 문구

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/dockerapi"
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/model"
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/store"
)

func TestParseInstallSpec(t *testing.T) {
	cases := []struct {
		manager, raw string
		want         InstallTarget
	}{
		{"pip", "requests", InstallTarget{Manager: "pip", Name: "requests", Label: "pip requests"}},
		{"pip", "numpy==1.21.0", InstallTarget{Manager: "pip", Name: "numpy", Version: "1.21.0", Exact: true, Label: "pip numpy==1.21.0"}},
		{"pip", "Requests[socks]>=2", InstallTarget{Manager: "pip", Name: "requests", Label: "pip requests"}},
		{"pip", "requests ==2.31.0", InstallTarget{Manager: "pip", Name: "requests", Version: "2.31.0", Exact: true, Label: "pip requests==2.31.0"}},
		{"pip", "requests===2.31.0", InstallTarget{Manager: "pip", Name: "requests", Version: "2.31.0", Exact: true, Label: "pip requests==2.31.0"}},
		{"pip", `requests==2.31.0; python_version>"3"`, InstallTarget{Manager: "pip", Name: "requests", Version: "2.31.0", Exact: true, Label: "pip requests==2.31.0"}},
		{"pip", "requests~=2.31", InstallTarget{Manager: "pip", Name: "requests", Label: "pip requests"}},
		{"pip", "numpy==1.21.*", InstallTarget{Manager: "pip", Name: "numpy", Label: "pip numpy"}},
		{"pip", "zope.interface", InstallTarget{Manager: "pip", Name: "zope.interface", Label: "pip zope.interface"}},
		{"pip", "./reqeusts", InstallTarget{Skip: SkipLocal}},
		{"pip", "/abs/pkg", InstallTarget{Skip: SkipLocal}},
		{"pip", "~/pkg", InstallTarget{Skip: SkipLocal}},
		{"pip", "git+https://github.com/psf/requests", InstallTarget{Skip: SkipLocal}},
		{"pip", "https://example.test/pkg-1.0.tar.gz", InstallTarget{Skip: SkipLocal}},
		{"pip", "file:pkg", InstallTarget{Skip: SkipLocal}},
		{"pip", "pkg-1.0-py3-none-any.whl", InstallTarget{Skip: SkipLocal}},
		{"pip", "pkg-1.0.tar.gz", InstallTarget{Skip: SkipLocal}},
		{"pip", "bad name!", InstallTarget{Skip: SkipInvalid}},
		{"pip", "pkg @ https://example.test/x", InstallTarget{Skip: SkipInvalid}},
		{"npm", "lodash@4.17.21", InstallTarget{Manager: "npm", Name: "lodash", Version: "4.17.21", Exact: true, Label: "npm lodash@4.17.21"}},
		{"npm", "@types/node@20.1.0", InstallTarget{Manager: "npm", Name: "@types/node", Version: "20.1.0", Exact: true, Label: "npm @types/node@20.1.0"}},
		{"npm", "@types/node", InstallTarget{Manager: "npm", Name: "@types/node", Label: "npm @types/node"}},
		{"npm", "lodash@^4", InstallTarget{Manager: "npm", Name: "lodash", Label: "npm lodash"}},
		{"npm", "lodash@latest", InstallTarget{Manager: "npm", Name: "lodash", Label: "npm lodash"}},
		{"npm", "lodash@4", InstallTarget{Manager: "npm", Name: "lodash", Label: "npm lodash"}},
		{"npm", "left-pad@1.0.0-beta.1", InstallTarget{Manager: "npm", Name: "left-pad", Version: "1.0.0-beta.1", Exact: true, Label: "npm left-pad@1.0.0-beta.1"}},
		{"npm", "./pkg", InstallTarget{Skip: SkipLocal}},
		{"npm", "github:user/repo", InstallTarget{Skip: SkipInvalid}},
		{"cargo", "serde", InstallTarget{Skip: SkipUnsupported}},
		{"cargo", "./local", InstallTarget{Skip: SkipUnsupported}},
	}
	for _, c := range cases {
		if got := ParseInstallSpec(c.manager, c.raw); got != c.want {
			t.Errorf("%s %q: got %+v, want %+v", c.manager, c.raw, got, c.want)
		}
	}
}

func session(id, manager string, pkgs ...string) model.InstallSession {
	return model.InstallSession{ID: id, Manager: manager, Packages: pkgs, Status: model.InstallRunning}
}

// gate: GuardDog 실행을 막아 두고(검사가 running 에 머문다) 동시에 몇 개가 돌았는지 센다
type gate struct {
	*recRunner
	open      chan struct{}
	mu        sync.Mutex
	cur, max  int
	gdStarted int
	code      int // GuardDog 종료 코드(0 = 정상)
	specs     []dockerapi.RunSpec
}

func newGate() *gate { return &gate{recRunner: &recRunner{}, open: make(chan struct{})} }

func (g *gate) release() {
	select {
	case <-g.open:
	default:
		close(g.open)
	}
}

func (g *gate) Run(ctx context.Context, s dockerapi.RunSpec) ([]byte, int, error) {
	g.mu.Lock()
	g.specs = append(g.specs, s)
	g.mu.Unlock()
	if strings.HasSuffix(s.Name, "-guarddog") && s.Cmd[len(s.Cmd)-1] != "--version" {
		g.mu.Lock()
		g.cur++
		g.gdStarted++
		g.max = max(g.max, g.cur)
		g.mu.Unlock()
		defer func() { g.mu.Lock(); g.cur--; g.mu.Unlock() }()
		select {
		case <-g.open:
		case <-ctx.Done():
			return nil, -1, ctx.Err()
		}
		if g.code != 0 {
			return []byte("Killed"), g.code, nil
		}
	}
	return g.recRunner.Run(ctx, s)
}

func (g *gate) started() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.gdStarted
}

func newGateSvc(t *testing.T, g *gate, o Options) *Service {
	t.Helper()
	g.dir = t.TempDir()
	o.Docker, o.Dir, o.Volume, o.Store, o.Blocker = g, g.dir, "v", store.NewMemory(), &fakeBlocker{}
	s := New(o)
	if err := s.Load(t.Context()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(g.release)
	return s
}

func waitFor(t *testing.T, what string, ok func() bool) {
	t.Helper()
	for i := 0; i < 400; i++ {
		if ok() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timeout: %s", what)
}

func fileInput(name string) Input {
	return Input{Kind: "file", FileName: name, File: bytes.NewReader([]byte("x = 1\n"))}
}

// 범위 · 미지정은 레지스트리의 최신 버전으로 검사하고, 라벨은 입력의 이름만(받은 버전은 target.version)
func TestFromInstallStartsPackageScan(t *testing.T) {
	fakeRegistry(t, "requests", "2.32.3")
	s := newRecSvc(t, &recRunner{})
	x := session("ins-0001", "pip", "Requests[socks]>=2", "numpy")
	id, skip := s.FromInstall(t.Context(), x)
	if id == "" || skip != "" {
		t.Fatalf("FromInstall: id %q skip %q", id, skip)
	}
	sc := waitDone(t, s, id)
	if sc.Status != "done" || sc.Target.Kind != "package" || sc.Target.Manager != "pip" || sc.Target.Name != "requests" ||
		sc.Target.Version != "2.32.3" || sc.Target.Label != "pip requests" {
		t.Fatalf("scan %s %q target %+v", sc.Status, sc.Error, sc.Target)
	}
	if sc.Trigger != model.ScanInstall || sc.InstallID == nil || *sc.InstallID != "ins-0001" {
		t.Fatalf("trigger %q installId %v", sc.Trigger, sc.InstallID)
	}
	x.ScanID = &id
	got := s.OfSession(x)
	zero := 0.0
	want := model.InstallScan{ID: id, Status: "done", Verdict: "clean", Label: "pip requests", Version: "2.32.3", RiskScore: &zero}
	if got == nil || got.RiskScore == nil || *got.RiskScore != 0 {
		t.Fatalf("OfSession: %+v", got)
	}
	g := *got
	g.RiskScore = want.RiskScore
	if g != want {
		t.Fatalf("OfSession: %+v, want %+v", g, want)
	}

	// 정확한 버전은 그 버전 · 라벨에 버전
	id2, _ := s.FromInstall(t.Context(), session("ins-0002", "pip", "requests==2.31.0"))
	sc2 := waitDone(t, s, id2)
	if sc2.Target.Version != "2.31.0" || sc2.Target.Label != "pip requests==2.31.0" || id2 == id {
		t.Fatalf("exact: %s %+v", id2, sc2.Target)
	}
	// 수동 검사는 trigger manual · installId 없음
	id3, err := s.Start(t.Context(), Input{Kind: "package", Manager: "pip", Name: "requests", Version: "2.32.3"})
	if err != nil {
		t.Fatal(err)
	}
	if sc3 := waitDone(t, s, id3); sc3.Trigger != model.ScanManual || sc3.InstallID != nil {
		t.Fatalf("manual: trigger %q installId %v", sc3.Trigger, sc3.InstallID)
	}
}

// 실행 중인 같은 manager:정규화 이름:버전 검사에 합류한다 — 미지정(최신)과 정확한 버전도 같은 버전이면 같은 검사
func TestFromInstallJoinsRunningScan(t *testing.T) {
	fakeRegistry(t, "requests", "2.32.3")
	g := newGate()
	s := newGateSvc(t, g, Options{})
	a := session("ins-0001", "pip", "requests")
	id1, skip := s.FromInstall(t.Context(), a)
	if id1 == "" || skip != "" {
		t.Fatalf("first: %q %q", id1, skip)
	}
	b := session("ins-0002", "pip", "Requests==2.32.3")
	id2, skip := s.FromInstall(t.Context(), b)
	if id2 != id1 || skip != "" {
		t.Fatalf("join: got %q %q, want %q", id2, skip, id1)
	}
	if n := len(s.List()); n != 1 {
		t.Fatalf("one scan expected, got %d", n)
	}
	a.ScanID, b.ScanID = &id1, &id2
	if v := s.OfSession(a); v == nil || v.Status != "running" || v.Reused || v.Verdict != "" {
		t.Fatalf("starter view: %+v", v)
	}
	if v := s.OfSession(b); v == nil || v.Status != "running" || !v.Reused {
		t.Fatalf("joined view must be reused: %+v", v)
	}
	g.release()
	if sc := waitDone(t, s, id1); sc.Status != "done" {
		t.Fatalf("%s %q", sc.Status, sc.Error)
	}
	if v := s.OfSession(b); v.Status != "done" || v.Verdict != "clean" || !v.Reused {
		t.Fatalf("joined view after done: %+v", v)
	}
}

// 24시간 안에 끝난(done) 같은 검사는 다시 돌리지 않는다 — 검사기가 꺼져 있어도 재사용(순서: 재사용 → off → busy)
func TestFromInstallReusesDoneScan(t *testing.T) {
	r := &recRunner{}
	s := newRecSvc(t, r)
	s.o.PyPI = "http://127.0.0.1:1" // 정확한 버전만 쓴다 — 레지스트리를 부르지 않는다
	now := time.Now().UTC()
	fin := now.Add(-time.Hour)
	old := now.Add(-25 * time.Hour)
	s.scans = []*model.Scan{
		{ID: "scan-0002", Target: model.ScanTarget{Kind: "package", Manager: "pip", Name: "requests", Version: "2.32.3", Label: "pip requests"}, Status: "done", Verdict: "clean",
			StartedAt: fin, FinishedAt: &fin, Trigger: model.ScanInstall, InstallID: ptrS("ins-0001")},
		{ID: "scan-0001", Target: model.ScanTarget{Kind: "package", Manager: "pip", Name: "six", Version: "1.16.0", Label: "pip six==1.16.0"}, Status: "done", Verdict: "clean",
			StartedAt: old, FinishedAt: &old, Trigger: model.ScanManual},
	}
	s.seq = 2
	x := session("ins-0005", "pip", "Requests==2.32.3")
	id, skip := s.FromInstall(t.Context(), x)
	if id != "scan-0002" || skip != "" {
		t.Fatalf("reuse: %q %q", id, skip)
	}
	x.ScanID = &id
	if v := s.OfSession(x); v == nil || !v.Reused || v.Status != "done" || v.Verdict != "clean" || v.Version != "2.32.3" {
		t.Fatalf("reused view: %+v", v)
	}
	// 검사기가 꺼져도 끝난 결과는 재사용, 새로 돌려야 하면 off
	r.pingErr = errors.New("docker down")
	if id, skip := s.FromInstall(t.Context(), session("ins-0006", "pip", "requests==2.32.3")); id != "scan-0002" || skip != "" {
		t.Fatalf("reuse while off: %q %q", id, skip)
	}
	if id, skip := s.FromInstall(t.Context(), session("ins-0007", "pip", "six==1.16.0")); id != "" || skip != SkipOff {
		t.Fatalf("25h old + off: %q %q", id, skip)
	}
	// 25시간 지난 결과는 새로 검사
	r.pingErr = nil
	id, _ = s.FromInstall(t.Context(), session("ins-0008", "pip", "six==1.16.0"))
	if id == "" || id == "scan-0001" {
		t.Fatalf("25h old must rescan: %q", id)
	}
	waitDone(t, s, id)
}

// failed 는 재사용하지 않고 다시 검사한다
func TestFromInstallRetriesFailedScan(t *testing.T) {
	fakeRegistry(t, "requests", "2.32.3")
	s := newRecSvc(t, &recRunner{})
	fin := time.Now().UTC().Add(-time.Minute)
	s.scans = []*model.Scan{{ID: "scan-0001", Target: model.ScanTarget{Kind: "package", Manager: "pip", Name: "requests", Version: "2.32.3", Label: "pip requests==2.32.3"},
		Status: "failed", Error: "network", StartedAt: fin, FinishedAt: &fin, Trigger: model.ScanInstall, InstallID: ptrS("ins-0001")}}
	s.seq = 1
	id, skip := s.FromInstall(t.Context(), session("ins-0002", "pip", "requests==2.32.3"))
	if id == "" || id == "scan-0001" || skip != "" {
		t.Fatalf("failed must be retried: %q %q", id, skip)
	}
	if sc := waitDone(t, s, id); sc.Status != "done" || sc.InstallID == nil || *sc.InstallID != "ins-0002" {
		t.Fatalf("retry: %s %q %v", sc.Status, sc.Error, sc.InstallID)
	}
}

func TestFromInstallSkips(t *testing.T) {
	r := &recRunner{}
	s := newRecSvc(t, r)
	for _, c := range []struct {
		manager, pkg, skip string
	}{
		{"pip", "./reqeusts", SkipLocal},
		{"pip", "git+https://github.com/psf/requests", SkipLocal},
		{"cargo", "serde", SkipUnsupported},
		{"pip", "bad name!", SkipInvalid},
	} {
		if id, skip := s.FromInstall(t.Context(), session("ins-0001", c.manager, c.pkg)); id != "" || skip != c.skip {
			t.Errorf("%s %s: %q %q, want skip %s", c.manager, c.pkg, id, skip, c.skip)
		}
	}
	if n := len(s.List()); n != 0 {
		t.Fatalf("skips must not create scans: %d", n)
	}
	// 거부된 세션은 시작하지도 건너뛰지도 않는다
	ref := session("ins-0002", "pip", "requests==1.0")
	ref.Status = model.InstallRefused
	if id, skip := s.FromInstall(t.Context(), ref); id != "" || skip != "" {
		t.Fatalf("refused: %q %q", id, skip)
	}
	// Docker 가 안 되면 off
	r.pingErr = errors.New("down")
	if id, skip := s.FromInstall(t.Context(), session("ins-0003", "pip", "requests==1.0")); id != "" || skip != SkipOff {
		t.Fatalf("ping fail: %q %q", id, skip)
	}
	// 검사기 서비스가 없으면(Docker 클라이언트 실패) off — 대상 해석이 먼저
	var none *Service
	if id, skip := none.FromInstall(t.Context(), session("ins-0004", "pip", "requests")); id != "" || skip != SkipOff {
		t.Fatalf("nil service: %q %q", id, skip)
	}
	if _, skip := none.FromInstall(t.Context(), session("ins-0004", "pip", "./x")); skip != SkipLocal {
		t.Fatalf("nil service local: %q", skip)
	}
	// 건너뛴 세션의 scan: id "" · skipped · 라벨은 「매니저 입력」
	x := session("ins-0001", "pip", "./reqeusts")
	x.ScanSkip = SkipLocal
	want := model.InstallScan{Status: "skipped", Label: "pip ./reqeusts", Skip: SkipLocal}
	if v := none.OfSession(x); v == nil || *v != want {
		t.Fatalf("skipped view: %+v", v)
	}
	// 옛 세션(scanId · scanSkip 없음) · 없는 검사 id → nil
	if v := s.OfSession(session("ins-0009", "pip", "requests")); v != nil {
		t.Fatalf("old session: %+v", v)
	}
	gone := session("ins-0010", "pip", "requests")
	gone.ScanID = ptrS("scan-9999")
	if v := s.OfSession(gone); v != nil {
		t.Fatalf("unknown scan: %+v", v)
	}
}

// 동시 실행 상한(SCAN_CONCURRENCY) — 수동 검사에도 적용, 기다리는 검사는 running 으로 보인다
func TestScanConcurrencyLimit(t *testing.T) {
	g := newGate()
	s := newGateSvc(t, g, Options{Concurrency: 1})
	a, err := s.Start(t.Context(), fileInput("a.py"))
	if err != nil {
		t.Fatal(err)
	}
	b, err := s.Start(t.Context(), fileInput("b.py"))
	if err != nil {
		t.Fatal(err)
	}
	waitFor(t, "first guarddog", func() bool { return g.started() >= 1 })
	time.Sleep(100 * time.Millisecond)
	if n := g.started(); n != 1 {
		t.Fatalf("only one scan may run at a time, guarddog started %d", n)
	}
	if sc, _ := s.Get(b); sc.Status != "running" {
		t.Fatalf("waiting scan is running: %s", sc.Status)
	}
	g.release()
	for _, id := range []string{a, b} {
		if sc := waitDone(t, s, id); sc.Status != "done" {
			t.Fatalf("%s %s %q", id, sc.Status, sc.Error)
		}
	}
	if g.max != 1 {
		t.Fatalf("max concurrent %d", g.max)
	}
}

// 자동 검사 대기 상한(SCAN_QUEUE) — 실행 + 대기가 상한이면 busy, 수동 검사는 그대로 받는다
func TestAutoQueueFullSkips(t *testing.T) {
	g := newGate()
	s := newGateSvc(t, g, Options{Concurrency: 1, Queue: 1, PyPI: "http://127.0.0.1:1"})
	if _, err := s.Start(t.Context(), fileInput("a.py")); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "first guarddog", func() bool { return g.started() >= 1 })
	id, skip := s.FromInstall(t.Context(), session("ins-0001", "pip", "aaa==1.0"))
	if id == "" || skip != "" {
		t.Fatalf("queued auto scan: %q %q", id, skip)
	}
	if id, skip := s.FromInstall(t.Context(), session("ins-0002", "pip", "bbb==1.0")); id != "" || skip != SkipBusy {
		t.Fatalf("queue full: %q %q", id, skip)
	}
	if _, err := s.Start(t.Context(), fileInput("c.py")); err != nil {
		t.Fatalf("manual scans are not limited by the queue: %v", err)
	}
	g.release()
}

// 슬롯 대기 상한(10분, 테스트는 짧게) — 넘으면 failed 「대기 시간 초과」, 검사 한 건의 타임아웃은 슬롯을 잡은 뒤부터
func TestQueueWaitTimeoutFails(t *testing.T) {
	g := newGate()
	s := newGateSvc(t, g, Options{Concurrency: 1, QueueWait: 150 * time.Millisecond, Timeout: 5 * time.Second})
	a, _ := s.Start(t.Context(), fileInput("a.py"))
	waitFor(t, "first guarddog", func() bool { return g.started() >= 1 })
	b, _ := s.Start(t.Context(), fileInput("b.py"))
	sc := waitDone(t, s, b)
	if sc.Status != "failed" || !strings.Contains(sc.Error, "대기 시간 초과") {
		t.Fatalf("queue wait: %s %q", sc.Status, sc.Error)
	}
	time.Sleep(200 * time.Millisecond) // a 는 슬롯을 잡은 뒤의 타임아웃(5초)만 센다 — 대기 상한이 a 에 걸리지 않는다
	if sc, _ := s.Get(a); sc.Status != "running" {
		t.Fatalf("slot holder must keep running: %s %q", sc.Status, sc.Error)
	}
	g.release()
	if sc := waitDone(t, s, a); sc.Status != "done" {
		t.Fatalf("a: %s %q", sc.Status, sc.Error)
	}
}

// 검사기 종료 코드 137(메모리 한도에 걸려 죽음) → 「검사기 메모리 부족」, 메모리 · CPU 는 설정값으로
func TestScannerOOMAndResources(t *testing.T) {
	g := newGate()
	g.code = 137
	g.release()
	s := newGateSvc(t, g, Options{MemoryMB: 768, CPUs: 1})
	id, _ := s.Start(t.Context(), fileInput("a.py"))
	sc := waitDone(t, s, id)
	if sc.Status != "failed" || !strings.Contains(sc.Error, "검사기 메모리 부족") {
		t.Fatalf("oom: %s %q", sc.Status, sc.Error)
	}
	for _, sp := range g.specs {
		if sp.MemoryMB != 768 || sp.CPUs != 1 {
			t.Fatalf("spec resources %d MB %v CPU", sp.MemoryMB, sp.CPUs)
		}
	}
	// 기본값: 1GB · 2코어(지금까지와 같다)
	d := New(Options{})
	if sp := d.spec("x", "guarddog", "img", false); sp.MemoryMB != 1024 || sp.CPUs != 2 {
		t.Fatalf("defaults %d %v", sp.MemoryMB, sp.CPUs)
	}
}

// AutoScan: 훅은 곧바로 돌아오고(세션 보고 응답을 붙잡지 않는다) 뒤에서 결과를 세션에 붙인다
func TestAutoScanAttaches(t *testing.T) {
	type call struct{ install, scan, skip string }
	got := make(chan call, 4)
	attach := func(_ context.Context, installID, scanID, skip string) error {
		got <- call{installID, scanID, skip}
		return nil
	}
	r := &recRunner{}
	block := make(chan struct{})
	slow := &slowPing{recRunner: r, wait: block}
	r.dir = t.TempDir()
	s := New(Options{Docker: slow, Dir: r.dir, Volume: "v", Store: store.NewMemory(), Blocker: &fakeBlocker{}, PyPI: "http://127.0.0.1:1"})
	hook := AutoScan(func() *Service { return s }, attach)
	start := time.Now()
	hook(session("ins-0001", "pip", "requests==1.0"))
	if d := time.Since(start); d > 200*time.Millisecond {
		t.Fatalf("hook must not block the session report: %v", d)
	}
	close(block)
	select {
	case c := <-got:
		if c.install != "ins-0001" || c.scan == "" || c.skip != "" {
			t.Fatalf("attach %+v", c)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("attach not called")
	}
	// 검사기 서비스가 없으면 off 로 붙인다 · 거부 세션은 붙이지 않는다
	none := AutoScan(func() *Service { return nil }, attach)
	ref := session("ins-0002", "pip", "requests")
	ref.Status = model.InstallRefused
	none(ref)
	none(session("ins-0003", "pip", "requests"))
	select {
	case c := <-got:
		if c != (call{"ins-0003", "", SkipOff}) {
			t.Fatalf("nil service attach %+v", c)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("attach not called for nil service")
	}
}

type slowPing struct {
	*recRunner
	wait chan struct{}
}

func (p *slowPing) Ping(ctx context.Context) error {
	select {
	case <-p.wait:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func ptrS(s string) *string { return &s }
