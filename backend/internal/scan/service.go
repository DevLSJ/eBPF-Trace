// Package scan: 공급망 검사(10/16) — 대상을 작업 볼륨에 내려받아 풀고, 격리된 검사 컨테이너에서
// GuardDog(Datadog, 악성 코드 패턴 · 파일:줄 · 위험 점수)와 OSV-Scanner(Google, 의존성의 알려진 취약점)를 돌린다.
// 코드는 실행하지 않는다. 검사기 컨테이너 이름은 supplyguard-scan-* (eBPF 감시 제외 대상).
package scan

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/dockerapi"
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/model"
)

type Runner interface {
	Run(ctx context.Context, s dockerapi.RunSpec) ([]byte, int, error)
}

type Store interface {
	SaveScan(ctx context.Context, s model.Scan) error
	ListScans(ctx context.Context) ([]model.Scan, error)
}

// Blocker: 「차단 목록에 올리기」 — 공급망 검사 건을 열고 악성으로 판정해 패키지 차단 제안을 만든다(review).
// pkgs 가 비면 패키지 검사의 대상 하나, 있으면(저장소 · 파일 검사) 결과에서 고른 패키지들(W4).
// reason: 확인 대화상자의 사유(선택, W18) — 판정 메모에 붙인다. 길이 검사는 review 가 한다
type Blocker interface {
	FromScan(ctx context.Context, s model.Scan, pkgs []model.ScanPackage, reason string) (model.Case, model.Proposal, error)
}

type Options struct {
	Docker        Runner
	Dir           string // 백엔드 안의 작업 볼륨 경로(예: /scan)
	Volume        string // 같은 볼륨의 Docker 이름(검사기가 /work 로 읽기 전용 마운트)
	GuardDogImage string
	OSVImage      string
	Store         Store
	Blocker       Blocker
	// GitHub: 저장소 tarball 을 받는 codeload 주소. 비면 https://codeload.github.com (테스트는 가짜 서버)
	GitHub string
	// PyPI · NPM: 레지스트리 주소. 비면 https://pypi.org · https://registry.npmjs.org (테스트는 가짜 서버)
	PyPI, NPM string
	// 자원(11/04): 동시 실행 상한(SCAN_CONCURRENCY, 기본 1 — 수동 검사에도) · 자동 검사의 대기 상한(SCAN_QUEUE, 기본 4 — 넘으면 busy) ·
	// 검사기 컨테이너 메모리 · CPU(SCAN_MEMORY_MB 기본 1024 · SCAN_CPUS 기본 2)
	Concurrency, Queue int
	MemoryMB           int64
	CPUs               float64
	// Timeout: 슬롯을 잡은 뒤 검사 한 건의 상한(기본 8분) · QueueWait: 슬롯 대기 상한(기본 10분, 넘으면 failed). 테스트는 짧게
	Timeout, QueueWait time.Duration
}

const keep = 30 * 24 * time.Hour

type Service struct {
	o       Options
	mu      sync.Mutex
	scans   []*model.Scan // 최신순
	seq     int
	engOnce sync.Once
	engines []model.ScanEngine
	// slots: 동시 실행 자리(SCAN_CONCURRENCY). active: 시작해 아직 끝나지 않은 검사 수(실행 중 + 자리 대기) — 자동 검사의 busy 판단
	slots  chan struct{}
	active int
	// autoMu: 자동 검사의 「합류 · 재사용 확인 → 시작」을 한 번에 — 같은 패키지 두 세션이 동시에 와도 검사는 하나
	autoMu sync.Mutex
}

// 자원 기본값(11/04) — 메모리 · CPU 는 지금까지의 하드코딩 값 그대로
const (
	defaultConcurrency = 1
	defaultQueue       = 4
	defaultMemoryMB    = 1024
	defaultCPUs        = 2
	defaultTimeout     = 8 * time.Minute
	defaultQueueWait   = 10 * time.Minute
)

func New(o Options) *Service {
	if o.Concurrency <= 0 {
		o.Concurrency = defaultConcurrency
	}
	if o.Queue <= 0 {
		o.Queue = defaultQueue
	}
	if o.MemoryMB <= 0 {
		o.MemoryMB = defaultMemoryMB
	}
	if o.CPUs <= 0 {
		o.CPUs = defaultCPUs
	}
	if o.Timeout <= 0 {
		o.Timeout = defaultTimeout
	}
	if o.QueueWait <= 0 {
		o.QueueWait = defaultQueueWait
	}
	return &Service{o: o, slots: make(chan struct{}, o.Concurrency)}
}

// registries: 비어 있으면 기본 주소(테스트가 바꾼 전역 값 포함)
func (s *Service) registries() registries {
	r := registries{s.o.PyPI, s.o.NPM}
	if r.pypi == "" {
		r.pypi = pypiBase
	}
	if r.npm == "" {
		r.npm = npmBase
	}
	return r
}

// Error: 입력 오류(400) · 크기 초과(413)
type Error struct {
	Status int
	Msg    string
}

func (e *Error) Error() string { return e.Msg }

func bad(f string, a ...any) error { return &Error{400, fmt.Sprintf(f, a...)} }

// Load: 저장소에서 30일 안의 결과를 읽고 번호를 잇는다. 실행 중이던 검사는 실패로 둔다
func (s *Service) Load(ctx context.Context) error {
	xs, err := s.o.Store.ListScans(ctx)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range xs {
		x := xs[i]
		if time.Since(x.StartedAt) > keep {
			continue
		}
		if x.Status == "running" {
			x.Status, x.Error = "failed", "서버가 다시 시작돼 검사가 끊겼습니다"
		}
		if x.Trigger == "" {
			x.Trigger = model.ScanManual // 11/04 이전 기록은 모두 수동 검사
		}
		s.scans = append(s.scans, &x)
		var n int
		if _, err := fmt.Sscanf(x.ID, "scan-%d", &n); err == nil && n > s.seq {
			s.seq = n
		}
	}
	slices.SortFunc(s.scans, func(a, b *model.Scan) int { return b.StartedAt.Compare(a.StartedAt) })
	return nil
}

type Input struct {
	Kind, Manager, Name, Version, URL string
	FileName                          string
	File                              io.Reader // kind=file
}

var (
	namePat = regexp.MustCompile(`^(@[\w.-]+/)?[\w.-]{1,214}$`)
	verPat  = regexp.MustCompile(`^[\w.+!-]{0,64}$`)
	depPat  = regexp.MustCompile(`(?i)(^requirements.*\.txt$|^package-lock\.json$|^yarn\.lock$|^pnpm-lock\.yaml$|^poetry\.lock$|^pipfile\.lock$)`)
	filePat = regexp.MustCompile(`(?i)\.(tar\.gz|tgz|whl|zip|py|js|mjs|cjs)$`)
)

// Start: 입력을 확인하고(파일은 여기서 받아 둔다) 검사를 뒤에서 돌린다 — 공급망 검사 화면 · API(trigger manual)
func (s *Service) Start(ctx context.Context, in Input) (string, error) {
	return s.start(ctx, in, startOpts{})
}

// startOpts: 자동 검사(11/04) — 시작한 설치 세션 · 라벨(최신으로 받는 것은 입력 이름만) · 대기 상한 적용
type startOpts struct {
	installID, label string
	auto             bool
}

// errBusy: 실행 + 대기가 SCAN_CONCURRENCY + SCAN_QUEUE 에 찼다(자동 검사만)
var errBusy = errors.New("검사 대기열이 가득 찼습니다")

func (s *Service) start(ctx context.Context, in Input, o startOpts) (string, error) {
	t := model.ScanTarget{Kind: in.Kind}
	switch in.Kind {
	case "package":
		if in.Manager != "pip" && in.Manager != "npm" {
			return "", bad("manager 는 pip | npm")
		}
		name, v := strings.TrimSpace(in.Name), strings.TrimSpace(in.Version)
		if !namePat.MatchString(name) || !verPat.MatchString(v) {
			return "", bad("패키지 이름 · 버전을 확인하세요")
		}
		sep := map[string]string{"pip": "==", "npm": "@"}[in.Manager]
		t.Manager, t.Name, t.Version, t.Label = in.Manager, name, v, in.Manager+" "+name+ver(v, sep)
		if o.label != "" {
			t.Label = o.label
		}
	case "repo":
		ref, err := ParseGitHubURL(in.URL)
		if err != nil {
			return "", err
		}
		t.URL, t.Name, t.Ref, t.Subpath, t.Label = ref.URL(), ref.Repo, ref.Ref, ref.Subpath, ref.Label()
	case "file":
		fn := filepath.Base(strings.TrimSpace(in.FileName))
		if in.File == nil || fn == "" || fn == "." {
			return "", bad("파일을 고르세요")
		}
		if !filePat.MatchString(fn) && !depPat.MatchString(fn) {
			return "", bad("패키지 압축(.tar.gz · .whl · .tgz · .zip) · 소스(.py · .js) · 의존성 파일(requirements.txt · package-lock.json 등)만 받습니다")
		}
		t.FileName, t.Label = fn, fn
	default:
		return "", bad("kind 는 package | repo | file")
	}

	// 검사를 띄울 수 없는 환경이면 기록을 만들기 전에 503 으로 원인을 알린다(11/02 — 전엔 「서버 오류」 500)
	if err := os.MkdirAll(s.o.Dir, 0o755); err != nil {
		return "", &Error{503, fmt.Sprintf("검사 작업 폴더를 만들 수 없습니다(SCAN_DIR=%s). 백엔드의 검사 작업 볼륨을 확인하세요", s.o.Dir)}
	}
	if p, ok := s.o.Docker.(interface{ Ping(context.Context) error }); ok {
		pctx, cancel := context.WithTimeout(ctx, 3*time.Second)
		err := p.Ping(pctx)
		cancel()
		if err != nil {
			return "", &Error{503, "검사기 컨테이너를 띄울 수 없습니다(Docker 에 연결되지 않음)"}
		}
	}
	s.mu.Lock()
	if o.auto && s.active >= s.o.Concurrency+s.o.Queue {
		s.mu.Unlock()
		return "", errBusy
	}
	s.seq++
	s.active++
	id := fmt.Sprintf("scan-%04d", s.seq)
	s.mu.Unlock()
	src := filepath.Join(s.o.Dir, id, "src")
	if err := os.MkdirAll(src, 0o755); err != nil {
		s.leave()
		return "", err
	}
	if in.Kind == "file" {
		// 의존성 파일 · 소스는 그대로, 압축은 푼다. 원본은 검사 뒤 폴더째 지운다
		lr := &io.LimitedReader{R: in.File, N: maxDownload + 1}
		err := extract(t.FileName, lr, src)
		if lr.N <= 0 {
			err = &Error{413, "파일은 50MB 까지 올릴 수 있습니다"}
		}
		if err != nil {
			_ = os.RemoveAll(filepath.Join(s.o.Dir, id))
			s.leave()
			var se *Error
			if errors.As(err, &se) {
				return "", err
			}
			return "", bad("%s", err.Error())
		}
		if fi, err := os.Stat(filepath.Join(src, t.FileName)); err == nil {
			t.Size = fi.Size()
		}
	}
	sc := &model.Scan{ID: id, Target: t, Status: "running", StartedAt: time.Now().UTC(), Findings: []model.ScanFinding{}, Vulns: []model.ScanVuln{}, Packages: []model.ScanPackage{}, Files: map[string]string{},
		Trigger: model.ScanManual}
	if o.auto {
		sc.Trigger, sc.InstallID = model.ScanInstall, &o.installID
	}
	s.mu.Lock()
	s.scans = slices.Insert(s.scans, 0, sc)
	s.mu.Unlock()
	s.save(sc)
	go s.run(sc)
	return id, nil
}

func (s *Service) leave() {
	s.mu.Lock()
	s.active--
	s.mu.Unlock()
}

// run: 동시 실행 자리를 기다렸다가(QueueWait 까지, 그동안 running) 검사한다. 타임아웃(8분)은 자리를 잡은 뒤부터 센다
func (s *Service) run(sc *model.Scan) {
	work := filepath.Join(s.o.Dir, sc.ID)
	defer os.RemoveAll(work) // 원본은 남기지 않는다
	err := s.acquire()
	if err == nil {
		ctx, cancel := context.WithTimeout(context.Background(), s.o.Timeout)
		err = s.scan(ctx, sc, filepath.Join(work, "src"))
		cancel()
		<-s.slots
	}
	s.mu.Lock()
	s.active--
	now := time.Now().UTC()
	sc.FinishedAt = &now
	if err != nil {
		sc.Status, sc.Error = "failed", err.Error()
		slog.Warn("scan failed", "id", sc.ID, "target", sc.Target.Label, "err", err)
	} else {
		sc.Status = "done"
		slog.Info("scan done", "id", sc.ID, "target", sc.Target.Label, "verdict", sc.Verdict, "threats", sc.Threats, "vulns", sc.VulnCount)
	}
	s.mu.Unlock()
	s.save(sc)
}

func (s *Service) acquire() error {
	select {
	case s.slots <- struct{}{}:
		return nil
	default:
	}
	tm := time.NewTimer(s.o.QueueWait)
	defer tm.Stop()
	select {
	case s.slots <- struct{}{}:
		return nil
	case <-tm.C:
		wait := s.o.QueueWait.String()
		if s.o.QueueWait >= time.Minute && s.o.QueueWait%time.Minute == 0 {
			wait = fmt.Sprintf("%d분", int(s.o.QueueWait.Minutes()))
		}
		return fmt.Errorf("검사 대기 시간 초과, %s 동안 앞선 검사가 끝나지 않았습니다(동시 실행 SCAN_CONCURRENCY=%d)", wait, s.o.Concurrency)
	}
}

// oom: 검사기 종료 코드 137 — 메모리 한도(SCAN_MEMORY_MB)에 걸려 죽었다
func (s *Service) oom(engine string) error {
	return fmt.Errorf("검사기 메모리 부족(%s, 종료 코드 137), SCAN_MEMORY_MB(지금 %d)를 늘리거나 더 작은 대상으로 검사하세요", engine, s.o.MemoryMB)
}

const exitOOM = 137

func (s *Service) scan(ctx context.Context, sc *model.Scan, src string) error {
	t := sc.Target
	switch t.Kind {
	case "package":
		v, err := fetchPackageFrom(ctx, s.registries(), t.Manager, t.Name, t.Version, src)
		if err != nil {
			return err
		}
		if t.Version == "" && v != "" {
			s.mu.Lock()
			sc.Target.Version = v // 받은 최신 버전을 남긴다(라벨은 입력 그대로)
			s.mu.Unlock()
		}
		if t.Version == "" {
			t.Version = v
		}
	case "repo":
		ref, err := ParseGitHubURL(t.URL)
		if err != nil {
			return err
		}
		base := s.o.GitHub
		if base == "" {
			base = defaultCodeload
		}
		if err := fetchRepo(ctx, base, ref, src); err != nil {
			return err
		}
	}
	rel := sc.ID + "/src"
	eng := s.engineList(ctx)
	s.mu.Lock()
	sc.Engines = eng
	s.mu.Unlock()

	depsOnly := t.Kind == "file" && depPat.MatchString(t.FileName)
	work := filepath.Dir(src)
	testsDir := filepath.Join(work, "tests")
	var findings []model.ScanFinding
	var risk *model.ScanRisk
	if !depsOnly {
		eco := "pypi"
		if t.Manager == "npm" || exists(src, "package.json") {
			eco = "npm"
		}
		// 테스트 코드는 따로 떼어(11/02) 본체만으로 위험 점수 · 판정을 내고, 테스트는 한 번 더 돌려 목록에만 「테스트 코드」로 붙인다
		nTests, err := splitTests(src, testsDir)
		if err != nil {
			return fmt.Errorf("테스트 코드 분리: %w", err)
		}
		out, code, err := s.o.Docker.Run(ctx, s.spec(sc.ID, "guarddog", s.o.GuardDogImage, false, eco, "scan", "/work/"+rel, "--output-format", "json"))
		if err != nil {
			return fmt.Errorf("GuardDog: %w", err)
		}
		if code == exitOOM {
			return s.oom("GuardDog")
		}
		if findings, risk, err = parseGuardDog(out, "/work/"+rel); err != nil {
			return err
		}
		if nTests > 0 {
			trel := sc.ID + "/tests"
			out, code, err := s.o.Docker.Run(ctx, s.spec(sc.ID, "guarddog-tests", s.o.GuardDogImage, false, eco, "scan", "/work/"+trel, "--output-format", "json"))
			if err != nil {
				return fmt.Errorf("GuardDog(테스트 코드): %w", err)
			}
			if code == exitOOM {
				return s.oom("GuardDog")
			}
			tf, _, err := parseGuardDog(out, "/work/"+trel)
			if err != nil {
				return err
			}
			for i := range tf {
				tf[i].Test = true
			}
			findings = append(findings, tf...)
		}
	}
	var vulns []model.ScanVuln
	var pkgs []model.ScanPackage
	if t.Kind == "package" && t.Version != "" {
		// 패키지 자기 이름 · 버전의 알려진 취약점(11/02) — 잠금 파일을 src 밖(osv/)에 만들어 OSV-Scanner 로 조회한다
		lf := ownLockfile(t.Manager, t.Name, t.Version)
		if err := os.MkdirAll(filepath.Join(work, "osv"), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(work, "osv", lf.name), lf.content, 0o644); err != nil {
			return err
		}
		lock := "/work/" + sc.ID + "/osv/" + lf.name
		out, code, err := s.o.Docker.Run(ctx, s.spec(sc.ID, "osv", s.o.OSVImage, true, "scan", "source", "--lockfile", lock, "--format", "json"))
		if err != nil {
			return fmt.Errorf("OSV-Scanner: %w", err)
		}
		if code == exitOOM {
			return s.oom("OSV-Scanner")
		}
		if code == 0 || code == 1 {
			if vulns, _, err = parseOSV(out, "/work/"+sc.ID+"/osv", map[string]bool{strings.ToLower(t.Name): true}); err != nil {
				return err
			}
		}
	}
	if depsOnly || t.Kind != "package" {
		// --no-call-analysis=all(11/06): OSV-Scanner 2.x 는 Go 호출 분석이 기본으로 켜져 Go 소스를 빌드하다 메모리 부족(3GB 에서도 137).
		// 이 제품은 호출 분석 결과를 쓰지 않는다(parse.go 는 ids · max_severity 만)
		args := []string{"scan", "source", "-r", "/work/" + rel, "--format", "json", "--no-call-analysis=all"}
		var direct map[string]bool
		if depsOnly {
			args = []string{"scan", "source", "--lockfile", "/work/" + rel + "/" + t.FileName, "--format", "json"}
			if b, err := os.ReadFile(filepath.Join(src, t.FileName)); err == nil {
				direct = directNames(t.FileName, b)
			}
		}
		out, code, err := s.o.Docker.Run(ctx, s.spec(sc.ID, "osv", s.o.OSVImage, true, args...))
		if err != nil {
			return fmt.Errorf("OSV-Scanner: %w", err)
		}
		if code == exitOOM {
			return s.oom("OSV-Scanner")
		}
		if code == 0 || code == 1 { // 1 = 취약점 있음, 128 = 검사할 의존성 파일 없음
			if vulns, pkgs, err = parseOSV(out, "/work/"+rel, direct); err != nil {
				return err
			}
		}
	}

	files := map[string]string{}
	for _, f := range findings {
		if f.Category != "threat" || files[f.File] != "" || len(files) >= 20 {
			continue
		}
		root := src
		if f.Test {
			root = testsDir
		}
		p := filepath.Join(root, filepath.FromSlash(f.File))
		if !strings.HasPrefix(p, root+string(os.PathSeparator)) {
			continue
		}
		if b, err := os.ReadFile(p); err == nil && len(b) <= 256<<10 {
			files[f.File] = string(b)
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	sc.Findings, sc.Risk, sc.Vulns, sc.Files = nonNil(findings), risk, nonNilV(vulns), files
	sc.Packages = pkgs
	if sc.Packages == nil {
		sc.Packages = []model.ScanPackage{}
	}
	sc.Threats, sc.Capabilities, sc.TestFindings, sc.VulnCount, sc.VulnMax = 0, 0, 0, 0, nil
	for _, f := range findings {
		if f.Test {
			sc.TestFindings++
		} else if f.Category == "threat" {
			sc.Threats++
		} else {
			sc.Capabilities++
		}
	}
	for _, v := range vulns {
		sc.VulnCount += v.Count
		var f float64
		if _, err := fmt.Sscan(v.MaxSeverity, &f); err == nil && (sc.VulnMax == nil || f > *sc.VulnMax) {
			sc.VulnMax = &f
		}
	}
	// 판정은 verdict.go(11/03 3단계) — 점수 하나로 하던 10/16 방식은 인기 패키지가 악성이 됐다(11/02 실측)
	sc.Verdict, sc.InstallThreats = verdictOf(risk, findings, sc.VulnCount)
	return nil
}

func nonNil(x []model.ScanFinding) []model.ScanFinding {
	if x == nil {
		return []model.ScanFinding{}
	}
	return x
}
func nonNilV(x []model.ScanVuln) []model.ScanVuln {
	if x == nil {
		return []model.ScanVuln{}
	}
	return x
}

func exists(dir, name string) bool {
	m, _ := filepath.Glob(filepath.Join(dir, "*", name))
	_, err := os.Stat(filepath.Join(dir, name))
	return err == nil || len(m) > 0
}

// spec: 검사기 컨테이너 — 작업 볼륨 읽기 전용, 권한 없음, SCAN_MEMORY_MB · SCAN_CPUS(기본 1GB · 2코어). GuardDog 는 네트워크 없이, OSV 는 취약점 DB 조회에 네트워크
func (s *Service) spec(id, engine, image string, network bool, args ...string) dockerapi.RunSpec {
	return dockerapi.RunSpec{Name: "supplyguard-scan-" + id + "-" + engine, Image: image, Cmd: args, Volume: s.o.Volume, Target: "/work",
		Network: network, MemoryMB: s.o.MemoryMB, CPUs: s.o.CPUs, Labels: map[string]string{"supplyguard.scan": id}}
}

// engineList: 검사기 버전(처음 한 번 --version 으로 읽는다)
func (s *Service) engineList(ctx context.Context) []model.ScanEngine {
	s.engOnce.Do(func() { s.engines = s.readVersions(ctx) })
	return s.engines
}

func (s *Service) readVersions(ctx context.Context) []model.ScanEngine {
	ver := func(engine, image string, args ...string) string {
		out, _, err := s.o.Docker.Run(ctx, s.spec("version", engine, image, false, args...))
		if err != nil {
			return "?"
		}
		first, _, _ := strings.Cut(strings.TrimSpace(string(out)), "\n") // osv-scanner: 「osv-scanner version: 2.7.0」 다음 줄에 commit · 빌드 시각
		f := strings.Fields(first)
		if len(f) == 0 {
			return "?"
		}
		return f[len(f)-1]
	}
	return []model.ScanEngine{{Name: "GuardDog", Version: ver("guarddog", s.o.GuardDogImage, "--version")}, {Name: "OSV-Scanner", Version: ver("osv", s.o.OSVImage, "--version")}}
}

func (s *Service) save(sc *model.Scan) {
	s.mu.Lock()
	c := *sc
	s.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := s.o.Store.SaveScan(ctx, c); err != nil {
		slog.Error("scan save", "id", sc.ID, "err", err)
	}
}

// List: 최신순(코드 · 찾은 것 목록은 빼고)
func (s *Service) List() []model.Scan {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]model.Scan, 0, len(s.scans))
	for _, x := range s.scans {
		if time.Since(x.StartedAt) > keep {
			continue
		}
		c := *x
		c.Findings, c.Vulns, c.Packages, c.Files = nil, nil, nil, nil
		out = append(out, c)
	}
	return out
}

func (s *Service) Get(id string) (model.Scan, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, x := range s.scans {
		if x.ID == id {
			return *x, true
		}
	}
	return model.Scan{}, false
}

// Block: 패키지 이름으로 검사한 것 — 선택 없이 그 패키지(기존 경로)
func (s *Service) Block(ctx context.Context, id string) (string, error) {
	return s.BlockPackages(ctx, id, nil, "")
}

const maxBlockPackages = 50

// BlockPackages: 「차단 목록에 올리기」(W4) — 패키지 검사는 그 패키지(선택 없음), 저장소 · 파일 검사는 결과의 패키지 목록(OSV 가 읽은 의존성) 중 고른 것만.
// 매니저를 비우면 결과에서 찾고(이름이 두 매니저에 있으면 지정 필요), 버전을 비우면 결과의 버전. 차단 키는 매니저:이름(버전 무관).
// 이미 같은 선택으로 올렸으면 그 제안을 돌려준다(review). reason(W18)은 판정 메모로 그대로 넘긴다
func (s *Service) BlockPackages(ctx context.Context, id string, sel []model.ScanPackage, reason string) (string, error) {
	sc, ok := s.Get(id)
	if !ok {
		return "", &Error{404, "검사 없음"}
	}
	if sc.Status != "done" {
		return "", bad("검사를 마친 것만 차단 목록에 올릴 수 있습니다")
	}
	var chosen []model.ScanPackage
	if sc.Target.Kind == "package" {
		if len(sel) > 0 {
			return "", bad("패키지 이름으로 검사한 것은 그 패키지를 올립니다. packages 없이 보내세요")
		}
	} else {
		switch {
		case len(sel) == 0:
			return "", bad("차단할 패키지를 고르세요(packages)")
		case len(sel) > maxBlockPackages:
			return "", bad("한 번에 %d개까지 올릴 수 있습니다", maxBlockPackages)
		case len(sc.Packages) == 0:
			return "", bad("이 검사 결과에는 패키지 목록이 없습니다. 잠금 · 의존성 파일(requirements.txt · package-lock.json · Cargo.lock)이 있어야 합니다")
		}
		for _, p := range sel {
			r, err := resolvePackage(sc.Packages, p)
			if err != nil {
				return "", err
			}
			chosen = append(chosen, r)
		}
	}
	c, p, err := s.o.Blocker.FromScan(ctx, sc, chosen, reason)
	if err != nil {
		return "", err
	}
	s.mu.Lock()
	for _, x := range s.scans {
		if x.ID == id {
			x.CaseID = &c.ID
		}
	}
	s.mu.Unlock()
	if x, ok := s.Get(id); ok {
		s.save(&x)
	}
	return p.ID, nil
}

// resolvePackage: 고른 패키지를 결과 목록에서 찾아 매니저 · 버전 · 출처를 채운다(이름은 대소문자 무시)
func resolvePackage(list []model.ScanPackage, p model.ScanPackage) (model.ScanPackage, error) {
	name := strings.TrimSpace(p.Name)
	if name == "" {
		return model.ScanPackage{}, bad("패키지 이름이 비어 있습니다")
	}
	if p.Manager != "" && !model.ValidManager(p.Manager) {
		return model.ScanPackage{}, bad("manager 는 pip | npm | cargo")
	}
	if !verPat.MatchString(p.Version) {
		return model.ScanPackage{}, bad("%s 의 버전 표기를 확인하세요", name)
	}
	byManager := map[string]model.ScanPackage{}
	var managers []string
	unsupported := false
	for _, x := range list {
		if !strings.EqualFold(x.Name, name) || (p.Manager != "" && x.Manager != p.Manager) {
			continue
		}
		if x.Manager == "" {
			unsupported = true
			continue
		}
		if _, dup := byManager[x.Manager]; !dup {
			byManager[x.Manager] = x
			managers = append(managers, x.Manager)
		}
	}
	switch {
	case len(managers) == 0 && unsupported:
		return model.ScanPackage{}, bad("%s 은(는) pip · npm · cargo 패키지가 아니라 차단 목록에 올릴 수 없습니다", name)
	case len(managers) == 0:
		return model.ScanPackage{}, bad("검사 결과에 없는 패키지: %s", name)
	case len(managers) > 1:
		return model.ScanPackage{}, bad("%s 은(는) 여러 매니저(%s)에 있습니다. manager 를 지정하세요", name, strings.Join(managers, " · "))
	}
	r := byManager[managers[0]]
	if p.Version != "" {
		r.Version = p.Version
	}
	return r, nil
}
