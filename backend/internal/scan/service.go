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
}

const keep = 30 * 24 * time.Hour

type Service struct {
	o       Options
	mu      sync.Mutex
	scans   []*model.Scan // 최신순
	seq     int
	engOnce sync.Once
	engines []model.ScanEngine
}

func New(o Options) *Service { return &Service{o: o} }

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

// Start: 입력을 확인하고(파일은 여기서 받아 둔다) 검사를 뒤에서 돌린다
func (s *Service) Start(ctx context.Context, in Input) (string, error) {
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

	s.mu.Lock()
	s.seq++
	id := fmt.Sprintf("scan-%04d", s.seq)
	s.mu.Unlock()
	src := filepath.Join(s.o.Dir, id, "src")
	if err := os.MkdirAll(src, 0o755); err != nil {
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
	sc := &model.Scan{ID: id, Target: t, Status: "running", StartedAt: time.Now().UTC(), Findings: []model.ScanFinding{}, Vulns: []model.ScanVuln{}, Packages: []model.ScanPackage{}, Files: map[string]string{}}
	s.mu.Lock()
	s.scans = slices.Insert(s.scans, 0, sc)
	s.mu.Unlock()
	s.save(sc)
	go s.run(sc)
	return id, nil
}

func (s *Service) run(sc *model.Scan) {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()
	work := filepath.Join(s.o.Dir, sc.ID)
	defer os.RemoveAll(work) // 원본은 남기지 않는다
	err := s.scan(ctx, sc, filepath.Join(work, "src"))
	s.mu.Lock()
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

func (s *Service) scan(ctx context.Context, sc *model.Scan, src string) error {
	t := sc.Target
	switch t.Kind {
	case "package":
		v, err := fetchPackage(ctx, t.Manager, t.Name, t.Version, src)
		if err != nil {
			return err
		}
		if t.Version == "" && v != "" {
			s.mu.Lock()
			sc.Target.Version = v // 받은 최신 버전을 남긴다(라벨은 입력 그대로)
			s.mu.Unlock()
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
	var findings []model.ScanFinding
	var risk *model.ScanRisk
	if !depsOnly {
		eco := "pypi"
		if t.Manager == "npm" || exists(src, "package.json") {
			eco = "npm"
		}
		out, _, err := s.o.Docker.Run(ctx, s.spec(sc.ID, "guarddog", s.o.GuardDogImage, false, eco, "scan", "/work/"+rel, "--output-format", "json"))
		if err != nil {
			return fmt.Errorf("GuardDog: %w", err)
		}
		if findings, risk, err = parseGuardDog(out, "/work/"+rel); err != nil {
			return err
		}
	}
	var vulns []model.ScanVuln
	var pkgs []model.ScanPackage
	if depsOnly || t.Kind != "package" {
		args := []string{"scan", "source", "-r", "/work/" + rel, "--format", "json"}
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
		p := filepath.Join(src, filepath.FromSlash(f.File))
		if !strings.HasPrefix(p, src+string(os.PathSeparator)) {
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
	sc.Threats, sc.Capabilities, sc.VulnCount, sc.VulnMax = 0, 0, 0, nil
	for _, f := range findings {
		if f.Category == "threat" {
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
	// 판정은 GuardDog 위험 점수(위협 · 연쇄 · 구체성을 합친 0~10)로 — 위협 줄은 점수가 낮아도 빨강으로 보인다(10/16 실측: 정상 requests 테스트 파일 4.3 · low)
	switch {
	case risk != nil && risk.Score >= 5:
		sc.Verdict = "malicious"
	case sc.VulnCount > 0:
		sc.Verdict = "vulnerable"
	default:
		sc.Verdict = "clean"
	}
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

// spec: 검사기 컨테이너 — 작업 볼륨 읽기 전용, 권한 없음, 1GB · 2코어. GuardDog 는 네트워크 없이, OSV 는 취약점 DB 조회에 네트워크
func (s *Service) spec(id, engine, image string, network bool, args ...string) dockerapi.RunSpec {
	return dockerapi.RunSpec{Name: "supplyguard-scan-" + id + "-" + engine, Image: image, Cmd: args, Volume: s.o.Volume, Target: "/work",
		Network: network, MemoryMB: 1024, CPUs: 2, Labels: map[string]string{"supplyguard.scan": id}}
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
			return "", bad("패키지 이름으로 검사한 것은 그 패키지를 올립니다 — packages 없이 보내세요")
		}
	} else {
		switch {
		case len(sel) == 0:
			return "", bad("차단할 패키지를 고르세요(packages)")
		case len(sel) > maxBlockPackages:
			return "", bad("한 번에 %d개까지 올릴 수 있습니다", maxBlockPackages)
		case len(sc.Packages) == 0:
			return "", bad("이 검사 결과에는 패키지 목록이 없습니다 — 잠금 · 의존성 파일(requirements.txt · package-lock.json · Cargo.lock)이 있어야 합니다")
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
		return model.ScanPackage{}, bad("%s 은(는) 여러 매니저(%s)에 있습니다 — manager 를 지정하세요", name, strings.Join(managers, " · "))
	}
	r := byManager[managers[0]]
	if p.Version != "" {
		r.Version = p.Version
	}
	return r, nil
}
