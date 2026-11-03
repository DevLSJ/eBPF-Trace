package scan

// 종합 판정(11/04 설계, 2026-11-03 승인) — sg-install 세션 보고(POST /api/installs)를 받으면 서버가 첫 패키지의 정적 검사를 스스로 시작한다.
// SANDBOX_TOKEN 에 새 권한을 주지 않는다: CLI 는 지금처럼 세션만 보고하고, 검사는 review 의 OnInstallStart 훅에서 뒤로 돈다.
//   - 대상: 첫 패키지만. pip ==X · npm @X.Y.Z 는 그 버전, 범위 · 미지정은 레지스트리의 최신 버전(라벨은 이름만, 받은 버전은 target.version)
//   - 건너뜀: local(. / ~ · git+ · URL · file: · .whl/.tar.gz) · unsupported(cargo) · invalid(이름 해석 실패) · off(검사기 없음 · Docker 안 됨) · busy(실행 + 대기 가득)
//   - 순서: 대상 해석 → 실행 중 합류 / 24시간 안 done 재사용 → off → busy. failed 는 다시 검사. 거부(refused) 세션은 시작하지 않는다

import (
	"context"
	"errors"
	"log/slog"
	"regexp"
	"strings"
	"time"

	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/model"
)

// 건너뛴 이유(세션의 scanSkip · 응답 scan.skip)
const (
	SkipLocal       = "local"
	SkipUnsupported = "unsupported"
	SkipBusy        = "busy"
	SkipOff         = "off"
	SkipInvalid     = "invalid"
)

// reuseFor: 이 시간 안에 끝난(done) 같은 검사는 다시 돌리지 않는다
const reuseFor = 24 * time.Hour

// InstallTarget: 설치 인자 하나를 정적 검사 대상으로 해석한 것. Skip 이 있으면 검사하지 않는다
type InstallTarget struct {
	Manager, Name string
	Version       string // Exact 일 때만 — 아니면 최신(시작할 때 레지스트리에서)
	Exact         bool
	Label         string // 「pip numpy==1.21.0」 · 최신이면 「pip requests」
	Skip          string
}

var (
	urlPat      = regexp.MustCompile(`(?i)^[a-z][\w+.-]*://`)
	archivePat  = regexp.MustCompile(`(?i)\.(whl|tar\.gz)$`)
	pipReq      = regexp.MustCompile(`^([^\s\[=<>!~;]+)\s*(\[[^\]]*\])?\s*(.*)$`)
	pipExactPat = regexp.MustCompile(`^===?\s*([\w.+!-]+)$`)
	npmExactPat = regexp.MustCompile(`^\d+\.\d+\.\d+([-+][\w.-]+)?$`)
	pep503      = regexp.MustCompile(`[-_.]+`)
)

// ParseInstallSpec: sg-install 인자 하나(예: 「Requests[socks]>=2」 · 「@types/node@20.1.0」 · 「./reqeusts」)
func ParseInstallSpec(manager, raw string) InstallTarget {
	if manager != "pip" && manager != "npm" {
		return InstallTarget{Skip: SkipUnsupported}
	}
	p := strings.TrimSpace(raw)
	lp := strings.ToLower(p)
	if strings.HasPrefix(p, ".") || strings.HasPrefix(p, "/") || strings.HasPrefix(p, "~") || strings.HasPrefix(lp, "git+") ||
		urlPat.MatchString(p) || strings.HasPrefix(lp, "file:") || archivePat.MatchString(p) {
		return InstallTarget{Skip: SkipLocal}
	}
	t := InstallTarget{Manager: manager}
	switch manager {
	case "pip":
		req, _, _ := strings.Cut(p, ";") // 환경 표식은 뗀다
		m := pipReq.FindStringSubmatch(strings.TrimSpace(req))
		if m == nil || (m[3] != "" && !strings.ContainsAny(m[3][:1], "=<>!~")) {
			return InstallTarget{Skip: SkipInvalid}
		}
		t.Name = strings.ToLower(m[1]) // [extras] 는 뗀다
		if e := pipExactPat.FindStringSubmatch(m[3]); e != nil {
			t.Version, t.Exact = e[1], true
		}
	case "npm":
		name, v := p, ""
		if i := strings.LastIndex(p, "@"); i > 0 { // 맨 앞 @ 는 스코프
			name, v = p[:i], p[i+1:]
		}
		t.Name = name
		if npmExactPat.MatchString(v) {
			t.Version, t.Exact = v, true
		}
	}
	if !namePat.MatchString(t.Name) || !verPat.MatchString(t.Version) {
		return InstallTarget{Skip: SkipInvalid}
	}
	t.Label = manager + " " + t.Name + ver(t.Version, map[string]string{"pip": "==", "npm": "@"}[manager])
	return t
}

// packageKey: 같은 검사인지 — 매니저 · 정규화 이름(pip 은 PEP 503, 차단 목록 키와 같은 규칙) · 버전
func packageKey(manager, name, version string) string {
	n := strings.ToLower(name)
	if manager == "pip" {
		n = pep503.ReplaceAllString(n, "-")
	}
	return manager + ":" + n + ":" + version
}

// FromInstall: 설치 세션의 첫 패키지를 검사한다 — 검사 id(새로 시작 · 합류 · 재사용) 또는 건너뛴 이유. 거부 세션은 둘 다 ""
// s 가 nil(Docker 클라이언트를 못 만듦)이어도 부를 수 있다 — 대상 해석 뒤 off
func (s *Service) FromInstall(ctx context.Context, x model.InstallSession) (scanID, skip string) {
	if x.Status == model.InstallRefused || x.RefusedBy != nil || len(x.Packages) == 0 {
		return "", ""
	}
	t := ParseInstallSpec(x.Manager, x.Packages[0])
	if t.Skip != "" {
		return "", t.Skip
	}
	if s == nil {
		return "", SkipOff
	}
	version := t.Version
	if !t.Exact {
		// 범위 · 미지정: 최신 버전을 먼저 알아내 같은 버전의 검사와 묶는다. 못 알아내면 버전 없이 시작(검사가 같은 이유로 실패를 남긴다)
		rctx, cancel := context.WithTimeout(ctx, 20*time.Second)
		v, _, err := packageMeta(rctx, s.registries(), t.Manager, t.Name, "")
		cancel()
		if err != nil {
			slog.Warn("install scan: latest version", "install", x.ID, "package", t.Name, "err", err)
		}
		version = v
	}
	s.autoMu.Lock()
	defer s.autoMu.Unlock()
	if id := s.reusable(t.Manager, t.Name, version); id != "" {
		return id, ""
	}
	id, err := s.start(ctx, Input{Kind: "package", Manager: t.Manager, Name: t.Name, Version: version}, startOpts{installID: x.ID, label: t.Label, auto: true})
	var se *Error
	switch {
	case err == nil:
		return id, ""
	case errors.Is(err, errBusy):
		return "", SkipBusy
	case errors.As(err, &se) && se.Status == 400:
		return "", SkipInvalid
	default: // 503(작업 폴더 · Docker) 와 그 밖의 시작 실패
		slog.Warn("install scan: start", "install", x.ID, "package", t.Name, "err", err)
		return "", SkipOff
	}
}

// reusable: 실행 중이거나 24시간 안에 끝난 같은 패키지 검사(최신순 — 가장 최근 것). failed 는 고르지 않는다
func (s *Service) reusable(manager, name, version string) string {
	key := packageKey(manager, name, version)
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, x := range s.scans {
		t := x.Target
		if t.Kind != "package" || packageKey(t.Manager, t.Name, t.Version) != key {
			continue
		}
		if x.Status == "running" || (x.Status == "done" && x.FinishedAt != nil && time.Since(*x.FinishedAt) < reuseFor) {
			return x.ID
		}
	}
	return ""
}

// Attach: review.Service.AttachScan — 세션에 검사 id 또는 건너뛴 이유를 남긴다
type Attach func(ctx context.Context, installID, scanID, skip string) error

// AutoScan: review.Options.OnInstallStart 에 붙이는 훅. 곧바로 돌아오고(세션 보고 응답 · sg-install 종료 코드에 영향 없음)
// 뒤에서 FromInstall → Attach 한다. svc 는 부를 때 읽는다(서버 조립 순서상 review 가 먼저 만들어진다) — nil 이면 off
func AutoScan(svc func() *Service, attach Attach) func(model.InstallSession) {
	return func(x model.InstallSession) {
		if x.Status == model.InstallRefused {
			return
		}
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			id, skip := svc().FromInstall(ctx, x)
			if id == "" && skip == "" {
				return
			}
			if err := attach(ctx, x.ID, id, skip); err != nil {
				slog.Warn("install scan: attach", "install", x.ID, "scan", id, "skip", skip, "err", err)
				return
			}
			slog.Info("install scan", "install", x.ID, "scan", id, "skip", skip)
		}()
	}
}

// OfSession: 설치 세션 응답의 scan(API 계약 11/04) — 읽을 때 계산한다. 옛 세션 · 검사 기록이 없으면 nil(필드 없음).
// 건너뛴 세션은 검사 서비스 없이도(s == nil) 계산한다
func (s *Service) OfSession(x model.InstallSession) *model.InstallScan {
	if x.ScanSkip != "" {
		pkg := ""
		if len(x.Packages) > 0 {
			pkg = x.Packages[0]
		}
		return &model.InstallScan{Status: "skipped", Label: x.Manager + " " + pkg, Skip: x.ScanSkip}
	}
	if x.ScanID == nil || s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, sc := range s.scans {
		if sc.ID != *x.ScanID {
			continue
		}
		out := &model.InstallScan{ID: sc.ID, Status: sc.Status, Label: sc.Target.Label, Version: sc.Target.Version,
			InstallThreats: sc.InstallThreats, Threats: sc.Threats, VulnCount: sc.VulnCount, Error: sc.Error,
			Reused: sc.InstallID == nil || *sc.InstallID != x.ID}
		if sc.Risk != nil {
			v := sc.Risk.Score
			out.RiskScore = &v
		}
		if sc.Status == "done" {
			out.Verdict = sc.Verdict
		}
		return out
	}
	return nil
}
