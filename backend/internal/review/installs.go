package review

import (
	"context"
	"slices"
	"strings"
	"time"

	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/model"
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/store"
)

// StartInput: POST /api/installs
type StartInput struct {
	Manager   string   `json:"manager"`
	Packages  []string `json:"packages"`
	Container string   `json:"container"`
	Image     string   `json:"image"`
}

// RefusedInput: POST /api/installs/refused
type RefusedInput struct {
	Manager  string   `json:"manager"`
	Packages []string `json:"packages"`
	Value    string   `json:"value"`
}

const maxPackages = 50

func validPackages(ps []string) error {
	if len(ps) == 0 || len(ps) > maxPackages {
		return invalid("packages: 1~%d개", maxPackages)
	}
	for _, p := range ps {
		if strings.TrimSpace(p) == "" || len(p) > 512 {
			return invalid("packages: 빈 값 또는 너무 긴 값")
		}
	}
	return nil
}

func newSession(id, manager string, packages []string, now time.Time) model.InstallSession {
	return model.InstallSession{
		ID: id, Manager: manager, Packages: slices.Clone(packages), StartedAt: now, Status: model.InstallRunning,
		Violations: []model.ViolationCount{},
		Activity: model.Activity{Kinds: map[model.Kind]int{model.KindExec: 0, model.KindOpen: 0, model.KindConnect: 0},
			Hosts: []model.HostActivity{}, Programs: []model.ProgramActivity{}},
	}
}

// StartInstall: CLI 가 컨테이너를 띄우기 직전에 보고한다.
func (s *Service) StartInstall(ctx context.Context, in StartInput) (model.InstallSession, error) {
	if !model.ValidManager(in.Manager) {
		return model.InstallSession{}, invalid("manager: pip | npm | cargo")
	}
	if err := validPackages(in.Packages); err != nil {
		return model.InstallSession{}, err
	}
	if !strings.HasPrefix(in.Container, SandboxPrefix) || len(in.Container) > 128 {
		return model.InstallSession{}, invalid("container: %s* 이름이어야 함", SandboxPrefix)
	}
	unlock := s.lockWrite()
	if _, dup := s.byContainer[in.Container]; dup {
		unlock()
		return model.InstallSession{}, conflict("이미 보고된 컨테이너: %s", in.Container)
	}
	x := newSession(s.nextID("ins"), in.Manager, in.Packages, s.o.Now())
	x.Container, x.Image = in.Container, in.Image
	if err := s.commitLocked(ctx, store.ReviewCommit{Installs: []model.InstallSession{x}}); err != nil {
		s.releaseID("ins")
		unlock()
		return model.InstallSession{}, err
	}
	s.putInstall(&x)
	out := s.view(&x)
	unlock()
	if s.o.OnInstallStart != nil {
		s.o.OnInstallStart(out)
	}
	return out, nil
}

// FinishInstall: CLI 가 컨테이너 종료 코드를 보고한다.
func (s *Service) FinishInstall(ctx context.Context, id string, exitCode int) (model.InstallSession, error) {
	unlock := s.lockWrite()
	defer unlock()
	cur, ok := s.installs[id]
	if !ok {
		return model.InstallSession{}, notFound("세션 없음")
	}
	if cur.Status == model.InstallRefused || cur.FinishedAt != nil {
		return model.InstallSession{}, conflict("이미 끝난 세션")
	}
	x := cur.Clone()
	now := s.o.Now()
	x.FinishedAt, x.ExitCode = &now, &exitCode
	x.Status = s.storedStatus(&x)
	if err := s.commitLocked(ctx, store.ReviewCommit{Installs: []model.InstallSession{x}}); err != nil {
		return model.InstallSession{}, err
	}
	s.putInstall(&x)
	return s.view(&x), nil
}

// RefusedInstall: 차단 목록 때문에 컨테이너 없이 거부된 설치 한 건을 남긴다.
func (s *Service) RefusedInstall(ctx context.Context, in RefusedInput) (model.InstallSession, error) {
	if !model.ValidManager(in.Manager) {
		return model.InstallSession{}, invalid("manager: pip | npm | cargo")
	}
	if err := validPackages(in.Packages); err != nil {
		return model.InstallSession{}, err
	}
	if strings.TrimSpace(in.Value) == "" || len(in.Value) > 512 {
		return model.InstallSession{}, invalid("value: 차단 목록 값이 필요함")
	}
	unlock := s.lockWrite()
	defer unlock()
	now := s.o.Now()
	x := newSession(s.nextID("ins"), in.Manager, in.Packages, now)
	x.Status, x.FinishedAt = model.InstallRefused, &now
	x.RefusedBy = &model.BlockRef{List: model.ListPackages, Value: in.Value}
	if err := s.commitLocked(ctx, store.ReviewCommit{Installs: []model.InstallSession{x}}); err != nil {
		s.releaseID("ins")
		return model.InstallSession{}, err
	}
	s.putInstall(&x)
	return s.view(&x), nil
}

// storedStatus: 저장해 두는 결과. unknown 은 읽을 때 시각으로 계산한다(view).
// 격리(격리된 위반) > 경고(그 밖의 위반) > 끝 보고(통과 · 설치 실패) > 진행 중
func (s *Service) storedStatus(x *model.InstallSession) model.InstallStatus {
	if x.Status == model.InstallRefused {
		return model.InstallRefused
	}
	for _, v := range x.Violations {
		if model.LevelOf(v.Verdict) == model.LevelKilled {
			return model.InstallIsolated
		}
	}
	if len(x.Violations) > 0 {
		return model.InstallWarned
	}
	if x.FinishedAt != nil {
		if x.ExitCode != nil && *x.ExitCode == 0 {
			return model.InstallPassed
		}
		return model.InstallFailed
	}
	return model.InstallRunning
}

// view: 응답용 사본 — 컨테이너가 끝나고 10분이 지나도 finish 가 없으면 unknown
func (s *Service) view(x *model.InstallSession) model.InstallSession {
	c := x.Clone()
	c.Status = s.storedStatus(x)
	c.ViolationCount = 0
	for _, v := range c.Violations {
		c.ViolationCount += v.Count
	}
	if c.Status == model.InstallRunning && c.ContainerExitedAt != nil && s.o.Now().Sub(*c.ContainerExitedAt) > UnknownAfter {
		c.Status = model.InstallUnknown
	}
	return c
}

type InstallQuery struct {
	Status  model.InstallStatus
	Manager string
	Limit   int
}

// ListInstalls: 최신순, 기본 50 · 상한 500
func (s *Service) ListInstalls(q InstallQuery) []model.InstallSession {
	if q.Limit <= 0 {
		q.Limit = 50
	}
	q.Limit = min(q.Limit, 500)
	s.mu.Lock()
	defer s.mu.Unlock()
	out := []model.InstallSession{}
	for i := len(s.installIDs) - 1; i >= 0 && len(out) < q.Limit; i-- {
		x := s.installs[s.installIDs[i]]
		if q.Manager != "" && x.Manager != q.Manager {
			continue
		}
		v := s.view(x)
		if q.Status != "" && v.Status != q.Status {
			continue
		}
		out = append(out, v)
	}
	return out
}

func (s *Service) GetInstall(id string) (model.InstallSession, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	x, ok := s.installs[id]
	if !ok {
		return model.InstallSession{}, notFound("세션 없음")
	}
	return s.view(x), nil
}

// ── 파이프라인에서 오는 것 ──────────────────────────────

// Observe: 평가 · 격리가 끝난 판정마다 부른다(정상 포함).
//   - 설치 샌드박스(sg-install-*): 그 세션의 활동 요약 · 위반을 모으고, 처음 위반이 나오면 건을 연다
//   - 런타임: 격리됨 · 격리 대상이면 같은 컨테이너의 열린 건에 더하거나 새 건을 연다(경고만으로는 열지 않음)
//
// v.CaseID · v.Install 을 채운다 — 감사 로그 행 · WebSocket 판정에 그대로 실린다.
func (s *Service) Observe(v *model.Verdict) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if v.Matched && v.RuleID == model.RuleBlockedImage {
		s.observeBlockedImage(v)
		return
	}
	if strings.HasPrefix(v.Event.ContainerName, SandboxPrefix) {
		s.observeInstall(v)
		return
	}
	s.observeRuntime(v)
}

func (s *Service) observeInstall(v *model.Verdict) {
	id, ok := s.byContainer[v.Event.ContainerName]
	if !ok {
		return // 보고되지 않은 샌드박스 컨테이너 (CLI 보고 실패 등)
	}
	x := s.installs[id]
	if x.ContainerID == "" {
		x.ContainerID = v.Event.ContainerID
	}
	if x.Image == "" {
		x.Image = v.Event.ImageName
	}
	v.Install = &model.InstallRef{ID: x.ID, Label: x.Label()}
	addActivity(&x.Activity, *v)
	s.dirtyInstalls[id] = true
	if !v.Matched {
		return
	}
	x.Violations = addViolation(x.Violations, *v, maxViolations)
	x.Status = s.storedStatus(x)

	var c *model.CaseRecord
	if x.CaseID != nil {
		c = s.cases[*x.CaseID]
		if c.Case.State == model.CaseClosed {
			c = nil // 이미 종결된 건은 다시 열지 않는다
		}
	} else {
		pkg := ""
		if len(x.Packages) > 0 {
			pkg, _ = NormalizePackage(x.Manager, x.Packages[0])
		}
		c = &model.CaseRecord{Case: model.Case{
			ID: s.nextID("case"), Source: model.CaseInstall, InstallID: ptr(x.ID),
			Container: x.Container, Label: x.Label(), Image: x.Image, Package: pkg, OpenedAt: s.o.Now(),
			RuleIDs: []string{}, State: model.CaseOpen, Decision: model.DecisionPending,
		}, Evidence: []model.ViolationCount{}}
		s.putCase(c)
		x.CaseID = ptr(c.Case.ID)
	}
	if c != nil {
		addToCase(c, *v)
		v.CaseID = ptr(c.Case.ID)
		s.dirtyCases[c.Case.ID] = true
		s.broadcastCase(c)
	}
}

// observeBlockedImage: 이미 악성으로 판정해 막은 이미지가 다시 뜬 것 — 새 건을 열지 않고(결정 2026-10-15)
// 그 차단을 만든 건의 id 를 판정 · 감사 로그 행에 붙인다.
func (s *Service) observeBlockedImage(v *model.Verdict) {
	for _, b := range s.blocklist {
		if b.List == model.ListImages && b.Value == v.Event.ImageName {
			if b.CaseID != nil {
				v.CaseID = ptr(*b.CaseID)
			}
			return
		}
	}
}

// observeRuntime: 격리됨 · 격리 대상은 열린 건에 더하거나 새 건을 연다.
// 경고는 같은 컨테이너의 열린(open · decided) 건이 있을 때만 그 건에 더한다(결정 2026-10-15) — 경고만으로 새 건은 열지 않는다.
func (s *Service) observeRuntime(v *model.Verdict) {
	if !v.Matched {
		return
	}
	lvl := model.LevelOf(*v)
	var c *model.CaseRecord
	for i := len(s.caseIDs) - 1; i >= 0; i-- {
		x := s.cases[s.caseIDs[i]]
		if x.Case.Source == model.CaseRuntime && x.Case.Container == v.Event.ContainerName && x.Case.State != model.CaseClosed {
			c = x
			break
		}
	}
	if c == nil && lvl != model.LevelKilled && lvl != model.LevelHeld {
		return
	}
	if c == nil {
		c = &model.CaseRecord{Case: model.Case{
			ID: s.nextID("case"), Source: model.CaseRuntime,
			Container: v.Event.ContainerName, Label: v.Event.ContainerName, Image: v.Event.ImageName, OpenedAt: s.o.Now(),
			RuleIDs: []string{}, State: model.CaseOpen, Decision: model.DecisionPending,
		}, Evidence: []model.ViolationCount{}}
		s.putCase(c)
	}
	addToCase(c, *v)
	v.CaseID = ptr(c.Case.ID)
	s.dirtyCases[c.Case.ID] = true
	s.broadcastCase(c)
}

func addToCase(c *model.CaseRecord, v model.Verdict) {
	c.Case.Violations++
	if l := model.LevelOf(v); l.Rank() > c.Case.Level.Rank() {
		c.Case.Level = l
	}
	if v.RuleID != "" && !slices.Contains(c.Case.RuleIDs, v.RuleID) {
		c.Case.RuleIDs = append(c.Case.RuleIDs, v.RuleID)
	}
	c.Evidence = addViolation(c.Evidence, v, maxEvidence)
}

// addViolation: 같은 규칙 · 종류 · 상세는 count 만 올린다. 더 센 판정이 오면 그 판정으로 바꾼다.
func addViolation(xs []model.ViolationCount, v model.Verdict, limit int) []model.ViolationCount {
	v.CaseID, v.Install = nil, nil
	for i := range xs {
		x := &xs[i]
		if x.RuleID == v.RuleID && x.Event.Kind == v.Event.Kind && x.Event.Detail() == v.Event.Detail() {
			x.Count++
			if model.LevelOf(v).Rank() > model.LevelOf(x.Verdict).Rank() {
				x.Verdict = v
			}
			return xs
		}
	}
	if len(xs) >= limit {
		return xs
	}
	return append(xs, model.ViolationCount{Verdict: v, Count: 1})
}

func addActivity(a *model.Activity, v model.Verdict) {
	e := v.Event
	if !e.Kind.Valid() {
		return
	}
	if a.Kinds == nil {
		a.Kinds = map[model.Kind]int{}
	}
	a.Kinds[e.Kind]++
	lvl := model.LevelOf(v)
	switch e.Kind {
	case model.KindConnect:
		for i := range a.Hosts {
			h := &a.Hosts[i]
			if h.Host == e.DstHost && h.IP == e.DstIP && h.Port == e.DstPort {
				h.Count++
				if lvl.Rank() > h.Level.Rank() {
					h.Level = lvl
				}
				return
			}
		}
		if len(a.Hosts) < maxActivityRows {
			a.Hosts = append(a.Hosts, model.HostActivity{Host: e.DstHost, IP: e.DstIP, Port: e.DstPort, Count: 1, Level: lvl})
		}
	case model.KindExec:
		args := e.Args
		if args == "" {
			args = e.Comm
		}
		for i := range a.Programs {
			p := &a.Programs[i]
			if p.Args == args {
				p.Count++
				if lvl.Rank() > p.Level.Rank() {
					p.Level = lvl
				}
				return
			}
		}
		if len(a.Programs) < maxActivityRows {
			a.Programs = append(a.Programs, model.ProgramActivity{Comm: e.Comm, Args: args, Count: 1, Level: lvl})
		}
	}
}

// ContainerStarted: docker-events start. 설치 세션이면 컨테이너 id · 이미지를 채우고,
// 이미지가 차단 목록에 있으면 그 값을 돌려준다(파이프라인이 blocked-image 로 격리한다).
func (s *Service) ContainerStarted(ev model.Event) (blockedImage string, blocked bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if id, ok := s.byContainer[ev.ContainerName]; ok {
		x := s.installs[id]
		if x.ContainerID == "" {
			x.ContainerID = ev.ContainerID
		}
		if x.Image == "" {
			x.Image = ev.ImageName
		}
		s.dirtyInstalls[id] = true
	}
	if ev.ImageName == "" {
		return "", false
	}
	for _, b := range s.blocklist {
		if b.List == model.ListImages && b.Value == ev.ImageName {
			return b.Value, true
		}
	}
	return "", false
}

// ContainerExited: docker-events die. 설치 세션의 containerExitedAt (결과 미확인 계산용)
func (s *Service) ContainerExited(ev model.Event) {
	s.mu.Lock()
	defer s.mu.Unlock()
	id, ok := s.byContainer[ev.ContainerName]
	if !ok {
		return
	}
	x := s.installs[id]
	if x.ContainerExitedAt == nil {
		t := ev.Timestamp
		if t.IsZero() {
			t = s.o.Now()
		}
		x.ContainerExitedAt = &t
		s.dirtyInstalls[id] = true
	}
}
