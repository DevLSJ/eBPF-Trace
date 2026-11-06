package pipeline

import (
	"context"
	"log/slog"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/model"
)

// 감시 · 격리 범위(11/06 사용자 결정 — 라벨 한 줄로 연동)
//
//	제외   IgnoreContainers 이름 패턴 → 항상 제외(자기 스택)
//	감시   WatchContainers 가 비면 전부. 아니면 이름 패턴 OR 라벨 supplyguard.watch=true
//	격리   Enforce 가 nil 이면 감시 대상 전부(옛 동작). 아니면 라벨 supplyguard.enforce=true ·
//	       supplyguard.sandbox(sg-install) · supplyguard.demo(시연) 중 하나 OR 이름 패턴 Enforce.Names.
//	       범위 밖의 kill 은 보류(DryRun) + EnforceSkip="label"
const (
	LabelWatch   = "supplyguard.watch"
	LabelEnforce = "supplyguard.enforce"
	LabelSandbox = "supplyguard.sandbox" // tools/sg-install 이 붙인다
	LabelDemo    = "supplyguard.demo"    // 시연 컨테이너(internal/demo)가 붙인다

	EnforceSkipLabel = "label"

	labelTimeout = time.Second
)

// Labeler: 컨테이너 ID → Docker 라벨(dockerapi · mock). 실패하면 이름 규칙만 쓴다
type Labeler interface {
	Labels(ctx context.Context, containerID string) (map[string]string, error)
}

// EnforceScope: 격리 범위. Names = 라벨 없이도 격리하는 이름 패턴(기본 sg-install-*)
type EnforceScope struct {
	Names []string
}

// labelCache: 컨테이너당 한 번 조회. 종료(KindExit) 때 지운다. 조회 실패도 기억해 이벤트마다 Docker 를 부르지 않는다
type labelCache struct {
	mu sync.Mutex
	m  map[string]map[string]string
}

func (p *Pipeline) labels(ctx context.Context, id string) map[string]string {
	if p.opt.Labels == nil || id == "" {
		return nil
	}
	p.lc.mu.Lock()
	l, ok := p.lc.m[id]
	p.lc.mu.Unlock()
	if ok {
		return l
	}
	lctx, cancel := context.WithTimeout(ctx, labelTimeout)
	defer cancel()
	l, err := p.opt.Labels.Labels(lctx, id)
	if err != nil {
		slog.Debug("container labels unavailable — name rules only", "id", id, "err", err)
		l = nil
	}
	if l == nil {
		l = map[string]string{}
	}
	p.lc.mu.Lock()
	if p.lc.m == nil {
		p.lc.m = map[string]map[string]string{}
	}
	p.lc.m[id] = l
	p.lc.mu.Unlock()
	return l
}

func (p *Pipeline) forgetLabels(id string) {
	p.lc.mu.Lock()
	delete(p.lc.m, id)
	p.lc.mu.Unlock()
}

func truthy(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "true", "1", "yes":
		return true
	}
	return false
}

func matchAny(globs []string, name string) bool {
	for _, g := range globs {
		if ok, _ := path.Match(g, name); ok {
			return true
		}
	}
	return false
}

// Scope: 한 컨테이너의 감시 · 격리 판정과 그 이유(연동 화면 GET /api/integration 과 파이프라인이 같은 규칙을 쓴다)
type Scope struct {
	Ignored   bool   `json:"ignored"`             // 제외 목록(자기 스택)
	Watched   bool   `json:"watched"`             // 평가 대상
	WatchBy   string `json:"watchBy,omitempty"`   // all(관찰 목록 없음) · name · label
	Enforce   bool   `json:"enforce"`             // kill 정책이면 실제로 격리
	EnforceBy string `json:"enforceBy,omitempty"` // all(Enforce 없음) · name · label · sandbox · demo
}

// Scope: 제외 → 감시(전체 · 이름 · 라벨) → 격리(전체 · 이름 · 라벨 · sandbox · demo) 순서. 감시가 아니면 격리도 아니다
func (p *Pipeline) Scope(name string, labels map[string]string) Scope {
	if matchAny(p.opt.IgnoreContainers, name) {
		return Scope{Ignored: true}
	}
	var s Scope
	switch {
	case len(p.opt.WatchContainers) == 0:
		s.Watched, s.WatchBy = true, "all"
	case matchAny(p.opt.WatchContainers, name):
		s.Watched, s.WatchBy = true, "name"
	case truthy(labels[LabelWatch]):
		s.Watched, s.WatchBy = true, "label"
	default:
		return s
	}
	switch {
	case p.opt.Enforce == nil:
		s.Enforce, s.EnforceBy = true, "all"
	case matchAny(p.opt.Enforce.Names, name):
		s.Enforce, s.EnforceBy = true, "name"
	case truthy(labels[LabelEnforce]):
		s.Enforce, s.EnforceBy = true, "label"
	case labels[LabelSandbox] != "":
		s.Enforce, s.EnforceBy = true, "sandbox"
	case labels[LabelDemo] != "":
		s.Enforce, s.EnforceBy = true, "demo"
	}
	return s
}

// scopeOf: 이벤트의 컨테이너 판정. 이름만으로 정해지면 라벨을 조회하지 않는다
func (p *Pipeline) scopeOf(ctx context.Context, ev model.Event) Scope {
	byName := p.Scope(ev.ContainerName, nil)
	if byName.Ignored || (byName.Watched && byName.Enforce) {
		return byName
	}
	return p.Scope(ev.ContainerName, p.labels(ctx, ev.ContainerID))
}

func (p *Pipeline) watched(ctx context.Context, ev model.Event) bool {
	return p.scopeOf(ctx, ev).Watched
}

func (p *Pipeline) enforceAllowed(ctx context.Context, ev model.Event) bool {
	return p.scopeOf(ctx, ev).Enforce
}

// SetObserver: 감시 대상 이벤트를 하나씩 넘긴다(연동 연결 테스트가 시험 컨테이너 이벤트를 센다). 잠금 밖에서 부르므로 빨리 돌아와야 한다
func (p *Pipeline) SetObserver(fn func(model.Event)) { p.observer = fn }
