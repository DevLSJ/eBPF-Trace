package pipeline

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/model"
)

// Tier 1 — 라벨로 연동(11/06 사용자 결정): 감시 = 이름 패턴 OR 라벨 supplyguard.watch, 격리 = 별도 라벨(supplyguard.enforce ·
// sg-install 의 supplyguard.sandbox · 시연의 supplyguard.demo) OR 이름 패턴 EnforceScope.Names. 제외 목록은 항상 우선.

type fakeLabeler struct {
	mu     sync.Mutex
	labels map[string]map[string]string
	err    error
	calls  map[string]int
}

func (f *fakeLabeler) Labels(_ context.Context, id string) (map[string]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.calls == nil {
		f.calls = map[string]int{}
	}
	f.calls[id]++
	if f.err != nil {
		return nil, f.err
	}
	return f.labels[id], nil
}

func ev(id, name, path string) model.Event {
	return model.Event{Kind: model.KindOpen, ContainerID: id, ContainerName: name, Path: path}
}

// 감시: 이름 패턴에 맞거나 supplyguard.watch=true 라벨이면 평가한다. 라벨 값은 true · 1 · yes 만 켜짐
func TestWatchByNameOrLabel(t *testing.T) {
	lb := &fakeLabeler{labels: map[string]map[string]string{
		"id-labeled": {LabelWatch: "true"},
		"id-one":     {LabelWatch: "1"},
		"id-false":   {LabelWatch: "false"},
		"id-self":    {LabelWatch: "true"},
	}}
	p, hub := newPipe(t, Options{IgnoreContainers: []string{"supplyguard-*"}, WatchContainers: []string{"sg-install-*"}, Labels: lb}, &fakeEnforcer{})
	cases := []struct {
		id, name string
		watched  bool
	}{
		{"id-name", "sg-install-pip-1", true},       // 이름 패턴
		{"id-labeled", "shop-api", true},            // 라벨
		{"id-one", "shop-db", true},                 // 라벨 값 1
		{"id-false", "shop-cache", false},           // 라벨 값 false
		{"id-none", "minikube", false},              // 둘 다 아님
		{"id-self", "supplyguard-backend-1", false}, // 제외 목록이 라벨보다 우선
	}
	for _, c := range cases {
		before := len(hub.snapshot())
		p.Handle(context.Background(), ev(c.id, c.name, "/app/x"))
		if got := len(hub.snapshot()) > before; got != c.watched {
			t.Errorf("%s(%s) watched = %v, want %v", c.name, c.id, got, c.watched)
		}
	}
}

// 라벨은 컨테이너마다 한 번만 조회하고, 종료 이벤트 뒤에는 잊는다. 조회 실패는 이름 규칙만으로
func TestLabelLookupCachedAndForgotten(t *testing.T) {
	lb := &fakeLabeler{labels: map[string]map[string]string{"id-a": {LabelWatch: "true"}}}
	p, hub := newPipe(t, Options{WatchContainers: []string{"sg-install-*"}, Labels: lb}, &fakeEnforcer{})
	for range 3 {
		p.Handle(context.Background(), ev("id-a", "shop-api", "/app/x"))
	}
	if lb.calls["id-a"] != 1 {
		t.Fatalf("label lookups = %d, want 1 (cached)", lb.calls["id-a"])
	}
	p.Handle(context.Background(), model.Event{Kind: model.KindExit, ContainerID: "id-a", ContainerName: "shop-api"})
	p.Handle(context.Background(), ev("id-a", "shop-api", "/app/x"))
	if lb.calls["id-a"] != 2 {
		t.Fatalf("label lookups after exit = %d, want 2 (forgotten)", lb.calls["id-a"])
	}
	if n := len(hub.snapshot()); n != 4 {
		t.Fatalf("verdicts = %d, want 4", n)
	}

	bad := &fakeLabeler{err: errors.New("docker down")}
	q, qhub := newPipe(t, Options{WatchContainers: []string{"sg-install-*"}, Labels: bad}, &fakeEnforcer{})
	q.Handle(context.Background(), ev("id-b", "shop-api", "/app/x"))
	q.Handle(context.Background(), ev("id-c", "sg-install-npm-1", "/app/x"))
	if got := qhub.snapshot(); len(got) != 1 || got[0].Event.ContainerName != "sg-install-npm-1" {
		t.Fatalf("lookup error must fall back to name rules: %+v", got)
	}
}

// 격리: kill 정책이라도 격리 범위(라벨 · 이름) 밖이면 보류(DryRun) + EnforceSkip="label", kill 을 부르지 않는다
func TestEnforceScope(t *testing.T) {
	lb := &fakeLabeler{labels: map[string]map[string]string{
		"id-watch":   {LabelWatch: "true"},
		"id-enforce": {LabelWatch: "true", LabelEnforce: "true"},
		"id-sandbox": {LabelSandbox: "1"},
		"id-demo":    {LabelDemo: "install"},
	}}
	cases := []struct {
		id, name string
		kill     bool
	}{
		{"id-watch", "shop-api", false},       // 감시만 — 격리 라벨 없음
		{"id-enforce", "shop-worker", true},   // supplyguard.enforce=true
		{"id-sandbox", "my-sandbox", true},    // sg-install 이 붙이는 라벨
		{"id-demo", "demo-x", true},           // 시연 컨테이너 라벨
		{"id-name", "sg-install-pip-9", true}, // 이름 패턴 EnforceScope.Names
		{"id-none", "web-api", false},         // 전체 감시(WatchContainers 비어 있음)지만 격리 범위 밖
	}
	for _, c := range cases {
		enf := &fakeEnforcer{}
		p, hub := newPipe(t, Options{EnforceKill: true, Labels: lb, Enforce: &EnforceScope{Names: []string{"sg-install-*"}}}, enf)
		p.Handle(context.Background(), ev(c.id, c.name, "/etc/shadow"))
		vs := hub.snapshot()
		if len(vs) != 1 {
			t.Fatalf("%s: verdicts = %d", c.name, len(vs))
		}
		v := vs[0]
		if got := len(enf.calls) == 1; got != c.kill {
			t.Errorf("%s: killed = %v, want %v", c.name, got, c.kill)
		}
		if c.kill && (!v.Enforced || v.DryRun || v.EnforceSkip != "") {
			t.Errorf("%s: want enforced verdict, got %+v", c.name, v)
		}
		if !c.kill && (!v.DryRun || v.Enforced || v.EnforceSkip != EnforceSkipLabel) {
			t.Errorf("%s: want held verdict with EnforceSkip=%q, got dryRun=%v enforced=%v skip=%q", c.name, EnforceSkipLabel, v.DryRun, v.Enforced, v.EnforceSkip)
		}
	}
}

// Enforce 가 없으면(옛 설정 · 테스트) 지금처럼 감시 대상 전부 격리
func TestEnforceScopeNilKeepsOldBehavior(t *testing.T) {
	enf := &fakeEnforcer{}
	p, _ := newPipe(t, Options{EnforceKill: true}, enf)
	p.Handle(context.Background(), ev("id-x", "web-api", "/etc/shadow"))
	if len(enf.calls) != 1 {
		t.Fatalf("kill calls = %d, want 1", len(enf.calls))
	}
}

// Scope: 연동 화면(GET /api/integration)이 쓰는 같은 판정 — 감시 이유(all · name · label) · 격리 이유(label · sandbox · demo · name · all)
func TestScopeExplains(t *testing.T) {
	p := &Pipeline{opt: Options{IgnoreContainers: []string{"supplyguard-*"}, WatchContainers: []string{"sg-install-*"}, Enforce: &EnforceScope{Names: []string{"sg-install-*"}}}}
	cases := []struct {
		name   string
		labels map[string]string
		want   Scope
	}{
		{"sg-install-pip-1", nil, Scope{Watched: true, WatchBy: "name", Enforce: true, EnforceBy: "name"}},
		{"shop-api", map[string]string{LabelWatch: "true"}, Scope{Watched: true, WatchBy: "label"}},
		{"shop-worker", map[string]string{LabelWatch: "true", LabelEnforce: "true"}, Scope{Watched: true, WatchBy: "label", Enforce: true, EnforceBy: "label"}},
		{"my-box", map[string]string{LabelSandbox: "1"}, Scope{}}, // sandbox 라벨만으로는 감시 안 함(이름 패턴 밖)
		{"minikube", nil, Scope{}},
		{"supplyguard-backend-1", map[string]string{LabelWatch: "true"}, Scope{Ignored: true}},
	}
	for _, c := range cases {
		if got := p.Scope(c.name, c.labels); got != c.want {
			t.Errorf("Scope(%s) = %+v, want %+v", c.name, got, c.want)
		}
	}
	all := &Pipeline{opt: Options{}}
	if got := all.Scope("web-api", nil); got != (Scope{Watched: true, WatchBy: "all", Enforce: true, EnforceBy: "all"}) {
		t.Errorf("no watch list · no enforce scope = %+v", got)
	}
}

// 관찰 훅: 감시 대상 이벤트만 넘긴다(연결 테스트가 시험 컨테이너 이벤트를 센다)
func TestObserverSeesWatchedEventsOnly(t *testing.T) {
	lb := &fakeLabeler{labels: map[string]map[string]string{"id-p": {LabelWatch: "true"}}}
	p, _ := newPipe(t, Options{WatchContainers: []string{"sg-install-*"}, Labels: lb}, &fakeEnforcer{})
	var mu sync.Mutex
	var seen []string
	p.SetObserver(func(ev model.Event) {
		mu.Lock()
		seen = append(seen, ev.ContainerName)
		mu.Unlock()
	})
	p.Handle(context.Background(), ev("id-p", "sg-probe-1", "/etc/hostname"))
	p.Handle(context.Background(), ev("id-x", "other", "/etc/hostname"))
	if len(seen) != 1 || seen[0] != "sg-probe-1" {
		t.Fatalf("observer saw %v", seen)
	}
}
