package pipeline

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/model"
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/rules"
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/stats"
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/store"
)

type fakeEnforcer struct {
	mu    sync.Mutex
	calls []string
	err   error
}

func (f *fakeEnforcer) Kill(_ context.Context, id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, id)
	return f.err
}

type fakeHub struct {
	mu   sync.Mutex
	msgs []model.Verdict
}

func (h *fakeHub) Broadcast(t string, d any) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if v, ok := d.(model.Verdict); ok && t == "verdict" {
		h.msgs = append(h.msgs, v)
	}
}

func newPipe(t *testing.T, opt Options, enf *fakeEnforcer) (*Pipeline, *fakeHub) {
	t.Helper()
	engine := rules.New([]rules.Rule{
		{ID: "shadow", Kind: model.KindOpen, Action: model.ActionKill, DenyPaths: []string{"/etc/shadow"}},
		{ID: "shadow-dry", Kind: model.KindOpen, Action: model.ActionKill, DryRun: true, DenyPaths: []string{"/etc/gshadow"}},
	})
	hub := &fakeHub{}
	mem := store.NewMemory()
	if opt.NormalEventRate == 0 {
		opt.NormalEventRate = 100
	}
	return New(opt, engine, enf, hub, stats.New(), mem, mem), hub
}

const cid = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func openEv(path string) model.Event {
	return model.Event{Kind: model.KindOpen, ContainerID: cid, ContainerName: "victim", Path: path}
}

func TestKillEnforced(t *testing.T) {
	enf := &fakeEnforcer{}
	p, hub := newPipe(t, Options{EnforceKill: true}, enf)
	p.Handle(context.Background(), openEv("/etc/shadow"))
	p.Handle(context.Background(), openEv("/etc/shadow")) // 잔여 이벤트: 다시 kill하지 않음
	if len(enf.calls) != 1 {
		t.Fatalf("kill calls = %d, want 1", len(enf.calls))
	}
	if !hub.msgs[0].Enforced || !hub.msgs[1].Enforced {
		t.Fatalf("verdicts must be marked enforced: %+v", hub.msgs)
	}
	if got := p.stats.Snapshot().KilledCount; got != 1 {
		t.Fatalf("killed count = %d", got)
	}
}

func TestGlobalDryRun(t *testing.T) {
	enf := &fakeEnforcer{}
	p, hub := newPipe(t, Options{EnforceKill: false}, enf)
	p.Handle(context.Background(), openEv("/etc/shadow"))
	if len(enf.calls) != 0 {
		t.Fatal("ENFORCE_KILL=false must not kill")
	}
	if v := hub.msgs[0]; !v.Matched || !v.DryRun || v.Enforced {
		t.Fatalf("want dry-run verdict, got %+v", v)
	}
}

func TestRuleDryRun(t *testing.T) {
	enf := &fakeEnforcer{}
	p, hub := newPipe(t, Options{EnforceKill: true}, enf)
	p.Handle(context.Background(), openEv("/etc/gshadow"))
	if len(enf.calls) != 0 || !hub.msgs[0].DryRun {
		t.Fatalf("rule dry-run must not kill: calls=%v verdict=%+v", enf.calls, hub.msgs[0])
	}
}

func TestKillFailureReported(t *testing.T) {
	enf := &fakeEnforcer{err: errors.New("socket unavailable")}
	p, hub := newPipe(t, Options{EnforceKill: true}, enf)
	p.Handle(context.Background(), openEv("/etc/shadow"))
	if v := hub.msgs[0]; v.Enforced || v.EnforceError == "" {
		t.Fatalf("want enforce error, got %+v", v)
	}
}

func TestIgnoredAndHostEvents(t *testing.T) {
	enf := &fakeEnforcer{}
	p, hub := newPipe(t, Options{EnforceKill: true, IgnoreContainers: []string{"supplyguard-*"}}, enf)
	ev := openEv("/etc/shadow")
	ev.ContainerName = "supplyguard-backend-1"
	p.Handle(context.Background(), ev)
	host := openEv("/etc/shadow")
	host.ContainerID = ""
	p.Handle(context.Background(), host)
	if len(enf.calls) != 0 || len(hub.msgs) != 0 {
		t.Fatal("own stack and host processes must be skipped")
	}
}

func TestNormalSampling(t *testing.T) {
	p, hub := newPipe(t, Options{NormalEventRate: 3}, &fakeEnforcer{})
	now := time.Now()
	for range 10 {
		ev := openEv("/etc/hosts")
		ev.Timestamp = now
		p.Handle(context.Background(), ev)
	}
	ev := openEv("/etc/shadow")
	ev.Timestamp = now
	p.Handle(context.Background(), ev)
	if len(hub.msgs) != 4 {
		t.Fatalf("want 3 sampled normal + 1 violation, got %d", len(hub.msgs))
	}
	if s := p.stats.Snapshot(); s.TotalEvents != 11 {
		t.Fatalf("stats must count every event, got %d", s.TotalEvents)
	}
}

func TestWatchContainersScopesEvaluation(t *testing.T) {
	p := &Pipeline{opt: Options{IgnoreContainers: []string{"supplyguard-*"}, WatchContainers: []string{"sg-install-*", "victim"}}}
	cases := map[string]bool{
		"sg-install-pip-1":      false, // 관찰 대상
		"victim":                false,
		"minikube":              true, // 목록 밖 → 무시
		"web-api":               true,
		"supplyguard-backend-1": true, // 제외 목록은 항상 우선
	}
	for name, ignored := range cases {
		if got := p.Ignored(name); got != ignored {
			t.Errorf("Ignored(%q) = %v, want %v", name, got, ignored)
		}
	}
	all := &Pipeline{opt: Options{IgnoreContainers: []string{"supplyguard-*"}}}
	if all.Ignored("minikube") {
		t.Error("empty WatchContainers must observe every container")
	}
}
