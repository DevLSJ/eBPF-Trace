package pipeline

import (
	"context"
	"errors"
	"strings"
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

func (h *fakeHub) snapshot() []model.Verdict {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]model.Verdict(nil), h.msgs...)
}

func waitVerdicts(t *testing.T, hub *fakeHub, n int) []model.Verdict {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if got := hub.snapshot(); len(got) >= n {
			return got
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %d verdicts, have %d", n, len(hub.snapshot()))
	return nil
}

func newDirectIPPipe(t *testing.T, grace time.Duration) (*Pipeline, *fakeHub) {
	t.Helper()
	engine := rules.New([]rules.Rule{{ID: "sandbox-egress", Kind: model.KindConnect, Action: model.ActionKill,
		DirectIP: "kill", AllowHosts: []string{"pypi.org"}, AllowCIDRs: []string{"10.0.0.0/8"}}})
	hub := &fakeHub{}
	mem := store.NewMemory()
	return New(Options{EnforceKill: true, NormalEventRate: 100, DNSGrace: grace}, engine, &fakeEnforcer{}, hub, stats.New(), mem, mem), hub
}

func connectEv() model.Event {
	return model.Event{Kind: model.KindConnect, ContainerID: cid, ContainerName: "sg-install-pip-1",
		DstIP: "151.101.0.223", DstPort: 443, DNSTraced: true}
}

// DNS 경쟁: connect 가 DNS 응답보다 먼저 와도 grace 뒤 리졸버를 다시 보고 도메인이 붙으면 통과한다.
func TestDNSGraceRelookup(t *testing.T) {
	p, hub := newDirectIPPipe(t, 30*time.Millisecond)
	ctx := context.Background()
	p.Handle(ctx, connectEv())
	if n := len(hub.snapshot()); n != 0 {
		t.Fatalf("direct-ip candidate must be deferred, got %d verdicts", n)
	}
	p.Handle(ctx, model.Event{Kind: model.KindDNS, ContainerID: cid, DNSName: "files.pypi.org.", DNSAddrs: []string{"151.101.0.223"}})
	got := waitVerdicts(t, hub, 1)
	if v := got[0]; v.Matched || v.Event.DstHost != "files.pypi.org" {
		t.Fatalf("late DNS answer must attach the host and pass, got %+v", v)
	}
}

func TestDNSGraceStillDirectWithoutAnswer(t *testing.T) {
	p, hub := newDirectIPPipe(t, 20*time.Millisecond)
	p.Handle(context.Background(), connectEv())
	got := waitVerdicts(t, hub, 1)
	if v := got[0]; !v.Matched || v.Action != model.ActionKill || !strings.Contains(v.Reason, "도메인 조회 없는 IP 직접 연결") || !v.Enforced {
		t.Fatalf("no DNS answer after grace must be a direct-ip kill, got %+v", v)
	}
}

func TestDNSGraceZeroIsImmediate(t *testing.T) {
	p, hub := newDirectIPPipe(t, 0)
	p.Handle(context.Background(), connectEv())
	if got := hub.snapshot(); len(got) != 1 || !got[0].Matched {
		t.Fatalf("grace 0 must evaluate inline, got %+v", got)
	}
	// 도메인을 이미 아는 연결과 사설 주소는 지연 없이 평가한다
	ev := connectEv()
	ev.DstHost = "pypi.org"
	p.Handle(context.Background(), ev)
	priv := connectEv()
	priv.DstIP = "10.0.0.5"
	p.Handle(context.Background(), priv)
	if got := hub.snapshot(); len(got) != 3 || got[1].Matched || got[2].Matched {
		t.Fatalf("got %+v", got)
	}
}

// Run 이 끝난 뒤 늦게 도는 grace 타이머는 닫힌 저장 큐에 쓰지 않는다
func TestDNSGraceAfterRunStops(t *testing.T) {
	p, hub := newDirectIPPipe(t, 20*time.Millisecond)
	events := make(chan model.Event, 1)
	events <- connectEv()
	close(events)
	p.Run(context.Background(), events) // 채널이 닫혀 바로 돌아온다 — 타이머는 아직 남아 있다
	time.Sleep(60 * time.Millisecond)
	if n := len(hub.snapshot()); n != 0 {
		t.Fatalf("late timer after shutdown must be dropped, got %d verdicts", n)
	}
}
