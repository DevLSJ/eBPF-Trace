package pipeline

import (
	"context"
	"strings"
	"testing"

	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/model"
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/rules"
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/stats"
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/store"
)

func newDNSPipe(t *testing.T) (*Pipeline, *fakeHub, *fakeEnforcer) {
	t.Helper()
	engine := rules.New([]rules.Rule{
		{ID: "block-c2-dns", Kind: model.KindDNS, Action: model.ActionKill, DenyHosts: []string{"evil.test"}},
		{ID: "sandbox-egress", Kind: model.KindConnect, Action: model.ActionKill, DirectIP: "kill", AllowHosts: []string{"pypi.org"}},
	})
	hub, enf, mem := &fakeHub{}, &fakeEnforcer{}, store.NewMemory()
	return New(Options{EnforceKill: true, NormalEventRate: 100, IgnoreContainers: []string{"supplyguard-*"}}, engine, enf, hub, stats.New(), mem, mem), hub, enf
}

func dnsQuery(name, qtype string) model.Event {
	return model.Event{Kind: model.KindDNS, ContainerID: cid, ContainerName: "web-api", Comm: "python3", DstHost: name, Qtype: qtype, DstIP: "127.0.0.11", DstPort: 53}
}

// DNS 질의(10/30)는 정책 평가 대상: 위반이면 격리 · 피드 · 통계에 실리고, 정상 질의도 피드에 흐른다
func TestDNSQueryEvaluated(t *testing.T) {
	p, hub, enf := newDNSPipe(t)
	ctx := context.Background()
	p.Handle(ctx, dnsQuery("c2.evil.test", "A"))
	if len(enf.calls) != 1 || enf.calls[0] != cid {
		t.Fatalf("dns kill must enforce once, calls=%v", enf.calls)
	}
	got := hub.snapshot()
	if len(got) != 1 || !got[0].Matched || got[0].RuleID != "block-c2-dns" || !got[0].Enforced || got[0].Reason != "금지 도메인 질의: c2.evil.test (A)" {
		t.Fatalf("verdict: %+v", got)
	}
	if got[0].Event.Detail() != "c2.evil.test (A)" || got[0].Event.Qtype != "A" {
		t.Fatalf("event detail: %+v", got[0].Event)
	}
	p.Handle(ctx, dnsQuery("pypi.org", "AAAA"))
	if got := hub.snapshot(); len(got) != 2 || got[1].Matched {
		t.Fatalf("normal dns query must flow as a normal verdict: %+v", got)
	}
	if s := p.stats.Snapshot(); s.TotalEvents != 2 || s.TotalViolations != 1 {
		t.Fatalf("stats must count dns queries: %+v", s)
	}
	// 제외 컨테이너의 질의는 평가하지 않는다
	ig := dnsQuery("c2.evil.test", "A")
	ig.ContainerName = "supplyguard-backend-1"
	p.Handle(ctx, ig)
	if len(enf.calls) != 1 || len(hub.snapshot()) != 2 {
		t.Fatal("ignored container's dns query must be skipped")
	}
}

// DNS 응답(DNSName 이 있음)은 지금처럼 리졸버 학습만 — 평가 · 피드 · 격리 없음. 제외 컨테이너의 응답도 배운다
func TestDNSResponseOnlyLearns(t *testing.T) {
	p, hub, enf := newDNSPipe(t)
	ctx := context.Background()
	resp := model.Event{Kind: model.KindDNS, ContainerID: cid, ContainerName: "web-api", DNSName: "files.pypi.org.", DNSAddrs: []string{"151.101.0.223"}, DstHost: "files.pypi.org", Qtype: "A"}
	p.Handle(ctx, resp)
	if len(hub.snapshot()) != 0 || len(enf.calls) != 0 {
		t.Fatalf("dns response must not be evaluated: verdicts=%d kills=%d", len(hub.snapshot()), len(enf.calls))
	}
	c := model.Event{Kind: model.KindConnect, ContainerID: cid, ContainerName: "web-api", DstIP: "151.101.0.223", DstPort: 443, DNSTraced: true}
	p.Handle(ctx, c)
	got := hub.snapshot()
	if len(got) != 1 || got[0].Matched || got[0].Event.DstHost != "files.pypi.org" {
		t.Fatalf("connect must get the learned host and pass: %+v", got)
	}
	other := model.Event{Kind: model.KindDNS, ContainerID: cid, ContainerName: "supplyguard-backend-1", DNSName: "evil.test", DNSAddrs: []string{"203.0.113.7"}}
	p.Handle(ctx, other)
	if len(hub.snapshot()) != 1 || p.resolver.Lookup(cid, "203.0.113.7") != "evil.test" {
		t.Fatal("responses from ignored containers must still teach the resolver without a verdict")
	}
	// 이름 없는 dns 이벤트(질의도 응답도 아님)는 버린다
	p.Handle(ctx, model.Event{Kind: model.KindDNS, ContainerID: cid, ContainerName: "web-api"})
	if len(hub.snapshot()) != 1 {
		t.Fatal("dns event without a name must be dropped")
	}
	if strings.Contains(string(mustJSON(t, got[0])), "DNSName") {
		t.Fatal("internal DNS fields must not leak")
	}
}

// WATCH_CONTAINERS=sg-install-* 는 시연 컨테이너 sg-install-demo-<unix> 도 포함한다(10/30)
func TestWatchGlobMatchesDemo(t *testing.T) {
	p := &Pipeline{opt: Options{IgnoreContainers: []string{"supplyguard-*"}, WatchContainers: []string{"sg-install-*"}}}
	if p.Ignored("sg-install-demo-1761800000") {
		t.Fatal("demo container must be observed under sg-install-*")
	}
	if !p.Ignored("sg-demo-1761800000") {
		t.Fatal("names outside the glob stay ignored")
	}
}
