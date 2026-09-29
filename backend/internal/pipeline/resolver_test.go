package pipeline

import (
	"testing"
	"time"

	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/model"
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/rules"
)

func TestResolverAttachesHostToConnect(t *testing.T) {
	r := NewResolver(time.Minute)
	now := time.Now()
	r.Learn("c1", "files.pythonhosted.org.", []string{"151.101.0.223", " 151.101.64.223"}, now)
	if got := r.Lookup("c1", "151.101.64.223"); got != "files.pythonhosted.org" {
		t.Fatalf("container lookup: %q", got)
	}
	if got := r.Lookup("other", "151.101.0.223"); got != "files.pythonhosted.org" {
		t.Fatalf("global fallback: %q", got)
	}
	if got := r.Lookup("c1", "203.0.113.7"); got != "" {
		t.Fatalf("unknown ip must be empty, got %q", got)
	}
	r.Learn("c1", "old.example", []string{"198.51.100.9"}, now.Add(-2*time.Minute))
	if got := r.Lookup("c1", "198.51.100.9"); got != "" {
		t.Fatalf("expired entry must be ignored, got %q", got)
	}

	// 파이프라인: dns 이벤트는 평가·전송 없이 캐시만, 다음 connect 에 DstHost 가 붙어 allowHosts 가 통과한다
	engine := rules.New([]rules.Rule{{ID: "egress", Kind: model.KindConnect, Action: model.ActionKill, AllowHosts: []string{"pythonhosted.org"}}})
	p, hub := newPipe(t, Options{EnforceKill: true}, nil)
	p.engine = engine
	p.Handle(t.Context(), model.Event{Kind: model.KindDNS, ContainerID: "c1", ContainerName: "sg-install-pip-1", DNSName: "files.pythonhosted.org", DNSAddrs: []string{"151.101.0.223"}})
	if n := len(hub.msgs); n != 0 {
		t.Fatalf("dns event must not be broadcast, got %d messages", n)
	}
	p.Handle(t.Context(), model.Event{Kind: model.KindConnect, ContainerID: "c1", ContainerName: "sg-install-pip-1", Comm: "pip", DstIP: "151.101.0.223", DstPort: 443})
	msgs := hub.msgs
	if len(msgs) != 1 || msgs[0].Matched || msgs[0].Event.DstHost != "files.pythonhosted.org" {
		t.Fatalf("connect must carry resolved host and pass allowHosts, got %+v", msgs)
	}
}
