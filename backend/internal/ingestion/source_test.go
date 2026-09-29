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
