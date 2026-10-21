package evidence

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/dockerapi"
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/model"
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/store"
)

const cid = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

// fakeDocker: 호출별로 결과 · 지연 · 오류를 정한다. 지연은 ctx 가 끝나면 바로 멈춘다.
type fakeDocker struct {
	logs    []byte
	changes []dockerapi.Change
	procs   []dockerapi.Proc
	delay   map[string]time.Duration // "inspect" | "logs" | "diff" | "top"
	fail    map[string]error
}

func (f *fakeDocker) wait(ctx context.Context, op string) error {
	if err := f.fail[op]; err != nil {
		return err
	}
	if d := f.delay[op]; d > 0 {
		select {
		case <-time.After(d):
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return ctx.Err()
}

func (f *fakeDocker) Inspect(ctx context.Context, id string) (dockerapi.Container, error) {
	if err := f.wait(ctx, "inspect"); err != nil {
		return dockerapi.Container{}, err
	}
	return dockerapi.Container{ID: id, Name: "sg-install-pip-1", Image: "python:3.12-slim", Running: true}, nil
}

func (f *fakeDocker) Logs(ctx context.Context, _ string, _ int, _ int64) ([]byte, error) {
	if err := f.wait(ctx, "logs"); err != nil {
		return nil, err
	}
	return f.logs, nil
}

func (f *fakeDocker) Diff(ctx context.Context, _ string) ([]dockerapi.Change, error) {
	if err := f.wait(ctx, "diff"); err != nil {
		return nil, err
	}
	return f.changes, nil
}

func (f *fakeDocker) Top(ctx context.Context, _ string) ([]dockerapi.Proc, error) {
	if err := f.wait(ctx, "top"); err != nil {
		return nil, err
	}
	return f.procs, nil
}

func newFake() *fakeDocker {
	return &fakeDocker{
		logs:    []byte("line1\nline2\n"),
		changes: []dockerapi.Change{{Kind: "A", Path: "/tmp/x"}, {Kind: "C", Path: "/etc/passwd"}},
		procs:   []dockerapi.Proc{{PID: 1, User: "root", Cmd: "pip install ./reqeusts"}},
		delay:   map[string]time.Duration{},
		fail:    map[string]error{},
	}
}

func TestCollectFull(t *testing.T) {
	mem := store.NewMemory()
	c := New(newFake(), mem)
	ev, err := c.Collect(context.Background(), cid)
	if err != nil {
		t.Fatal(err)
	}
	if ev.Partial || ev.Error != "" {
		t.Fatalf("full collection must not be partial: %+v", ev)
	}
	if ev.ContainerID != cid || ev.ContainerName != "sg-install-pip-1" || ev.Image != "python:3.12-slim" {
		t.Fatalf("identity: %+v", ev)
	}
	if ev.Logs != "line1\nline2\n" || len(ev.Changes) != 2 || len(ev.Processes) != 1 {
		t.Fatalf("content: %+v", ev)
	}
	if ev.Changes[0] != (model.FileChange{Kind: "A", Path: "/tmp/x"}) || ev.Processes[0].Cmd != "pip install ./reqeusts" {
		t.Fatalf("mapping: %+v", ev)
	}
	if ev.ID == "" || ev.CollectedAt.IsZero() || ev.DurationMs < 0 {
		t.Fatalf("meta: %+v", ev)
	}
	// 저장됐다
	got, err := mem.EvidenceByContainer(context.Background(), "sg-install-pip-1")
	if err != nil || len(got) != 1 || got[0].ID != ev.ID {
		t.Fatalf("saved: %v %+v", err, got)
	}
}

// 상한: 한 부분이 멈춰도 예산 안에 돌아오고, 모은 것은 남는다
func TestCollectBudgetPartial(t *testing.T) {
	f := newFake()
	f.delay["diff"] = 5 * time.Second // ctx 가 끝날 때까지 안 돌아온다
	mem := store.NewMemory()
	c := New(f, mem)
	c.Budget = 150 * time.Millisecond

	start := time.Now()
	ev, err := c.Collect(context.Background(), cid)
	elapsed := time.Since(start)
	if err != nil {
		t.Fatal(err)
	}
	if elapsed > c.Budget+300*time.Millisecond {
		t.Fatalf("collect took %v, budget %v", elapsed, c.Budget)
	}
	if !ev.Partial {
		t.Fatal("stuck diff must mark partial")
	}
	if !strings.Contains(ev.Error, "diff") {
		t.Fatalf("error must name the missing part: %q", ev.Error)
	}
	if ev.Logs == "" || len(ev.Processes) != 1 || len(ev.Changes) != 0 {
		t.Fatalf("keep what finished: logs=%q procs=%d changes=%d", ev.Logs, len(ev.Processes), len(ev.Changes))
	}
	if ev.ContainerName != "sg-install-pip-1" {
		t.Fatalf("inspect result kept: %+v", ev)
	}
	got, _ := mem.EvidenceByContainer(context.Background(), cid)
	if len(got) != 1 || !got[0].Partial {
		t.Fatalf("partial evidence must still be saved: %+v", got)
	}
}

// 한 부분의 오류는 partial + Error 에 남고 나머지는 모은다
func TestCollectPartOnError(t *testing.T) {
	f := newFake()
	f.fail["top"] = errors.New("docker /containers/x/top: 409 Conflict")
	c := New(f, store.NewMemory())
	ev, err := c.Collect(context.Background(), cid)
	if err != nil {
		t.Fatal(err)
	}
	if !ev.Partial || !strings.Contains(ev.Error, "top") || len(ev.Processes) != 0 || len(ev.Changes) != 2 {
		t.Fatalf("%+v", ev)
	}
}

// Inspect 가 실패해도 이름 없이 계속 모은다
func TestCollectInspectFails(t *testing.T) {
	f := newFake()
	f.fail["inspect"] = errors.New("docker: 404")
	c := New(f, store.NewMemory())
	ev, err := c.Collect(context.Background(), cid)
	if err != nil {
		t.Fatal(err)
	}
	if ev.ContainerID != cid || ev.ContainerName != "" || !ev.Partial || len(ev.Changes) != 2 {
		t.Fatalf("%+v", ev)
	}
}

// 로그 바이트 상한 256KB: 뒤(최신)를 남긴다
func TestCollectLogByteCap(t *testing.T) {
	f := newFake()
	var b strings.Builder
	for i := 0; b.Len() < LogBytes+64<<10; i++ {
		b.WriteString(strings.Repeat("x", 1000) + "\n")
	}
	b.WriteString("LAST-LINE\n")
	f.logs = []byte(b.String())
	c := New(f, store.NewMemory())
	ev, err := c.Collect(context.Background(), cid)
	if err != nil {
		t.Fatal(err)
	}
	if len(ev.Logs) > LogBytes {
		t.Fatalf("logs %d bytes > cap %d", len(ev.Logs), LogBytes)
	}
	if !strings.HasSuffix(ev.Logs, "LAST-LINE\n") {
		t.Fatal("cap must keep the newest end of the log")
	}
	if ev.Partial {
		t.Fatal("a capped log is not a partial collection")
	}
}

// 파일 변경 500 상한
func TestCollectChangesCap(t *testing.T) {
	f := newFake()
	f.changes = nil
	for i := 0; i < MaxChanges+100; i++ {
		f.changes = append(f.changes, dockerapi.Change{Kind: "A", Path: "/tmp/f"})
	}
	c := New(f, store.NewMemory())
	ev, err := c.Collect(context.Background(), cid)
	if err != nil {
		t.Fatal(err)
	}
	if len(ev.Changes) != MaxChanges {
		t.Fatalf("changes=%d want %d", len(ev.Changes), MaxChanges)
	}
}

// BeforeKill 훅 모양: enforcer.Docker.BeforeKill 에 바로 꽂힌다. 저장 실패는 로그만
type failStore struct{ *store.Memory }

func (*failStore) SaveEvidence(context.Context, model.Evidence) error { return errors.New("db down") }

func TestBeforeKillHookNeverPanics(t *testing.T) {
	c := New(newFake(), &failStore{store.NewMemory()})
	var hook func(context.Context, string) = c.BeforeKill
	hook(context.Background(), cid) // 오류는 삼킨다
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	hook(ctx, cid) // 이미 끝난 ctx 로도 터지지 않는다
}
