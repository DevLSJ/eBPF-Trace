package integration

import (
	"context"
	"testing"

	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/dockerapi"
)

type fakeDocker struct {
	spec    dockerapi.CreateSpec
	calls   []string
	list    []dockerapi.Container
	waitErr error
}

func (f *fakeDocker) List(context.Context) ([]dockerapi.Container, error) { return f.list, nil }
func (f *fakeDocker) CreateContainer(_ context.Context, s dockerapi.CreateSpec) (string, error) {
	f.spec = s
	f.calls = append(f.calls, "create")
	return "cid", nil
}
func (f *fakeDocker) StartContainer(context.Context, string) error {
	f.calls = append(f.calls, "start")
	return nil
}
func (f *fakeDocker) WaitContainer(context.Context, string) (int, error) {
	f.calls = append(f.calls, "wait")
	return 0, f.waitErr
}
func (f *fakeDocker) RemoveContainer(_ context.Context, _ string, force bool) error {
	if force {
		f.calls = append(f.calls, "remove-force")
	}
	return nil
}

// Tier 1 — 시험 컨테이너: busybox · 감시 라벨만(격리 라벨 없음) · 만들기 → 시작 → 대기 → 강제 삭제
func TestDockerProbe(t *testing.T) {
	f := &fakeDocker{}
	if err := (Docker{API: f}).Probe(context.Background(), "sg-probe-1"); err != nil {
		t.Fatal(err)
	}
	if got := f.calls; len(got) != 4 || got[0] != "create" || got[3] != "remove-force" {
		t.Fatalf("calls = %v", got)
	}
	s := f.spec
	if s.Name != "sg-probe-1" || s.Image != ProbeImage || s.Labels["supplyguard.watch"] != "true" || s.Labels["supplyguard.enforce"] != "" {
		t.Fatalf("spec = %+v", s)
	}
}

// 목록: 실행 중인 것만, 라벨 그대로
func TestDockerContainers(t *testing.T) {
	f := &fakeDocker{list: []dockerapi.Container{
		{ID: "1", Name: "a", Running: true, Labels: map[string]string{"supplyguard.watch": "true"}},
		{ID: "2", Name: "b", Running: false},
	}}
	cs, err := (Docker{API: f}).Containers(context.Background())
	if err != nil || len(cs) != 1 || cs[0].Name != "a" || cs[0].Labels["supplyguard.watch"] != "true" {
		t.Fatalf("containers = %+v %v", cs, err)
	}
}
