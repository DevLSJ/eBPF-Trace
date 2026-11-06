package integration

import (
	"context"
	"fmt"
	"time"

	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/dockerapi"
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/pipeline"
)

// DockerAPI: dockerapi.Client 중 연동이 쓰는 부분(테스트에서 대체)
type DockerAPI interface {
	List(ctx context.Context) ([]dockerapi.Container, error)
	CreateContainer(ctx context.Context, s dockerapi.CreateSpec) (string, error)
	StartContainer(ctx context.Context, id string) error
	WaitContainer(ctx context.Context, id string) (int, error)
	RemoveContainer(ctx context.Context, id string, force bool) error
}

// Docker: 가젯 소스의 Lister · Prober
type Docker struct{ API DockerAPI }

func (d Docker) Containers(ctx context.Context) ([]Container, error) {
	cs, err := d.API.List(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]Container, 0, len(cs))
	for _, c := range cs {
		if c.Running {
			out = append(out, Container{ID: c.ID, Name: c.Name, Image: c.Image, Labels: c.Labels})
		}
	}
	return out, nil
}

// Probe: busybox 시험 컨테이너 — 감시 라벨만(격리 라벨 없음) · 끝나면(또는 제한 시간이 지나면) 강제로 지운다
func (d Docker) Probe(ctx context.Context, name string) error {
	id, err := d.API.CreateContainer(ctx, dockerapi.CreateSpec{Name: name, Image: ProbeImage, Cmd: ProbeCmd,
		Labels: map[string]string{pipeline.LabelWatch: "true", "supplyguard.probe": "1"}})
	if err != nil {
		return fmt.Errorf("시험 컨테이너를 만들 수 없습니다: %w", err)
	}
	defer func() {
		rctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = d.API.RemoveContainer(rctx, id, true)
	}()
	if err := d.API.StartContainer(ctx, id); err != nil {
		return fmt.Errorf("시험 컨테이너를 시작할 수 없습니다: %w", err)
	}
	if _, err := d.API.WaitContainer(ctx, id); err != nil {
		return fmt.Errorf("시험 컨테이너가 끝나지 않았습니다: %w", err)
	}
	return nil
}
