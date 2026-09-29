//go:build linux

package ingestion

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/cilium/ebpf/rlimit"
	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	containerutilsTypes "github.com/inspektor-gadget/inspektor-gadget/pkg/container-utils/types"
	tracercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/tracer-collection"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/types"

	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/dockerapi"
)

// dockerCollection: Inspektor Gadget 의 컨테이너 컬렉션을 runc/fanotify 훅 대신 Docker 이벤트 API 로 채운다.
// fanotify 는 Docker Desktop VM 루트 파일시스템에서 EINVAL 이 나서 컬렉션 자체가 만들어지지 않는다.
// 컨테이너 ID·PID 는 Docker 에서 직접 얻고, 나머지(이름·이미지·cgroup·mntns·tracer 맵)는 IG enricher 가 채운다.
type dockerCollection struct {
	cc  containercollection.ContainerCollection
	tc  *tracercollection.TracerCollection
	cli *dockerapi.Client
}

func newDockerCollection(ctx context.Context, dockerHost string) (*dockerCollection, error) {
	cli, err := dockerapi.New(dockerHost)
	if err != nil {
		return nil, err
	}
	if cli.SocketPath == "" {
		return nil, fmt.Errorf("CONTAINER_DISCOVERY=docker-events 는 unix 소켓 DOCKER_HOST 만 지원")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("removing memlock rlimit: %w", err)
	}
	d := &dockerCollection{cli: cli}
	d.tc, err = tracercollection.NewTracerCollection(&d.cc)
	if err != nil {
		return nil, fmt.Errorf("tracer collection: %w", err)
	}
	rc := []*containerutilsTypes.RuntimeConfig{{Name: types.RuntimeNameDocker, SocketPath: cli.SocketPath}}
	// 순서가 중요: 런타임 enricher(이름·이미지) → cgroup → 네임스페이스(mntns/netns, PID 필요) → tracer 맵 등록
	if err := d.cc.Initialize(
		containercollection.WithMultipleContainerRuntimesEnrichment(rc),
		containercollection.WithCgroupEnrichment(),
		containercollection.WithLinuxNamespaceEnrichment(),
		containercollection.WithTracerCollection(d.tc),
	); err != nil {
		return nil, fmt.Errorf("container collection: %w", err)
	}
	if err := d.syncRunning(ctx); err != nil {
		return nil, err
	}
	go d.watch(ctx)
	return d, nil
}

func (d *dockerCollection) Close() {
	d.cc.Close()
	d.tc.Close()
}

func (d *dockerCollection) add(ctx context.Context, id string) {
	c, err := d.cli.Inspect(ctx, id)
	if err != nil || !c.Running || c.Pid == 0 {
		slog.Debug("container discovery: skip", "id", id, "err", err)
		return
	}
	if d.cc.GetContainer(c.ID) != nil {
		return
	}
	d.cc.AddContainer(&containercollection.Container{
		Runtime: containercollection.RuntimeMetadata{BasicRuntimeMetadata: types.BasicRuntimeMetadata{
			RuntimeName: types.RuntimeNameDocker, ContainerID: c.ID, ContainerName: c.Name,
			ContainerImageName: c.Image, ContainerPID: uint32(c.Pid),
		}},
	})
	if d.cc.GetContainer(c.ID) == nil {
		slog.Warn("container discovery: enrichment dropped container", "name", c.Name, "id", c.ID[:12])
		return
	}
	slog.Info("container discovery: tracking", "name", c.Name, "image", c.Image, "pid", c.Pid)
}

// syncRunning: 시작 시점에 이미 떠 있는 컨테이너
func (d *dockerCollection) syncRunning(ctx context.Context) error {
	list, err := d.cli.List(ctx)
	if err != nil {
		return fmt.Errorf("docker list: %w", err)
	}
	for _, c := range list {
		if c.Running {
			d.add(ctx, c.ID)
		}
	}
	return nil
}

// watch: start → 추가, die/destroy → 제거. 스트림이 끊기면 백오프 후 다시 붙고 목록을 재동기화한다.
func (d *dockerCollection) watch(ctx context.Context) {
	backoff := time.Second
	for ctx.Err() == nil {
		err := d.cli.Events(ctx, func(ev dockerapi.Event) {
			switch ev.Action {
			case "start":
				d.add(ctx, ev.ID)
			case "die", "destroy":
				if d.cc.GetContainer(ev.ID) != nil {
					d.cc.RemoveContainer(ev.ID)
					slog.Info("container discovery: removed", "name", ev.Name)
				}
			}
		})
		if ctx.Err() != nil {
			return
		}
		slog.Warn("docker events stream ended; reconnecting", "err", err, "in", backoff)
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		backoff = min(backoff*2, 30*time.Second)
		_ = d.syncRunning(ctx)
	}
}
