package ingestion

import (
	"context"
	"log/slog"
	"time"

	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/dockerapi"
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/model"
)

// DockerLifecycle: Docker 이벤트 API 의 컨테이너 start · die 를 KindStart · KindExit 로 보낸다.
// 가젯 소스와 따로 돈다 — 컨테이너 탐색 방식(docker-events · fanotify)과 상관없이
// 차단 이미지 격리(start)와 설치 세션의 컨테이너 종료 시각(die)을 얻기 위해서다.
type DockerLifecycle struct {
	DockerHost string
}

func (d *DockerLifecycle) Run(ctx context.Context, out chan<- model.Event) error {
	cli, err := dockerapi.New(d.DockerHost)
	if err != nil {
		return err
	}
	backoff := time.Second
	for ctx.Err() == nil {
		err := cli.Events(ctx, func(ev dockerapi.Event) {
			var k model.Kind
			switch ev.Action {
			case "start":
				k = model.KindStart
			case "die":
				k = model.KindExit
			default:
				return
			}
			send(out, model.Event{Kind: k, Timestamp: time.Now().UTC(), ContainerID: ev.ID, ContainerName: ev.Name, ImageName: ev.Image})
		})
		if ctx.Err() != nil {
			break
		}
		slog.Warn("docker lifecycle events ended; reconnecting", "err", err, "in", backoff)
		select {
		case <-ctx.Done():
		case <-time.After(backoff):
		}
		backoff = min(backoff*2, 30*time.Second)
	}
	return ctx.Err()
}
