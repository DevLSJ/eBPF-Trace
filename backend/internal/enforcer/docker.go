// Package enforcer isolates violating containers. Inspektor Gadget only observes;
// the kill is done here through the Docker Engine API.
package enforcer

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// Enforcer: 컨테이너 격리 수단. 데모용 mock 소스는 자체 구현을 쓴다.
type Enforcer interface {
	Kill(ctx context.Context, containerID string) error
}

// Times: 격리 타임라인(10/30)에 들어가는 단계별 시각 — 해당 없으면 0 값.
// EvidenceStartedAt · EvidenceDoneAt 는 before-kill 훅의 시작 · 끝(예산을 넘기면 예산이 다한 시점), KilledAt 은 Docker kill 응답 시각(성공했을 때만)
type Times struct {
	EvidenceStartedAt time.Time
	EvidenceDoneAt    time.Time
	KilledAt          time.Time
}

// Timed: 단계별 시각을 돌려주는 격리 수단(Docker). pipeline 은 이 인터페이스가 있으면 KillTimed 를, 없으면 Kill 을 부른다
type Timed interface {
	KillTimed(ctx context.Context, containerID string) (Times, error)
}

var containerIDPattern = regexp.MustCompile(`^[a-f0-9]{12,64}$`)

// Docker: Engine API(`POST /containers/{id}/kill`)를 직접 호출한다.
// Docker SDK 전체를 끌어오지 않으려고 HTTP 한 번으로 처리한다.
type Docker struct {
	client *http.Client
	base   string
	// BeforeKill: kill 요청 직전에 부르는 훅(증거 보존, 10/20). 선택적 — nil 이면 기존 동작 그대로.
	// beforeKillBudget 안에 끝나지 않으면 기다리지 않고 kill 을 보낸다. 훅의 패닉은 삼킨다 (kill 이 늦어지면 안 된다).
	BeforeKill func(ctx context.Context, containerID string)
}

// beforeKillBudget: 훅을 기다리는 상한. 넘으면 훅은 뒤에서 끝나게 두고 kill 을 진행한다
const beforeKillBudget = 700 * time.Millisecond

// NewDocker: dockerHost는 unix:///var/run/docker.sock 또는 tcp://host:2375 형식
func NewDocker(dockerHost string) (*Docker, error) {
	u, err := url.Parse(dockerHost)
	if err != nil {
		return nil, fmt.Errorf("DOCKER_HOST: %w", err)
	}
	tr := &http.Transport{}
	base := ""
	switch u.Scheme {
	case "unix":
		sock := u.Path
		tr.DialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", sock)
		}
		base = "http://docker"
	case "tcp", "http":
		base = "http://" + u.Host
	default:
		return nil, fmt.Errorf("DOCKER_HOST: unsupported scheme %q", u.Scheme)
	}
	return &Docker{client: &http.Client{Transport: tr, Timeout: 10 * time.Second}, base: base}, nil
}

// Kill: SIGKILL로 컨테이너 강제 종료
func (d *Docker) Kill(ctx context.Context, containerID string) error {
	_, err := d.KillTimed(ctx, containerID)
	return err
}

// KillTimed: Kill 과 같되 단계별 시각(증거 훅 시작 · 끝, kill 응답)을 함께 돌려준다 — 격리 타임라인(10/30).
// 동작은 Kill 과 똑같다: 잘못된 id 는 요청 없이 거절, 훅은 예산 안에서만 기다리고, 그 다음 kill 요청을 보낸다
func (d *Docker) KillTimed(ctx context.Context, containerID string) (Times, error) {
	var ts Times
	if !containerIDPattern.MatchString(containerID) {
		return ts, fmt.Errorf("invalid container id %q", containerID)
	}
	if d.BeforeKill != nil {
		ts.EvidenceStartedAt = time.Now().UTC()
		d.runBeforeKill(ctx, containerID)
		ts.EvidenceDoneAt = time.Now().UTC()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		d.base+"/containers/"+containerID+"/kill?signal=SIGKILL", nil)
	if err != nil {
		return ts, err
	}
	resp, err := d.client.Do(req)
	if err != nil {
		return ts, fmt.Errorf("docker kill: %w", err)
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusNoContent:
		ts.KilledAt = time.Now().UTC()
		return ts, nil
	case http.StatusConflict:
		return ts, ErrNotRunning
	case http.StatusNotFound:
		return ts, ErrNotFound
	}
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
	return ts, fmt.Errorf("docker kill: %s: %s", resp.Status, strings.TrimSpace(string(b)))
}

// runBeforeKill: 훅을 별도 고루틴에서 돌리고 끝나거나 예산이 다할 때까지만 기다린다.
// 훅이 ctx 를 무시해도 kill 은 beforeKillBudget 뒤에 나간다. 패닉은 여기서 받는다.
func (d *Docker) runBeforeKill(ctx context.Context, containerID string) {
	hook := d.BeforeKill // 고루틴 밖에서 읽는다 — 예산을 넘겨 아직 도는 훅과 훅 교체가 경쟁하지 않게
	hctx, cancel := context.WithTimeout(ctx, beforeKillBudget)
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer cancel()
		defer func() {
			if r := recover(); r != nil {
				slog.Error("before-kill hook panicked", "id", containerID, "panic", r)
			}
		}()
		hook(hctx, containerID)
	}()
	select {
	case <-done:
	case <-hctx.Done():
		select {
		case <-done:
		default:
			slog.Warn("before-kill hook exceeded budget; killing anyway", "id", containerID, "budget", beforeKillBudget)
		}
	}
}

var (
	ErrNotRunning = errors.New("container is not running")
	ErrNotFound   = errors.New("container not found")
)
