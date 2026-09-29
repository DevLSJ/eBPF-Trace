// Package enforcer isolates violating containers. Inspektor Gadget only observes;
// the kill is done here through the Docker Engine API.
package enforcer

import (
	"context"
	"errors"
	"fmt"
	"io"
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

var containerIDPattern = regexp.MustCompile(`^[a-f0-9]{12,64}$`)

// Docker: Engine API(`POST /containers/{id}/kill`)를 직접 호출한다.
// Docker SDK 전체를 끌어오지 않으려고 HTTP 한 번으로 처리한다.
type Docker struct {
	client *http.Client
	base   string
}

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
	if !containerIDPattern.MatchString(containerID) {
		return fmt.Errorf("invalid container id %q", containerID)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		d.base+"/containers/"+containerID+"/kill?signal=SIGKILL", nil)
	if err != nil {
		return err
	}
	resp, err := d.client.Do(req)
	if err != nil {
		return fmt.Errorf("docker kill: %w", err)
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusNoContent:
		return nil
	case http.StatusConflict:
		return ErrNotRunning
	case http.StatusNotFound:
		return ErrNotFound
	}
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
	return fmt.Errorf("docker kill: %s: %s", resp.Status, strings.TrimSpace(string(b)))
}

var (
	ErrNotRunning = errors.New("container is not running")
	ErrNotFound   = errors.New("container not found")
)
