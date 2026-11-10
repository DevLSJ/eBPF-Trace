// Package dockerapi is a minimal Docker Engine API client over the unix socket:
// list/inspect containers and stream container events. It exists so the gadget
// source can track containers through Docker events instead of the runc/fanotify
// hook (which does not work on Docker Desktop's VM filesystem).
package dockerapi

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type Client struct {
	http *http.Client
	base string
	// SocketPath: unix 소켓 경로 (IG 런타임 enricher 에도 넘긴다). tcp 면 빈 문자열.
	SocketPath string
}

// New: dockerHost 는 unix:///var/run/docker.sock 또는 tcp://host:2375
func New(dockerHost string) (*Client, error) {
	u, err := url.Parse(dockerHost)
	if err != nil {
		return nil, fmt.Errorf("DOCKER_HOST: %w", err)
	}
	tr := &http.Transport{}
	c := &Client{}
	switch u.Scheme {
	case "unix":
		sock := u.Path
		tr.DialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", sock)
		}
		c.base, c.SocketPath = "http://docker", sock
	case "tcp", "http":
		c.base = "http://" + u.Host
	default:
		return nil, fmt.Errorf("DOCKER_HOST: unsupported scheme %q", u.Scheme)
	}
	c.http = &http.Client{Transport: tr} // 이벤트 스트림은 오래 열어 두므로 전체 타임아웃은 두지 않는다
	return c, nil
}

type Container struct {
	ID      string
	Name    string // 앞의 '/' 를 뗀 이름
	Image   string
	Pid     int
	Running bool
	Labels  map[string]string // 11/06: 감시 · 격리 범위(supplyguard.watch · supplyguard.enforce). 없으면 빈 맵
	// MountDests: 마운트의 컨테이너 안 경로만(Inspect, 11/10 증거 코드 보기). 호스트 경로는 담지 않는다
	MountDests []string
}

// List: 실행 중인 컨테이너 목록 (PID 는 없음 — Inspect 로 얻는다)
func (c *Client) List(ctx context.Context) ([]Container, error) {
	var raw []struct {
		ID     string            `json:"Id"`
		Names  []string          `json:"Names"`
		Image  string            `json:"Image"`
		State  string            `json:"State"`
		Labels map[string]string `json:"Labels"`
	}
	if err := c.getJSON(ctx, "/containers/json", &raw); err != nil {
		return nil, err
	}
	out := make([]Container, 0, len(raw))
	for _, r := range raw {
		name := ""
		if len(r.Names) > 0 {
			name = strings.TrimPrefix(r.Names[0], "/")
		}
		out = append(out, Container{ID: r.ID, Name: name, Image: r.Image, Running: r.State == "running", Labels: orEmpty(r.Labels)})
	}
	return out, nil
}

// Inspect: 이름·이미지·init PID·라벨
func (c *Client) Inspect(ctx context.Context, id string) (Container, error) {
	var raw struct {
		ID     string `json:"Id"`
		Name   string `json:"Name"`
		Config struct {
			Image  string            `json:"Image"`
			Labels map[string]string `json:"Labels"`
		} `json:"Config"`
		State struct {
			Pid     int  `json:"Pid"`
			Running bool `json:"Running"`
		} `json:"State"`
		Mounts []struct {
			Destination string `json:"Destination"`
		} `json:"Mounts"`
	}
	if err := c.getJSON(ctx, "/containers/"+url.PathEscape(id)+"/json", &raw); err != nil {
		return Container{}, err
	}
	var dests []string
	for _, m := range raw.Mounts {
		dests = append(dests, m.Destination)
	}
	return Container{ID: raw.ID, Name: strings.TrimPrefix(raw.Name, "/"), Image: raw.Config.Image, Pid: raw.State.Pid, Running: raw.State.Running, Labels: orEmpty(raw.Config.Labels), MountDests: dests}, nil
}

// Labels: 컨테이너 라벨(파이프라인 감시 · 격리 범위, pipeline.Labeler)
func (c *Client) Labels(ctx context.Context, id string) (map[string]string, error) {
	ct, err := c.Inspect(ctx, id)
	if err != nil {
		return nil, err
	}
	return ct.Labels, nil
}

func orEmpty(m map[string]string) map[string]string {
	if m == nil {
		return map[string]string{}
	}
	return m
}

type Event struct {
	Action string // start, die, destroy, ...
	ID     string
	Name   string
	Image  string
}

// Events: 컨테이너 start/die/destroy 이벤트를 ctx 가 끝나거나 연결이 끊길 때까지 fn 으로 넘긴다.
func (c *Client) Events(ctx context.Context, fn func(Event)) error {
	filters := url.QueryEscape(`{"type":["container"],"event":["start","die","destroy"]}`)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base+"/events?filters="+filters, nil)
	if err != nil {
		return err
	}
	res, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(res.Body, 4096))
		return fmt.Errorf("docker events: %s: %s", res.Status, strings.TrimSpace(string(b)))
	}
	dec := json.NewDecoder(bufio.NewReader(res.Body))
	for {
		var raw struct {
			Action string `json:"Action"`
			Actor  struct {
				ID         string            `json:"ID"`
				Attributes map[string]string `json:"Attributes"`
			} `json:"Actor"`
		}
		if err := dec.Decode(&raw); err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return fmt.Errorf("docker events stream: %w", err)
		}
		fn(Event{Action: raw.Action, ID: raw.Actor.ID, Name: raw.Actor.Attributes["name"], Image: raw.Actor.Attributes["image"]})
	}
}

func (c *Client) getJSON(ctx context.Context, path string, out any) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base+path, nil)
	if err != nil {
		return err
	}
	res, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(res.Body, 4096))
		err := fmt.Errorf("docker %s: %s: %s", path, res.Status, strings.TrimSpace(string(b)))
		if res.StatusCode == http.StatusNotFound {
			return notFound{err}
		}
		return err
	}
	return json.NewDecoder(res.Body).Decode(out)
}
