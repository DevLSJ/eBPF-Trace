package dockerapi

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// 시연 컨테이너(10/30, Tier 1) — 만들기 · 패키지 올리기 · 시작 · 종료 대기 · 지우기를 단계별로 부른다(Run 은 한 번에 다 한다).

// CreateSpec: 이름 · 이미지 · 명령 · 환경 · 라벨. 네트워크는 기본(bridge), 볼륨 없음 — 패키지는 PutArchive 로 올린다
type CreateSpec struct {
	Name   string
	Image  string
	Cmd    []string
	Env    []string
	Labels map[string]string
}

// Ping: GET /_ping — 데몬에 닿는지 (5초)
func (c *Client) Ping(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base+"/_ping", nil)
	if err != nil {
		return err
	}
	res, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	_, _ = io.Copy(io.Discard, res.Body)
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("docker ping: %s", res.Status)
	}
	return nil
}

// CreateContainer: POST /containers/create?name= — 이미지가 없으면(404) 한 번 받고 다시 만든다. 컨테이너 id 를 돌려준다
func (c *Client) CreateContainer(ctx context.Context, s CreateSpec) (string, error) {
	body := map[string]any{
		"Image": s.Image, "Cmd": s.Cmd, "Env": s.Env, "Labels": s.Labels,
		"HostConfig": map[string]any{"NetworkMode": "bridge"},
	}
	var created struct{ Id string }
	create := func() (int, error) {
		return c.do(ctx, http.MethodPost, "/containers/create?name="+url.QueryEscape(s.Name), body, &created)
	}
	code, err := create()
	if code == http.StatusNotFound {
		if err := c.pull(ctx, s.Image); err != nil {
			return "", err
		}
		_, err = create()
	}
	if err != nil {
		return "", err
	}
	return created.Id, nil
}

// PutArchive: PUT /containers/{id}/archive?path= — tar 를 컨테이너 안 path(있어야 함)에 푼다
func (c *Client) PutArchive(ctx context.Context, id, path string, r io.Reader) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPut,
		c.base+"/containers/"+url.PathEscape(id)+"/archive?path="+url.QueryEscape(path), r)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-tar")
	res, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode/100 != 2 {
		b, _ := io.ReadAll(io.LimitReader(res.Body, 4096))
		return fmt.Errorf("docker put archive: %s: %s", res.Status, strings.TrimSpace(string(b)))
	}
	_, _ = io.Copy(io.Discard, res.Body)
	return nil
}

// StartContainer: POST /containers/{id}/start
func (c *Client) StartContainer(ctx context.Context, id string) error {
	_, err := c.do(ctx, http.MethodPost, "/containers/"+url.PathEscape(id)+"/start", nil, nil)
	return err
}

// WaitContainer: POST /containers/{id}/wait — 끝날 때까지 막히고 종료 코드를 돌려준다 (ctx 로 상한을 둔다)
func (c *Client) WaitContainer(ctx context.Context, id string) (int, error) {
	var waited struct{ StatusCode int }
	_, err := c.do(ctx, http.MethodPost, "/containers/"+url.PathEscape(id)+"/wait", nil, &waited)
	return waited.StatusCode, err
}

// RemoveContainer: DELETE /containers/{id}[?force=1] — force 면 돌고 있어도 죽이고 지운다
func (c *Client) RemoveContainer(ctx context.Context, id string, force bool) error {
	q := ""
	if force {
		q = "?force=1"
	}
	_, err := c.do(ctx, http.MethodDelete, "/containers/"+url.PathEscape(id)+q, nil, nil)
	return err
}
