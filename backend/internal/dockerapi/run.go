package dockerapi

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// RunSpec: 한 번 돌고 끝나는 컨테이너(공급망 검사기). 결과는 표준 출력
type RunSpec struct {
	Name     string
	Image    string
	Cmd      []string
	Volume   string // 이름 있는 볼륨 → Target 에 읽기 전용. 절대 경로면 그 폴더를 bind(make dev — 백엔드가 호스트에서 직접 돌 때, 11/06)
	Target   string
	Network  bool // false = network none
	MemoryMB int64
	CPUs     float64
	Labels   map[string]string
}

// Run: 만들기 → 시작 → 끝날 때까지 기다림 → 표준 출력(최대 32MB) · 종료 코드 → 지우기.
// 이미지가 없으면 한 번 받는다. ctx 가 끝나면 컨테이너를 지운다.
func (c *Client) Run(ctx context.Context, s RunSpec) ([]byte, int, error) {
	body := map[string]any{
		"Image": s.Image, "Cmd": s.Cmd, "Labels": s.Labels, "AttachStdout": true, "AttachStderr": true,
		"HostConfig": map[string]any{
			"NetworkMode": map[bool]string{true: "bridge", false: "none"}[s.Network],
			"Memory":      s.MemoryMB << 20, "NanoCpus": int64(s.CPUs * 1e9),
			"Mounts":      []map[string]any{{"Type": mountType(s.Volume), "Source": s.Volume, "Target": s.Target, "ReadOnly": true}},
			"SecurityOpt": []string{"no-new-privileges"}, "CapDrop": []string{"ALL"},
		},
	}
	var created struct{ Id string }
	create := func() (int, error) {
		return c.do(ctx, http.MethodPost, "/containers/create?name="+url.QueryEscape(s.Name), body, &created)
	}
	code, err := create()
	if code == http.StatusNotFound {
		if err := c.pull(ctx, s.Image); err != nil {
			return nil, -1, err
		}
		code, err = create()
	}
	if err != nil {
		return nil, -1, err
	}
	defer func() {
		_, _ = c.do(context.Background(), http.MethodDelete, "/containers/"+created.Id+"?force=1", nil, nil)
	}()
	if _, err := c.do(ctx, http.MethodPost, "/containers/"+created.Id+"/start", nil, nil); err != nil {
		return nil, -1, err
	}
	var waited struct{ StatusCode int }
	if _, err := c.do(ctx, http.MethodPost, "/containers/"+created.Id+"/wait", nil, &waited); err != nil {
		return nil, -1, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base+"/containers/"+created.Id+"/logs?stdout=1&stderr=0", nil)
	if err != nil {
		return nil, -1, err
	}
	res, err := c.http.Do(req)
	if err != nil {
		return nil, -1, err
	}
	defer res.Body.Close()
	out, err := demux(io.LimitReader(res.Body, 32<<20))
	return out, waited.StatusCode, err
}

// mountType: 절대 경로는 호스트 폴더(bind), 그 밖은 이름 있는 볼륨
func mountType(src string) string {
	if strings.HasPrefix(src, "/") {
		return "bind"
	}
	return "volume"
}

// demux: TTY 없는 컨테이너 로그(8바이트 머리 + 본문)에서 표준 출력만
func demux(r io.Reader) ([]byte, error) {
	var out bytes.Buffer
	hdr := make([]byte, 8)
	for {
		if _, err := io.ReadFull(r, hdr); err != nil {
			if err == io.EOF || err == io.ErrUnexpectedEOF {
				return out.Bytes(), nil
			}
			return out.Bytes(), err
		}
		n := int64(binary.BigEndian.Uint32(hdr[4:]))
		if hdr[0] == 1 {
			if _, err := io.CopyN(&out, r, n); err != nil {
				return out.Bytes(), nil
			}
		} else if _, err := io.CopyN(io.Discard, r, n); err != nil {
			return out.Bytes(), nil
		}
	}
}

func (c *Client) pull(ctx context.Context, image string) error {
	name, tag := image, "latest"
	if i := strings.LastIndex(image, ":"); i > strings.LastIndex(image, "/") {
		name, tag = image[:i], image[i+1:]
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+"/images/create?fromImage="+url.QueryEscape(name)+"&tag="+url.QueryEscape(tag), nil)
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
		return fmt.Errorf("docker pull %s: %s", image, res.Status)
	}
	return nil
}

// do: JSON 요청 · 응답. 2xx 가 아니면 상태 코드와 오류
func (c *Client) do(ctx context.Context, method, path string, in, out any) (int, error) {
	var rd io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return 0, err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, rd)
	if err != nil {
		return 0, err
	}
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	res, err := c.http.Do(req)
	if err != nil {
		return 0, err
	}
	defer res.Body.Close()
	if res.StatusCode/100 != 2 {
		b, _ := io.ReadAll(io.LimitReader(res.Body, 4096))
		return res.StatusCode, fmt.Errorf("docker %s %s: %s: %s", method, path, res.Status, strings.TrimSpace(string(b)))
	}
	if out != nil {
		return res.StatusCode, json.NewDecoder(res.Body).Decode(out)
	}
	_, _ = io.Copy(io.Discard, res.Body)
	return res.StatusCode, nil
}
