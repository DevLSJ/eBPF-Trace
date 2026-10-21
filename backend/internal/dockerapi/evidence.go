package dockerapi

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// 증거 보존(10/20)에 쓰는 읽기 전용 호출 — docker logs · diff · top 상당. 모두 ctx 로 취소된다.

// Change: docker diff 한 줄. Kind 는 A(추가) · C(변경) · D(삭제)
type Change struct {
	Kind string
	Path string
}

// Proc: docker top 한 줄
type Proc struct {
	PID  int
	User string
	Cmd  string
}

// Logs: stdout+stderr 마지막 tail 줄을 시간순으로. 응답은 limit 바이트까지만 읽는다(머리말 포함).
// TTY 없는 컨테이너는 8바이트 머리말이 붙은 다중화 스트림이라 풀어서 합치고, TTY 컨테이너는 그대로 돌려준다.
func (c *Client) Logs(ctx context.Context, id string, tail int, limit int64) ([]byte, error) {
	q := "stdout=1&stderr=1&tail=" + strconv.Itoa(tail)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base+"/containers/"+url.PathEscape(id)+"/logs?"+q, nil)
	if err != nil {
		return nil, err
	}
	res, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(res.Body, 4096))
		return nil, fmt.Errorf("docker logs: %s: %s", res.Status, strings.TrimSpace(string(b)))
	}
	raw, err := io.ReadAll(io.LimitReader(res.Body, limit))
	if err != nil && ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if isMultiplexed(raw) {
		return demuxAll(bytes.NewReader(raw)), nil
	}
	return raw, nil
}

// isMultiplexed: 다중화 머리말은 [stream(0·1·2), 0, 0, 0, 길이 4바이트]. 텍스트 출력은 이 모양으로 시작하지 않는다.
func isMultiplexed(b []byte) bool {
	return len(b) >= 8 && b[0] <= 2 && b[1] == 0 && b[2] == 0 && b[3] == 0
}

// demuxAll: 다중화 스트림에서 stdout · stderr 를 순서대로 합친다 (demux 는 stdout 만)
func demuxAll(r io.Reader) []byte {
	var out bytes.Buffer
	hdr := make([]byte, 8)
	for {
		if _, err := io.ReadFull(r, hdr); err != nil {
			return out.Bytes()
		}
		n := int64(binary.BigEndian.Uint32(hdr[4:]))
		if _, err := io.CopyN(&out, r, n); err != nil {
			return out.Bytes()
		}
	}
}

// Diff: 컨테이너 레이어의 파일 변경 목록 (경로순)
func (c *Client) Diff(ctx context.Context, id string) ([]Change, error) {
	var raw []struct {
		Path string `json:"Path"`
		Kind int    `json:"Kind"` // 0 변경 · 1 추가 · 2 삭제
	}
	if err := c.getJSON(ctx, "/containers/"+url.PathEscape(id)+"/changes", &raw); err != nil {
		return nil, err
	}
	out := make([]Change, 0, len(raw))
	for _, r := range raw {
		kind := "C"
		switch r.Kind {
		case 1:
			kind = "A"
		case 2:
			kind = "D"
		}
		out = append(out, Change{Kind: kind, Path: r.Path})
	}
	return out, nil
}

// Top: 실행 중인 프로세스 목록 (ps -ef 기준 열 이름으로 PID · 사용자 · 명령을 고른다)
func (c *Client) Top(ctx context.Context, id string) ([]Proc, error) {
	var raw struct {
		Titles    []string   `json:"Titles"`
		Processes [][]string `json:"Processes"`
	}
	if err := c.getJSON(ctx, "/containers/"+url.PathEscape(id)+"/top", &raw); err != nil {
		return nil, err
	}
	col := func(names ...string) int {
		for _, n := range names {
			for i, t := range raw.Titles {
				if strings.EqualFold(t, n) {
					return i
				}
			}
		}
		return -1
	}
	pidC, userC, cmdC := col("PID"), col("USER", "UID"), col("CMD", "COMMAND")
	out := make([]Proc, 0, len(raw.Processes))
	for _, row := range raw.Processes {
		p := Proc{}
		if pidC >= 0 && pidC < len(row) {
			p.PID, _ = strconv.Atoi(row[pidC])
		}
		if userC >= 0 && userC < len(row) {
			p.User = row[userC]
		}
		if cmdC >= 0 && cmdC < len(row) {
			p.Cmd = strings.Join(row[cmdC:], " ") // CMD 는 마지막 열 — 공백이 들어가도 잘리지 않게
		}
		out = append(out, p)
	}
	return out, nil
}
