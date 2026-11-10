package dockerapi

import (
	"archive/tar"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// ErrNotFile: 경로가 일반 파일이 아니다(폴더 · 링크 등) — 증거 코드 보기는 일반 파일만 읽는다
var ErrNotFile = errors.New("docker: not a regular file")

// ReadFile: 컨테이너 안 파일 하나를 앞에서 limit 바이트까지 읽는다(증거 코드 보기, 11/10).
// GET /containers/{id}/archive?path= 가 주는 tar 의 첫 항목만 본다. size 는 잘리기 전 원래 크기.
// 없는 컨테이너 · 없는 경로는 ErrNotFound(errors.Is). ctx 로 취소된다.
func (c *Client) ReadFile(ctx context.Context, id, path string, limit int64) ([]byte, int64, error) {
	u := c.base + "/containers/" + url.PathEscape(id) + "/archive?path=" + url.QueryEscape(path)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, 0, err
	}
	res, err := c.http.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(res.Body, 4096))
		err := fmt.Errorf("docker archive %s: %s: %s", path, res.Status, strings.TrimSpace(string(b)))
		if res.StatusCode == http.StatusNotFound {
			return nil, 0, notFound{err}
		}
		return nil, 0, err
	}
	tr := tar.NewReader(res.Body)
	h, err := tr.Next()
	if err != nil {
		if ctx.Err() != nil {
			return nil, 0, ctx.Err()
		}
		return nil, 0, fmt.Errorf("docker archive %s: %w", path, err)
	}
	if h.Typeflag != tar.TypeReg {
		return nil, 0, ErrNotFile
	}
	b, err := io.ReadAll(io.LimitReader(tr, limit))
	if err != nil {
		if ctx.Err() != nil {
			return nil, 0, ctx.Err()
		}
		return nil, 0, err
	}
	return b, h.Size, nil
}
