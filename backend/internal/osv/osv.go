// Package osv looks packages up in osv.dev for the static-analysis comparison
// (GET /api/osv). Results are cached for an hour; a failed lookup is reported in
// the response's error field instead of failing the request.
package osv

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/model"
)

const (
	DefaultURL = "https://api.osv.dev"
	Source     = "osv.dev"
	cacheMax   = 1000
	maxPages   = 10
)

// Ecosystems: 매니저 → OSV 생태계 (pip PyPI · npm npm · cargo crates.io)
var Ecosystems = map[string]string{"pip": "PyPI", "npm": "npm", "cargo": "crates.io"}

func ValidEcosystem(e string) bool {
	for _, v := range Ecosystems {
		if v == e {
			return true
		}
	}
	return false
}

type Client struct {
	URL     string        // 기본 https://api.osv.dev (테스트에서 바꾼다)
	Timeout time.Duration // 기본 5초
	TTL     time.Duration // 기본 1시간
	HTTP    *http.Client
	Now     func() time.Time

	mu    sync.Mutex
	cache map[string]model.Osv
}

func New() *Client { return &Client{} }

func (c *Client) defaults() {
	if c.URL == "" {
		c.URL = DefaultURL
	}
	if c.Timeout <= 0 {
		c.Timeout = 5 * time.Second
	}
	if c.TTL <= 0 {
		c.TTL = time.Hour
	}
	if c.HTTP == nil {
		c.HTTP = &http.Client{}
	}
	if c.Now == nil {
		c.Now = func() time.Time { return time.Now().UTC() }
	}
}

// Query: 버전 없이 이름으로 조회한다. 실패는 캐시하지 않고 Error 에 담는다.
func (c *Client) Query(ctx context.Context, ecosystem, name string) model.Osv {
	c.mu.Lock()
	c.defaults()
	key := ecosystem + "\x00" + name
	if hit, ok := c.cache[key]; ok && c.Now().Sub(hit.QueriedAt) < c.TTL {
		c.mu.Unlock()
		return hit
	}
	c.mu.Unlock()

	out := model.Osv{Ecosystem: ecosystem, Name: name, IDs: []string{}, QueriedAt: c.Now(), Source: Source}
	ids, err := c.fetch(ctx, ecosystem, name)
	if err != nil {
		msg := "osv.dev 조회 실패: " + err.Error()
		out.Error = &msg
		return out
	}
	out.IDs, out.Vulns = ids, len(ids)

	c.mu.Lock()
	if c.cache == nil || len(c.cache) >= cacheMax {
		c.cache = map[string]model.Osv{}
	}
	c.cache[key] = out
	c.mu.Unlock()
	return out
}

func (c *Client) fetch(ctx context.Context, ecosystem, name string) ([]string, error) {
	ctx, cancel := context.WithTimeout(ctx, c.Timeout)
	defer cancel()
	ids := []string{}
	token := ""
	for range maxPages {
		body := map[string]any{"package": map[string]string{"name": name, "ecosystem": ecosystem}}
		if token != "" {
			body["page_token"] = token
		}
		b, _ := json.Marshal(body)
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.URL+"/v1/query", bytes.NewReader(b))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/json")
		res, err := c.HTTP.Do(req)
		if err != nil {
			return nil, err
		}
		var raw struct {
			Vulns []struct {
				ID string `json:"id"`
			} `json:"vulns"`
			NextPageToken string `json:"next_page_token"`
		}
		if res.StatusCode != http.StatusOK {
			snippet, _ := io.ReadAll(io.LimitReader(res.Body, 256))
			res.Body.Close()
			return nil, fmt.Errorf("%s: %s", res.Status, bytes.TrimSpace(snippet))
		}
		err = json.NewDecoder(io.LimitReader(res.Body, 8<<20)).Decode(&raw)
		res.Body.Close()
		if err != nil {
			return nil, err
		}
		for _, v := range raw.Vulns {
			ids = append(ids, v.ID)
		}
		if raw.NextPageToken == "" {
			return ids, nil
		}
		token = raw.NextPageToken
	}
	return ids, nil
}
