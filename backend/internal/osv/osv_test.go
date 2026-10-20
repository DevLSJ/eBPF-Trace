package osv

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// 시간 초과(기본 5초)면 실패를 error 에 담고 캐시하지 않는다.
func TestQueryTimeout(t *testing.T) {
	block := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-block:
		case <-r.Context().Done():
		}
	}))
	t.Cleanup(func() { close(block); srv.Close() })
	c := &Client{URL: srv.URL, Timeout: 50 * time.Millisecond}
	start := time.Now()
	got := c.Query(context.Background(), "PyPI", "requests")
	if got.Error == nil || time.Since(start) > 2*time.Second {
		t.Fatalf("want a quick timeout error, got %+v after %v", got, time.Since(start))
	}
	if len(c.cache) != 0 {
		t.Fatal("failures must not be cached")
	}
	if New().Timeout != 0 {
		t.Fatal("zero means default")
	}
	c2 := &Client{}
	c2.defaults()
	if c2.Timeout != 5*time.Second || c2.TTL != time.Hour || c2.URL != DefaultURL {
		t.Fatalf("defaults: %v %v %s", c2.Timeout, c2.TTL, c2.URL)
	}
}

// 페이지가 나뉘면 next_page_token 으로 이어 받는다. 캐시는 TTL 이 지나면 다시 조회한다.
func TestQueryPagesAndTTL(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		var q map[string]any
		_ = json.NewDecoder(r.Body).Decode(&q)
		if q["page_token"] == nil {
			_, _ = io.WriteString(w, `{"vulns":[{"id":"A"}],"next_page_token":"p2"}`)
			return
		}
		_, _ = io.WriteString(w, `{"vulns":[{"id":"B"}]}`)
	}))
	t.Cleanup(srv.Close)
	now := time.Date(2026, 10, 15, 0, 0, 0, 0, time.UTC)
	c := &Client{URL: srv.URL, Now: func() time.Time { return now }}
	got := c.Query(context.Background(), "npm", "x")
	if got.Vulns != 2 || got.IDs[1] != "B" || calls != 2 {
		t.Fatalf("pages: %+v calls=%d", got, calls)
	}
	now = now.Add(59 * time.Minute)
	c.Query(context.Background(), "npm", "x")
	if calls != 2 {
		t.Fatal("within an hour → cache")
	}
	now = now.Add(2 * time.Minute)
	c.Query(context.Background(), "npm", "x")
	if calls != 4 {
		t.Fatalf("after an hour → query again, calls=%d", calls)
	}
}

func TestEcosystems(t *testing.T) {
	for _, e := range []string{"PyPI", "npm", "crates.io"} {
		if !ValidEcosystem(e) {
			t.Errorf("%s", e)
		}
	}
	if ValidEcosystem("pypi") || ValidEcosystem("Maven") {
		t.Error("only the three ecosystems")
	}
}
