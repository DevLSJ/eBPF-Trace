package dockerapi

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// Tier 1 — 시연 컨테이너 호출(10/30): 경로 · 메서드 · 본문이 Docker Engine API 모양 그대로이고, 이미지가 없으면 받은 뒤 다시 만든다
func TestContainerCalls(t *testing.T) {
	var mu sync.Mutex
	var calls []string
	var created map[string]any
	var archive []byte
	missing := true
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		calls = append(calls, r.Method+" "+r.URL.RequestURI())
		mu.Unlock()
		switch {
		case r.URL.Path == "/_ping":
			w.WriteHeader(200)
		case r.URL.Path == "/containers/create":
			if missing {
				w.WriteHeader(404)
				return
			}
			_ = json.NewDecoder(r.Body).Decode(&created)
			w.WriteHeader(201)
			_, _ = w.Write([]byte(`{"Id":"cid123"}`))
		case r.URL.Path == "/images/create":
			missing = false
			w.WriteHeader(200)
		case r.URL.Path == "/containers/cid123/archive":
			if r.Method != http.MethodPut || r.Header.Get("Content-Type") != "application/x-tar" {
				w.WriteHeader(400)
				return
			}
			archive, _ = io.ReadAll(r.Body)
			w.WriteHeader(200)
		case r.URL.Path == "/containers/cid123/start":
			w.WriteHeader(204)
		case r.URL.Path == "/containers/cid123/wait":
			_, _ = w.Write([]byte(`{"StatusCode":137}`))
		case r.URL.Path == "/containers/cid123" && r.Method == http.MethodDelete:
			w.WriteHeader(204)
		default:
			w.WriteHeader(500)
		}
	}))
	defer srv.Close()
	c, err := New("tcp://" + strings.TrimPrefix(srv.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := c.Ping(ctx); err != nil {
		t.Fatal(err)
	}
	id, err := c.CreateContainer(ctx, CreateSpec{Name: "sg-install-demo-1", Image: "python:3.12-slim", Cmd: []string{"pip", "install", "/pkg/reqeusts"},
		Env: []string{"SG_DEMO_SCENARIOS=all"}, Labels: map[string]string{"supplyguard.demo": "install"}})
	if err != nil || id != "cid123" {
		t.Fatalf("create: %q %v", id, err)
	}
	if created["Image"] != "python:3.12-slim" || created["Labels"].(map[string]any)["supplyguard.demo"] != "install" || created["HostConfig"].(map[string]any)["NetworkMode"] != "bridge" {
		t.Fatalf("create body: %v", created)
	}
	if err := c.PutArchive(ctx, id, "/", strings.NewReader("TARBYTES")); err != nil || string(archive) != "TARBYTES" {
		t.Fatalf("archive: %v %q", err, archive)
	}
	if err := c.StartContainer(ctx, id); err != nil {
		t.Fatal(err)
	}
	if code, err := c.WaitContainer(ctx, id); err != nil || code != 137 {
		t.Fatalf("wait: %d %v", code, err)
	}
	if err := c.RemoveContainer(ctx, id, true); err != nil {
		t.Fatal(err)
	}
	want := []string{"GET /_ping", "POST /containers/create?name=sg-install-demo-1", "POST /images/create?fromImage=python&tag=3.12-slim",
		"POST /containers/create?name=sg-install-demo-1", "PUT /containers/cid123/archive?path=%2F", "POST /containers/cid123/start",
		"POST /containers/cid123/wait", "DELETE /containers/cid123?force=1"}
	mu.Lock()
	got := strings.Join(calls, "\n")
	mu.Unlock()
	if got != strings.Join(want, "\n") {
		t.Fatalf("calls:\n%s\nwant:\n%s", got, strings.Join(want, "\n"))
	}
	// 데몬이 없으면 Ping 이 실패한다
	down, _ := New("tcp://127.0.0.1:1")
	if err := down.Ping(ctx); err == nil {
		t.Fatal("ping to a closed port must fail")
	}
}
