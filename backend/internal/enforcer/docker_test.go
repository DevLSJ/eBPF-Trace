package enforcer

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

const id = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func TestDockerKill(t *testing.T) {
	var gotPath, gotSignal string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotSignal = r.URL.Path, r.URL.Query().Get("signal")
		switch {
		case strings.Contains(r.URL.Path, "aaaaaaaaaaaa"):
			w.WriteHeader(http.StatusConflict)
		case r.Method != http.MethodPost:
			w.WriteHeader(http.StatusMethodNotAllowed)
		default:
			w.WriteHeader(http.StatusNoContent)
		}
	}))
	defer srv.Close()

	d, err := NewDocker("tcp://" + strings.TrimPrefix(srv.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	if err := d.Kill(context.Background(), id); err != nil {
		t.Fatal(err)
	}
	if gotPath != "/containers/"+id+"/kill" || gotSignal != "SIGKILL" {
		t.Fatalf("path=%s signal=%s", gotPath, gotSignal)
	}
	if err := d.Kill(context.Background(), "aaaaaaaaaaaa"); !errors.Is(err, ErrNotRunning) {
		t.Fatalf("want ErrNotRunning, got %v", err)
	}
	if err := d.Kill(context.Background(), "../images/x"); err == nil {
		t.Fatal("invalid id must be rejected before any request")
	}
}

// BeforeKill 훅(증거 보존, 10/20): 느리거나 터져도 kill 을 막지 못한다 — Tier 1
func TestDockerKillBeforeKillHook(t *testing.T) {
	var mu sync.Mutex
	var killedAt []time.Time
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		killedAt = append(killedAt, time.Now())
		mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()
	d, err := NewDocker("tcp://" + strings.TrimPrefix(srv.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	kills := func() int { mu.Lock(); defer mu.Unlock(); return len(killedAt) }

	// 1) ctx 를 무시하고 2초 버티는 훅 — kill 은 약 700ms 뒤에 나가야 한다
	stop := make(chan struct{})
	defer close(stop)
	var hmu sync.Mutex
	var gotID string
	d.BeforeKill = func(_ context.Context, cid string) {
		hmu.Lock()
		gotID = cid
		hmu.Unlock()
		select {
		case <-time.After(2 * time.Second):
		case <-stop:
		}
	}
	start := time.Now()
	if err := d.Kill(context.Background(), id); err != nil {
		t.Fatal(err)
	}
	elapsed := time.Since(start)
	t.Logf("slow hook: kill returned after %v", elapsed)
	if elapsed < beforeKillBudget-50*time.Millisecond || elapsed > 1000*time.Millisecond {
		t.Fatalf("kill must proceed ~%v after a stuck hook, took %v", beforeKillBudget, elapsed)
	}
	hmu.Lock()
	got := gotID
	hmu.Unlock()
	if got != id || kills() != 1 {
		t.Fatalf("hook id=%q kills=%d", got, kills())
	}

	// 2) 패닉하는 훅 — kill 은 그대로 성공
	d.BeforeKill = func(context.Context, string) { panic("collector bug") }
	if err := d.Kill(context.Background(), id); err != nil {
		t.Fatalf("panicking hook must not block kill: %v", err)
	}
	if kills() != 2 {
		t.Fatalf("kills=%d", kills())
	}

	// 3) 빨리 끝나는 훅 — 훅이 kill 요청보다 먼저 끝난다(증거는 kill 전에 모은다)
	var hookDone time.Time
	d.BeforeKill = func(context.Context, string) { hmu.Lock(); hookDone = time.Now(); hmu.Unlock() }
	if err := d.Kill(context.Background(), id); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	last := killedAt[len(killedAt)-1]
	mu.Unlock()
	hmu.Lock()
	done := hookDone
	hmu.Unlock()
	if done.IsZero() || last.Before(done) {
		t.Fatal("hook must complete before the kill request")
	}

	// 4) 잘못된 id — 훅도 kill 도 부르지 않는다
	called := false
	d.BeforeKill = func(context.Context, string) { hmu.Lock(); called = true; hmu.Unlock() }
	if err := d.Kill(context.Background(), "../x"); err == nil || called || kills() != 3 {
		t.Fatalf("invalid id: err=%v called=%v kills=%d", err, called, kills())
	}

	// 5) 훅 없음 — 기존 동작 그대로
	d.BeforeKill = nil
	if err := d.Kill(context.Background(), id); err != nil || kills() != 4 {
		t.Fatalf("no hook: err=%v kills=%d", err, kills())
	}
}
