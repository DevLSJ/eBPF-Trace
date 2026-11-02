package enforcer

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// Tier 1 — 격리 타임라인(10/30): KillTimed 는 증거 훅 시작 · 끝과 Docker kill 응답 시각을 돌려준다. 훅이 없으면 증거 시각은 비고,
// 훅이 예산(0.7초)을 넘기면 끝 시각은 예산 시점이며 kill 은 그 뒤에 나간다. kill 이 실패(409)하면 killedAt 이 없다
func TestVerdictTimelineOnKill(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "aaaaaaaaaaaa") {
			w.WriteHeader(http.StatusConflict)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()
	d, err := NewDocker("tcp://" + strings.TrimPrefix(srv.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	var _ Timed = d // Docker 는 Timed 를 구현한다

	// 1) 훅 없음: 증거 시각 없음, killedAt 만
	start := time.Now()
	ts, err := d.KillTimed(context.Background(), id)
	if err != nil || !ts.EvidenceStartedAt.IsZero() || !ts.EvidenceDoneAt.IsZero() || ts.KilledAt.IsZero() || ts.KilledAt.Before(start) {
		t.Fatalf("no hook: %+v %v", ts, err)
	}
	// 2) 20ms 훅: 시작 ≤ 끝 ≤ kill, 끝−시작 ≥ 20ms
	d.BeforeKill = func(context.Context, string) { time.Sleep(20 * time.Millisecond) }
	ts, err = d.KillTimed(context.Background(), id)
	if err != nil || ts.EvidenceStartedAt.IsZero() || ts.EvidenceDoneAt.Before(ts.EvidenceStartedAt) || ts.KilledAt.Before(ts.EvidenceDoneAt) {
		t.Fatalf("hook order: %+v %v", ts, err)
	}
	if ts.EvidenceDoneAt.Sub(ts.EvidenceStartedAt) < 20*time.Millisecond {
		t.Fatalf("evidence span must cover the hook: %v", ts.EvidenceDoneAt.Sub(ts.EvidenceStartedAt))
	}
	// 3) 예산을 넘기는 훅: 끝 시각은 약 0.7초, kill 은 그 뒤
	stop := make(chan struct{})
	defer close(stop)
	d.BeforeKill = func(context.Context, string) {
		select {
		case <-time.After(2 * time.Second):
		case <-stop:
		}
	}
	ts, err = d.KillTimed(context.Background(), id)
	span := ts.EvidenceDoneAt.Sub(ts.EvidenceStartedAt)
	if err != nil || span < beforeKillBudget-50*time.Millisecond || span > time.Second || ts.KilledAt.Before(ts.EvidenceDoneAt) {
		t.Fatalf("budget: span=%v %+v %v", span, ts, err)
	}
	// 4) 409(이미 멈춤): killedAt 없음, ErrNotRunning
	d.BeforeKill = nil
	ts, err = d.KillTimed(context.Background(), "aaaaaaaaaaaa")
	if !errors.Is(err, ErrNotRunning) || !ts.KilledAt.IsZero() {
		t.Fatalf("not running: %+v %v", ts, err)
	}
	// 5) Kill 은 KillTimed 와 같은 결과(호환)
	if err := d.Kill(context.Background(), id); err != nil {
		t.Fatal(err)
	}
}
