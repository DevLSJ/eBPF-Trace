package enforcer

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
)

// pauseServer: Docker Engine API 흉내 — pause · kill 요청을 순서대로 적고, pause 응답 코드 · 본문은 정해 둔 대로 돌려준다.
// 응답 본문은 11/16 sg-vm(Docker 29.8 · API 1.56) 실측 문장 그대로
type pauseServer struct {
	mu        sync.Mutex
	log       []string
	pauseCode int
	pauseBody string
}

func (s *pauseServer) add(x string) {
	s.mu.Lock()
	s.log = append(s.log, x)
	s.mu.Unlock()
}

func (s *pauseServer) got() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.log)
}

func (s *pauseServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/pause"):
		s.add("pause")
		w.WriteHeader(s.pauseCode)
		if s.pauseBody != "" {
			_, _ = w.Write([]byte(s.pauseBody))
		}
	case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/kill"):
		s.add("kill")
		w.WriteHeader(http.StatusNoContent)
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

// Tier 1 — 격리 순서(11/16 사용자 결정 「먼저 멈추고 증거 수집」): 증거 훅이 있으면 ① Docker pause → ② 증거 → ③ kill.
// pause 가 409 「not running」 · 404 면 컨테이너가 이미 끝났으니 증거도 kill 도 하지 않는다(격리 아님 + 사유, PR #16 과 같은 방식).
// 그 밖의 pause 실패(이미 정지 409 · 500)는 예전 순서(증거 → kill)로 계속한다. 증거 훅이 없으면 pause 없이 바로 kill
func TestPauseBeforeEvidence(t *testing.T) {
	cases := []struct {
		name      string
		code      int
		body      string
		hook      bool
		wantLog   []string
		wantErr   error
		wantNoErr bool
	}{
		{name: "paused", code: http.StatusNoContent, hook: true, wantLog: []string{"pause", "hook", "kill"}, wantNoErr: true},
		{name: "not running", code: http.StatusConflict, body: `{"message":"container 0123 is not running"}`, hook: true, wantLog: []string{"pause"}, wantErr: ErrNotRunning},
		{name: "not found", code: http.StatusNotFound, body: `{"message":"No such container: 0123"}`, hook: true, wantLog: []string{"pause"}, wantErr: ErrNotFound},
		{name: "already paused", code: http.StatusConflict, body: `{"message":"container 0123 is already paused"}`, hook: true, wantLog: []string{"pause", "hook", "kill"}, wantNoErr: true},
		{name: "server error", code: http.StatusInternalServerError, body: `{"message":"boom"}`, hook: true, wantLog: []string{"pause", "hook", "kill"}, wantNoErr: true},
		{name: "no hook", code: http.StatusNoContent, wantLog: []string{"kill"}, wantNoErr: true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := &pauseServer{pauseCode: c.code, pauseBody: c.body}
			srv := httptest.NewServer(s)
			defer srv.Close()
			d, err := NewDocker("tcp://" + strings.TrimPrefix(srv.URL, "http://"))
			if err != nil {
				t.Fatal(err)
			}
			if c.hook {
				d.BeforeKill = func(context.Context, string) { s.add("hook") }
			}
			ts, err := d.KillTimed(context.Background(), id)
			if got := s.got(); !slices.Equal(got, c.wantLog) {
				t.Fatalf("order = %v, want %v (err=%v)", got, c.wantLog, err)
			}
			switch {
			case c.wantNoErr && err != nil:
				t.Fatalf("err = %v, want nil", err)
			case c.wantErr != nil && !errors.Is(err, c.wantErr):
				t.Fatalf("err = %v, want %v", err, c.wantErr)
			}
			// 시각: 멈춘 경우만 pausedAt(≤ 증거 시작 ≤ 증거 끝 ≤ kill), 멈추지 못하고 계속한 경우는 사유만, 이미 끝난 경우는 모두 비어 있다
			paused := c.name == "paused"
			if paused != !ts.PausedAt.IsZero() {
				t.Fatalf("pausedAt = %v (case %s)", ts.PausedAt, c.name)
			}
			if paused && (ts.EvidenceStartedAt.Before(ts.PausedAt) || ts.EvidenceDoneAt.Before(ts.EvidenceStartedAt) || ts.KilledAt.Before(ts.EvidenceDoneAt)) {
				t.Fatalf("times out of order: %+v", ts)
			}
			if wantPauseErr := c.name == "already paused" || c.name == "server error"; wantPauseErr != (ts.PauseError != "") {
				t.Fatalf("pauseError = %q (case %s)", ts.PauseError, c.name)
			}
			if c.wantErr != nil && (!ts.EvidenceStartedAt.IsZero() || !ts.KilledAt.IsZero()) {
				t.Fatalf("stopped container must have no evidence · kill times: %+v", ts)
			}
		})
	}
}
