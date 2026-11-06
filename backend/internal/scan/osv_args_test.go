package scan

import (
	"context"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/dockerapi"
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/store"
)

// osvCmdRunner: OSV-Scanner 실행 인자만 모은다
type osvCmdRunner struct {
	mu   sync.Mutex
	cmds [][]string
}

func (r *osvCmdRunner) Run(_ context.Context, s dockerapi.RunSpec) ([]byte, int, error) {
	if len(s.Cmd) > 0 && s.Cmd[len(s.Cmd)-1] == "--version" {
		return []byte("tool 1.0"), 0, nil
	}
	if strings.HasSuffix(s.Name, "-osv") {
		r.mu.Lock()
		r.cmds = append(r.cmds, s.Cmd)
		r.mu.Unlock()
		return []byte(`{"results":[]}`), 0, nil
	}
	return []byte(`{"results":{},"risk_score":{"score":0,"label":"no_risks_detected"}}`), 0, nil
}

// 11/06 실측: OSV-Scanner 2.x 는 Go 호출 분석이 기본으로 켜져 있어, Go 소스가 있는 저장소(이 저장소 6.6MB)를
// 소스째 빌드하다 1024MB · 3072MB 모두 메모리 부족(137). 이 제품은 호출 분석 결과를 쓰지 않는다 — 저장소 · 파일 검사는 끈다
func TestRepoScanDisablesOSVCallAnalysis(t *testing.T) {
	body := fakeTarball(t, "app-abc123", map[string]string{
		"go.mod":  "module example.com/app\n\ngo 1.22\n",
		"main.go": "package main\n\nfunc main() {}\n",
	})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(body) }))
	defer srv.Close()
	r := &osvCmdRunner{}
	s := New(Options{Docker: r, Dir: t.TempDir(), Volume: "v", Store: store.NewMemory(), Blocker: &fakeBlocker{}, GitHub: srv.URL})
	if err := s.Load(t.Context()); err != nil {
		t.Fatal(err)
	}
	id, err := s.Start(t.Context(), Input{Kind: "repo", URL: "https://github.com/o/app"})
	if err != nil {
		t.Fatal(err)
	}
	if sc := waitDone(t, s, id); sc.Status != "done" {
		t.Fatalf("status %s err %q", sc.Status, sc.Error)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.cmds) == 0 {
		t.Fatal("OSV-Scanner was not run")
	}
	for _, c := range r.cmds {
		if !slices.Contains(c, "--no-call-analysis=all") {
			t.Errorf("OSV cmd without --no-call-analysis=all: %v", c)
		}
	}
}
