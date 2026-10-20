package api

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/model"
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/review"
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/rules"
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/stats"
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/store"
)

// 정책 저장 전 확인(10/16): POST /api/policies/preview {rule} → Preview. 쓰기 없음이라 토큰 없이(제안 미리보기와 같음)
func TestPolicyPreviewHTTP(t *testing.T) {
	s := newReviewServer(t, "admin-token", "sandbox-token", false, seedRules)
	u := s.srv.URL
	s.observe(t, model.Event{Kind: model.KindConnect, ContainerID: strings.Repeat("b", 64), ContainerName: "web-api", DstIP: "140.82.112.3", DstPort: 9418, DstHost: "github.com"})

	r := do(t, "POST", u+"/api/policies/preview", "", `{"id":"egress-allowlist","kind":"connect","action":"kill","allowPorts":[443]}`)
	want(t, r, http.StatusOK, "preview")
	pv := decode[review.Preview](t, r)
	if pv.Evaluated != 1 || pv.Counts.ToBlocked != 1 || len(pv.Changed) != 1 || pv.Changed[0].After != model.LevelKilled {
		t.Fatalf("preview: %+v", pv)
	}
	if rs := s.engine.Rules(); rs[1].Action != model.ActionAlert {
		t.Fatal("preview must not save")
	}
	want(t, do(t, "POST", u+"/api/policies/preview", "", `{"id":"x",`), http.StatusBadRequest, "bad json")
	want(t, do(t, "POST", u+"/api/policies/preview", "", `{"id":"Bad ID","kind":"open","action":"alert"}`), http.StatusUnprocessableEntity, "invalid rule")
	want(t, do(t, "POST", u+"/api/policies/preview", "", `{"id":"blocklist-hosts","kind":"connect","action":"kill"}`), http.StatusConflict, "system rule")
}

// 서버 설정 보기(10/16): /api/info 에 감시 범위 · 제외 목록. 비어 있으면 null 이 아니라 []
func TestInfoScope(t *testing.T) {
	mem := store.NewMemory()
	for _, c := range []struct {
		in        Info
		watch, ig string
	}{
		{Info{}, `"watchContainers":[]`, `"ignoreContainers":[]`},
		{Info{WatchContainers: []string{"sg-install-*"}, IgnoreContainers: []string{"supplyguard-*"}}, `"watchContainers":["sg-install-*"]`, `"ignoreContainers":["supplyguard-*"]`},
	} {
		srv := httptest.NewServer(Router(Deps{Engine: rules.New(nil), Policies: mem, Audit: mem, Buffer: mem, Stats: stats.New().Snapshot, Info: c.in}))
		r := do(t, "GET", srv.URL+"/api/info", "", "")
		body := readBody(t, r)
		srv.Close()
		if !strings.Contains(body, c.watch) || !strings.Contains(body, c.ig) {
			t.Fatalf("info %s", body)
		}
	}
}

func readBody(t *testing.T, r *http.Response) string {
	t.Helper()
	defer r.Body.Close()
	b, err := io.ReadAll(r.Body)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
