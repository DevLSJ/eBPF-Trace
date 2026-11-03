package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/rules"
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/stats"
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/store"
)

// 기본 정책 파일과 지금 정책을 비교한다: 파일에만 있는 규칙(missing) · 같은 id 인데 조건이 다른 규칙(differs)
func TestPolicyDefaultsDiff(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "default.yaml")
	if err := os.WriteFile(file, []byte(`rules:
  - id: shadow
    kind: open
    action: kill
    denyPaths: [/etc/shadow]
  - id: egress
    kind: connect
    action: kill
    directIp: kill
    allowHosts: [pypi.org]
  - id: runtime-direct-ip
    kind: connect
    action: alert
    directIp: alert
`), 0o600); err != nil {
		t.Fatal(err)
	}
	// 지금 정책: shadow 는 같음(설명 · 꺼짐 여부만 다름), egress 는 directIp 가 없음, runtime-direct-ip 는 없음, mine 은 사용자 규칙
	engine := rules.New([]rules.Rule{
		{ID: "shadow", Kind: "open", Action: "kill", DenyPaths: []string{"/etc/shadow"}, Description: "내 설명", Disabled: true},
		{ID: "egress", Kind: "connect", Action: "kill", AllowHosts: []string{"pypi.org"}},
		{ID: "mine", Kind: "exec", Action: "alert", DenyComms: []string{"curl"}},
	})
	mem := store.NewMemory()
	srv := httptest.NewServer(Router(Deps{Engine: engine, Policies: mem, Audit: mem, Buffer: mem, Stats: stats.New().Snapshot, PolicyFile: file}))
	t.Cleanup(srv.Close)

	resp := do(t, http.MethodGet, srv.URL+"/api/policies/defaults", "", "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d", resp.StatusCode)
	}
	var got struct {
		Missing []rules.Rule `json:"missing"`
		Differs []struct {
			ID      string     `json:"id"`
			Default rules.Rule `json:"default"`
			Current rules.Rule `json:"current"`
		} `json:"differs"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if len(got.Missing) != 1 || got.Missing[0].ID != "runtime-direct-ip" {
		t.Fatalf("missing = %+v", got.Missing)
	}
	if len(got.Differs) != 1 || got.Differs[0].ID != "egress" || got.Differs[0].Default.DirectIP != "kill" || got.Differs[0].Current.DirectIP != "" {
		t.Fatalf("differs = %+v", got.Differs)
	}
}

// 기본 정책 파일이 없으면 라우트를 열지 않는다(「백엔드 미지원」과 같은 처리 — DELETE /api/policies/{id} 와 겹쳐 405 일 수 있다)
func TestPolicyDefaultsWithoutFile(t *testing.T) {
	srv, _, _ := newServer(t, "", true)
	if resp := do(t, http.MethodGet, srv.URL+"/api/policies/defaults", "", ""); resp.StatusCode == http.StatusOK {
		t.Fatalf("status %d", resp.StatusCode)
	}
}

// 연쇄 규칙(11/04): 비교는 steps 안의 조건까지 본다 — 같은 단계면 차이 없음(설명 · dryRun 은 비교 밖), 단계 경로 하나 · 창이 다르면 differs
func TestPolicyDefaultsSequenceSteps(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "default.yaml")
	if err := os.WriteFile(file, []byte(`rules:
  - id: chain-same
    kind: sequence
    action: kill
    dryRun: true
    windowSeconds: 10
    steps:
      - kind: exec
        denyComms: [curl, wget]
      - kind: open
        denyPaths: [/root/.netrc, /root/.kube/config]
  - id: chain-diff
    kind: sequence
    action: kill
    windowSeconds: 10
    steps:
      - kind: exec
        denyComms: [curl, wget]
      - kind: open
        denyPaths: [/root/.netrc, /root/.kube/config]
`), 0o600); err != nil {
		t.Fatal(err)
	}
	steps := func(paths ...string) []rules.Rule {
		return []rules.Rule{{Kind: "exec", DenyComms: []string{"curl", "wget"}}, {Kind: "open", DenyPaths: paths}}
	}
	engine := rules.New([]rules.Rule{
		{ID: "chain-same", Kind: "sequence", Action: "kill", Description: "내 설명", WindowSeconds: 10, Steps: steps("/root/.netrc", "/root/.kube/config")},
		{ID: "chain-diff", Kind: "sequence", Action: "kill", WindowSeconds: 20, Steps: steps("/root/.netrc")},
	})
	mem := store.NewMemory()
	srv := httptest.NewServer(Router(Deps{Engine: engine, Policies: mem, Audit: mem, Buffer: mem, Stats: stats.New().Snapshot, PolicyFile: file}))
	t.Cleanup(srv.Close)

	resp := do(t, http.MethodGet, srv.URL+"/api/policies/defaults", "", "")
	var got policyDefaults
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if len(got.Missing) != 0 || len(got.Differs) != 1 || got.Differs[0].ID != "chain-diff" {
		t.Fatalf("defaults = %+v", got)
	}
	d := got.Differs[0]
	if len(d.Default.Steps) != 2 || len(d.Default.Steps[1].DenyPaths) != 2 || len(d.Current.Steps[1].DenyPaths) != 1 || d.Current.WindowSeconds != 20 {
		t.Fatalf("steps must round-trip in differs: %+v", d)
	}
}
