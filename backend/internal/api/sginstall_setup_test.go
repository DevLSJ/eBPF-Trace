package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/auth"
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/model"
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/rules"
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/stats"
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/store"
)

// 설치 검사 「사용 방법」(11/06 결정 B, 11/09 구현): GET /api/sginstall/setup 은 실행 주소 안내 · 토큰 필요 여부,
// 관리자에게만 SANDBOX_TOKEN 을 채워 준다(조회자는 비움). GET /api/tools/sg-install 은 서버에 있는 스크립트를 내려받는다.
func sgSetupServer(t *testing.T, d Deps, role model.Role) *httptest.Server {
	t.Helper()
	mem := store.NewMemory()
	d.Engine, d.Policies, d.Audit, d.Buffer, d.Stats = rules.New(nil), mem, mem, mem, stats.New().Snapshot
	h := Router(d)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if role != "" {
			r = r.WithContext(auth.WithActor(r.Context(), auth.Actor{ID: "u1", Username: "u1", Name: "u1", Role: role}))
		}
		h.ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)
	return srv
}

type sgSetup struct {
	Download      string `json:"download"`
	API           string `json:"api"`
	TokenRequired bool   `json:"tokenRequired"`
	Token         string `json:"token"`
	Reporting     bool   `json:"reporting"`
}

func getSetup(t *testing.T, srv *httptest.Server) (sgSetup, string) {
	t.Helper()
	body := readBody(t, do(t, "GET", srv.URL+"/api/sginstall/setup", "", ""))
	var s sgSetup
	if err := json.Unmarshal([]byte(body), &s); err != nil {
		t.Fatalf("setup %q: %v", body, err)
	}
	return s, body
}

func TestSGInstallSetup(t *testing.T) {
	script := filepath.Join(t.TempDir(), "sg-install")
	if err := os.WriteFile(script, []byte("#!/usr/bin/env bash\necho sg-install\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	gadget := Deps{SandboxToken: "sbx-secret-token", SGInstallFile: script, Info: Info{Source: "gadget"}}

	// 관리자: 토큰 채움 · 서버 안 실행 주소는 nginx(80)
	s, _ := getSetup(t, sgSetupServer(t, gadget, model.RoleAdmin))
	if s.Token != "sbx-secret-token" || !s.TokenRequired || !s.Reporting || s.API != "http://127.0.0.1" || s.Download != "/api/tools/sg-install" {
		t.Errorf("admin setup = %+v", s)
	}
	// 조회자: 토큰 없음(필요하다는 것만)
	s, body := getSetup(t, sgSetupServer(t, gadget, model.RoleViewer))
	if s.Token != "" || strings.Contains(body, "sbx-secret-token") || !s.TokenRequired {
		t.Errorf("viewer setup = %s", body)
	}
	// mock(make dev): 토큰 없어도 보고 받음 · 백엔드 직접 :8000
	s, _ = getSetup(t, sgSetupServer(t, Deps{AllowAnonymousWrites: true, SGInstallFile: script, Info: Info{Source: "mock"}}, model.RoleAdmin))
	if s.TokenRequired || !s.Reporting || s.API != "http://127.0.0.1:8000" {
		t.Errorf("mock setup = %+v", s)
	}
	// 가젯인데 SANDBOX_TOKEN 이 없으면 보고가 꺼져 있다고 알린다 · 파일이 없으면 내려받기 없음
	s, _ = getSetup(t, sgSetupServer(t, Deps{Info: Info{Source: "gadget"}}, model.RoleAdmin))
	if s.Reporting || s.Download != "" {
		t.Errorf("no token setup = %+v", s)
	}

	// SG_INSTALL_API 가 있으면 추정 대신 그 값(11/09 — make dev 는 실제 가젯인데 nginx 없이 :8000)
	s, _ = getSetup(t, sgSetupServer(t, Deps{SandboxToken: "x", SGInstallAPI: "http://127.0.0.1:8000", Info: Info{Source: "gadget"}}, model.RoleAdmin))
	if s.API != "http://127.0.0.1:8000" {
		t.Errorf("SG_INSTALL_API override = %+v", s)
	}

	// 내려받기: 스크립트 그대로 · 첨부 파일 이름 sg-install
	srv := sgSetupServer(t, gadget, model.RoleViewer)
	r := do(t, "GET", srv.URL+"/api/tools/sg-install", "", "")
	if r.StatusCode != 200 || !strings.Contains(r.Header.Get("Content-Disposition"), `filename="sg-install"`) {
		t.Errorf("download %d %q", r.StatusCode, r.Header.Get("Content-Disposition"))
	}
	if b := readBody(t, r); b != "#!/usr/bin/env bash\necho sg-install\n" {
		t.Errorf("download body %q", b)
	}
	// 파일이 없으면 404
	srv = sgSetupServer(t, Deps{SGInstallFile: filepath.Join(t.TempDir(), "none"), Info: Info{Source: "gadget"}}, model.RoleAdmin)
	if r := do(t, "GET", srv.URL+"/api/tools/sg-install", "", ""); r.StatusCode != http.StatusNotFound {
		t.Errorf("missing file %d", r.StatusCode)
	}
}
