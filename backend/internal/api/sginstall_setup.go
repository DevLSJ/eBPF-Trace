package api

import (
	"net/http"
	"os"

	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/auth"
)

// 설치 검사 「사용 방법」(11/06 결정 B · 11/09): 화면이 sg-install 내려받기 · 환경 변수 · 실행 명령을 채워 보인다.
// SANDBOX_TOKEN 은 sg-install 의 세션 보고 · 차단 확인에만 쓰이는 토큰이라 관리자에게는 채워 준다(조회자는 「관리자에게 받기」).

type sgInstallSetup struct {
	// Download: 내려받기 경로(서버에 스크립트가 있을 때만). 화면은 로그인한 채 이 경로를 연다
	Download string `json:"download,omitempty"`
	// API: 서버 안에서 실행할 때 SUPPLYGUARD_API — compose(nginx 80) 는 http://127.0.0.1, make dev(mock) 는 백엔드 :8000.
	// sg-install 은 감시받는 호스트에서 돌아야 한다(eBPF 는 그 호스트의 컨테이너만 본다)
	API string `json:"api"`
	// TokenRequired: SUPPLYGUARD_SANDBOX_TOKEN 이 필요한지. Token 은 관리자에게만
	TokenRequired bool   `json:"tokenRequired"`
	Token         string `json:"token,omitempty"`
	// Reporting: 백엔드가 설치 보고를 받는지(가젯 소스인데 SANDBOX_TOKEN 이 비면 꺼져 있다)
	Reporting bool `json:"reporting"`
}

func (h *handlers) sginstallSetup(w http.ResponseWriter, r *http.Request) {
	out := sgInstallSetup{
		API:           "http://127.0.0.1",
		TokenRequired: h.SandboxToken != "",
		Reporting:     h.SandboxToken != "" || h.AllowAnonymousWrites,
	}
	if h.Info.Source == "mock" {
		out.API = "http://127.0.0.1:8000"
	}
	if h.sginstallFileOK() {
		out.Download = "/api/tools/sg-install"
	}
	if a, ok := auth.ActorFrom(r.Context()); ok && a.IsAdmin() {
		out.Token = h.SandboxToken
	}
	writeJSON(w, http.StatusOK, out)
}

func (h *handlers) sginstallFileOK() bool {
	if h.SGInstallFile == "" {
		return false
	}
	st, err := os.Stat(h.SGInstallFile)
	return err == nil && st.Mode().IsRegular()
}

// sginstallScript: 서버 이미지에 든 tools/sg-install 그대로(서버와 같은 판). 로그인 뒤 모든 역할
func (h *handlers) sginstallScript(w http.ResponseWriter, r *http.Request) {
	if !h.sginstallFileOK() {
		writeErr(w, http.StatusNotFound, "서버에 sg-install 이 없음(SG_INSTALL_FILE)")
		return
	}
	w.Header().Set("Content-Type", "text/x-shellscript; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="sg-install"`)
	w.Header().Set("Cache-Control", "no-store")
	http.ServeFile(w, r, h.SGInstallFile)
}
