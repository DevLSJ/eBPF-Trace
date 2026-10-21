package api

import (
	"net/http"
	"strings"
	"testing"

	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/model"
)

// sg-install 결과 출력(W14): CLI 는 SANDBOX_TOKEN 으로 받는 finish 응답만 읽는다(감사 로그 · 화면 API 는 로그인 뒤).
// 그래서 finish 응답에 판정(status) · 위반 수 · 상위 규칙 · 건 id · 대시보드 경로가 함께 있어야 한다.
func TestFinishResponseCarriesResult(t *testing.T) {
	s := newReviewServer(t, "", "", true, seedRules)
	u := s.srv.URL
	r := do(t, "POST", u+"/api/installs", "", `{"manager":"pip","packages":["./reqeusts"],"container":"sg-install-pip-7-7","image":"python:3.12-slim"}`)
	want(t, r, http.StatusCreated, "start")
	id := decode[map[string]any](t, r)["id"].(string)

	base := model.Event{ContainerID: strings.Repeat("b", 64), ContainerName: "sg-install-pip-7-7", ImageName: "python:3.12-slim", Comm: "python3"}
	conn := base
	conn.Kind, conn.DstIP, conn.DstPort, conn.DstHost = model.KindConnect, "203.0.113.7", 8081, "cdn.reqeusts-update.test"
	open := base
	open.Kind, open.Path = model.KindOpen, "/etc/shadow"
	for _, ev := range []model.Event{conn, conn, open} {
		s.observe(t, ev)
	}

	r = do(t, "PUT", u+"/api/installs/"+id+"/finish", "", `{"exitCode":137}`)
	want(t, r, http.StatusOK, "finish")
	got := decode[map[string]any](t, r)
	if got["status"] != "isolated" || got["violationCount"] != float64(3) || got["caseId"] == nil {
		t.Fatalf("status · violationCount · caseId: %v %v %v", got["status"], got["violationCount"], got["caseId"])
	}
	if got["link"] != "/installs?id="+id {
		t.Fatalf("link: %v", got["link"])
	}
	top, _ := got["topRules"].([]any)
	if len(top) != 2 {
		t.Fatalf("topRules: %v", got["topRules"])
	}
	first := top[0].(map[string]any)
	if first["ruleId"] != "sandbox-egress" || first["count"] != float64(2) {
		t.Fatalf("topRules[0] 은 가장 많은 규칙: %v", top)
	}
	if _, ok := got["violations"]; !ok {
		t.Fatal("기존 세션 필드는 그대로")
	}

	// 위반이 없으면 topRules 는 빈 배열(null 아님), caseId null
	r = do(t, "POST", u+"/api/installs", "", `{"manager":"pip","packages":["requests"],"container":"sg-install-pip-8-8","image":"python:3.12-slim"}`)
	id = decode[map[string]any](t, r)["id"].(string)
	got = decode[map[string]any](t, do(t, "PUT", u+"/api/installs/"+id+"/finish", "", `{"exitCode":0}`))
	if top, ok := got["topRules"].([]any); !ok || len(top) != 0 || got["caseId"] != nil || got["status"] != "passed" {
		t.Fatalf("clean finish: %v", got)
	}
}
