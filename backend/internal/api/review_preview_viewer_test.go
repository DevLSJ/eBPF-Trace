package api

import (
	"strings"
	"testing"

	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/model"
)

// W15: 판정 미리보기는 읽기 전용 POST — 조회자도 쓸 수 있다(ViewerWritePatterns). 판정 · 적용 · 버림 · 해제는 403 그대로.
func TestDecisionPreviewViewer(t *testing.T) {
	e := newWiredEnv(t)
	admin := e.browser(t)
	activateAdmin(t, e.authEnv, admin, false)

	v := e.engine.Evaluate(model.Event{Kind: model.KindOpen, ContainerID: strings.Repeat("a", 64), ContainerName: "web-1",
		ImageName: "demo/web:1", Path: "/etc/shadow"})
	v.Enforced = true
	e.rv.Observe(&v)
	if v.CaseID == nil {
		t.Fatal("runtime kill must open a case")
	}
	cid := *v.CaseID

	r := admin.must(201, "POST", "/api/users", `{"username":"viewer1","displayName":"김조회","role":"viewer"}`)
	temp := str(r.body, "tempPassword")
	viewer := e.browser(t)
	viewer.must(200, "POST", "/api/auth/login", `{"username":"viewer1","password":"`+temp+`"}`)
	viewer.must(200, "POST", "/api/auth/password", `{"current":"`+temp+`","next":"viewer-pass-12"}`)

	pv := viewer.must(200, "POST", "/api/cases/"+cid+"/preview", `{"decision":"malicious"}`)
	if _, ok := pv.body["effects"]; !ok {
		t.Fatalf("viewer preview: %v", pv.body)
	}
	viewer.must(403, "POST", "/api/cases/"+cid+"/decide", `{"decision":"malicious"}`)
	if c, _ := e.rv.GetCase(cid); c.State != model.CaseOpen {
		t.Fatalf("viewer must not change the case: %+v", c)
	}
	r = admin.must(200, "POST", "/api/cases/"+cid+"/decide", `{"decision":"malicious"}`)
	pid := str(r.body["proposal"].(map[string]any), "id")
	viewer.must(403, "POST", "/api/proposals/"+pid+"/discard", `{"reason":"x"}`)
	viewer.must(403, "POST", "/api/proposals/"+pid+"/apply", `{"reason":"x"}`)
}
