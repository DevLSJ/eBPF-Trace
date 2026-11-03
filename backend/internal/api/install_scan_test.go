package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/dockerapi"
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/model"
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/osv"
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/review"
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/rules"
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/scan"
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/stats"
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/store"
)

type noRunner struct{}

func (noRunner) Run(context.Context, dockerapi.RunSpec) ([]byte, int, error) { return nil, 0, nil }

// installScanServer: 설치 세션 API + 공급망 검사(기록 3건: 끝난 검사 · 실행 중 · 실패)
func installScanServer(t *testing.T, withScans bool) (*httptest.Server, *review.Service) {
	t.Helper()
	mem := store.NewMemory()
	fin := time.Now().UTC().Add(-time.Minute)
	ins := "ins-0001"
	for _, sc := range []model.Scan{
		{ID: "scan-0007", Target: model.ScanTarget{Kind: "package", Manager: "pip", Name: "requests", Version: "2.32.3", Label: "pip requests"}, Status: "done",
			StartedAt: fin, FinishedAt: &fin, Verdict: "malicious", Risk: &model.ScanRisk{Score: 7.5, Label: "malicious"}, Threats: 3, InstallThreats: 2, VulnCount: 1,
			Trigger: model.ScanInstall, InstallID: &ins},
		{ID: "scan-0008", Target: model.ScanTarget{Kind: "package", Manager: "npm", Name: "lodash", Label: "npm lodash"}, Status: "failed", Error: "npm 에 lodash 이(가) 없습니다",
			StartedAt: fin, FinishedAt: &fin, Trigger: model.ScanInstall, InstallID: &ins},
	} {
		if err := mem.SaveScan(t.Context(), sc); err != nil {
			t.Fatal(err)
		}
	}
	engine := rules.New(nil)
	svc := review.New(review.Options{Store: mem, Policies: mem, Audit: mem, Engine: engine})
	if err := svc.Load(t.Context()); err != nil {
		t.Fatal(err)
	}
	d := Deps{Engine: engine, Policies: mem, Audit: mem, Buffer: mem, Stats: stats.New().Snapshot, AllowAnonymousWrites: true,
		Review: svc, OSV: &osv.Client{URL: "http://127.0.0.1:1"}}
	if withScans {
		sc := scan.New(scan.Options{Docker: noRunner{}, Dir: t.TempDir(), Store: mem})
		if err := sc.Load(t.Context()); err != nil {
			t.Fatal(err)
		}
		d.Scans = sc
	}
	srv := httptest.NewServer(Router(d))
	t.Cleanup(srv.Close)
	return srv, svc
}

func startSession(t *testing.T, u, pkg, container string) string {
	t.Helper()
	r := do(t, "POST", u+"/api/installs", "", `{"manager":"pip","packages":["`+pkg+`"],"container":"`+container+`","image":"python:3.12-slim"}`)
	want(t, r, http.StatusCreated, "start")
	return decode[map[string]any](t, r)["id"].(string)
}

// GET 목록 · 상세 · PUT finish 응답에 읽을 때 계산한 scan(설계 「API 계약」 모양 그대로) — scanSkip 은 scan.skip 으로만
func TestInstallResponseIncludesScan(t *testing.T) {
	srv, svc := installScanServer(t, true)
	u, ctx := srv.URL, t.Context()
	a := startSession(t, u, "requests", "sg-install-pip-1-1") // ins-0001: 검사를 시작한 세션
	b := startSession(t, u, "Requests", "sg-install-pip-2-2") // ins-0002: 같은 검사 재사용
	c := startSession(t, u, "./reqeusts", "sg-install-pip-3-3")
	d := startSession(t, u, "lodash", "sg-install-pip-4-4")
	for _, x := range []struct{ id, scan, skip string }{{a, "scan-0007", ""}, {b, "scan-0007", ""}, {c, "", "local"}, {d, "scan-0008", ""}} {
		if err := svc.AttachScan(ctx, x.id, x.scan, x.skip); err != nil {
			t.Fatal(err)
		}
	}
	wantA := map[string]any{"id": "scan-0007", "status": "done", "verdict": "malicious", "label": "pip requests", "version": "2.32.3", "riskScore": 7.5,
		"installThreats": float64(2), "threats": float64(3), "vulnCount": float64(1), "error": "", "skip": "", "reused": false}
	wantC := map[string]any{"id": "", "status": "skipped", "label": "pip ./reqeusts", "version": "", "riskScore": nil,
		"installThreats": float64(0), "threats": float64(0), "vulnCount": float64(0), "error": "", "skip": "local", "reused": false}
	wantD := map[string]any{"id": "scan-0008", "status": "failed", "label": "npm lodash", "version": "", "riskScore": nil,
		"installThreats": float64(0), "threats": float64(0), "vulnCount": float64(0), "error": "npm 에 lodash 이(가) 없습니다", "skip": "", "reused": true}
	same := func(what string, got any, want map[string]any) {
		t.Helper()
		m, ok := got.(map[string]any)
		if !ok || len(m) != len(want) {
			t.Fatalf("%s scan: %v", what, got)
		}
		for k, v := range want {
			if m[k] != v {
				t.Fatalf("%s scan.%s = %v, want %v (%v)", what, k, m[k], v, m)
			}
		}
	}

	list := decode[[]map[string]any](t, do(t, "GET", u+"/api/installs", "", ""))
	byID := map[string]map[string]any{}
	for _, x := range list {
		byID[x["id"].(string)] = x
		if _, ok := x["scanSkip"]; ok {
			t.Fatalf("scanSkip is carried by scan.skip only: %v", x)
		}
	}
	same("list a", byID[a]["scan"], wantA)
	if byID[a]["scanId"] != "scan-0007" || byID[c]["scanId"] != nil {
		t.Fatalf("scanId: %v %v", byID[a]["scanId"], byID[c]["scanId"])
	}
	wantB := map[string]any{}
	for k, v := range wantA {
		wantB[k] = v
	}
	wantB["reused"] = true
	same("list b", byID[b]["scan"], wantB)
	same("list c", byID[c]["scan"], wantC)
	same("list d", byID[d]["scan"], wantD)

	one := decode[map[string]any](t, do(t, "GET", u+"/api/installs/"+a, "", ""))
	same("get a", one["scan"], wantA)

	r := do(t, "PUT", u+"/api/installs/"+c+"/finish", "", `{"exitCode":0}`)
	want(t, r, http.StatusOK, "finish")
	fin := decode[map[string]any](t, r)
	same("finish c", fin["scan"], wantC)
	if fin["link"] != "/installs?id="+c || fin["topRules"] == nil || fin["status"] != "passed" {
		t.Fatalf("finish keeps its fields: %v", fin)
	}
}

// 옛 세션 · 검사가 붙지 않은 세션은 scan 필드가 없다(하위 호환). 검사 서비스가 없어도 건너뜀(off)은 보인다
func TestInstallWithoutScanOmitsScan(t *testing.T) {
	for _, withScans := range []bool{true, false} {
		srv, svc := installScanServer(t, withScans)
		u := srv.URL
		id := startSession(t, u, "requests", "sg-install-pip-1-1")
		check := func(what string, m map[string]any) {
			t.Helper()
			if _, ok := m["scan"]; ok {
				t.Fatalf("%s (scans=%v): scan must be absent: %v", what, withScans, m["scan"])
			}
			if v, ok := m["scanId"]; !ok || v != nil {
				t.Fatalf("%s: scanId null for old sessions: %v", what, m)
			}
		}
		check("list", decode[[]map[string]any](t, do(t, "GET", u+"/api/installs", "", ""))[0])
		check("get", decode[map[string]any](t, do(t, "GET", u+"/api/installs/"+id, "", "")))
		check("finish", decode[map[string]any](t, do(t, "PUT", u+"/api/installs/"+id+"/finish", "", `{"exitCode":0}`)))

		// 검사 기록에 없는 id(30일 지나 지워짐 · 검사 서비스 없음) → scan 없음
		id2 := startSession(t, u, "six", "sg-install-pip-2-2")
		if err := svc.AttachScan(t.Context(), id2, "scan-9999", ""); err != nil {
			t.Fatal(err)
		}
		if m := decode[map[string]any](t, do(t, "GET", u+"/api/installs/"+id2, "", "")); m["scan"] != nil {
			t.Fatalf("unknown scan id: %v", m["scan"])
		}
		id3 := startSession(t, u, "six", "sg-install-pip-3-3")
		if err := svc.AttachScan(t.Context(), id3, "", "off"); err != nil {
			t.Fatal(err)
		}
		m := decode[map[string]any](t, do(t, "GET", u+"/api/installs/"+id3, "", ""))
		if sc, _ := m["scan"].(map[string]any); sc == nil || sc["status"] != "skipped" || sc["skip"] != "off" {
			t.Fatalf("off skip (scans=%v): %v", withScans, m["scan"])
		}
	}
}
