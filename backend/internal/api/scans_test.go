package api

import (
	"bytes"
	"context"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
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

// scanRunner: 검사기 컨테이너 대신 고정 결과 — OSV 는 requirements.txt 의 패키지 2개(urllib3 취약 · six 정상)
type scanRunner struct{}

const osvOut = `{"results":[{"source":{"path":"/work/%s/src/requirements.txt","type":"lockfile"},"packages":[
 {"package":{"name":"urllib3","version":"1.26.4","ecosystem":"PyPI"},"vulnerabilities":[{"id":"GHSA-1"}],"groups":[{"max_severity":"7.5"}]},
 {"package":{"name":"six","version":"1.16.0","ecosystem":"PyPI"}}]}]}`

func (scanRunner) Run(_ context.Context, s dockerapi.RunSpec) ([]byte, int, error) {
	if slices.Contains(s.Cmd, "--version") {
		return []byte("tool 1.0"), 0, nil
	}
	if s.Image == "osv" {
		id := strings.TrimSuffix(strings.TrimPrefix(s.Name, "supplyguard-scan-"), "-osv")
		return []byte(strings.ReplaceAll(osvOut, "%s", id)), 1, nil
	}
	return []byte(`{"results":{},"risk_score":{"score":0,"label":"no_risks_detected"}}`), 0, nil
}

type scanServer struct {
	srv   *httptest.Server
	scans *scan.Service
	mu    sync.Mutex
	hits  []string
}

func (s *scanServer) codeloadHits() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.hits)
}

// newScanServer: 검사 서비스 + review(차단 제안) + 가짜 codeload(404 만 돌려준다 — 실제 GitHub 에 닿지 않는다)
func newScanServer(t *testing.T, admin string) *scanServer {
	t.Helper()
	ss := &scanServer{}
	gh := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ss.mu.Lock()
		ss.hits = append(ss.hits, r.URL.Path)
		ss.mu.Unlock()
		http.NotFound(w, r)
	}))
	t.Cleanup(gh.Close)
	mem := store.NewMemory()
	if err := mem.ReplacePolicies(t.Context(), seedRules); err != nil {
		t.Fatal(err)
	}
	engine := rules.New(seedRules)
	rv := review.New(review.Options{Store: mem, Policies: mem, Audit: mem, Engine: engine, EnforceKill: true})
	if err := rv.Load(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := rv.Reload(t.Context()); err != nil {
		t.Fatal(err)
	}
	ss.scans = scan.New(scan.Options{Docker: scanRunner{}, Dir: t.TempDir(), Volume: "v", GuardDogImage: "guarddog", OSVImage: "osv", Store: mem, Blocker: rv, GitHub: gh.URL})
	if err := ss.scans.Load(t.Context()); err != nil {
		t.Fatal(err)
	}
	ss.srv = httptest.NewServer(Router(Deps{
		Engine: engine, Policies: mem, Audit: mem, Buffer: mem, Stats: stats.New().Snapshot,
		AdminToken: admin, Review: rv, Scans: ss.scans, OSV: &osv.Client{URL: "http://127.0.0.1:1"},
	}))
	t.Cleanup(ss.srv.Close)
	return ss
}

func (s *scanServer) wait(t *testing.T, id string) model.Scan {
	t.Helper()
	for i := 0; i < 200; i++ {
		r := do(t, "GET", s.srv.URL+"/api/scans/"+id, "", "")
		want(t, r, http.StatusOK, "get scan")
		sc := decode[model.Scan](t, r)
		if sc.Status != "running" {
			return sc
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("scan %s still running", id)
	return model.Scan{}
}

// 저장소 주소 확장(W4): tree/<ref>/<하위경로> 를 받고 라벨 · ref · subpath 를 남긴다. 404 는 안내 문구
func TestScanRepoURLHTTP(t *testing.T) {
	s := newScanServer(t, "tok")
	u := s.srv.URL
	want(t, do(t, "POST", u+"/api/scans", "", `{"kind":"repo","url":"https://github.com/psf/requests"}`), http.StatusUnauthorized, "no token")
	r := do(t, "POST", u+"/api/scans", "tok", `{"kind":"repo","url":"https://github.com/psf/requests/pull/1"}`)
	want(t, r, http.StatusBadRequest, "pull url")
	if msg := decode[map[string]string](t, r)["error"]; !strings.Contains(msg, "tree/") {
		t.Fatalf("hint %q", msg)
	}
	r = do(t, "POST", u+"/api/scans", "tok", `{"kind":"repo","url":"https://www.github.com/psf/requests/tree/v2.31.0/src/requests/"}`)
	want(t, r, http.StatusAccepted, "start")
	id := decode[map[string]string](t, r)["id"]
	sc := s.wait(t, id)
	tg := sc.Target
	if tg.Ref != "v2.31.0" || tg.Subpath != "src/requests" || tg.Label != "github.com/psf/requests@v2.31.0/src/requests" || tg.URL != "https://github.com/psf/requests/tree/v2.31.0/src/requests" {
		t.Fatalf("target %+v", tg)
	}
	if sc.Status != "failed" || !strings.Contains(sc.Error, "공개 저장소") || !strings.Contains(sc.Error, "브랜치/태그") {
		t.Fatalf("status %s err %q", sc.Status, sc.Error)
	}
	if hits := s.codeloadHits(); len(hits) != 1 || hits[0] != "/psf/requests/tar.gz/v2.31.0" {
		t.Fatalf("codeload path %v", hits)
	}
	list := decode[[]model.Scan](t, do(t, "GET", u+"/api/scans", "", ""))
	if len(list) != 1 || list[0].Target.Label != tg.Label || list[0].Packages != nil {
		t.Fatalf("list %+v", list)
	}
}

func multipartBody(t *testing.T, name, content string) (string, *bytes.Buffer) {
	t.Helper()
	var b bytes.Buffer
	mw := multipart.NewWriter(&b)
	fw, err := mw.CreateFormFile("file", name)
	if err != nil {
		t.Fatal(err)
	}
	fw.Write([]byte(content))
	mw.Close()
	return mw.FormDataContentType(), &b
}

// 파일(의존성) 검사 → 결과의 패키지 목록 → 고른 것만 차단 제안(W4)
func TestScanBlockSelectedPackagesHTTP(t *testing.T) {
	s := newScanServer(t, "tok")
	u := s.srv.URL
	ct, body := multipartBody(t, "requirements.txt", "urllib3==1.26.4\nsix\n")
	req, _ := http.NewRequest("POST", u+"/api/scans", body)
	req.Header.Set("Content-Type", ct)
	req.Header.Set("Authorization", "Bearer tok")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	want(t, res, http.StatusAccepted, "upload")
	id := decode[map[string]string](t, res)["id"]
	sc := s.wait(t, id)
	if sc.Status != "done" || sc.Verdict != "vulnerable" || len(sc.Packages) != 2 || sc.Packages[0].Manager != "pip" || sc.Packages[0].Name != "urllib3" || sc.Packages[0].Vulns != 1 || sc.Packages[1].Name != "six" {
		t.Fatalf("scan %+v packages %+v", sc.Status, sc.Packages)
	}
	block := u + "/api/scans/" + id + "/block"
	want(t, do(t, "POST", block, "", `{"packages":[{"name":"six"}]}`), http.StatusUnauthorized, "block without token")
	want(t, do(t, "POST", block, "tok", ""), http.StatusBadRequest, "file scan needs a selection")
	want(t, do(t, "POST", block, "tok", `{"packages":[]}`), http.StatusBadRequest, "empty selection")
	want(t, do(t, "POST", block, "tok", `{"packages":[{"name":"nope"}]}`), http.StatusBadRequest, "not in result")
	want(t, do(t, "POST", block, "tok", `{"bogus":1}`), http.StatusBadRequest, "unknown field")
	want(t, do(t, "POST", block, "tok", `{"packages":`), http.StatusBadRequest, "broken json")
	want(t, do(t, "POST", u+"/api/scans/scan-9999/block", "tok", `{"packages":[{"name":"six"}]}`), http.StatusNotFound, "unknown scan")

	r := do(t, "POST", block, "tok", `{"packages":[{"name":"urllib3","version":"1.26.4"},{"manager":"pip","name":"six"}]}`)
	want(t, r, http.StatusOK, "block")
	pid := decode[map[string]string](t, r)["proposalId"]
	if pid == "" {
		t.Fatal("no proposalId")
	}
	p := decode[model.Proposal](t, do(t, "GET", u+"/api/proposals/"+pid, "", ""))
	var vals []string
	for _, c := range p.Changes {
		if c.Op == "block" && c.List == model.ListPackages {
			vals = append(vals, c.Value)
		}
	}
	if strings.Join(vals, ",") != "pip:six,pip:urllib3" {
		t.Fatalf("changes %+v", p.Changes)
	}
	c := decode[model.Case](t, do(t, "GET", u+"/api/cases/"+p.CaseID, "", ""))
	if c.Source != model.CaseScan || c.ScanID == nil || *c.ScanID != id || c.Package != "pip:six, pip:urllib3" {
		t.Fatalf("case %+v", c)
	}
	if again := s.wait(t, id); again.CaseID == nil || *again.CaseID != c.ID {
		t.Fatalf("scan caseId %+v", again.CaseID)
	}
	// 같은 선택 → 같은 제안
	if pid2 := decode[map[string]string](t, do(t, "POST", block, "tok", `{"packages":[{"name":"six"},{"name":"urllib3"}]}`))["proposalId"]; pid2 != pid {
		t.Fatalf("same selection %q != %q", pid2, pid)
	}
}

// W18: 「차단 목록에 올리기」 본문의 사유(reason, 선택, 500자) → 공급망 검사 건의 판정 메모(note)
func TestScanBlockReasonHTTP(t *testing.T) {
	s := newScanServer(t, "tok")
	u := s.srv.URL
	ct, body := multipartBody(t, "requirements.txt", "urllib3==1.26.4\nsix\n")
	req, _ := http.NewRequest("POST", u+"/api/scans", body)
	req.Header.Set("Content-Type", ct)
	req.Header.Set("Authorization", "Bearer tok")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	want(t, res, http.StatusAccepted, "upload")
	id := decode[map[string]string](t, res)["id"]
	if sc := s.wait(t, id); sc.Status != "done" {
		t.Fatalf("scan %s", sc.Status)
	}
	block := u + "/api/scans/" + id + "/block"
	long := `{"packages":[{"name":"six"}],"reason":"` + strings.Repeat("가", 501) + `"}`
	want(t, do(t, "POST", block, "tok", long), http.StatusBadRequest, "reason 501")

	r := do(t, "POST", block, "tok", `{"packages":[{"name":"six"}],"reason":"  취약 버전 고정 전까지 차단  "}`)
	want(t, r, http.StatusOK, "block with reason")
	pid := decode[map[string]string](t, r)["proposalId"]
	p := decode[model.Proposal](t, do(t, "GET", u+"/api/proposals/"+pid, "", ""))
	c := decode[model.Case](t, do(t, "GET", u+"/api/cases/"+p.CaseID, "", ""))
	if !strings.Contains(c.Note, "공급망 검사 "+id) || !strings.HasSuffix(c.Note, "사유: 취약 버전 고정 전까지 차단") {
		t.Fatalf("case note must keep the scan context and end with the reason: %q", c.Note)
	}
	// 사유 없이도 된다(예전 호출)
	want(t, do(t, "POST", block, "tok", `{"packages":[{"name":"urllib3"}]}`), http.StatusOK, "block without reason")
}
