package api

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/rules"
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/stats"
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/store"
)

// 평가 결과(11/04): GET /api/evaluation 은 bench/reports 의 JSON 4개를 해석하지 않고 그대로 묶어 내려 준다.

func evalServer(t *testing.T, dir string) *httptest.Server {
	t.Helper()
	mem := store.NewMemory()
	srv := httptest.NewServer(Router(Deps{
		Engine: rules.New(nil), Policies: mem, Audit: mem, Buffer: mem,
		Stats: stats.New().Snapshot, EvalReportsDir: dir,
	}))
	t.Cleanup(srv.Close)
	return srv
}

func writeEval(t *testing.T, dir string, files map[string]string) {
	t.Helper()
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

// getEval: 응답 코드와 최상위 키별 원문(JSON) — null 이면 "null"
func getEval(t *testing.T, srv *httptest.Server) (int, map[string]json.RawMessage) {
	t.Helper()
	resp := do(t, http.MethodGet, srv.URL+"/api/evaluation", "", "")
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]json.RawMessage
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("body %q: %v", b, err)
	}
	return resp.StatusCode, got
}

func sameJSON(t *testing.T, got json.RawMessage, want string) {
	t.Helper()
	var a, b any
	if err := json.Unmarshal(got, &a); err != nil {
		t.Fatalf("got %s: %v", got, err)
	}
	if err := json.Unmarshal([]byte(want), &b); err != nil {
		t.Fatal(err)
	}
	ja, _ := json.Marshal(a)
	jb, _ := json.Marshal(b)
	if string(ja) != string(jb) {
		t.Fatalf("got %s, want %s", ja, jb)
	}
}

func TestEvaluationAllFiles(t *testing.T) {
	dir := t.TempDir()
	writeEval(t, dir, map[string]string{
		"static.json":        `{"schema":1,"datasets":[{"id":"datadog-pypi","n":3}]}`,
		"runtime.json":       `{"schema":1,"runs":[]}`,
		"model.json":         `{"scope":"pypi","models":{"rules":{"f1":0.5}}}`,
		"model-all.json":     `{"scope":"all"}`,
		"static-items.jsonl": `{"pkg":"a"}` + "\n" + `{"pkg":"b"}` + "\n", // 내려 주지 않는다
	})
	code, got := getEval(t, evalServer(t, dir))
	if code != http.StatusOK {
		t.Fatalf("status %d %v", code, got)
	}
	if len(got) != 4 {
		t.Fatalf("keys must be exactly static · runtime · model · modelAll: %v", got)
	}
	sameJSON(t, got["static"], `{"schema":1,"datasets":[{"id":"datadog-pypi","n":3}]}`)
	sameJSON(t, got["runtime"], `{"schema":1,"runs":[]}`)
	sameJSON(t, got["model"], `{"scope":"pypi","models":{"rules":{"f1":0.5}}}`)
	sameJSON(t, got["modelAll"], `{"scope":"all"}`)
}

// 지금 main 과 같은 모양: model-all.json 없음 → 그 칸만 null
func TestEvaluationSomeMissing(t *testing.T) {
	dir := t.TempDir()
	writeEval(t, dir, map[string]string{"static.json": `{"a":1}`, "runtime.json": `[1,2]`, "model.json": `{"m":true}`})
	code, got := getEval(t, evalServer(t, dir))
	if code != http.StatusOK {
		t.Fatalf("status %d", code)
	}
	sameJSON(t, got["static"], `{"a":1}`)
	sameJSON(t, got["runtime"], `[1,2]`)
	sameJSON(t, got["model"], `{"m":true}`)
	if v, ok := got["modelAll"]; !ok || string(v) != "null" {
		t.Fatalf("modelAll must be null: %s (present %v)", v, ok)
	}
}

func TestEvaluationNoneIs404(t *testing.T) {
	for name, dir := range map[string]string{
		"empty dir":   t.TempDir(),
		"missing dir": filepath.Join(t.TempDir(), "nope"),
		"unset":       "",
	} {
		t.Run(name, func(t *testing.T) {
			if name == "empty dir" {
				// jsonl · md 만 있어도 결과 없음
				writeEval(t, dir, map[string]string{"static-items.jsonl": `{"pkg":"a"}`, "static.md": "# x"})
			}
			code, got := getEval(t, evalServer(t, dir))
			if code != http.StatusNotFound {
				t.Fatalf("status %d", code)
			}
			if string(got["error"]) != `"평가 결과 없음"` {
				t.Fatalf("body %v", got)
			}
		})
	}
}

// 파싱 안 되는 파일 · 상한을 넘는 파일은 null (나머지는 그대로). 파일이 있긴 하므로 404 가 아니다
func TestEvaluationBrokenAndOversize(t *testing.T) {
	dir := t.TempDir()
	writeEval(t, dir, map[string]string{
		"static.json":  `{"ok":1}`,
		"runtime.json": `{"broken":`,
		"model.json":   `{"big":"` + strings.Repeat("x", maxEvalReport) + `"}`, // 상한(5MB) 초과
	})

	code, got := getEval(t, evalServer(t, dir))
	if code != http.StatusOK {
		t.Fatalf("status %d", code)
	}
	sameJSON(t, got["static"], `{"ok":1}`)
	for _, k := range []string{"runtime", "model", "modelAll"} {
		if string(got[k]) != "null" {
			t.Fatalf("%s must be null: %s", k, got[k])
		}
	}

	// 전부 깨져 있어도 200 + null (없음과 구분)
	writeEval(t, dir, map[string]string{"static.json": `nope`})
	if code, got = getEval(t, evalServer(t, dir)); code != http.StatusOK || string(got["static"]) != "null" {
		t.Fatalf("all broken: %d %v", code, got)
	}
}

// 로그인 뒤 모든 역할이 읽는다: 익명 401 · 조회자 200 · Bearer ADMIN_TOKEN 200. 쓰기 메서드는 없다
func TestEvaluationWiredAuth(t *testing.T) {
	e := newWiredEnv(t)
	writeEval(t, e.evalDir, map[string]string{"static.json": `{"s":1}`})

	e.browser(t).must(401, "GET", "/api/evaluation", "")

	admin := e.browser(t)
	activateAdmin(t, e.authEnv, admin, false)
	if r := admin.must(200, "GET", "/api/evaluation", ""); r.body["static"] == nil {
		t.Fatalf("admin: %v", r.body)
	}

	r := admin.must(201, "POST", "/api/users", `{"username":"viewer1","displayName":"김조회","role":"viewer"}`)
	temp := str(r.body, "tempPassword")
	viewer := e.browser(t)
	viewer.must(200, "POST", "/api/auth/login", `{"username":"viewer1","password":"`+temp+`"}`)
	viewer.must(200, "POST", "/api/auth/password", `{"current":"`+temp+`","next":"viewer-pass-12"}`)
	r = viewer.must(200, "GET", "/api/evaluation", "")
	if s, _ := r.body["static"].(map[string]any); s["s"] != float64(1) || r.body["model"] != nil {
		t.Fatalf("viewer: %v", r.body)
	}

	if r := e.bearer(t, flowAdminTok, "GET", "/api/evaluation", ""); r.code != 200 {
		t.Fatalf("cli bearer: %d %v", r.code, r.body)
	}
	if r := e.bearer(t, flowAdminTok, "POST", "/api/evaluation", "{}"); r.code == 200 {
		t.Fatalf("no write route: %d", r.code)
	}
}
