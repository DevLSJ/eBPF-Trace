package scan

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
)

// GitHub URL 파서(W4) — 받는 형식 전부와 거절 케이스
func TestParseGitHubURL(t *testing.T) {
	ok := []struct {
		in   string
		want RepoRef
	}{
		{"https://github.com/psf/requests", RepoRef{Owner: "psf", Repo: "requests"}},
		{"https://github.com/psf/requests.git", RepoRef{Owner: "psf", Repo: "requests"}},
		{"https://github.com/psf/requests/", RepoRef{Owner: "psf", Repo: "requests"}},
		{"https://www.github.com/psf/requests", RepoRef{Owner: "psf", Repo: "requests"}},
		{"  https://github.com/psf/requests?tab=readme-ov-file#readme ", RepoRef{Owner: "psf", Repo: "requests"}},
		{"https://github.com/psf/requests/tree/main", RepoRef{Owner: "psf", Repo: "requests", Ref: "main"}},
		{"https://github.com/psf/requests/tree/main/", RepoRef{Owner: "psf", Repo: "requests", Ref: "main"}},
		{"https://github.com/psf/requests/tree/v2.31.0/src/requests", RepoRef{Owner: "psf", Repo: "requests", Ref: "v2.31.0", Subpath: "src/requests"}},
		{"https://github.com/psf/requests/tree/main/src/requests/", RepoRef{Owner: "psf", Repo: "requests", Ref: "main", Subpath: "src/requests"}},
		{"https://github.com/psf/requests/commit/0e322af87745eff34caffe4df68456ebc20d9068", RepoRef{Owner: "psf", Repo: "requests", Ref: "0e322af87745eff34caffe4df68456ebc20d9068"}},
		{"https://github.com/psf/requests/releases/tag/v2.31.0", RepoRef{Owner: "psf", Repo: "requests", Ref: "v2.31.0"}},
		// 브랜치 이름의 / 는 지원하지 않는다 — 첫 조각이 ref 로 잡힌다(내려받기 404 · 폴더 없음 안내에서 알린다)
		{"https://github.com/psf/requests/tree/feature/x", RepoRef{Owner: "psf", Repo: "requests", Ref: "feature", Subpath: "x"}},
	}
	for _, c := range ok {
		got, err := ParseGitHubURL(c.in)
		if err != nil {
			t.Errorf("%q: unexpected error %v", c.in, err)
			continue
		}
		if got != c.want {
			t.Errorf("%q: got %+v, want %+v", c.in, got, c.want)
		}
	}
	bad := []struct{ in, hint string }{
		{"", "github.com"},
		{"github.com/psf/requests", "https://github.com"},
		{"http://github.com/psf/requests", "https://github.com"},
		{"https://gitlab.com/psf/requests", "github.com"},
		{"https://github.com/psf", "저장소"},
		{"https://github.com/psf/requests/pull/1", "tree/"},
		{"https://github.com/psf/requests/issues", "tree/"},
		{"https://github.com/psf/requests/blob/main/setup.py", "파일 올리기"},
		{"https://github.com/psf/requests/tree", "tree/"},
		{"https://github.com/psf/requests/tree/main/../x", "경로"},
		{"https://github.com/psf/requests/tree/main/a/./b", "경로"},
		{"https://github.com/psf/requests/releases", "tree/"},
		{"https://github.com/psf/requests/releases/tag", "tree/"},
		{"https://github.com/psf/re quests", "저장소"},
		{"https://github.com/../requests", "저장소"},
	}
	for _, c := range bad {
		got, err := ParseGitHubURL(c.in)
		if err == nil {
			t.Errorf("%q: expected rejection, got %+v", c.in, got)
			continue
		}
		var se *Error
		if !errors.As(err, &se) || se.Status != 400 {
			t.Errorf("%q: want *Error 400, got %v", c.in, err)
		}
		if !strings.Contains(err.Error(), c.hint) {
			t.Errorf("%q: message %q should mention %q", c.in, err.Error(), c.hint)
		}
	}
}

func TestRepoRefURLsAndLabel(t *testing.T) {
	cases := []struct {
		r              RepoRef
		tarball, label string
		canonical      string
	}{
		{RepoRef{Owner: "psf", Repo: "requests"}, "https://codeload.github.com/psf/requests/tar.gz/HEAD", "github.com/psf/requests", "https://github.com/psf/requests"},
		{RepoRef{Owner: "psf", Repo: "requests", Ref: "main"}, "https://codeload.github.com/psf/requests/tar.gz/main", "github.com/psf/requests@main", "https://github.com/psf/requests/tree/main"},
		{RepoRef{Owner: "o", Repo: "r", Ref: "v1.0+b", Subpath: "pkg/sub"}, "https://codeload.github.com/o/r/tar.gz/v1.0+b", "github.com/o/r@v1.0+b/pkg/sub", "https://github.com/o/r/tree/v1.0+b/pkg/sub"},
	}
	for _, c := range cases {
		if got := c.r.Tarball(defaultCodeload); got != c.tarball {
			t.Errorf("%+v tarball %q want %q", c.r, got, c.tarball)
		}
		if got := c.r.Label(); got != c.label {
			t.Errorf("%+v label %q want %q", c.r, got, c.label)
		}
		if got := c.r.URL(); got != c.canonical {
			t.Errorf("%+v url %q want %q", c.r, got, c.canonical)
		}
		// 정규화한 주소는 다시 읽어도 같다
		if back, err := ParseGitHubURL(c.r.URL()); err != nil || back != c.r {
			t.Errorf("%+v roundtrip %+v %v", c.r, back, err)
		}
	}
}

// fakeTarball: GitHub 식 tarball — 최상위 폴더 하나(repo-ref) 아래에 파일
func fakeTarball(t *testing.T, top string, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		b := []byte(files[n])
		if err := tw.WriteHeader(&tar.Header{Name: top + "/" + n, Mode: 0o644, Size: int64(len(b)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(b); err != nil {
			t.Fatal(err)
		}
	}
	tw.Close()
	gz.Close()
	return buf.Bytes()
}

func listFiles(t *testing.T, dir string) []string {
	t.Helper()
	var out []string
	err := filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			rel, _ := filepath.Rel(dir, p)
			out = append(out, filepath.ToSlash(rel))
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(out)
	return out
}

// 내려받기: codeload 주소 생성 · 하위 경로만 추출 · 경로 탈출 방지 · 404 안내
func TestFetchRepoSubpath(t *testing.T) {
	body := fakeTarball(t, "requests-abc123", map[string]string{
		"README.md":          "# hi",
		"pkg/setup.py":       "import os",
		"pkg/sub/a.py":       "x=1",
		"other/b.py":         "y=2",
		"pkg/../../evil.py":  "bad", // 정리하면 최상위 폴더 밖 → 버린다
		"pkg/sub/../../c.py": "z=3", // 정리하면 c.py — pkg 밖
	})
	var mu sync.Mutex
	var paths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		paths = append(paths, r.URL.Path)
		mu.Unlock()
		if strings.HasSuffix(r.URL.Path, "/tar.gz/nope") {
			http.NotFound(w, r)
			return
		}
		w.Write(body)
	}))
	defer srv.Close()
	last := func() string {
		mu.Lock()
		defer mu.Unlock()
		return paths[len(paths)-1]
	}
	ctx := context.Background()

	t.Run("whole repo strips the top folder", func(t *testing.T) {
		dst := t.TempDir()
		if err := fetchRepo(ctx, srv.URL, RepoRef{Owner: "psf", Repo: "requests"}, dst); err != nil {
			t.Fatal(err)
		}
		want := []string{"README.md", "c.py", "other/b.py", "pkg/setup.py", "pkg/sub/a.py"}
		if got := listFiles(t, dst); strings.Join(got, ",") != strings.Join(want, ",") {
			t.Fatalf("files %v want %v", got, want)
		}
		if p := last(); p != "/psf/requests/tar.gz/HEAD" {
			t.Fatalf("path %q", p)
		}
	})
	t.Run("subpath keeps only that folder", func(t *testing.T) {
		dst := t.TempDir()
		if err := fetchRepo(ctx, srv.URL, RepoRef{Owner: "psf", Repo: "requests", Ref: "main", Subpath: "pkg"}, dst); err != nil {
			t.Fatal(err)
		}
		want := []string{"pkg/setup.py", "pkg/sub/a.py"}
		if got := listFiles(t, dst); strings.Join(got, ",") != strings.Join(want, ",") {
			t.Fatalf("files %v want %v", got, want)
		}
		if p := last(); p != "/psf/requests/tar.gz/main" {
			t.Fatalf("path %q", p)
		}
		// 작업 폴더 밖으로 나간 파일이 없다
		if _, err := os.Stat(filepath.Join(filepath.Dir(dst), "evil.py")); err == nil {
			t.Fatal("path escape")
		}
	})
	t.Run("nested subpath", func(t *testing.T) {
		dst := t.TempDir()
		if err := fetchRepo(ctx, srv.URL, RepoRef{Owner: "psf", Repo: "requests", Ref: "main", Subpath: "pkg/sub"}, dst); err != nil {
			t.Fatal(err)
		}
		if got := listFiles(t, dst); strings.Join(got, ",") != "pkg/sub/a.py" {
			t.Fatalf("files %v", got)
		}
	})
	t.Run("missing subpath explains slash branches", func(t *testing.T) {
		err := fetchRepo(ctx, srv.URL, RepoRef{Owner: "psf", Repo: "requests", Ref: "feature", Subpath: "x"}, t.TempDir())
		if err == nil || !strings.Contains(err.Error(), "x") || !strings.Contains(err.Error(), "브랜치 이름에 /") {
			t.Fatalf("err %v", err)
		}
	})
	t.Run("404 says public repo and ref", func(t *testing.T) {
		err := fetchRepo(ctx, srv.URL, RepoRef{Owner: "psf", Repo: "requests", Ref: "nope"}, t.TempDir())
		if err == nil || !strings.Contains(err.Error(), "공개 저장소") || !strings.Contains(err.Error(), "브랜치/태그") || !strings.Contains(err.Error(), "@nope") {
			t.Fatalf("err %v", err)
		}
	})
}
