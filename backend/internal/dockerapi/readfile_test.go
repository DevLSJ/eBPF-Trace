package dockerapi

import (
	"archive/tar"
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// 증거 코드 보기(11/10): GET /containers/{id}/archive?path= 의 tar 에서 첫 항목(일반 파일)만 limit 바이트까지 읽는다.
func tarOf(t *testing.T, name string, typ byte, body string) []byte {
	t.Helper()
	var b bytes.Buffer
	w := tar.NewWriter(&b)
	if err := w.WriteHeader(&tar.Header{Name: name, Typeflag: typ, Mode: 0o644, Size: int64(len(body))}); err != nil {
		t.Fatal(err)
	}
	if typ == tar.TypeReg {
		_, _ = w.Write([]byte(body))
	}
	_ = w.Close()
	return b.Bytes()
}

func TestReadFile(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Query().Get("path")
		switch {
		case strings.Contains(r.URL.Path, "/gone/"):
			http.Error(w, `{"message":"No such container"}`, http.StatusNotFound)
		case gotPath == "/pkg/demo":
			_, _ = w.Write(tarOf(t, "demo", tar.TypeDir, ""))
		case gotPath == "/missing":
			http.Error(w, `{"message":"Could not find the file /missing in container x"}`, http.StatusNotFound)
		default:
			_, _ = w.Write(tarOf(t, "setup.py", tar.TypeReg, "import os\nprint('hi')\n"))
		}
	}))
	defer srv.Close()
	c := &Client{http: srv.Client(), base: srv.URL}
	ctx := context.Background()

	b, size, err := c.ReadFile(ctx, "abc", "/pkg/demo/setup.py", 1<<10)
	if err != nil || string(b) != "import os\nprint('hi')\n" || size != int64(len(b)) || gotPath != "/pkg/demo/setup.py" {
		t.Fatalf("ReadFile = %q %d %v (path %q)", b, size, err, gotPath)
	}
	// 상한: 앞에서 limit 바이트만, size 는 원래 크기
	b, size, err = c.ReadFile(ctx, "abc", "/pkg/demo/setup.py", 5)
	if err != nil || string(b) != "impor" || size != 22 {
		t.Fatalf("limited = %q %d %v", b, size, err)
	}
	if _, _, err := c.ReadFile(ctx, "abc", "/pkg/demo", 1<<10); !errors.Is(err, ErrNotFile) {
		t.Fatalf("dir = %v, want ErrNotFile", err)
	}
	if _, _, err := c.ReadFile(ctx, "abc", "/missing", 1<<10); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing = %v, want ErrNotFound", err)
	}
	if _, _, err := c.ReadFile(ctx, "gone", "/x", 1<<10); !errors.Is(err, ErrNotFound) {
		t.Fatalf("gone = %v, want ErrNotFound", err)
	}
}
