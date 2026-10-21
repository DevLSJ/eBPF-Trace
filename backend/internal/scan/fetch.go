package scan

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
)

// 대상을 작업 폴더(dst)에 풀어 둔다 — 검사기는 이 폴더만 읽기 전용으로 본다. 코드는 실행하지 않는다.

const (
	maxDownload = 50 << 20  // 내려받기 · 업로드 상한
	maxExtract  = 200 << 20 // 풀었을 때 합 상한(압축 폭탄 방지)
	maxFiles    = 20000
)

var httpc = &http.Client{}

func get(ctx context.Context, u string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "SupplyGuard-scan")
	res, err := httpc.Do(req)
	if err != nil {
		return nil, err
	}
	if res.StatusCode == http.StatusNotFound {
		res.Body.Close()
		return nil, errNotFound
	}
	if res.StatusCode != http.StatusOK {
		res.Body.Close()
		return nil, fmt.Errorf("%s: %s", u, res.Status)
	}
	return res, nil
}

var errNotFound = errors.New("찾을 수 없음")

// fetchPackage: PyPI · npm 레지스트리에서 pip · npm 이 실제로 설치하는 파일을 내려받아 푼다 — pip 은 wheel 우선, 없으면 sdist(설치 때 setup.py 가 돈다)
func fetchPackage(ctx context.Context, manager, name, version, dst string) (string, error) {
	var archive, resolved string
	switch manager {
	case "pip":
		u := "https://pypi.org/pypi/" + url.PathEscape(name) + "/json"
		if version != "" {
			u = "https://pypi.org/pypi/" + url.PathEscape(name) + "/" + url.PathEscape(version) + "/json"
		}
		res, err := get(ctx, u)
		if err != nil {
			if errors.Is(err, errNotFound) {
				return "", fmt.Errorf("PyPI 에 %s%s 이(가) 없습니다", name, ver(version, "=="))
			}
			return "", err
		}
		var meta struct {
			Info struct{ Version string } `json:"info"`
			URLs []struct {
				PackageType string `json:"packagetype"`
				URL         string `json:"url"`
			} `json:"urls"`
		}
		err = json.NewDecoder(io.LimitReader(res.Body, 8<<20)).Decode(&meta)
		res.Body.Close()
		if err != nil {
			return "", err
		}
		resolved = meta.Info.Version
		for _, want := range []string{"bdist_wheel", "sdist"} {
			for _, x := range meta.URLs {
				if x.PackageType == want && archive == "" {
					archive = x.URL
				}
			}
		}
	case "npm":
		tag := version
		if tag == "" {
			tag = "latest"
		}
		res, err := get(ctx, "https://registry.npmjs.org/"+strings.ReplaceAll(url.PathEscape(name), "%40", "@")+"/"+url.PathEscape(tag))
		if err != nil {
			if errors.Is(err, errNotFound) {
				return "", fmt.Errorf("npm 에 %s%s 이(가) 없습니다", name, ver(version, "@"))
			}
			return "", err
		}
		var meta struct {
			Version string `json:"version"`
			Dist    struct {
				Tarball string `json:"tarball"`
			} `json:"dist"`
		}
		err = json.NewDecoder(io.LimitReader(res.Body, 8<<20)).Decode(&meta)
		res.Body.Close()
		if err != nil {
			return "", err
		}
		resolved, archive = meta.Version, meta.Dist.Tarball
	}
	if archive == "" {
		return "", fmt.Errorf("%s 의 내려받을 파일이 없습니다", name)
	}
	res, err := get(ctx, archive)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()
	return resolved, extract(path.Base(archive), io.LimitReader(res.Body, maxDownload+1), dst)
}

// fetchRepo: GitHub tarball(codeload, base 는 기본 codeload 주소 또는 테스트 서버) — ref 가 비면 HEAD.
// tarball 의 최상위 폴더(repo-ref)를 벗겨 저장소 기준 경로로 두고, 하위 경로가 있으면 그 폴더 아래만 둔다(그 밖은 읽지 않고 건너뛴다).
// 항목 이름은 먼저 정리(path.Clean)하므로 ../ 로 하위 경로 밖 · 작업 폴더 밖으로 나가지 못한다(writeFile 이 한 번 더 막는다)
func fetchRepo(ctx context.Context, base string, ref RepoRef, dst string) error {
	res, err := get(ctx, ref.Tarball(base))
	if err != nil {
		if errors.Is(err, errNotFound) {
			msg := ref.Label() + " 을(를) 찾을 수 없습니다 — 공개 저장소 · 브랜치/태그를 확인하세요"
			if ref.Subpath != "" {
				msg += "(브랜치 이름에 / 가 있으면 지원하지 않습니다)"
			}
			return errors.New(msg)
		}
		return err
	}
	defer res.Body.Close()
	prefix := ""
	if ref.Subpath != "" {
		prefix = ref.Subpath + "/"
	}
	n, err := extractTarGz(io.LimitReader(res.Body, maxDownload+1), dst, func(name string) (string, bool) {
		clean := path.Clean("/" + filepath.ToSlash(name))[1:]
		_, rest, ok := strings.Cut(clean, "/") // 최상위 폴더를 벗긴다
		if !ok || rest == "" || (prefix != "" && !strings.HasPrefix(rest, prefix)) {
			return "", false
		}
		return rest, true
	})
	if err != nil {
		return err
	}
	if n == 0 && ref.Subpath != "" {
		return fmt.Errorf("내려받은 압축본에 %s 폴더가 없습니다 — 경로 · 브랜치를 확인하세요. 브랜치 이름에 / 가 있으면 지원하지 않고, 저장소의 .gitattributes 가 export-ignore 로 뺀 폴더(흔히 tests/)는 GitHub 압축본에 들어 있지 않습니다", ref.Subpath)
	}
	return nil
}

func ver(v, sep string) string {
	if v == "" {
		return ""
	}
	return sep + v
}

// extract: 이름으로 형식을 고른다. .tar.gz · .tgz → tar, .whl · .zip → zip, 그 밖은 파일 하나로 둔다.
// 경로 탈출(../, 절대 경로) · 링크 · 크기 폭탄을 막는다(일반 파일만 쓴다).
func extract(name string, r io.Reader, dst string) error {
	low := strings.ToLower(name)
	switch {
	case strings.HasSuffix(low, ".tar.gz") || strings.HasSuffix(low, ".tgz"):
		_, err := extractTarGz(r, dst, func(name string) (string, bool) { return name, true })
		return err
	case strings.HasSuffix(low, ".whl") || strings.HasSuffix(low, ".zip"):
		tmp, err := os.CreateTemp("", "sg-zip-*")
		if err != nil {
			return err
		}
		defer os.Remove(tmp.Name())
		defer tmp.Close()
		size, err := io.Copy(tmp, r)
		if err != nil {
			return err
		}
		if size > maxDownload {
			return errors.New("파일은 50MB 까지 올릴 수 있습니다")
		}
		zr, err := zip.NewReader(tmp, size)
		if err != nil {
			return fmt.Errorf("압축을 풀 수 없습니다: %w", err)
		}
		if len(zr.File) > maxFiles {
			return errors.New("파일이 너무 많습니다")
		}
		var total uint64
		for _, f := range zr.File {
			if f.FileInfo().IsDir() || !f.Mode().IsRegular() {
				continue
			}
			if total += f.UncompressedSize64; total > maxExtract {
				return errors.New("풀었을 때 200MB 를 넘습니다")
			}
			rc, err := f.Open()
			if err != nil {
				return err
			}
			err = writeFile(dst, f.Name, rc, int64(f.UncompressedSize64))
			rc.Close()
			if err != nil {
				return err
			}
		}
		return nil
	default:
		return writeFile(dst, filepath.Base(name), r, maxDownload)
	}
}

// extractTarGz: tar.gz 를 dst 에 푼다. mapName 이 항목 이름을 쓸 경로로 바꾸거나(false 면) 건너뛴다. 쓴 파일 수를 돌려준다.
// 일반 파일만, 개수 · 합계 크기 상한, 경로 탈출은 writeFile 이 막는다
func extractTarGz(r io.Reader, dst string, mapName func(string) (string, bool)) (int, error) {
	gz, err := gzip.NewReader(r)
	if err != nil {
		return 0, fmt.Errorf("압축을 풀 수 없습니다: %w", err)
	}
	tr := tar.NewReader(gz)
	var total int64
	written := 0
	for n := 0; ; n++ {
		h, err := tr.Next()
		if err == io.EOF {
			return written, nil
		}
		if err != nil {
			return written, fmt.Errorf("압축을 풀 수 없습니다: %w", err)
		}
		if n > maxFiles {
			return written, errors.New("파일이 너무 많습니다")
		}
		if h.Typeflag != tar.TypeReg {
			continue
		}
		name, ok := mapName(h.Name)
		if !ok {
			continue
		}
		if total += h.Size; total > maxExtract {
			return written, errors.New("풀었을 때 200MB 를 넘습니다")
		}
		if err := writeFile(dst, name, tr, h.Size); err != nil {
			return written, err
		}
		written++
	}
}

func writeFile(dst, name string, r io.Reader, limit int64) error {
	clean := filepath.Clean("/" + filepath.ToSlash(name))[1:]
	if clean == "" || strings.HasPrefix(clean, "..") {
		return fmt.Errorf("잘못된 경로: %q", name)
	}
	p := filepath.Join(dst, clean)
	if !strings.HasPrefix(p, filepath.Clean(dst)+string(os.PathSeparator)) {
		return fmt.Errorf("잘못된 경로: %q", name)
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return err
	}
	f, err := os.OpenFile(p, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	n, err := io.Copy(f, io.LimitReader(r, limit+1))
	if err != nil {
		return err
	}
	if n > limit {
		return errors.New("파일이 너무 큽니다")
	}
	return nil
}
