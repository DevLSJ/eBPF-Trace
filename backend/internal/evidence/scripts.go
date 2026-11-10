package evidence

import (
	"context"
	"path"
	"sort"
	"strings"
	"sync"
	"unicode/utf8"

	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/dockerapi"
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/model"
)

// 증거 코드 보기(11/10 사용자 「코드를 볼 수 있게」): 격리 직전, 같은 예산(Budget) 안에서 설치 스크립트 내용만 저장한다.
// 이미지 스냅샷 · 전체 파일 복사는 하지 않는다(10/20 결정 그대로). 예산을 넘기면 못 읽은 채로 격리한다.
const (
	// MaxFiles · FileBytes: 저장하는 스크립트 수 · 파일당 바이트 상한
	MaxFiles  = 6
	FileBytes = 64 << 10
)

// FileReader: 컨테이너 안 파일을 읽는 선택 기능. *dockerapi.Client 가 구현한다(없으면 파일 없이 지금처럼)
type FileReader interface {
	ReadFile(ctx context.Context, id, path string, limit int64) ([]byte, int64, error)
}

// installScripts: 패키지 설치 때 실행되거나 실행 명령을 담는 파일 이름
var installScripts = map[string]bool{"setup.py": true, "pyproject.toml": true, "package.json": true, "build.rs": true}

// skipDirs: 캐시 · 빌드 도구 · 표준 라이브러리 — 설치하는 패키지의 스크립트가 아니다
var skipDirs = []string{"/.cache/", "/pip-build-env-", "/site-packages/", "/dist-packages/", "/usr/lib/", "/usr/share/", "/proc/", "/sys/"}

// pickScripts: 저장할 파일 경로를 고른다(최대 MaxFiles).
//  1. 로컬 패키지 폴더 /pkg/<이름>(sg-install 이 읽기 전용으로 붙임 — 바인드라 diff 에 안의 파일이 안 나온다)의 설치 스크립트
//  2. diff 에서 추가 · 변경된 설치 스크립트와 .sh — 얕은 경로 먼저, 같은 깊이는 diff 순서.
//     node_modules 는 바로 아래 패키지(@scope 포함)의 package.json 만(의존성의 의존성 제외)
func pickScripts(changes []dockerapi.Change) []string {
	var out []string
	seen := map[string]bool{}
	add := func(p string) {
		if len(out) < MaxFiles && !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	var dirs []string
	for _, ch := range changes {
		dirs = append(dirs, ch.Path)
	}
	for _, p := range pkgScripts(dirs) {
		add(p)
	}
	type cand struct {
		path  string
		depth int
		i     int
	}
	var cs []cand
	for i, ch := range changes {
		p := ch.Path
		if ch.Kind == "D" || strings.HasPrefix(p, "/pkg/") || !isScript(p) {
			continue
		}
		cs = append(cs, cand{p, strings.Count(p, "/"), i})
	}
	sort.SliceStable(cs, func(a, b int) bool { return cs[a].depth < cs[b].depth })
	for _, c := range cs {
		add(c.path)
	}
	return out
}

// pkgScripts: 로컬 패키지 폴더(/pkg/<이름>, inspect 의 마운트 또는 diff 의 폴더 줄)에서 볼 설치 스크립트 경로
func pkgScripts(dirs []string) []string {
	var out []string
	for _, d := range dirs {
		if strings.Count(d, "/") == 2 && strings.HasPrefix(d, "/pkg/") {
			for _, n := range []string{"setup.py", "pyproject.toml", "package.json", "build.rs"} {
				out = append(out, d+"/"+n)
			}
		}
	}
	return out
}

func isScript(p string) bool {
	for _, d := range skipDirs {
		if strings.Contains(p, d) {
			return false
		}
	}
	base := path.Base(p)
	if !installScripts[base] && !strings.HasSuffix(base, ".sh") {
		return false
	}
	if i := strings.LastIndex(p, "/node_modules/"); i >= 0 {
		// node_modules/<pkg>/package.json 또는 node_modules/@scope/<pkg>/package.json 만
		rest := strings.Split(p[i+len("/node_modules/"):], "/")
		if strings.Count(p, "/node_modules/") > 1 || base != "package.json" {
			return false
		}
		if !(len(rest) == 2 || (len(rest) == 3 && strings.HasPrefix(rest[0], "@"))) {
			return false
		}
	}
	return true
}

// readScripts: 고른 파일을 동시에 읽는다. 없는 파일 · 폴더 · 글이 아닌 파일은 건너뛴다(오류 아님).
// ctx 가 끝나면(예산) 오류를 돌려준다 — 그때까지 읽은 것은 버리지 않고 돌려준다
func readScripts(ctx context.Context, r FileReader, id string, paths []string) ([]model.EvidenceFile, error) {
	files := make([]*model.EvidenceFile, len(paths))
	var wg sync.WaitGroup
	for i, p := range paths {
		wg.Add(1)
		go func() {
			defer wg.Done()
			b, size, err := r.ReadFile(ctx, id, p, FileBytes)
			if err != nil {
				return
			}
			truncated := size > int64(len(b))
			if truncated {
				b = trimPartialRune(b)
			}
			if !utf8.Valid(b) || strings.IndexByte(string(b), 0) >= 0 {
				return
			}
			files[i] = &model.EvidenceFile{Path: p, Size: size, Truncated: truncated, Content: string(b)}
		}()
	}
	wg.Wait()
	out := []model.EvidenceFile{}
	for _, f := range files {
		if f != nil {
			out = append(out, *f)
		}
	}
	if err := ctx.Err(); err != nil {
		return out, err
	}
	return out, nil
}

// trimPartialRune: 상한에서 잘린 끝의 덜 끝난 UTF-8 글자(최대 3바이트)를 뗀다
func trimPartialRune(b []byte) []byte {
	for k := 0; k < 3 && len(b) > 0 && !utf8.Valid(b); k++ {
		b = b[:len(b)-1]
	}
	return b
}

// orderFiles: 읽은 파일을 맡긴 순서(로컬 폴더 먼저 · 얕은 경로 먼저)로 놓고 MaxFiles 개까지
func orderFiles(files []model.EvidenceFile, order []string) []model.EvidenceFile {
	rank := make(map[string]int, len(order))
	for i, p := range order {
		rank[p] = i
	}
	out := append([]model.EvidenceFile(nil), files...)
	sort.SliceStable(out, func(a, b int) bool { return rank[out[a].Path] < rank[out[b].Path] })
	if len(out) > MaxFiles {
		out = out[:MaxFiles]
	}
	return out
}
