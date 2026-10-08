package main

import (
	"archive/tar"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// Component — SBOM 한 항목. purl 형식(pkg:npm/..@.., pkg:pypi/..@..)로 커밋 축과 연결한다(docs/13 §8).
type Component struct {
	Purl string `json:"purl"`
}

// manifestSpec — 컨테이너별로 읽을 매니페스트 경로와 파서.
type manifestSpec struct {
	path  string
	parse func([]byte) []Component
}

// 컨테이너 이름 접두 → 매니페스트 사양.
var manifestByName = map[string]manifestSpec{
	"carrot-pay-service":   {path: "/app/package.json", parse: parsePackageJSON},
	"carrot-image-service": {path: "/app/requirements.txt", parse: parseRequirements},
}

// readFileFromContainer — Docker archive API로 컨테이너 안 파일 1개를 읽는다(tar 스트림).
func (r *Resolver) readFileFromContainer(ctx context.Context, id, path string) ([]byte, error) {
	u := "http://docker/containers/" + id + "/archive?path=" + url.QueryEscape(path)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	resp, err := r.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		io.Copy(io.Discard, resp.Body)
		return nil, io.EOF
	}
	tr := tar.NewReader(resp.Body)
	for {
		hdr, err := tr.Next()
		if err != nil {
			return nil, err
		}
		if hdr.Typeflag == tar.TypeReg {
			return io.ReadAll(io.LimitReader(tr, 256*1024))
		}
	}
}

// collectSBOM — 추적 컨테이너들의 매니페스트를 읽어 컨테이너별 컴포넌트 목록을 만든다.
func (r *Resolver) collectSBOM(ctx context.Context) map[string][]Component {
	out := map[string][]Component{}
	for _, c := range r.containers() {
		spec, ok := manifestByName[c.Name]
		if !ok {
			continue
		}
		data, err := r.readFileFromContainer(ctx, c.ID, spec.path)
		if err != nil {
			continue
		}
		out[c.Name] = spec.parse(data)
	}
	return out
}

func parsePackageJSON(data []byte) []Component {
	var pkg struct {
		Dependencies map[string]string `json:"dependencies"`
	}
	if err := json.Unmarshal(data, &pkg); err != nil {
		return nil
	}
	out := make([]Component, 0, len(pkg.Dependencies))
	for name, ver := range pkg.Dependencies {
		out = append(out, Component{Purl: "pkg:npm/" + name + "@" + cleanVer(ver)})
	}
	return out
}

func parseRequirements(data []byte) []Component {
	var out []Component
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		name, ver := line, ""
		if i := strings.Index(line, "@"); i >= 0 { // PEP 508 직접 참조: name @ file://...
			name = strings.TrimSpace(line[:i])
		} else {
			for _, sep := range []string{"==", ">=", "~=", "<=", ">", "<"} {
				if i := strings.Index(line, sep); i >= 0 {
					name, ver = strings.TrimSpace(line[:i]), strings.TrimSpace(line[i+len(sep):])
					break
				}
			}
		}
		out = append(out, Component{Purl: "pkg:pypi/" + name + "@" + ver})
	}
	return out
}

func cleanVer(v string) string {
	return strings.TrimLeft(v, "^~>=<v ")
}
