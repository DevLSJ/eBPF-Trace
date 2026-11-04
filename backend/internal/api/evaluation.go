package api

import (
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
)

// 평가 결과(11/04): bench/ 하네스가 만든 결과 JSON 을 읽기 전용으로 내려 준다.
// 내용은 해석하지 않는다(스키마는 bench 쪽이 정한다). static-items.jsonl · static.md 는 내려 주지 않는다.

// maxEvalReport: 결과 파일 하나의 크기 상한 — 넘으면 그 칸은 null + 경고
const maxEvalReport = 5 << 20

// evalFiles: 응답 키 → 파일 이름. 이 4개만 읽는다(요청 값으로 경로를 만들지 않는다)
var evalFiles = []struct{ key, name string }{
	{"static", "static.json"},
	{"runtime", "runtime.json"},
	{"model", "model.json"},
	{"modelAll", "model-all.json"},
}

// evaluation: GET /api/evaluation — 파일 4개 중 하나라도 있으면 200(없거나 깨진 칸은 null), 전부 없으면 404.
// 파일이 작고 요청이 드물어 요청마다 읽는다(캐시 없음 — 결과를 바꿔 넣으면 다음 요청에 바로 보인다).
func (h *handlers) evaluation(w http.ResponseWriter, _ *http.Request) {
	out := make(map[string]json.RawMessage, len(evalFiles))
	found := false
	for _, f := range evalFiles {
		raw, exists := readEvalReport(h.EvalReportsDir, f.name)
		found = found || exists
		out[f.key] = raw // nil → null
	}
	if !found {
		writeErr(w, http.StatusNotFound, "평가 결과 없음")
		return
	}
	writeJSON(w, http.StatusOK, out)
}

// readEvalReport: (내용, 파일이 있는지). 없으면 (nil, false). 있는데 일반 파일이 아니거나 · 상한을 넘거나 ·
// 읽기 실패 · JSON 이 아니면 (nil, true) 와 경고 로그.
func readEvalReport(dir, name string) (json.RawMessage, bool) {
	if dir == "" {
		return nil, false
	}
	path := filepath.Join(dir, name)
	f, err := os.Open(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, false
	}
	if err != nil {
		slog.Warn("evaluation: open", "file", path, "err", err)
		return nil, true
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() {
		slog.Warn("evaluation: not a regular file", "file", path, "err", err)
		return nil, true
	}
	if st.Size() > maxEvalReport {
		slog.Warn("evaluation: file too large", "file", path, "bytes", st.Size(), "max", maxEvalReport)
		return nil, true
	}
	b, err := io.ReadAll(io.LimitReader(f, maxEvalReport+1))
	if err != nil {
		slog.Warn("evaluation: read", "file", path, "err", err)
		return nil, true
	}
	if len(b) > maxEvalReport { // Stat 뒤에 커진 경우
		slog.Warn("evaluation: file too large", "file", path, "max", maxEvalReport)
		return nil, true
	}
	if !json.Valid(b) {
		slog.Warn("evaluation: invalid JSON", "file", path)
		return nil, true
	}
	return json.RawMessage(b), true
}
