package api

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// 서버가 만들어 화면에 보이는 문구(11/09 사용자 결정 「모든 페이지와 탭의 — 표기는 없앤다」): API 오류 · 판정 사유 ·
// 제안 안내 · 미리보기 · 공급망 검사 오류 · 연동 시험 · 감사 내용 · 챗봇 사실 문장은 문자열 그대로 화면에 나간다.
// 백엔드 Go 소스(시험 제외)의 문자열 상수에 긴 대시(U+2014)가 없어야 한다. 화면에 나가지 않는 두 곳만 뺀다:
//   - 로그(slog · *slog.Logger 의 Debug/Info/Warn/Error)
//   - 시작 오류(cmd/server · internal/config 의 fmt.Errorf — 프로세스 로그에만 남고 서버가 뜨지 않는다)
func TestScreenTextHasNoEmDash(t *testing.T) {
	root := filepath.Join("..", "..")
	var bad []string
	for _, dir := range []string{"cmd", "internal"} {
		err := filepath.WalkDir(filepath.Join(root, dir), func(p string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() || !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
				return err
			}
			rel, _ := filepath.Rel(root, p)
			rel = filepath.ToSlash(rel)
			fset := token.NewFileSet()
			f, err := parser.ParseFile(fset, p, nil, 0)
			if err != nil {
				return err
			}
			startup := strings.HasPrefix(rel, "cmd/server/") || strings.HasPrefix(rel, "internal/config/")
			exempt := map[*ast.BasicLit]bool{}
			ast.Inspect(f, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				if isLogCall(call) || (startup && isErrorf(call)) {
					ast.Inspect(call, func(m ast.Node) bool {
						if bl, ok := m.(*ast.BasicLit); ok {
							exempt[bl] = true
						}
						return true
					})
				}
				return true
			})
			ast.Inspect(f, func(n ast.Node) bool {
				if bl, ok := n.(*ast.BasicLit); ok && bl.Kind == token.STRING && !exempt[bl] && strings.ContainsRune(bl.Value, '—') {
					bad = append(bad, rel+":"+strconv.Itoa(fset.Position(bl.Pos()).Line)+": "+bl.Value)
				}
				return true
			})
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	if len(bad) > 0 {
		t.Fatalf("긴 대시(U+2014)가 든 화면 문구 %d개:\n%s", len(bad), strings.Join(bad, "\n"))
	}
}

var logMethods = map[string]bool{
	"Debug": true, "Info": true, "Warn": true, "Error": true,
	"DebugContext": true, "InfoContext": true, "WarnContext": true, "ErrorContext": true, "Log": true, "LogAttrs": true,
}

// isLogCall: slog.X(…) · s.log.X(…) · logger.X(…) — 받는 쪽 이름에 log 가 든 로그 호출
func isLogCall(c *ast.CallExpr) bool {
	sel, ok := c.Fun.(*ast.SelectorExpr)
	if !ok || !logMethods[sel.Sel.Name] {
		return false
	}
	switch x := sel.X.(type) {
	case *ast.Ident:
		return strings.Contains(strings.ToLower(x.Name), "log")
	case *ast.SelectorExpr:
		return strings.Contains(strings.ToLower(x.Sel.Name), "log")
	}
	return false
}

func isErrorf(c *ast.CallExpr) bool {
	sel, ok := c.Fun.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "Errorf" {
		return false
	}
	id, ok := sel.X.(*ast.Ident)
	return ok && id.Name == "fmt"
}
