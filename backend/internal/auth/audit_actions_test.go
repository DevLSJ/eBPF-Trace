package auth

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strconv"
	"testing"
)

// Tier 1 — 감사 action 허용 목록(AuditActions)이 service.go 가 실제로 남기는 값과 같아야 한다.
// s.audit(ctx, actor, ACTION, …) · s.otpFail(ctx, sess, u, ip, ACTION, …) 의 문자열 인자를 소스에서 모은다.
// 새 action 을 남기면서 목록에 안 넣으면(필터로 못 고름) 또는 목록에만 남은 값이 있으면 실패한다.
func TestAuditActionsMatchService(t *testing.T) {
	f, err := parser.ParseFile(token.NewFileSet(), "service.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	argPos := map[string]int{"audit": 2, "otpFail": 4}
	used := map[string]bool{}
	ast.Inspect(f, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		pos, ok := argPos[sel.Sel.Name]
		if !ok || len(call.Args) <= pos {
			return true
		}
		switch a := call.Args[pos].(type) {
		case *ast.BasicLit:
			v, _ := strconv.Unquote(a.Value)
			used[v] = true
		case *ast.Ident:
			if !(sel.Sel.Name == "audit" && a.Name == "action") { // otpFail 안의 s.audit(…, action, …) 만 변수 허용
				t.Errorf("%s 의 action 인자가 문자열 상수가 아님: %s", sel.Sel.Name, a.Name)
			}
		default:
			t.Errorf("%s 의 action 인자가 문자열 상수가 아님", sel.Sel.Name)
		}
		return true
	})
	if len(used) == 0 {
		t.Fatal("service.go 에서 감사 호출을 못 찾음")
	}
	for a := range used {
		if !ValidAuditAction(a) {
			t.Errorf("service 가 남기는 %q 가 AuditActions 에 없음", a)
		}
	}
	for _, a := range AuditActions {
		if !used[a] {
			t.Errorf("AuditActions 의 %q 를 service 가 남기지 않음", a)
		}
	}
	if ValidAuditAction("") || ValidAuditAction("LOGIN") || ValidAuditAction("nope") {
		t.Error("허용 목록 밖 값이 통과")
	}
}
