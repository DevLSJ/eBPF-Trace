package review

import (
	"fmt"
	"path"
	"regexp"
	"strings"

	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/model"
)

var pep503 = regexp.MustCompile(`[-_.]+`)

// NormalizePackage: 차단 목록 키 「매니저:이름」을 만든다 (계약 「동작 규칙」).
//   - 로컬 디렉터리는 마지막 경로 이름 (./reqeusts → reqeusts)
//   - 버전 표기는 뗀다: 마지막 @ 뒤 (npm 스코프 @a/b 의 맨 앞 @ 는 그대로), pip 는 == 등 비교 연산자 · [extras] · ; 표식 앞까지
//   - 대소문자를 무시한다. pip 는 PEP 503 정규화(-, _, . 연속 → -) — 표기만 바꿔 차단을 피하지 못하게
func NormalizePackage(manager, raw string) (string, error) {
	if !model.ValidManager(manager) {
		return "", fmt.Errorf("manager: pip | npm | cargo")
	}
	p := strings.TrimRight(strings.TrimSpace(raw), "/")
	if p == "" {
		return "", fmt.Errorf("package: 비어 있음")
	}
	scoped := manager == "npm" && strings.HasPrefix(p, "@")
	if !scoped && (strings.HasPrefix(p, ".") || strings.HasPrefix(p, "/") || strings.HasPrefix(p, "~") || strings.Contains(p, "/")) {
		p = path.Base(p)
	}
	if i := strings.LastIndex(p, "@"); i > 0 {
		p = p[:i]
	}
	if manager == "pip" {
		if i := strings.IndexAny(p, "=<>!~;[ ("); i >= 0 {
			p = p[:i]
		}
	}
	name := strings.ToLower(strings.TrimSpace(p))
	if manager == "pip" {
		name = pep503.ReplaceAllString(name, "-")
	}
	if name == "" || name == "." || name == "@" {
		return "", fmt.Errorf("package %q: 이름을 알 수 없음", raw)
	}
	return manager + ":" + name, nil
}
