package rules

import (
	"strings"
	"testing"
)

// 화면에 보이는 규칙 문구(11/09 사용자 결정 「— 표기 없앰」): 시스템 규칙 설명은 정책 목록 · 시트에 그대로 보인다
func TestSystemRuleDescriptionText(t *testing.T) {
	sys, ok := BlocklistHostsRule([]string{"evil.test"})
	if !ok {
		t.Fatal("blocklist-hosts")
	}
	if want := "악성 판정으로 차단한 도메인(차단 목록에서 관리)"; sys.Description != want {
		t.Fatalf("description %q, want %q", sys.Description, want)
	}
	if strings.ContainsRune(sys.Description, '—') {
		t.Fatalf("description has an em dash: %q", sys.Description)
	}
}
