package chat

import (
	"context"
	"strings"
	"testing"
)

// 11/09 정책 화면 분리(사이드바 하위 메뉴 정책 · 차단 목록 · 변경 이력): 챗봇 링크와 「이 화면」 설명이 새 주소를 가리킨다
func TestPolicyPagesSplit(t *testing.T) {
	s := newTestService(t, newFakeOllama(t), nil)
	_, links, err := s.RunTool(context.Background(), ToolBlocklist, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(links) != 1 || links[0].Href != "/policies/blocklist" || strings.Contains(links[0].Label, "정책 화면") {
		t.Errorf("차단 목록 링크 = %+v, want 「차단 목록」 → /policies/blocklist", links)
	}
	for _, p := range []string{"/policies/blocklist", "/policies/changes", "#/policies/changes?id=chg-1"} {
		if txt := pageText(p); strings.HasPrefix(txt, "SupplyGuard 화면입니다.") {
			t.Errorf("%s 화면 설명이 없음: %q", p, txt)
		}
	}
	if !strings.Contains(pageText("/policies/blocklist"), "차단 목록") || !strings.Contains(pageText("/policies/changes"), "변경 이력") {
		t.Errorf("설명 내용: %q / %q", pageText("/policies/blocklist"), pageText("/policies/changes"))
	}
}
