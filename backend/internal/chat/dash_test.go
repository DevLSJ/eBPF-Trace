package chat

import (
	"strings"
	"testing"
	"unicode/utf8"
)

// 긴 대시(11/09 사용자 결정 「— 표기 없앰」): 모델이 지시를 어겨도 화면에 보이는 답에는 「—」가 남지 않는다.
func TestCleanDashes(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{"대시 없는 답은 그대로 둡니다.  ", "대시 없는 답은 그대로 둡니다.  "},
		{"no-shell-download 위반 — 격리됨", "no-shell-download 위반, 격리됨"},
		{"원인—설치 스크립트", "원인, 설치 스크립트"},
		{"- 격리 완료 —\n- 다음 할 일", "- 격리 완료\n- 다음 할 일"},
		{"— 설치 중 외부 스크립트 실행\n  — 들여쓴 항목", "- 설치 중 외부 스크립트 실행\n  - 들여쓴 항목"},
		{"요약\n———\n본문", "요약\n\n본문"},
		{"A —— B", "A, B"},
		{"A — B — C", "A, B, C"},
		{"점수(— 없음)", "점수(없음)"},
		{"결과: — 위반 없음", "결과: 위반 없음"},
		{"끝 —.", "끝."},
		{"3—5개", "3~5개"},
		{"「curl — x」 관찰", "「curl, x」 관찰"},
		{"—", ""},
	} {
		if got := cleanDashes(c.in); got != c.want {
			t.Errorf("cleanDashes(%q) = %q, want %q", c.in, got, c.want)
		}
		if strings.ContainsRune(cleanDashes(c.in), emDash) {
			t.Errorf("cleanDashes(%q) still has an em dash", c.in)
		}
	}
}

// 흘려보내기: 조각을 어디서 끊어도 이어 붙인 결과는 답 전체를 한 번에 고친 것과 같고, 조각마다 「—」가 없다
func TestDashStreamMatchesWhole(t *testing.T) {
	for _, s := range []string{
		"- [격리] no-shell-download 위반 — 컨테이너 종료됨\n- 원인 — 설치 스크립트가 셸로 내려받음 —\n— 다음 할 일 확인 필요",
		"대시 없는 답 그대로   \n둘째 줄 ",
		"A —— B   —   \n———\n3—5개 (— 없음) 끝 —.",
	} {
		want := cleanDashes(s)
		rs := []rune(s)
		for i := 0; i <= len(rs); i++ {
			for j := i; j <= len(rs); j++ {
				var parts []string
				ds := &dashStream{emit: func(tok string) error {
					if tok == "" || strings.ContainsRune(tok, emDash) || !utf8.ValidString(tok) {
						t.Fatalf("bad piece %q", tok)
					}
					parts = append(parts, tok)
					return nil
				}}
				for _, p := range []string{string(rs[:i]), string(rs[i:j]), string(rs[j:])} {
					if p != "" {
						if err := ds.write(p); err != nil {
							t.Fatal(err)
						}
					}
				}
				if err := ds.flush(); err != nil {
					t.Fatal(err)
				}
				if got := strings.Join(parts, ""); got != want {
					t.Fatalf("split %d/%d of %q: got %q, want %q", i, j, s, got, want)
				}
			}
		}
	}
}
