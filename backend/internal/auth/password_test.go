package auth

import (
	"regexp"
	"strings"
	"testing"
)

func TestValidatePassword(t *testing.T) {
	cases := []struct {
		user, pw string
		ok       bool
	}{
		// 최소 5자(사용자 결정 10/20 — 10자에서 낮춤)
		{"admin", "abcd", false},                  // 4자
		{"admin", "short", true},                  // 5자
		{"admin", "1234567890", true},             // 10자
		{"longusername", "LongUserName", false},   // 아이디와 같음(대소문자 무시)
		{"admin", "가나다라", false},                  // 글자 수로 센다 — 4자
		{"admin", "가나다라마", true},                  // 5자
		{"admin", strings.Repeat("a", 73), false}, // bcrypt 72바이트 한도
	}
	for _, c := range cases {
		err := ValidatePassword(c.user, c.pw)
		if (err == nil) != c.ok {
			t.Errorf("ValidatePassword(%q, %q) = %v, want ok=%v", c.user, c.pw, err, c.ok)
		}
	}
}

func TestHashPassword(t *testing.T) {
	h, err := HashPassword("correct horse battery", 4)
	if err != nil {
		t.Fatal(err)
	}
	if !CheckPassword(h, "correct horse battery") || CheckPassword(h, "wrong horse battery") || CheckPassword("", "x") {
		t.Fatal("check")
	}
}

func TestRecoveryCodes(t *testing.T) {
	codes, err := NewRecoveryCodes()
	if err != nil {
		t.Fatal(err)
	}
	if len(codes) != 10 {
		t.Fatalf("10개: %d", len(codes))
	}
	re := regexp.MustCompile(`^[2-9A-HJ-NP-Z]{4}-[2-9A-HJ-NP-Z]{4}$`)
	seen := map[string]bool{}
	for _, c := range codes {
		if !re.MatchString(c) || seen[c] {
			t.Fatalf("형식 · 중복: %q", c)
		}
		seen[c] = true
	}
	// 소문자 · 하이픈 없이 넣어도 같은 해시, 사용자가 다르면 다른 해시
	c := codes[0]
	if RecoveryHash("u1", c) != RecoveryHash("u1", strings.ToLower(strings.ReplaceAll(c, "-", ""))) {
		t.Fatal("정규화")
	}
	if RecoveryHash("u1", c) == RecoveryHash("u2", c) {
		t.Fatal("사용자별 소금")
	}
}

func TestTempPassword(t *testing.T) {
	p, err := TempPassword()
	if err != nil || ValidatePassword("someone", p) != nil {
		t.Fatalf("임시 비밀번호도 정책을 지킨다: %q %v", p, err)
	}
}

func TestSealer(t *testing.T) {
	plain := newSealer("")
	if s, _ := plain.seal("u1", "ABC"); s != "ABC" {
		t.Fatal("키가 없으면 평문")
	}
	k := newSealer("server-secret")
	s, err := k.seal("u1", "JBSWY3DPEHPK3PXP")
	if err != nil || !strings.HasPrefix(s, "v1:") || strings.Contains(s, "JBSWY3DPEHPK3PXP") {
		t.Fatalf("암호화: %q %v", s, err)
	}
	if got, err := k.open("u1", s); err != nil || got != "JBSWY3DPEHPK3PXP" {
		t.Fatalf("복호화: %q %v", got, err)
	}
	if _, err := k.open("u2", s); err == nil {
		t.Fatal("다른 사용자 행으로 옮긴 암호문은 거절(AAD)")
	}
	if _, err := plain.open("u1", s); err == nil {
		t.Fatal("키 없이 암호문을 열 수 없다")
	}
	if got, err := k.open("u1", "PLAINOLD"); err != nil || got != "PLAINOLD" {
		t.Fatal("키를 나중에 넣어도 예전 평문은 읽힌다")
	}
}
