package main

import (
	"strings"
	"testing"
)

// Tier 1: 실제 가젯 소스는 OTP 비밀값 암호화 키(32자 이상) 없이 시작하지 않는다. mock 은 선택
func TestValidateAuthSecret(t *testing.T) {
	for _, c := range []struct {
		source, key string
		ok          bool
	}{
		{"gadget", "", false},
		{"gadget", strings.Repeat("a", 31), false},
		{"gadget", strings.Repeat("가", 31), false}, // 글자 수로 센다
		{"gadget", strings.Repeat("a", 32), true},
		{"gadget", strings.Repeat("f", 64), true}, // openssl rand -hex 32
		{"mock", "", true},
		{"mock", "short", true},
	} {
		err := validateAuthSecret(c.source, c.key)
		if (err == nil) != c.ok {
			t.Errorf("%s len=%d: err=%v, want ok=%v", c.source, len([]rune(c.key)), err, c.ok)
		}
		if err != nil && strings.Contains(err.Error(), c.key) && c.key != "" {
			t.Errorf("오류 문구에 키 값이 들어가면 안 됨: %v", err)
		}
	}
}
