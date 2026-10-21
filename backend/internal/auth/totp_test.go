package auth

import (
	"net/url"
	"strings"
	"testing"
	"time"
)

// RFC 6238 부록 B — SHA1, 비밀값 "12345678901234567890"(ASCII), 30초 스텝.
var rfc6238 = []struct {
	unix int64
	want string // 8자리
}{
	{59, "94287082"},
	{1111111109, "07081804"},
	{1111111111, "14050471"},
	{1234567890, "89005924"},
	{2000000000, "69279037"},
	{20000000000, "65353130"},
}

var rfcSecret = []byte("12345678901234567890")

func TestTOTPRFC6238Vectors(t *testing.T) {
	for _, v := range rfc6238 {
		step := Step(time.Unix(v.unix, 0))
		if got := hotp(rfcSecret, step, 8); got != v.want {
			t.Errorf("T=%d 8자리: %s, want %s", v.unix, got, v.want)
		}
		// 6자리는 같은 동적 절단 값의 끝 6자리
		if got := TOTP(rfcSecret, step); got != v.want[2:] {
			t.Errorf("T=%d 6자리: %s, want %s", v.unix, got, v.want[2:])
		}
	}
}

func TestVerifyTOTPWindow(t *testing.T) {
	now := time.Unix(1234567890, 0)
	cur := Step(now)
	for _, d := range []int64{-1, 0, 1} {
		code := TOTP(rfcSecret, cur+d)
		step, ok := VerifyTOTP(rfcSecret, code, now, 0)
		if !ok || step != cur+d {
			t.Errorf("±1 스텝 d=%d: ok=%v step=%d", d, ok, step)
		}
	}
	for _, d := range []int64{-2, 2} {
		if _, ok := VerifyTOTP(rfcSecret, TOTP(rfcSecret, cur+d), now, 0); ok {
			t.Errorf("±2 스텝 d=%d 는 거절해야 함", d)
		}
	}
	for _, bad := range []string{"", "12345", "1234567", "abcdef", " 89005924"} {
		if _, ok := VerifyTOTP(rfcSecret, bad, now, 0); ok {
			t.Errorf("형식 오류 %q 통과", bad)
		}
	}
}

// 같은 스텝(또는 이전 스텝)의 코드는 다시 쓸 수 없다.
func TestVerifyTOTPRejectsReuse(t *testing.T) {
	now := time.Unix(1234567890, 0)
	cur := Step(now)
	code := TOTP(rfcSecret, cur)
	step, ok := VerifyTOTP(rfcSecret, code, now, 0)
	if !ok {
		t.Fatal("첫 사용은 통과")
	}
	if _, ok := VerifyTOTP(rfcSecret, code, now, step); ok {
		t.Fatal("같은 스텝 재사용은 거절")
	}
	if _, ok := VerifyTOTP(rfcSecret, TOTP(rfcSecret, cur-1), now, step); ok {
		t.Fatal("이전 스텝 코드도 거절")
	}
	if _, ok := VerifyTOTP(rfcSecret, TOTP(rfcSecret, cur+1), now, step); !ok {
		t.Fatal("다음 스텝 코드는 통과")
	}
}

func TestOTPSecretAndURI(t *testing.T) {
	s, err := NewOTPSecret()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := DecodeSecret(s)
	if err != nil || len(raw) != 20 {
		t.Fatalf("비밀값 20바이트: %d %v", len(raw), err)
	}
	if strings.Contains(s, "=") {
		t.Fatal("base32 패딩 없음")
	}
	// 공백 · 소문자로 넣어도 같은 값
	if raw2, err := DecodeSecret(strings.ToLower(s[:4]) + " " + s[4:]); err != nil || string(raw2) != string(raw) {
		t.Fatal("공백 · 소문자 허용")
	}
	u, err := url.Parse(OTPAuthURI("admin", s))
	if err != nil {
		t.Fatal(err)
	}
	if u.Scheme != "otpauth" || u.Host != "totp" || u.Path != "/SupplyGuard:admin" {
		t.Fatalf("uri: %s", u)
	}
	q := u.Query()
	if q.Get("secret") != s || q.Get("issuer") != "SupplyGuard" {
		t.Fatalf("query: %v", q)
	}
}
