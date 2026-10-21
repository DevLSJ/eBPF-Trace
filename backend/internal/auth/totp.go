package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// RFC 6238 TOTP — HMAC-SHA1 · 30초 · 6자리 (Google Authenticator 기본값과 같다)
const (
	totpPeriod = 30
	totpDigits = 6
	// totpSkew: 앞뒤 1스텝(±30초)까지 허용 — 휴대폰 시계 오차
	totpSkew = 1
	// otpSecretBytes: RFC 4226 권장 160비트
	otpSecretBytes = 20
	issuer         = "SupplyGuard"
)

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// Step: 유닉스 시각을 30초로 나눈 카운터 (RFC 6238 의 T)
func Step(t time.Time) int64 { return t.Unix() / totpPeriod }

// hotp: RFC 4226 — HMAC-SHA1(secret, 카운터 8바이트 빅엔디언) → 동적 절단 → 10^digits 나머지
func hotp(secret []byte, counter int64, digits int) string {
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(counter))
	m := hmac.New(sha1.New, secret)
	m.Write(msg[:])
	sum := m.Sum(nil)
	off := sum[len(sum)-1] & 0x0f                             // 마지막 바이트 하위 4비트 = 오프셋
	v := binary.BigEndian.Uint32(sum[off:off+4]) & 0x7fffffff // 31비트 (부호 비트 제거)
	mod := uint32(1)
	for range digits {
		mod *= 10
	}
	return fmt.Sprintf("%0*d", digits, v%mod)
}

// TOTP: 스텝의 6자리 코드
func TOTP(secret []byte, step int64) string { return hotp(secret, step, totpDigits) }

// VerifyTOTP: now 기준 -1 · 0 · +1 스텝 중 맞는 스텝을 돌려준다.
// lastStep 이하 스텝은 건너뛴다 — 같은 코드(또는 더 이전 코드)의 재사용을 막는다.
// 형식(숫자 6자리)이 아니면 계산 없이 거절. 비교는 상수 시간이고, 세 스텝을 모두 비교한다(일찍 끝내지 않음).
func VerifyTOTP(secret []byte, code string, now time.Time, lastStep int64) (int64, bool) {
	if len(code) != totpDigits || strings.Trim(code, "0123456789") != "" {
		return 0, false
	}
	cur := Step(now)
	var found int64
	ok := false
	for d := int64(-totpSkew); d <= totpSkew; d++ {
		s := cur + d
		match := subtle.ConstantTimeCompare([]byte(TOTP(secret, s)), []byte(code)) == 1
		if match && s > lastStep {
			found, ok = s, true // 같은 코드가 두 스텝에 겹치면(10^-6) 뒤 스텝을 쓴다
		}
	}
	return found, ok
}

// NewOTPSecret: 20바이트 난수의 base32(패딩 없음) — 인증 앱 수동 입력 키
func NewOTPSecret() (string, error) {
	b := make([]byte, otpSecretBytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return b32.EncodeToString(b), nil
}

// DecodeSecret: 공백 · 하이픈 · 소문자 · 패딩을 허용해 base32 를 푼다
func DecodeSecret(s string) ([]byte, error) {
	s = strings.ToUpper(strings.NewReplacer(" ", "", "-", "", "=", "").Replace(s))
	return b32.DecodeString(s)
}

// OTPAuthURI: QR 로 만들 등록 주소 — otpauth://totp/SupplyGuard:<user>?secret=…&issuer=SupplyGuard
func OTPAuthURI(username, secret string) string {
	q := url.Values{}
	q.Set("secret", secret)
	q.Set("issuer", issuer)
	q.Set("algorithm", "SHA1")
	q.Set("digits", "6")
	q.Set("period", "30")
	return "otpauth://totp/" + url.PathEscape(issuer+":"+username) + "?" + q.Encode()
}
