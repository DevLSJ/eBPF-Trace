package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"math/big"
	"strings"
	"unicode/utf8"

	"golang.org/x/crypto/bcrypt"
)

// DefaultBcryptCost: 12 (약 0.2~0.3초) — 무차별 대입 비용
const DefaultBcryptCost = 12

const (
	minPasswordRunes = 5  // 사용자 결정 10/20 (10자에서 낮춤 — 잠금 5회/5분 · OTP 가 보완)
	maxPasswordBytes = 72 // bcrypt 는 72바이트 넘는 입력을 받지 않는다
	recoveryCount    = 10
	tempPasswordLen  = 16
)

// codeAlphabet: 헷갈리는 글자(0 O 1 I L)를 뺀 32자 — 복구 코드 · 임시 비밀번호
const codeAlphabet = "23456789ABCDEFGHJKLMNPQRSTUVWXYZ"
const tempAlphabet = codeAlphabet + "abcdefghijkmnpqrstuvwxyz"

// ValidatePassword: 5자 이상 · 72바이트 이하 · 아이디와 다름(대소문자 무시)
func ValidatePassword(username, pw string) error {
	if err := validatePasswordSize(pw); err != nil {
		return err
	}
	if strings.EqualFold(strings.TrimSpace(pw), strings.TrimSpace(username)) {
		return errors.New("비밀번호는 아이디와 달라야 합니다")
	}
	return nil
}

// validatePasswordSize: 5자 이상 · 72바이트 이하만 (AUTH_DEV_MODE 의 초기 관리자가 쓴다 — 아이디와 같아도 됨)
func validatePasswordSize(pw string) error {
	if utf8.RuneCountInString(pw) < minPasswordRunes {
		return errors.New("비밀번호는 5자 이상이어야 합니다")
	}
	if len(pw) > maxPasswordBytes {
		return errors.New("비밀번호가 너무 깁니다(72바이트 이하)")
	}
	return nil
}

func HashPassword(pw string, cost int) (string, error) {
	if cost == 0 {
		cost = DefaultBcryptCost
	}
	b, err := bcrypt.GenerateFromPassword([]byte(pw), cost)
	return string(b), err
}

// CheckPassword: bcrypt 비교 (상수 시간). 해시가 비었거나 깨졌으면 false
func CheckPassword(hash, pw string) bool {
	return hash != "" && bcrypt.CompareHashAndPassword([]byte(hash), []byte(pw)) == nil
}

func randomString(alphabet string, n int) (string, error) {
	var sb strings.Builder
	max := big.NewInt(int64(len(alphabet)))
	for range n {
		i, err := rand.Int(rand.Reader, max)
		if err != nil {
			return "", err
		}
		sb.WriteByte(alphabet[i.Int64()])
	}
	return sb.String(), nil
}

// NewRecoveryCodes: XXXX-XXXX 10개 (각 40비트). 원문은 한 번만 보여 주고 해시만 저장한다
func NewRecoveryCodes() ([]string, error) {
	seen := map[string]bool{}
	out := make([]string, 0, recoveryCount)
	for len(out) < recoveryCount {
		s, err := randomString(codeAlphabet, 8)
		if err != nil {
			return nil, err
		}
		if seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s[:4]+"-"+s[4:])
	}
	return out, nil
}

// RecoveryHash: SHA-256(사용자 id + ":" + 정규화 코드). 대소문자 · 하이픈 · 공백 무시
func RecoveryHash(userID, code string) string {
	norm := strings.ToUpper(strings.NewReplacer("-", "", " ", "").Replace(strings.TrimSpace(code)))
	sum := sha256.Sum256([]byte(userID + ":" + norm))
	return hex.EncodeToString(sum[:])
}

// TempPassword: 관리자가 만든 계정 · 초기화에 주는 1회용 비밀번호 (첫 로그인에서 바꿔야 한다)
func TempPassword() (string, error) { return randomString(tempAlphabet, tempPasswordLen) }
