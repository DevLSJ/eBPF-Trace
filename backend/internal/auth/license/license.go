// Package license checks product keys. 지금은 형식만 본다(숫자 16자리면 1년 평가판).
// 나중에 서명 검증으로 바꿀 때는 ValidateAt 의 본문만 바꾼다 — 호출하는 쪽은 그대로.
package license

import (
	"errors"
	"strings"
	"time"

	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/model"
)

const (
	KindTrial = "trial"
	keyDigits = 16
)

var ErrInvalid = errors.New("라이선스 키 형식이 아닙니다(숫자 16자리, XXXX-XXXX-XXXX-XXXX)")

// Validate: 키를 확인하고 저장할 라이선스(가린 키 · 종류 · 기간)를 돌려준다
func Validate(key string) (model.License, error) { return ValidateAt(key, time.Now()) }

// ValidateAt: 하이픈 · 공백을 빼고 ASCII 숫자 16자리면 통과 → 지금부터 1년짜리 평가판
func ValidateAt(key string, now time.Time) (model.License, error) {
	digits := strings.NewReplacer("-", "", " ", "").Replace(strings.TrimSpace(key))
	if len(digits) != keyDigits || strings.Trim(digits, "0123456789") != "" {
		return model.License{}, ErrInvalid
	}
	now = now.UTC().Truncate(time.Second)
	return model.License{
		KeyMasked: "****-****-****-" + digits[12:],
		Kind:      KindTrial,
		IssuedAt:  now,
		ExpiresAt: now.AddDate(1, 0, 0),
	}, nil
}
