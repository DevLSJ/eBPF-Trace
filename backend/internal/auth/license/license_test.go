package license

import (
	"testing"
	"time"
)

func TestValidate(t *testing.T) {
	now := time.Date(2026, 10, 20, 9, 0, 0, 0, time.UTC)
	for _, k := range []string{"1234-5678-9012-3456", "1234567890123456", " 1234 5678 9012 3456 ", "1234-5678 9012-3456"} {
		l, err := ValidateAt(k, now)
		if err != nil {
			t.Errorf("%q: %v", k, err)
			continue
		}
		if l.Kind != "trial" || !l.IssuedAt.Equal(now) || !l.ExpiresAt.Equal(now.AddDate(1, 0, 0)) {
			t.Errorf("%q: %+v", k, l)
		}
		if l.KeyMasked != "****-****-****-3456" {
			t.Errorf("가린 키: %q", l.KeyMasked)
		}
	}
	for _, k := range []string{"", "1234-5678-9012-345", "1234-5678-9012-34567", "ABCD-5678-9012-3456", "1234_5678_9012_3456", "１２３４５６７８９０１２３４５６"} {
		if _, err := ValidateAt(k, now); err == nil {
			t.Errorf("%q 는 거절해야 함", k)
		}
	}
	if _, err := Validate("1234-5678-9012-3456"); err != nil {
		t.Fatal(err)
	}
}
