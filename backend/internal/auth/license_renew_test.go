package auth

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/model"
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/store"
)

const renewKey = "9876-5432-1098-7654"

// Tier 1 — 관리자 갱신: 기존 라이선스(단일 행)를 바꾸고 만료일을 지금부터 1년으로 새로 계산한다.
// 만료된 뒤에도 갱신할 수 있다. 감사에는 가린 키만 남는다.
func TestRenewLicense(t *testing.T) {
	s, st, c := newTestService(t, false, "")
	ctx := t.Context()
	admin := Actor{ID: "u1", Username: "admin", Name: "관리자", Role: model.RoleAdmin}

	// 만료된 라이선스(1년 전 등록)
	old := model.License{KeyMasked: "****-****-****-3456", Kind: "trial",
		IssuedAt: c.Now().AddDate(-1, 0, -1), ExpiresAt: c.Now().AddDate(0, 0, -1), RegisteredBy: "admin"}
	if err := st.SaveLicense(ctx, old); err != nil {
		t.Fatal(err)
	}
	if l, _ := s.License(ctx); !s.Expired(*l) {
		t.Fatal("준비: 만료 상태여야 함")
	}

	c.Add(time.Hour)
	l, err := s.RenewLicense(ctx, admin, renewKey, "10.0.0.1")
	if err != nil {
		t.Fatalf("renew: %v", err)
	}
	want := c.Now().UTC().Truncate(time.Second).AddDate(1, 0, 0)
	if l.KeyMasked != "****-****-****-7654" || !l.ExpiresAt.Equal(want) || l.RegisteredBy != "admin" || s.Expired(l) {
		t.Fatalf("갱신 결과: %+v", l)
	}
	if cur, _ := s.License(ctx); cur == nil || *cur != l {
		t.Fatalf("저장값: %+v", cur)
	}

	// 형식 오류 → 400, 로그인 단계와 같은 문구, 저장값 그대로
	_, err = s.RenewLicense(ctx, admin, "1234-5678-9012-345X", "10.0.0.1")
	if status(err) != 400 || err.Error() != "라이선스 키 형식이 아닙니다(숫자 16자리, XXXX-XXXX-XXXX-XXXX)" {
		t.Fatalf("형식 오류: %d %v", status(err), err)
	}
	if cur, _ := s.License(ctx); *cur != l {
		t.Fatalf("형식 오류 뒤 저장값이 바뀜: %+v", cur)
	}

	// 조회자 → 403 (라우트의 RequireAdmin 뒤 한 겹 더)
	viewer := Actor{ID: "u2", Username: "viewer1", Name: "조회", Role: model.RoleViewer}
	if _, err := s.RenewLicense(ctx, viewer, renewKey, "10.0.0.2"); status(err) != 403 {
		t.Fatalf("조회자: %d %v", status(err), err)
	}

	// 감사: license_renew 성공 · 실패, 어디에도 키 원문(숫자 16자리 · 하이픈 형태)이 없다
	ev, _ := s.AuthAudit(ctx, store.AuthAuditQuery{Limit: 100})
	if !hasAction(ev, "license_renew", true) || !hasAction(ev, "license_renew", false) {
		t.Fatalf("감사: %+v", ev)
	}
	raw, _ := json.Marshal(ev)
	for _, k := range []string{renewKey, strings.ReplaceAll(renewKey, "-", ""), "1234-5678-9012-345X", "123456789012345X"} {
		if strings.Contains(string(raw), k) {
			t.Fatalf("감사에 키 원문 %q: %s", k, raw)
		}
	}
	for _, e := range ev {
		if e.Action == "license_renew" && e.OK && e.Target != "****-****-****-7654" {
			t.Fatalf("성공 감사 대상은 가린 키: %+v", e)
		}
	}
}
