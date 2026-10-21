package store

import "testing"

// SUPPLYGUARD_TEST_DATABASE_URL 이 있을 때만 돈다 (testPG 가 건너뛴다). 인증 테이블을 비우고 같은 계약을 확인한다.
func TestPostgresAuthContract(t *testing.T) {
	p := testPG(t)
	ctx := t.Context()
	if err := p.MigrateAuth(ctx); err != nil {
		t.Fatal(err)
	}
	if err := p.MigrateAuth(ctx); err != nil { // 멱등
		t.Fatal(err)
	}
	if _, err := p.pool.Exec(ctx, `TRUNCATE sessions, users, license, auth_audit`); err != nil {
		t.Fatal(err)
	}
	authStoreContract(t, p)
}
