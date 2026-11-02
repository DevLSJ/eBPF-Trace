package store

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/model"
)

// 1분 단위 수집량: 같은 분은 더하고, 구간 [from, to) 만 돌려준다(시간순)
func TestMemoryCollected(t *testing.T) {
	m := NewMemory()
	ctx := t.Context()
	t0 := time.Date(2026, 10, 16, 9, 0, 0, 0, time.UTC)
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(m.AddCollected(ctx, []model.MinuteCount{{Minute: t0, Exec: 1, Open: 2, DNS: 7}, {Minute: t0.Add(time.Minute), Connect: 3}})) // 10/30 dns
	must(m.AddCollected(ctx, []model.MinuteCount{{Minute: t0, Exec: 4, DNS: 1}}))
	got, err := m.CollectedRange(ctx, t0, t0.Add(2*time.Minute))
	must(err)
	if len(got) != 2 || got[0].Exec != 5 || got[0].Open != 2 || got[0].DNS != 8 || got[1].Connect != 3 || got[1].DNS != 0 { // 10/30 dns 합산
		t.Fatalf("range: %+v", got)
	}
	if got, _ := m.CollectedRange(ctx, t0.Add(time.Minute), t0.Add(time.Hour)); len(got) != 1 {
		t.Fatalf("from is inclusive, earlier minutes excluded: %+v", got)
	}
	// 10/30: 8일 보관 컷은 저장된 가장 최근 분 기준 — 고정 날짜 픽스처가 벽시계와 무관하게 남고, 그보다 8일 넘게 오래된 분만 지워진다
	must(m.AddCollected(ctx, []model.MinuteCount{{Minute: t0.Add(9 * 24 * time.Hour), Open: 1}}))
	if got, _ := m.CollectedRange(ctx, t0, t0.Add(10*24*time.Hour)); len(got) != 1 || got[0].Open != 1 {
		t.Fatalf("minutes older than 8 days before the newest must be pruned: %+v", got)
	}
}

// 격리 타임라인(10/30): 감사 로그 행에 timeline 이 그대로 남고(저장 뒤 바뀌지 않음), 없는 구간 키는 생략된다
func TestAuditTimelinePersisted(t *testing.T) {
	m := NewMemory()
	ctx := t.Context()
	base := time.Date(2026, 10, 30, 9, 0, 0, 123456789, time.UTC)
	killed := base.Add(420 * time.Millisecond)
	tl := &model.Timeline{DetectedAt: base, MatchedAt: base.Add(2 * time.Millisecond), KilledAt: &killed}
	v := model.Verdict{Matched: true, RuleID: "sensitive-files", Action: model.ActionKill, Enforced: true, Timeline: tl,
		Event: model.Event{Kind: model.KindOpen, Timestamp: base, ContainerName: "sg-install-pip-1", Path: "/etc/shadow"}}
	id, err := m.SaveAudit(ctx, v)
	if err != nil || id != 1 {
		t.Fatalf("save: %d %v", id, err)
	}
	later := killed.Add(time.Second)
	tl.NotifiedAt = &later // 저장 뒤에 호출자가 더 채워도 기록은 그대로
	plain := model.Verdict{Matched: true, RuleID: "egress-allowlist", Action: model.ActionAlert, Event: model.Event{Kind: model.KindConnect, Timestamp: base, ContainerName: "web-api", DstIP: "203.0.113.7", DstPort: 8081}}
	if id, err := m.SaveAudit(ctx, plain); err != nil || id != 2 {
		t.Fatalf("second save: %d %v", id, err)
	}
	rows, err := m.QueryAudit(ctx, AuditQuery{})
	if err != nil || len(rows) != 2 {
		t.Fatalf("query: %d %v", len(rows), err)
	}
	got := rows[1] // 최신순이라 두 번째가 첫 행
	if got.ID != 1 || got.Timeline == nil || !got.Timeline.DetectedAt.Equal(base) || got.Timeline.KilledAt == nil || !got.Timeline.KilledAt.Equal(killed) || got.Timeline.NotifiedAt != nil {
		t.Fatalf("timeline round trip: %+v", got.Timeline)
	}
	if ms, ok := got.Timeline.IsolationMs(); !ok || ms != 420 {
		t.Fatalf("isolation ms: %d %v", ms, ok)
	}
	b, _ := json.Marshal(got)
	s := string(b)
	for _, want := range []string{`"timeline":{`, `"detectedAt":"2026-10-30T09:00:00.123456789Z"`, `"matchedAt":"2026-10-30T09:00:00.125456789Z"`, `"killedAt":"2026-10-30T09:00:00.543456789Z"`} {
		if !strings.Contains(s, want) {
			t.Errorf("want %s in %s", want, s)
		}
	}
	for _, no := range []string{"evidenceStartedAt", "evidenceDoneAt", "notifiedAt"} {
		if strings.Contains(s, no) {
			t.Errorf("%s must be omitted: %s", no, s)
		}
	}
	if b, _ := json.Marshal(rows[0]); strings.Contains(string(b), "timeline") {
		t.Fatalf("alert without a timeline must not carry the key: %s", b)
	}
	var back model.AuditEntry
	if err := json.Unmarshal([]byte(s), &back); err != nil || back.Timeline == nil || !back.Timeline.KilledAt.Equal(killed) {
		t.Fatalf("json round trip: %+v %v", back.Timeline, err)
	}
}

// PG: timeline 열 — SUPPLYGUARD_TEST_DATABASE_URL 이 있을 때만
func TestPostgresAuditTimeline(t *testing.T) {
	url := os.Getenv("SUPPLYGUARD_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("SUPPLYGUARD_TEST_DATABASE_URL not set")
	}
	p, err := NewPostgres(t.Context(), url)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)
	ctx := t.Context()
	base := time.Now().UTC().Truncate(time.Microsecond)
	killed := base.Add(300 * time.Millisecond)
	v := model.Verdict{Matched: true, RuleID: "sensitive-files", Action: model.ActionKill, Enforced: true,
		Timeline: &model.Timeline{DetectedAt: base, MatchedAt: base.Add(time.Millisecond), KilledAt: &killed},
		Event:    model.Event{Kind: model.KindOpen, Timestamp: base, ContainerName: "sg-install-pip-tl", Path: "/etc/shadow"}}
	id, err := p.SaveAudit(ctx, v)
	if err != nil || id <= 0 {
		t.Fatalf("save: %d %v", id, err)
	}
	var col []byte
	if err := p.pool.QueryRow(ctx, `SELECT timeline FROM audit_log WHERE id = $1`, id).Scan(&col); err != nil {
		t.Fatal(err)
	}
	var tl model.Timeline
	if err := json.Unmarshal(col, &tl); err != nil || tl.KilledAt == nil || !tl.KilledAt.Equal(killed) {
		t.Fatalf("timeline column: %s %v", col, err)
	}
	rows, err := p.QueryAudit(ctx, AuditQuery{Container: "sg-install-pip-tl", Limit: 1})
	if err != nil || len(rows) != 1 || rows[0].ID != id || rows[0].Timeline == nil || !rows[0].Timeline.KilledAt.Equal(killed) {
		t.Fatalf("query: %+v %v", rows, err)
	}
	if _, err := p.SaveAudit(ctx, model.Verdict{Matched: true, RuleID: "x", Action: model.ActionAlert, Event: model.Event{Kind: model.KindExec, Timestamp: base, ContainerName: "sg-install-pip-tl"}}); err != nil {
		t.Fatalf("alert without timeline (NULL column): %v", err)
	}
	_, _ = p.pool.Exec(ctx, `DELETE FROM audit_log WHERE container_name = 'sg-install-pip-tl'`)
}
