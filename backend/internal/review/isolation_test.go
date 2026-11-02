package review

import (
	"testing"
	"time"

	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/model"
)

// 격리 타임라인(10/30): 감사 로그에 저장된 첫 실제 kill 판정이 설치 세션 · 건의 isolation{auditId, timeline} 이 된다. 뒤의 kill 은 덮어쓰지 않는다
func TestIsolationAttached(t *testing.T) {
	e := newEnv(t)
	ctx := t.Context()
	s, err := e.svc.StartInstall(ctx, StartInput{Manager: "pip", Packages: []string{"./reqeusts"}, Container: "sg-install-pip-1", Image: "python:3.12-slim"})
	if err != nil {
		t.Fatal(err)
	}
	ev := sandboxEv(s.Container)
	ev.Kind, ev.Path = model.KindOpen, "/etc/shadow"
	v := e.observe(t, ev)
	killed := e.now.Add(420 * time.Millisecond)
	v.Timeline = &model.Timeline{DetectedAt: e.now, MatchedAt: e.now.Add(time.Millisecond), KilledAt: &killed}
	e.svc.AuditSaved(v, 7)
	got, _ := e.svc.GetInstall(s.ID)
	if got.Isolation == nil || got.Isolation.AuditID != 7 || got.Isolation.Timeline.KilledAt == nil || !got.Isolation.Timeline.KilledAt.Equal(killed) {
		t.Fatalf("session isolation: %+v", got.Isolation)
	}
	c, _ := e.svc.GetCase(*v.CaseID)
	if c.Isolation == nil || c.Isolation.AuditID != 7 {
		t.Fatalf("case isolation: %+v", c.Isolation)
	}
	// 두 번째 kill 판정(잔여 이벤트)은 첫 기록을 덮어쓰지 않는다
	v2 := e.observe(t, ev)
	later := killed.Add(time.Second)
	v2.Timeline = &model.Timeline{DetectedAt: e.now, MatchedAt: e.now, KilledAt: &later}
	e.svc.AuditSaved(v2, 8)
	if got, _ = e.svc.GetInstall(s.ID); got.Isolation.AuditID != 7 {
		t.Fatalf("first kill must stay: %+v", got.Isolation)
	}
	// kill 이 없는 판정(알림 · dry-run)은 붙이지 않는다
	s2, _ := e.svc.StartInstall(ctx, StartInput{Manager: "pip", Packages: []string{"x"}, Container: "sg-install-pip-2"})
	ev2 := sandboxEv(s2.Container)
	ev2.Kind, ev2.DstIP, ev2.DstPort = model.KindConnect, "203.0.113.9", 8081 // egress-allowlist alert
	a := e.observe(t, ev2)
	a.Timeline = &model.Timeline{DetectedAt: e.now, MatchedAt: e.now}
	e.svc.AuditSaved(a, 9)
	if got, _ := e.svc.GetInstall(s2.ID); got.Isolation != nil {
		t.Fatalf("alert must not attach isolation: %+v", got.Isolation)
	}
	// 런타임 건
	run := model.Event{Kind: model.KindOpen, ContainerID: sandboxCID, ContainerName: "web-api", Path: "/etc/shadow"}
	rv := e.observe(t, run)
	rv.Timeline = &model.Timeline{DetectedAt: e.now, MatchedAt: e.now, KilledAt: &killed}
	e.svc.AuditSaved(rv, 10)
	if c, _ := e.svc.GetCase(*rv.CaseID); c.Isolation == nil || c.Isolation.AuditID != 10 {
		t.Fatalf("runtime case isolation: %+v", c.Isolation)
	}
	// 저장소로 흘러간다(flush) — 사본에 남는다
	e.svc.Flush(ctx)
	snap, _ := e.store.LoadReview(ctx)
	var found bool
	for _, x := range snap.Installs {
		if x.ID == s.ID && x.Isolation != nil && x.Isolation.AuditID == 7 {
			found = true
		}
	}
	if !found {
		t.Fatalf("isolation must be persisted: %+v", snap.Installs)
	}
}
