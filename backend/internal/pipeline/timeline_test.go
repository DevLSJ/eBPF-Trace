package pipeline

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/enforcer"
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/model"
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/notify"
)

// timedEnforcer: 단계별 시각을 돌려주는 가짜 격리 수단(enforcer.Timed)
type timedEnforcer struct {
	fakeEnforcer
	times enforcer.Times
}

func (f *timedEnforcer) KillTimed(ctx context.Context, id string) (enforcer.Times, error) {
	err := f.Kill(ctx, id)
	return f.times, err
}

type fakeNotifier struct {
	mu   sync.Mutex
	msgs []notify.Message
}

func (f *fakeNotifier) Notify(_ context.Context, m notify.Message) {
	f.mu.Lock()
	f.msgs = append(f.msgs, m)
	f.mu.Unlock()
}

// Tier 1 — 격리 타임라인(10/30): matched 판정에만 붙고, detectedAt=이벤트 시각 · matchedAt=평가 완료 · 증거/kill 은 격리 수단이 준 시각 · notifiedAt=알림 큐 투입
func TestVerdictTimelineOnKill(t *testing.T) {
	base := time.Date(2026, 10, 30, 9, 0, 0, 0, time.UTC)
	enf := &timedEnforcer{times: enforcer.Times{EvidenceStartedAt: base.Add(120 * time.Millisecond), EvidenceDoneAt: base.Add(400 * time.Millisecond), KilledAt: base.Add(420 * time.Millisecond)}}
	p, hub := newPipe(t, Options{EnforceKill: true}, &fakeEnforcer{})
	p.enforcer = enf
	ntf := &fakeNotifier{}
	p.SetNotifier(ntf)

	ev := openEv("/etc/shadow")
	ev.Timestamp = base
	before := time.Now()
	p.Handle(context.Background(), ev)
	v := hub.snapshot()[0]
	tl := v.Timeline
	if tl == nil || !tl.DetectedAt.Equal(base) || tl.MatchedAt.Before(before) || tl.MatchedAt.After(time.Now()) {
		t.Fatalf("detected · matched: %+v", tl)
	}
	if tl.EvidenceStartedAt == nil || !tl.EvidenceStartedAt.Equal(enf.times.EvidenceStartedAt) || tl.EvidenceDoneAt == nil || !tl.EvidenceDoneAt.Equal(enf.times.EvidenceDoneAt) ||
		tl.KilledAt == nil || !tl.KilledAt.Equal(enf.times.KilledAt) {
		t.Fatalf("evidence · kill from enforcer: %+v", tl)
	}
	if tl.NotifiedAt == nil || len(ntf.msgs) != 1 {
		t.Fatalf("notifiedAt must be set when a notifier queued the message: %+v msgs=%d", tl, len(ntf.msgs))
	}
	if ms, ok := tl.IsolationMs(); !ok || ms != 420 {
		t.Fatalf("isolation ms = %d %v", ms, ok)
	}
	// 잔여 이벤트(이미 격리한 컨테이너): kill 을 다시 보내지 않으므로 killedAt 없음, 나머지는 있음
	p.Handle(context.Background(), ev)
	if v2 := hub.snapshot()[1]; v2.Timeline == nil || v2.Timeline.KilledAt != nil || v2.Timeline.EvidenceStartedAt != nil || !v2.Enforced {
		t.Fatalf("residual event: %+v", v2.Timeline)
	}
	// 정상 판정에는 타임라인이 없다
	p.Handle(context.Background(), openEv("/etc/hosts"))
	if v3 := hub.snapshot()[2]; v3.Matched || v3.Timeline != nil {
		t.Fatalf("normal verdict must not carry a timeline: %+v", v3)
	}
	// dry-run(규칙): 평가 시각까지만, kill 없음
	p.Handle(context.Background(), openEv("/etc/gshadow"))
	if v4 := hub.snapshot()[3]; v4.Timeline == nil || v4.Timeline.KilledAt != nil || !v4.DryRun {
		t.Fatalf("dry-run: %+v", v4.Timeline)
	}
	// 알림이 없으면 notifiedAt 없음; 시각 없이 kill 만 하는 격리 수단(mock)은 killedAt 을 응답 시각으로 채운다
	p2, hub2 := newPipe(t, Options{EnforceKill: true}, &fakeEnforcer{})
	p2.Handle(context.Background(), openEv("/etc/shadow"))
	if v5 := hub2.snapshot()[0]; v5.Timeline == nil || v5.Timeline.NotifiedAt != nil || v5.Timeline.KilledAt == nil || v5.Timeline.KilledAt.Before(before) {
		t.Fatalf("plain enforcer: %+v", v5.Timeline)
	}
	// 전역 dry-run: 격리 없음 → killedAt 없음
	p3, hub3 := newPipe(t, Options{EnforceKill: false}, &fakeEnforcer{})
	p3.Handle(context.Background(), openEv("/etc/shadow"))
	if v6 := hub3.snapshot()[0]; v6.Timeline == nil || v6.Timeline.KilledAt != nil {
		t.Fatalf("global dry-run: %+v", v6.Timeline)
	}
}

// 저장 뒤 AuditSaved: 실제 kill 이 있는 판정만 감사 로그 id 와 함께 review 에 알린다(설치 세션 · 건의 isolation)
func TestAuditSavedAfterPersist(t *testing.T) {
	enf := &timedEnforcer{times: enforcer.Times{KilledAt: time.Now()}}
	p, _ := newPipe(t, Options{EnforceKill: true, NormalEventRate: 100}, &fakeEnforcer{})
	p.enforcer = enf
	rv := &fakeReviewer{}
	p.SetReview(rv)
	events := make(chan model.Event, 4)
	events <- openEv("/etc/shadow")  // kill → AuditSaved
	events <- openEv("/etc/gshadow") // dry-run → 저장은 되지만 AuditSaved 는 없음
	events <- openEv("/etc/hosts")   // 정상 → 저장 안 함
	close(events)
	p.Run(context.Background(), events) // 채널이 닫히면 persist 를 비우고 돌아온다
	got := rv.saved()
	if len(got) != 1 || got[0].id <= 0 || got[0].v.RuleID != "shadow" || got[0].v.Timeline == nil || got[0].v.Timeline.KilledAt == nil {
		t.Fatalf("audit saved: %+v", got)
	}
}

// Tier 1 — 정지 시각(11/16 「먼저 멈추고 증거 수집」): 격리 수단이 준 pause 시각 · pause 오류를 타임라인에 그대로 옮긴다.
// 탐지 → 정지(PauseMs)는 보조 값이고, 격리 지연(IsolationMs = 탐지 → kill)의 정의는 그대로다
func TestVerdictTimelinePause(t *testing.T) {
	base := time.Date(2026, 11, 16, 9, 0, 0, 0, time.UTC)
	enf := &timedEnforcer{times: enforcer.Times{
		PausedAt: base.Add(30 * time.Millisecond), EvidenceStartedAt: base.Add(31 * time.Millisecond),
		EvidenceDoneAt: base.Add(330 * time.Millisecond), KilledAt: base.Add(500 * time.Millisecond),
	}}
	p, hub := newPipe(t, Options{EnforceKill: true}, &fakeEnforcer{})
	p.enforcer = enf
	ev := openEv("/etc/shadow")
	ev.Timestamp = base
	p.Handle(context.Background(), ev)
	tl := hub.snapshot()[0].Timeline
	if tl == nil || tl.PausedAt == nil || !tl.PausedAt.Equal(enf.times.PausedAt) || tl.PauseError != "" {
		t.Fatalf("pausedAt from enforcer: %+v", tl)
	}
	if ms, ok := tl.PauseMs(); !ok || ms != 30 {
		t.Fatalf("pause ms = %d %v", ms, ok)
	}
	if ms, ok := tl.IsolationMs(); !ok || ms != 500 {
		t.Fatalf("isolation ms must stay detected → killed: %d %v", ms, ok)
	}
	// 잔여 이벤트: kill · pause 를 다시 보내지 않으므로 정지 시각도 없다
	p.Handle(context.Background(), ev)
	if v := hub.snapshot()[1]; !v.Enforced || v.Timeline == nil || v.Timeline.PausedAt != nil {
		t.Fatalf("residual event: %+v", v.Timeline)
	}

	// pause 가 실패했지만(500 등) 예전 순서로 격리한 경우: 정지 시각 없음 · 사유 남음 · 격리는 성공
	enf2 := &timedEnforcer{times: enforcer.Times{PauseError: "docker pause: 500 Internal Server Error: boom", KilledAt: base.Add(400 * time.Millisecond)}}
	p2, hub2 := newPipe(t, Options{EnforceKill: true}, &fakeEnforcer{})
	p2.enforcer = enf2
	p2.Handle(context.Background(), ev)
	v2 := hub2.snapshot()[0]
	if !v2.Enforced || v2.Timeline == nil || v2.Timeline.PausedAt != nil || v2.Timeline.PauseError != enf2.times.PauseError {
		t.Fatalf("pause failed, kill ok: enforced=%v %+v", v2.Enforced, v2.Timeline)
	}

	// pause 가 「이미 끝남」(409 · 404)을 돌려준 경우: 격리 아님 + 사유, 정지 · kill 시각 없음(PR #16 과 같은 방식)
	enf3 := &timedEnforcer{fakeEnforcer: fakeEnforcer{err: enforcer.ErrNotRunning}}
	p3, hub3 := newPipe(t, Options{EnforceKill: true}, &fakeEnforcer{})
	p3.enforcer = enf3
	p3.Handle(context.Background(), ev)
	p3.Handle(context.Background(), ev) // 잔여 이벤트
	if len(enf3.calls) != 1 {
		t.Fatalf("isolation calls = %d, want 1", len(enf3.calls))
	}
	for i, v := range hub3.snapshot() {
		if v.Enforced || v.EnforceError != enforcer.ErrNotRunning.Error() || v.Timeline == nil || v.Timeline.PausedAt != nil || v.Timeline.KilledAt != nil {
			t.Fatalf("verdict %d after stopped container: enforced=%v err=%q %+v", i, v.Enforced, v.EnforceError, v.Timeline)
		}
	}
}

// Tier 1 — 이미 끝난 컨테이너(11/16 사용자 결정 「끝난 컨테이너도 증거는」): 격리 수단이 증거 시각과 ErrNotRunning 을 함께 주면
// 타임라인에 증거 시작 · 끝만 남기고 정지 · kill 은 비운다. 결과는 격리 아님 + 사유, 같은 컨테이너의 잔여 이벤트는 첫 결과를 따르고 다시 부르지 않는다
func TestVerdictTimelineExitedContainerEvidence(t *testing.T) {
	base := time.Date(2026, 11, 16, 9, 0, 0, 0, time.UTC)
	enf := &timedEnforcer{fakeEnforcer: fakeEnforcer{err: enforcer.ErrNotRunning}, times: enforcer.Times{
		EvidenceStartedAt: base.Add(25 * time.Millisecond), EvidenceDoneAt: base.Add(140 * time.Millisecond),
	}}
	p, hub := newPipe(t, Options{EnforceKill: true}, &fakeEnforcer{})
	p.enforcer = enf
	ev := openEv("/etc/shadow")
	ev.Timestamp = base
	p.Handle(context.Background(), ev)
	p.Handle(context.Background(), ev) // 잔여 이벤트
	if len(enf.calls) != 1 {
		t.Fatalf("isolation calls = %d, want 1", len(enf.calls))
	}
	got := hub.snapshot()
	v := got[0]
	tl := v.Timeline
	if v.Enforced || v.EnforceError != enforcer.ErrNotRunning.Error() {
		t.Fatalf("exited container is not isolated: enforced=%v err=%q", v.Enforced, v.EnforceError)
	}
	if tl == nil || tl.EvidenceStartedAt == nil || !tl.EvidenceStartedAt.Equal(enf.times.EvidenceStartedAt) ||
		tl.EvidenceDoneAt == nil || !tl.EvidenceDoneAt.Equal(enf.times.EvidenceDoneAt) || tl.PausedAt != nil || tl.KilledAt != nil {
		t.Fatalf("evidence times only: %+v", tl)
	}
	if _, ok := tl.IsolationMs(); ok {
		t.Fatal("no isolation latency without a kill")
	}
	if r := got[1]; r.Enforced || r.EnforceError != enforcer.ErrNotRunning.Error() || r.Timeline == nil || r.Timeline.EvidenceStartedAt != nil {
		t.Fatalf("residual event follows the first result without new evidence: enforced=%v err=%q %+v", r.Enforced, r.EnforceError, r.Timeline)
	}
}
