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
