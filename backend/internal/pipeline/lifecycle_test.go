package pipeline

import (
	"context"
	"testing"

	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/model"
)

// fakeReviewer: 차단 이미지 목록만 가진 가짜 review.Service
type fakeReviewer struct {
	blocked  map[string]bool
	observed []model.Verdict
	exited   []string
}

func (f *fakeReviewer) Observe(v *model.Verdict) { f.observed = append(f.observed, *v) }
func (f *fakeReviewer) ContainerStarted(ev model.Event) (string, bool) {
	if f.blocked[ev.ImageName] {
		return ev.ImageName, true
	}
	return "", false
}
func (f *fakeReviewer) ContainerExited(ev model.Event) { f.exited = append(f.exited, ev.ContainerName) }

func startEv(name, image string) model.Event {
	return model.Event{Kind: model.KindStart, ContainerID: cid, ContainerName: name, ImageName: image}
}

// Tier 1 — 차단 목록의 이미지로 컨테이너가 시작되면 즉시 격리한다(사유 blocked-image). 판정은 건 묶기 · 피드로 간다.
func TestBlockedImageKilledOnStart(t *testing.T) {
	enf := &fakeEnforcer{}
	p, hub := newPipe(t, Options{EnforceKill: true}, enf)
	rv := &fakeReviewer{blocked: map[string]bool{"demo/reqeusts:1.0.2": true}}
	p.SetReview(rv)

	p.Handle(context.Background(), startEv("pkg-reqeusts", "demo/reqeusts:1.0.2"))
	if len(enf.calls) != 1 || enf.calls[0] != cid {
		t.Fatalf("blocked image must be killed once, calls=%v", enf.calls)
	}
	if len(hub.msgs) != 1 {
		t.Fatalf("want 1 verdict, got %d", len(hub.msgs))
	}
	v := hub.msgs[0]
	if !v.Matched || v.RuleID != "blocked-image" || v.Action != model.ActionKill || !v.Enforced {
		t.Fatalf("verdict: %+v", v)
	}
	if len(rv.observed) != 1 || rv.observed[0].RuleID != "blocked-image" {
		t.Fatalf("verdict must go to case tracking: %+v", rv.observed)
	}

	p.Handle(context.Background(), startEv("web-api", "node:22-alpine"))
	if len(enf.calls) != 1 || len(hub.msgs) != 1 {
		t.Fatal("an allowed image start must not be killed or shown in the feed")
	}
}

// 관찰 범위(WATCH_CONTAINERS) 밖 · 자기 스택은 차단 이미지여도 건드리지 않는다.
func TestBlockedImageRespectsScope(t *testing.T) {
	enf := &fakeEnforcer{}
	p, hub := newPipe(t, Options{EnforceKill: true, WatchContainers: []string{"sg-install-*"}, IgnoreContainers: []string{"supplyguard-*"}}, enf)
	p.SetReview(&fakeReviewer{blocked: map[string]bool{"demo/reqeusts:1.0.2": true}})
	p.Handle(context.Background(), startEv("minikube", "demo/reqeusts:1.0.2"))
	p.Handle(context.Background(), startEv("supplyguard-backend-1", "demo/reqeusts:1.0.2"))
	if len(enf.calls) != 0 || len(hub.msgs) != 0 {
		t.Fatalf("out-of-scope containers must be left alone: calls=%v msgs=%d", enf.calls, len(hub.msgs))
	}
}

// 전역 ENFORCE_KILL=false 면 차단 이미지도 알림만(격리 대상).
func TestBlockedImageDryRun(t *testing.T) {
	enf := &fakeEnforcer{}
	p, hub := newPipe(t, Options{EnforceKill: false}, enf)
	p.SetReview(&fakeReviewer{blocked: map[string]bool{"demo/reqeusts:1.0.2": true}})
	p.Handle(context.Background(), startEv("pkg-reqeusts", "demo/reqeusts:1.0.2"))
	if len(enf.calls) != 0 {
		t.Fatal("ENFORCE_KILL=false must not kill")
	}
	if len(hub.msgs) != 1 || !hub.msgs[0].DryRun || hub.msgs[0].Enforced {
		t.Fatalf("want a dry-run blocked-image verdict, got %+v", hub.msgs)
	}
}

// 종료 이벤트는 피드에 나가지 않고 세션의 containerExitedAt 에만 쓴다.
func TestExitEventRecorded(t *testing.T) {
	p, hub := newPipe(t, Options{}, &fakeEnforcer{})
	rv := &fakeReviewer{}
	p.SetReview(rv)
	p.Handle(context.Background(), model.Event{Kind: model.KindExit, ContainerID: cid, ContainerName: "sg-install-pip-1"})
	if len(rv.exited) != 1 || len(hub.msgs) != 0 {
		t.Fatalf("exit: %v msgs=%d", rv.exited, len(hub.msgs))
	}
}
