package integration

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/model"
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/pipeline"
)

type fakeLister struct{ cs []Container }

func (f fakeLister) Containers(context.Context) ([]Container, error) { return f.cs, nil }

type fakeScoper struct{}

// 이름 규칙 흉내: supplyguard-* 제외, 라벨 watch 면 감시, enforce 면 격리
func (fakeScoper) Scope(name string, l map[string]string) pipeline.Scope {
	switch {
	case name == "supplyguard-backend-1":
		return pipeline.Scope{Ignored: true}
	case l[pipeline.LabelEnforce] == "true":
		return pipeline.Scope{Watched: true, WatchBy: "label", Enforce: true, EnforceBy: "label"}
	case l[pipeline.LabelWatch] == "true":
		return pipeline.Scope{Watched: true, WatchBy: "label"}
	}
	return pipeline.Scope{}
}

type fakeRecorder struct {
	mu   sync.Mutex
	got  []string
	kind []model.ChangeKind
}

func (r *fakeRecorder) RecordChange(_ context.Context, k model.ChangeKind, s string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.kind, r.got = append(r.kind, k), append(r.got, s)
	return nil
}

// fakeProber: Probe 동안 svc.Observe 로 이벤트를 흘린다(파이프라인 관찰 훅 흉내)
type fakeProber struct {
	svc    *Service
	events []model.Kind
	err    error
	gate   chan struct{}
}

func (p *fakeProber) Probe(_ context.Context, name string) error {
	if p.gate != nil {
		<-p.gate
	}
	p.svc.Observe(model.Event{Kind: model.KindStart, ContainerName: name})
	for _, k := range p.events {
		p.svc.Observe(model.Event{Kind: k, ContainerName: name})
	}
	p.svc.Observe(model.Event{Kind: model.KindOpen, ContainerName: "other"}) // 다른 컨테이너는 세지 않는다
	p.svc.Observe(model.Event{Kind: model.KindExit, ContainerName: name})
	return p.err
}

// 목록: 자기 스택은 빼고, 감시 중이 먼저 · 이름순. 판정은 Scoper(파이프라인과 같은 규칙)
func TestStatusContainers(t *testing.T) {
	s := New(Options{Scoper: fakeScoper{}, Lister: fakeLister{cs: []Container{
		{ID: "1", Name: "zeta", Labels: map[string]string{}},
		{ID: "2", Name: "shop-api", Labels: map[string]string{pipeline.LabelWatch: "true"}},
		{ID: "3", Name: "supplyguard-backend-1", Labels: map[string]string{pipeline.LabelWatch: "true"}},
		{ID: "4", Name: "alpha-worker", Labels: map[string]string{pipeline.LabelEnforce: "true"}},
	}}, EnforceNames: []string{"sg-install-*"}, Source: "gadget"})
	st := s.Status(context.Background())
	var names []string
	for _, c := range st.Containers {
		names = append(names, c.Name)
	}
	if got := len(names); got != 3 || names[0] != "alpha-worker" || names[1] != "shop-api" || names[2] != "zeta" {
		t.Fatalf("containers = %v", names)
	}
	if !st.Containers[0].Enforce || st.Containers[1].Enforce || st.Containers[2].Watched {
		t.Fatalf("scope = %+v", st.Containers)
	}
	if st.Env.LabelWatch != "supplyguard.watch" || st.Env.Testable || st.Test != nil {
		t.Fatalf("env = %+v test = %+v", st.Env, st.Test)
	}
}

// 연결 테스트: 시험 컨테이너 이벤트만 종류별로 세고, 받았으면 passed · 변경 이력 1줄 · 진행 중엔 409(ErrBusy)
func TestStartTestPasses(t *testing.T) {
	rec := &fakeRecorder{}
	p := &fakeProber{events: []model.Kind{model.KindExec, model.KindExec, model.KindOpen}, gate: make(chan struct{})}
	s := New(Options{Prober: p, Recorder: rec, Now: func() time.Time { return time.Unix(1700000000, 0) }})
	p.svc = s
	tst, err := s.StartTest(context.Background())
	if err != nil || tst.State != "running" || tst.Container != "sg-probe-1700000000" {
		t.Fatalf("start = %+v, %v", tst, err)
	}
	if _, err := s.StartTest(context.Background()); !errors.Is(err, ErrBusy) {
		t.Fatalf("second start = %v, want ErrBusy", err)
	}
	close(p.gate)
	s.Wait()
	got := s.Status(context.Background()).Test
	if got == nil || got.State != "passed" || got.Events["exec"] != 2 || got.Events["open"] != 1 || got.EndedAt == nil {
		t.Fatalf("test = %+v", got)
	}
	if len(rec.got) != 1 || rec.kind[0] != ChangeKind || rec.got[0] != "연결 테스트: sg-probe-1700000000" {
		t.Fatalf("change = %v %v", rec.kind, rec.got)
	}
	// 같은 초에 다시 눌러도 이름이 겹치지 않는다
	next, err := s.StartTest(context.Background())
	if err != nil || next.Container != "sg-probe-1700000001" {
		t.Fatalf("next = %+v %v", next, err)
	}
	s.Wait()
}

// 이벤트가 하나도 안 오면 failed + 원인 안내, Probe 오류는 그대로, Prober 없으면 ErrUnavailable
func TestStartTestFails(t *testing.T) {
	p := &fakeProber{}
	s := New(Options{Prober: p})
	p.svc = s
	if _, err := s.StartTest(context.Background()); err != nil {
		t.Fatal(err)
	}
	s.Wait()
	// 원인 안내(11/09 「— 표기 없앰」): 두 문장으로 나눈다
	if got := s.Status(context.Background()).Test; got.State != "failed" ||
		got.Error != "시험 컨테이너의 이벤트가 들어오지 않았습니다. 가젯 · 컨테이너 발견 방식 · 감시 범위를 확인하세요" {
		t.Fatalf("no events = %+v", got)
	}
	p2 := &fakeProber{err: errors.New("pull busybox: denied"), events: []model.Kind{model.KindExec}}
	s2 := New(Options{Prober: p2})
	p2.svc = s2
	_, _ = s2.StartTest(context.Background())
	s2.Wait()
	if got := s2.Status(context.Background()).Test; got.State != "failed" || got.Error != "pull busybox: denied" {
		t.Fatalf("probe error = %+v", got)
	}
	if _, err := New(Options{}).StartTest(context.Background()); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("no prober = %v", err)
	}
}
