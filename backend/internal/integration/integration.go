// Package integration: 「연동」 화면(11/06) — 환경 점검 · 감시 중 컨테이너(라벨 · 이름) · 연결 테스트.
//
// 연결 테스트는 감시 라벨(supplyguard.watch=true)만 붙인 무해한 시험 컨테이너 sg-probe-<unix> 를 띄워
// 파이프라인이 그 컨테이너의 이벤트를 실제로 받는지 센다. 격리 라벨은 붙이지 않는다(정책에 걸려도 보류).
// 동시 1개 · 45초 제한 · 변경 이력 「연결 테스트」. 가젯은 Docker(busybox), mock 은 같은 이벤트를 모의 재생한다.
package integration

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/model"
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/pipeline"
)

const (
	ProbePrefix  = "sg-probe-"
	ProbeImage   = "busybox:1.36"
	testTimeout  = 45 * time.Second
	ChangeKind   = model.ChangeKind("integration_test")
	probeSummary = "연결 테스트: "
)

// ProbeCmd: 시험 컨테이너 본문 — 1초 쉬고(docker-events 발견이 붙을 시간) 파일 하나 읽고 목록 하나 보고 끝. 네트워크 없음
var ProbeCmd = []string{"sh", "-c", "sleep 1; cat /etc/hostname >/dev/null; ls /etc >/dev/null; sleep 2"}

// Container: 화면에 보일 컨테이너 한 줄
type Container struct {
	ID     string            `json:"id"`
	Name   string            `json:"name"`
	Image  string            `json:"image"`
	Labels map[string]string `json:"-"`
	pipeline.Scope
}

// Lister: 실행 중인 컨테이너와 라벨(가젯 = Docker List, mock = 흉내 컨테이너)
type Lister interface {
	Containers(ctx context.Context) ([]Container, error)
}

// Prober: 시험 컨테이너를 띄우고 끝날 때까지 기다린 뒤 지운다(가젯 = Docker, mock = 재생)
type Prober interface {
	Probe(ctx context.Context, name string) error
}

// Scoper: pipeline.Pipeline.Scope — 감시 · 격리 판정은 파이프라인과 같은 규칙
type Scoper interface {
	Scope(name string, labels map[string]string) pipeline.Scope
}

// Recorder: review.Service.RecordChange — 변경 이력
type Recorder interface {
	RecordChange(ctx context.Context, kind model.ChangeKind, summary string) error
}

type Options struct {
	Lister   Lister
	Prober   Prober // nil 이면 연결 테스트 없음(503)
	Scoper   Scoper
	Recorder Recorder
	// 환경 점검에 보일 값(main 이 채운다)
	Source       string
	EnforceKill  bool
	EnforceNames []string
	HostRoot     string // 호스트 /etc/os-release 를 읽을 루트(HOST_ROOT, 컨테이너 안이면 /host)
	Now          func() time.Time
}

// Test: 연결 테스트 한 번
type Test struct {
	ID        string         `json:"id"`
	Container string         `json:"container"`
	State     string         `json:"state"` // running · passed · failed
	StartedAt time.Time      `json:"startedAt"`
	EndedAt   *time.Time     `json:"endedAt,omitempty"`
	Events    map[string]int `json:"events"` // 종류별 받은 이벤트 수
	Error     string         `json:"error,omitempty"`
}

// Env: 환경 점검
type Env struct {
	Source       string   `json:"source"`
	OS           string   `json:"os"`
	Kernel       string   `json:"kernel"`
	EnforceKill  bool     `json:"enforceKill"`
	EnforceNames []string `json:"enforceNames"`
	LabelWatch   string   `json:"labelWatch"`
	LabelEnforce string   `json:"labelEnforce"`
	ProbeImage   string   `json:"probeImage"`
	Testable     bool     `json:"testable"`
}

type Status struct {
	Env        Env         `json:"env"`
	Containers []Container `json:"containers"`
	ListError  string      `json:"listError,omitempty"`
	Test       *Test       `json:"test"`
}

var (
	ErrBusy        = errors.New("연결 테스트가 이미 진행 중입니다")
	ErrUnavailable = errors.New("이 서버에서는 연결 테스트를 할 수 없습니다")
)

type Service struct {
	o      Options
	base   context.Context // Shutdown 이 끊는다 → 진행 중인 시험 컨테이너를 지우고 끝낸다
	cancel context.CancelFunc
	mu     sync.Mutex
	last   *Test
	seq    int64
	wg     sync.WaitGroup
}

func New(o Options) *Service {
	if o.Now == nil {
		o.Now = time.Now
	}
	base, cancel := context.WithCancel(context.Background())
	return &Service{o: o, base: base, cancel: cancel}
}

// Shutdown: 진행 중인 연결 테스트를 끊고(시험 컨테이너 강제 삭제) 끝날 때까지 기다린다(ctx 상한)
func (s *Service) Shutdown(ctx context.Context) error {
	s.cancel()
	done := make(chan struct{})
	go func() { s.wg.Wait(); close(done) }()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Observe: 파이프라인 관찰 훅 — 진행 중인 시험 컨테이너의 이벤트만 센다
func (s *Service) Observe(ev model.Event) {
	if !strings.HasPrefix(ev.ContainerName, ProbePrefix) {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.last != nil && s.last.State == "running" && s.last.Container == ev.ContainerName && ev.Kind != model.KindStart && ev.Kind != model.KindExit {
		s.last.Events[string(ev.Kind)]++
	}
}

func (s *Service) Status(ctx context.Context) Status {
	st := Status{Env: s.env(), Containers: []Container{}}
	if s.o.Lister != nil {
		cs, err := s.o.Lister.Containers(ctx)
		if err != nil {
			st.ListError = err.Error()
		}
		for _, c := range cs {
			if s.o.Scoper != nil {
				c.Scope = s.o.Scoper.Scope(c.Name, c.Labels)
			}
			if c.Ignored {
				continue // 자기 스택은 목록에서 뺀다
			}
			st.Containers = append(st.Containers, c)
		}
	}
	// 감시 중 → 이름순
	sort.SliceStable(st.Containers, func(i, j int) bool {
		a, b := st.Containers[i], st.Containers[j]
		if a.Watched != b.Watched {
			return a.Watched
		}
		return a.Name < b.Name
	})
	s.mu.Lock()
	if s.last != nil {
		t := s.last.clone()
		st.Test = &t
	}
	s.mu.Unlock()
	return st
}

// StartTest: 시험 컨테이너를 띄우고 바로 돌아온다. 결과는 Status().Test
func (s *Service) StartTest(ctx context.Context) (Test, error) {
	if s.o.Prober == nil {
		return Test{}, ErrUnavailable
	}
	s.mu.Lock()
	if s.last != nil && s.last.State == "running" {
		s.mu.Unlock()
		return Test{}, ErrBusy
	}
	now := s.o.Now().UTC()
	unix := now.Unix()
	if unix <= s.seq {
		unix = s.seq + 1 // 같은 초에 다시 눌러도 이름이 겹치지 않게
	}
	s.seq = unix
	t := &Test{ID: fmt.Sprintf("probe-%d", unix), Container: fmt.Sprintf("%s%d", ProbePrefix, unix), State: "running", StartedAt: now, Events: map[string]int{}}
	s.last = t
	out := t.clone()
	s.mu.Unlock()

	if s.o.Recorder != nil {
		if err := s.o.Recorder.RecordChange(ctx, ChangeKind, probeSummary+out.Container); err != nil {
			slog.Warn("integration: change record", "err", err)
		}
	}
	s.wg.Add(1)
	go s.run(t.Container)
	return out, nil
}

func (s *Service) run(name string) {
	defer s.wg.Done()
	ctx, cancel := context.WithTimeout(s.base, testTimeout)
	defer cancel()
	err := s.o.Prober.Probe(ctx, name)
	// 마지막 이벤트가 파이프라인을 지나갈 틈
	time.Sleep(300 * time.Millisecond)
	s.mu.Lock()
	defer s.mu.Unlock()
	t := s.last
	if t == nil || t.Container != name {
		return
	}
	end := s.o.Now().UTC()
	t.EndedAt = &end
	n := 0
	for _, v := range t.Events {
		n += v
	}
	switch {
	case err != nil:
		t.State, t.Error = "failed", err.Error()
	case n == 0:
		t.State, t.Error = "failed", "시험 컨테이너의 이벤트가 들어오지 않았습니다. 가젯 · 컨테이너 발견 방식 · 감시 범위를 확인하세요"
	default:
		t.State = "passed"
	}
	slog.Info("integration test", "container", name, "state", t.State, "events", t.Events, "err", t.Error)
}

// Wait: 진행 중인 테스트가 끝날 때까지(서버 종료 · 테스트)
func (s *Service) Wait() { s.wg.Wait() }

func (t Test) clone() Test {
	ev := make(map[string]int, len(t.Events))
	for k, v := range t.Events {
		ev[k] = v
	}
	t.Events = ev
	if t.EndedAt != nil {
		e := *t.EndedAt
		t.EndedAt = &e
	}
	return t
}

func (s *Service) env() Env {
	names := s.o.EnforceNames
	if names == nil {
		names = []string{}
	}
	return Env{
		Source: s.o.Source, OS: osName(s.o.HostRoot), Kernel: kernel(), EnforceKill: s.o.EnforceKill, EnforceNames: names,
		LabelWatch: pipeline.LabelWatch, LabelEnforce: pipeline.LabelEnforce, ProbeImage: ProbeImage, Testable: s.o.Prober != nil,
	}
}

// kernel: 리눅스 커널 버전(컨테이너 안이어도 호스트 커널). 리눅스가 아니면 빈 값
func kernel() string {
	b, err := os.ReadFile("/proc/sys/kernel/osrelease")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// osName: 호스트 /etc/os-release 의 PRETTY_NAME(HOST_ROOT 아래 먼저, 없으면 이 프로세스의 것)
func osName(hostRoot string) string {
	for _, p := range []string{filepath.Join(hostRoot, "etc/os-release"), "/etc/os-release"} {
		if hostRoot == "" && p != "/etc/os-release" {
			continue
		}
		b, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(b), "\n") {
			if v, ok := strings.CutPrefix(line, "PRETTY_NAME="); ok {
				return strings.Trim(strings.TrimSpace(v), `"`)
			}
		}
	}
	return ""
}
