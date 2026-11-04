package demo_test

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/demo"
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/ingestion"
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/model"
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/rules"
)

// defaultEngine: 저장소 기본 정책(backend/policies/default.yaml) 그대로의 엔진 — sg-vm 첫 시드와 같다
func defaultEngine(t *testing.T) *rules.Engine {
	t.Helper()
	rs, err := rules.LoadFile(filepath.Join("..", "..", "policies", "default.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	return rules.New(rs)
}

// collect: 컨테이너 이름이 name 인 이벤트를 종료(exit)까지 모은다
func collect(t *testing.T, out <-chan model.Event, name string) []model.Event {
	t.Helper()
	var evs []model.Event
	deadline := time.After(5 * time.Second)
	for {
		select {
		case ev := <-out:
			if ev.ContainerName != name {
				continue
			}
			evs = append(evs, ev)
			if ev.Kind == model.KindExit {
				return evs
			}
		case <-deadline:
			t.Fatalf("timed out; events so far %d", len(evs))
		}
	}
}

func eventKey(ev model.Event) string {
	k := string(ev.Kind)
	switch ev.Kind {
	case model.KindExec:
		k += ":" + ev.Comm
	case model.KindConnect:
		k += ":" + ev.DstHost
		if ev.DstHost == "" {
			k += ev.DstIP
		}
	case model.KindOpen:
		k += ":" + ev.Path
	case model.KindDNS:
		k += ":" + ev.Qtype + ":" + ev.DstHost
	}
	return k
}

// 11/04 — 시나리오 목록 끝에 새 시나리오가 붙는다(기존 순서 유지), 400 문구도 함께
func TestDemoScenarioList1104(t *testing.T) {
	want := "all shell revshell direct-ip domain dns-exfil benign"
	if got := strings.Join(demo.Scenarios, " "); got != want {
		t.Fatalf("scenarios: %q, want %q", got, want)
	}
	if demo.ErrScenario.Error() != "scenario: all | shell | revshell | direct-ip | domain | dns-exfil | benign" {
		t.Fatalf("ErrScenario: %q", demo.ErrScenario)
	}
}

// Tier 1 — benign(정상 설치 대조군) 가젯 소스: 같은 Docker 순서(ping → create → archive → start → wait → remove),
// 패키지는 sg-demo-benign 만 올리고 pip 설치 대상도 그것. 세션 라벨은 「pip ./sg-demo-benign」, 끝나면 통과
func TestDemoBenignDockerFlow(t *testing.T) {
	fd := &fakeDocker{exit: 0}
	h := newHarness(t, demo.Options{Docker: fd, Image: "python:3.12-slim", Timeout: time.Second}, false, nil)
	run, err := h.svc.Start(context.Background(), "benign")
	if err != nil || run.Status != "running" || run.Scenario != "benign" || !strings.HasPrefix(run.Container, "sg-install-demo-") {
		t.Fatalf("start: %+v %v", run, err)
	}
	h.svc.Wait()
	want := []string{"ping", "create", "archive:cid123", "start:cid123", "wait:cid123", "remove:cid123:true"}
	if calls := fd.list(); strings.Join(calls, " ") != strings.Join(want, " ") {
		t.Fatalf("docker calls:\n got %v\nwant %v", calls, want)
	}
	sp := fd.spec
	if sp.Name != run.Container || sp.Image != "python:3.12-slim" || strings.Join(sp.Cmd, " ") != "pip install --no-cache-dir --progress-bar off /pkg/sg-demo-benign" {
		t.Fatalf("create spec: %+v", sp)
	}
	if strings.Join(sp.Env, ",") != "PIP_DISABLE_PIP_VERSION_CHECK=1" || sp.Labels["supplyguard.demo"] != "install" {
		t.Fatalf("env · labels: %+v", sp)
	}
	tarb := string(fd.archive)
	for _, f := range []string{"pkg/sg-demo-benign/setup.py", "pkg/sg-demo-benign/README.md", "pkg/sg-demo-benign/sg_demo_benign.py"} {
		if !strings.Contains(tarb, f) {
			t.Errorf("archive must carry %s", f)
		}
	}
	if strings.Contains(tarb, "pkg/reqeusts") || strings.Contains(tarb, "203.0.113") {
		t.Fatal("benign archive must not carry the attack package")
	}
	s, err := h.rv.GetInstall(run.InstallID)
	if err != nil || s.Label() != "pip ./sg-demo-benign" || !s.Demo || s.Status != model.InstallPassed {
		t.Fatalf("session: %+v %v", s, err)
	}
	if ch := h.rv.ListChanges(1); len(ch) != 1 || ch[0].Summary != "시연 실행: benign" {
		t.Fatalf("change: %+v", ch)
	}
}

// benign 은 reqeusts 와 다른 패키지라 pip:reqeusts 가 차단 목록에 있어도 거부되지 않는다(대조군은 언제나 돈다)
func TestDemoBenignNotRefusedByReqeustsBlock(t *testing.T) {
	sim := &gateSim{release: make(chan struct{})}
	h := newHarness(t, demo.Options{Simulator: sim}, false, nil, "pip:reqeusts")
	run, err := h.svc.Start(context.Background(), "benign")
	if err != nil || run.Status != "running" {
		t.Fatalf("benign with pip:reqeusts blocked: %+v %v", run, err)
	}
	close(sim.release)
	h.svc.Wait()
	// 반대로 benign 패키지가 차단돼 있으면 benign 이 거부된다
	h2 := newHarness(t, demo.Options{Simulator: &gateSim{release: make(chan struct{})}}, false, nil, "pip:sg-demo-benign")
	if r, err := h2.svc.Start(context.Background(), "benign"); err != nil || r.Status != "refused" {
		t.Fatalf("benign blocked: %+v %v", r, err)
	}
}

// mock 소스: benign 은 pip 정상 설치 이벤트만 재생하고(설치 대상 ./sg-demo-benign) 0 으로 끝나 통과.
// 그 이벤트를 저장소 기본 정책(default.yaml)으로 평가하면 위반이 0건이어야 한다
func TestDemoBenignMockPassesDefaultPolicy(t *testing.T) {
	m := ingestion.NewMock()
	m.Interval, m.AttackIn, m.RestartIn, m.Step = time.Hour, time.Hour, time.Hour, time.Millisecond
	out := make(chan model.Event, 4096)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go m.Run(ctx, out)
	for range 3 {
		<-out
	}
	h := newHarness(t, demo.Options{Simulator: m}, false, m.SimulateInstall)
	run, err := h.svc.Start(context.Background(), "benign")
	if err != nil {
		t.Fatal(err)
	}
	evs := collect(t, out, run.Container)
	var keys []string
	for _, ev := range evs {
		keys = append(keys, eventKey(ev))
	}
	want := "start exec:pip connect:pypi.org connect:files.pythonhosted.org open:/usr/local/lib/python3.12/site-packages/setuptools/__init__.py exit"
	if strings.Join(keys, " ") != want {
		t.Fatalf("events:\n got %v\nwant %s", keys, want)
	}
	if evs[1].Args != "pip install --no-cache-dir ./sg-demo-benign" {
		t.Fatalf("pip args: %q", evs[1].Args)
	}
	eng := defaultEngine(t)
	for _, ev := range evs {
		if v := eng.Observe(ev); v.Matched {
			t.Errorf("benign event must not violate the default policy: %s → %s (%s)", eventKey(ev), v.RuleID, v.Reason)
		}
	}
	h.svc.Wait()
	if st := h.svc.Status(); st.Last == nil || st.Last.Status != "finished" || *st.Last.ExitCode != 0 {
		t.Fatalf("status: %+v", st.Last)
	}
	if s, _ := h.rv.GetInstall(run.InstallID); s.Status != model.InstallPassed || s.Label() != "pip ./sg-demo-benign" {
		t.Fatalf("session: %+v", s)
	}
}
