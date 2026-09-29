// Package pipeline wires events → rules → enforcement → audit/buffer/stats/WebSocket.
package pipeline

import (
	"context"
	"errors"
	"log/slog"
	"path"
	"sync"
	"time"

	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/enforcer"
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/model"
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/rules"
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/stats"
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/store"
)

// Broadcaster: ws.Hub (테스트에서 대체)
type Broadcaster interface {
	Broadcast(msgType string, data any)
}

type Options struct {
	EnforceKill      bool
	IgnoreContainers []string
	NormalEventRate  int
}

type Pipeline struct {
	opt      Options
	engine   *rules.Engine
	enforcer enforcer.Enforcer
	hub      Broadcaster
	stats    *stats.Aggregator
	audit    store.AuditStore
	buffer   store.Buffer

	persist chan model.Verdict
	killed  map[string]time.Time // 컨테이너 ID → 격리 시각 (중복 kill 방지)

	rateSec   int64
	rateCount int
}

const (
	killTimeout  = 5 * time.Second
	killDedupe   = 10 * time.Minute
	persistQueue = 2048
)

func New(opt Options, engine *rules.Engine, enf enforcer.Enforcer, hub Broadcaster,
	agg *stats.Aggregator, audit store.AuditStore, buffer store.Buffer) *Pipeline {
	return &Pipeline{
		opt: opt, engine: engine, enforcer: enf, hub: hub, stats: agg, audit: audit, buffer: buffer,
		persist: make(chan model.Verdict, persistQueue),
		killed:  map[string]time.Time{},
	}
}

// Run: events 채널이 닫히거나 ctx가 끝날 때까지 평가 루프를 돈다.
func (p *Pipeline) Run(ctx context.Context, events <-chan model.Event) {
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		p.persistLoop()
	}()
	defer func() {
		close(p.persist)
		wg.Wait()
	}()

	for {
		select {
		case <-ctx.Done():
			return
		case ev, ok := <-events:
			if !ok {
				return
			}
			p.Handle(ctx, ev)
		}
	}
}

// Ignored: 자기 스택(supplyguard-*) 등 관찰·격리 제외 대상
func (p *Pipeline) Ignored(containerName string) bool {
	for _, g := range p.opt.IgnoreContainers {
		if ok, _ := path.Match(g, containerName); ok {
			return true
		}
	}
	return false
}

func (p *Pipeline) Handle(ctx context.Context, ev model.Event) {
	if ev.ContainerID == "" || p.Ignored(ev.ContainerName) {
		return // 호스트 프로세스 또는 보호 대상
	}
	if ev.Timestamp.IsZero() {
		ev.Timestamp = time.Now().UTC()
	}
	v := p.engine.Evaluate(ev)
	if v.Matched && v.Action == model.ActionKill && !v.DryRun {
		p.enforce(ctx, &v)
	}
	p.stats.Observe(v)

	if v.Matched || p.allowNormal(ev.Timestamp) {
		p.hub.Broadcast("verdict", v)
		select {
		case p.persist <- v:
		default:
			slog.Warn("persist queue full; dropping verdict", "matched", v.Matched)
		}
	}
}

func (p *Pipeline) enforce(ctx context.Context, v *model.Verdict) {
	if !p.opt.EnforceKill {
		v.DryRun = true // 전역 dry-run: 격리 대상이지만 알림만
		return
	}
	id := v.Event.ContainerID
	if at, ok := p.killed[id]; ok && time.Since(at) < killDedupe {
		v.Enforced = true // 이미 격리 요청을 보낸 컨테이너의 잔여 이벤트
		return
	}
	kctx, cancel := context.WithTimeout(ctx, killTimeout)
	defer cancel()
	err := p.enforcer.Kill(kctx, id)
	switch {
	case err == nil:
		v.Enforced = true
		p.killed[id] = time.Now()
		p.stats.Killed(id, v.Event.ContainerName)
		slog.Warn("container killed", "container", v.Event.ContainerName, "id", id, "rule", v.RuleID, "reason", v.Reason)
	case errors.Is(err, enforcer.ErrNotRunning), errors.Is(err, enforcer.ErrNotFound):
		p.killed[id] = time.Now()
		v.EnforceError = err.Error()
	default:
		v.EnforceError = err.Error()
		slog.Error("kill failed", "container", v.Event.ContainerName, "id", id, "err", err)
	}
	for k, at := range p.killed {
		if time.Since(at) > killDedupe {
			delete(p.killed, k)
		}
	}
}

// allowNormal: 정상 이벤트는 초당 NormalEventRate개까지만 스트리밍한다 (위반은 항상).
func (p *Pipeline) allowNormal(t time.Time) bool {
	sec := t.Unix()
	if sec != p.rateSec {
		p.rateSec, p.rateCount = sec, 0
	}
	if p.rateCount >= p.opt.NormalEventRate {
		return false
	}
	p.rateCount++
	return true
}

// persistLoop: DB·Redis 지연이 평가 루프를 막지 않도록 분리
func (p *Pipeline) persistLoop() {
	for v := range p.persist {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		if err := p.buffer.Push(ctx, v); err != nil {
			slog.Warn("buffer push", "err", err)
		}
		if v.Matched {
			if err := p.audit.SaveAudit(ctx, v); err != nil {
				slog.Error("audit save", "err", err)
			}
		}
		cancel()
	}
}
