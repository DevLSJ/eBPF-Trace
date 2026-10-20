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

// Reviewer: review.Service — 설치 세션 · 건 묶기와 차단 이미지 확인 (테스트에서 대체)
type Reviewer interface {
	Observe(v *model.Verdict)
	ContainerStarted(ev model.Event) (blockedImage string, blocked bool)
	ContainerExited(ev model.Event)
}

type Options struct {
	EnforceKill      bool
	IgnoreContainers []string
	// WatchContainers: 비어 있지 않으면 여기에 맞는 이름의 컨테이너만 평가·격리한다 (설치 샌드박스 모드: sg-install-*).
	// 개발자 PC 처럼 남의 컨테이너(minikube 등)가 같이 도는 호스트에서 오탐 격리를 막는 안전장치.
	WatchContainers []string
	NormalEventRate int
}

type Pipeline struct {
	resolver *Resolver
	opt      Options
	engine   *rules.Engine
	enforcer enforcer.Enforcer
	hub      Broadcaster
	stats    *stats.Aggregator
	audit    store.AuditStore
	buffer   store.Buffer
	review   Reviewer

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
	resolver := NewResolver(15 * time.Minute)
	return &Pipeline{
		resolver: resolver,
		opt:      opt, engine: engine, enforcer: enf, hub: hub, stats: agg, audit: audit, buffer: buffer,
		persist: make(chan model.Verdict, persistQueue),
		killed:  map[string]time.Time{},
	}
}

// SetReview: 판정을 설치 세션 · 건에 묶는다. Run 전에 부른다.
func (p *Pipeline) SetReview(r Reviewer) { p.review = r }

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

// Ignored: 자기 스택(supplyguard-*) 등 제외 대상이거나, 관찰 목록(WatchContainers)이 있는데 그 밖이면 true
func (p *Pipeline) Ignored(containerName string) bool {
	for _, g := range p.opt.IgnoreContainers {
		if ok, _ := path.Match(g, containerName); ok {
			return true
		}
	}
	if len(p.opt.WatchContainers) == 0 {
		return false
	}
	for _, g := range p.opt.WatchContainers {
		if ok, _ := path.Match(g, containerName); ok {
			return false
		}
	}
	return true
}

func (p *Pipeline) Handle(ctx context.Context, ev model.Event) {
	if ev.Timestamp.IsZero() {
		ev.Timestamp = time.Now().UTC()
	}
	if ev.Kind == model.KindDNS {
		// DNS 응답은 정책 평가·피드 대상이 아니다. 목적지 도메인 캐시만 채운다 (제외 컨테이너도 포함해 배운다).
		p.resolver.Learn(ev.ContainerID, ev.DNSName, ev.DNSAddrs, ev.Timestamp)
		return
	}
	if ev.ContainerID == "" || p.Ignored(ev.ContainerName) {
		return // 호스트 프로세스 또는 보호 대상
	}
	if ev.Kind == model.KindStart || ev.Kind == model.KindExit {
		p.lifecycle(ctx, ev)
		return
	}
	if ev.Kind == model.KindConnect && ev.DstHost == "" {
		ev.DstHost = p.resolver.Lookup(ev.ContainerID, ev.DstIP)
	}
	v := p.engine.Evaluate(ev)
	if v.Matched && v.Action == model.ActionKill && !v.DryRun {
		p.enforce(ctx, &v)
	}
	p.emit(v)
}

// emit: 건 묶기 → 통계 → WebSocket · 저장
func (p *Pipeline) emit(v model.Verdict) {
	if p.review != nil {
		p.review.Observe(&v)
	}
	p.stats.Observe(v)

	if v.Matched || p.allowNormal(v.Event.Timestamp) {
		p.hub.Broadcast("verdict", v)
		select {
		case p.persist <- v:
		default:
			slog.Warn("persist queue full; dropping verdict", "matched", v.Matched)
		}
	}
}

// lifecycle: 컨테이너 시작 · 종료 (관찰 범위 안의 컨테이너만 — Ignored 는 Handle 에서 이미 걸렀다)
func (p *Pipeline) lifecycle(ctx context.Context, ev model.Event) {
	if p.review == nil {
		return
	}
	if ev.Kind == model.KindExit {
		p.review.ContainerExited(ev)
		return
	}
	image, blocked := p.review.ContainerStarted(ev)
	if !blocked {
		return // 정상 기동은 피드에 내지 않는다
	}
	// 차단 목록의 이미지: 정책 규칙과 같은 격리 경로(전역 ENFORCE_KILL · 중복 kill 방지)를 탄다
	v := model.Verdict{
		Event: model.Event{
			Kind: model.KindExec, Timestamp: ev.Timestamp, ContainerID: ev.ContainerID, ContainerName: ev.ContainerName,
			ImageName: ev.ImageName, Comm: "container-start", Args: "container start " + image,
		},
		Matched: true, RuleID: model.RuleBlockedImage, Action: model.ActionKill, Reason: "차단된 이미지: " + image,
	}
	p.enforce(ctx, &v)
	p.emit(v)
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
