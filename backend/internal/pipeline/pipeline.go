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
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/notify"
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
	// AuditSaved: 위반 판정이 감사 로그에 저장된 뒤(행 id 와 함께) — 실제 kill 이 있는 판정만 부른다(격리 타임라인, 10/30)
	AuditSaved(v model.Verdict, auditID int64)
}

type Options struct {
	EnforceKill      bool
	IgnoreContainers []string
	// WatchContainers: 비어 있지 않으면 여기에 맞는 이름의 컨테이너만 평가·격리한다 (설치 샌드박스 모드: sg-install-*).
	// 개발자 PC 처럼 남의 컨테이너(minikube 등)가 같이 도는 호스트에서 오탐 격리를 막는 안전장치.
	WatchContainers []string
	NormalEventRate int
	// DNSGrace: trace_dns 가 켜져 있는데 도메인이 없는 공인 IP connect 는 이만큼 기다렸다 리졸버를 다시 보고 평가한다
	// (connect 가 DNS 응답보다 먼저 처리되는 경쟁 완화). 0 이면 바로 평가.
	DNSGrace time.Duration
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
	notifier notify.Notifier

	persist chan model.Verdict
	killed  map[string]time.Time // 컨테이너 ID → 격리 시각 (중복 kill 방지)

	rateSec   int64
	rateCount int

	// mu: 평가 · 격리 · 전송은 한 번에 하나만 — Run 루프와 DNS 유예 타이머(time.AfterFunc)가 같이 들어오므로.
	// closed: Run 이 끝나 persist 가 닫힌 뒤 늦게 깬 타이머가 쓰지 않도록.
	mu     sync.Mutex
	closed bool
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

// SetNotifier: 위반을 외부 알림(웹훅 · Slack)으로 보낸다. Run 전에 부른다.
func (p *Pipeline) SetNotifier(n notify.Notifier) { p.notifier = n }

// Run: events 채널이 닫히거나 ctx가 끝날 때까지 평가 루프를 돈다.
func (p *Pipeline) Run(ctx context.Context, events <-chan model.Event) {
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		p.persistLoop()
	}()
	defer func() {
		p.mu.Lock()
		p.closed = true
		p.mu.Unlock()
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
		if ev.DNSName != "" {
			// DNS 응답은 정책 평가·피드 대상이 아니다. 목적지 도메인 캐시만 채운다 (제외 컨테이너도 포함해 배운다).
			p.resolver.Learn(ev.ContainerID, ev.DNSName, ev.DNSAddrs, ev.Timestamp)
			return
		}
		if ev.DstHost == "" {
			return // 질의 이름도 응답도 없는 dns 이벤트 — 모양이 맞지 않는다
		}
		// DNS 질의(10/30)는 아래로 흘러 kind: dns 규칙으로 평가한다 (DNS 유예 없음)
	}
	if ev.ContainerID == "" || p.Ignored(ev.ContainerName) {
		return // 호스트 프로세스 또는 보호 대상
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return
	}
	if ev.Kind == model.KindStart || ev.Kind == model.KindExit {
		p.lifecycle(ctx, ev)
		return
	}
	if ev.Kind == model.KindConnect && ev.DstHost == "" {
		ev.DstHost = p.resolver.Lookup(ev.ContainerID, ev.DstIP)
		// DNS 경쟁: 응답 패킷보다 connect 가 먼저 처리될 수 있다. 직접 IP 연결로 판정될 후보만(trace_dns 켜짐 · 도메인 없음 · 공인 주소)
		// 이 이벤트 하나만 DNSGrace 만큼 미뤘다가 리졸버를 다시 보고 평가한다. 다른 이벤트는 그대로 흐른다.
		if ev.DstHost == "" && ev.DNSTraced && p.opt.DNSGrace > 0 && rules.IsPublicAddr(ev.DstIP) {
			time.AfterFunc(p.opt.DNSGrace, func() {
				p.mu.Lock()
				defer p.mu.Unlock()
				if p.closed || ctx.Err() != nil {
					return
				}
				ev.DstHost = p.resolver.Lookup(ev.ContainerID, ev.DstIP)
				p.evaluate(ctx, ev)
			})
			return
		}
	}
	p.evaluate(ctx, ev)
}

// evaluate: 규칙 평가 → (kill) 격리 → 전송. p.mu 를 쥔 채 부른다.
// Observe = 상태 없는 단일 규칙 평가 + 연쇄 규칙(kind: sequence, 11/03) 진행. 판정은 이벤트마다 1건이다.
func (p *Pipeline) evaluate(ctx context.Context, ev model.Event) {
	v := p.engine.Observe(ev)
	if v.Matched {
		// 격리 타임라인(10/30): 탐지 = 이벤트 시각(소스), 판정 = 지금. 증거 · kill · 알림 시각은 뒤 단계가 채운다
		v.Timeline = &model.Timeline{DetectedAt: ev.Timestamp.UTC(), MatchedAt: time.Now().UTC()}
	}
	if v.Matched && v.Action == model.ActionKill && !v.DryRun {
		p.enforce(ctx, &v)
	}
	p.emit(v)
}

// notifierQueues: 알림이 실제로 큐에 들어가는지(채널이 있는지). Enabled 를 모르는 구현은 들어간다고 본다
func notifierQueues(n notify.Notifier) bool {
	if e, ok := n.(interface{ Enabled() bool }); ok {
		return e.Enabled()
	}
	return true
}

// stamp: 격리 수단이 준 시각 — 0 이면 키 생략
func stamp(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	u := t.UTC()
	return &u
}

// emit: 건 묶기 → 통계 → WebSocket · 저장
func (p *Pipeline) emit(v model.Verdict) {
	if p.review != nil {
		p.review.Observe(&v)
	}
	// 외부 알림(10/20): 건 id · 설치 ref 가 채워진 뒤라야 링크가 맞다. 큐에 넣고 바로 돌아온다
	if p.notifier != nil {
		if m, ok := notify.FromVerdict(v); ok {
			p.notifier.Notify(context.Background(), m)
			if v.Timeline != nil && notifierQueues(p.notifier) {
				v.Timeline.NotifiedAt = stamp(time.Now()) // 큐 투입 시각(발송 완료 아님)
			}
		}
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
	if ev.Kind == model.KindExit {
		p.engine.Forget(ev.ContainerID) // 끝난 컨테이너의 연쇄 상태 — 설치 세션 추적(review)과 무관하게 버린다
	}
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
		Timeline: &model.Timeline{DetectedAt: ev.Timestamp.UTC(), MatchedAt: time.Now().UTC()},
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
	// 격리 타임라인(10/30): Docker 는 단계별 시각(증거 훅 · kill 응답)을 준다. 시각이 없는 격리 수단(mock)은 성공 시각을 kill 시각으로 쓴다
	var times enforcer.Times
	var err error
	if te, ok := p.enforcer.(enforcer.Timed); ok {
		times, err = te.KillTimed(kctx, id)
	} else if err = p.enforcer.Kill(kctx, id); err == nil {
		times.KilledAt = time.Now().UTC()
	}
	if v.Timeline != nil {
		v.Timeline.EvidenceStartedAt, v.Timeline.EvidenceDoneAt, v.Timeline.KilledAt = stamp(times.EvidenceStartedAt), stamp(times.EvidenceDoneAt), stamp(times.KilledAt)
	}
	switch {
	case err == nil:
		v.Enforced = true
		p.killed[id] = time.Now()
		p.engine.Forget(id) // 격리한 컨테이너의 연쇄 상태를 버린다
		p.stats.Killed(id, v.Event.ContainerName)
		slog.Warn("container killed", "container", v.Event.ContainerName, "id", id, "rule", v.RuleID, "reason", v.Reason)
	case errors.Is(err, enforcer.ErrNotRunning), errors.Is(err, enforcer.ErrNotFound):
		p.killed[id] = time.Now()
		p.engine.Forget(id) // 이미 멈춘 컨테이너 — 연쇄 상태도 버린다
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
			id, err := p.audit.SaveAudit(ctx, v)
			switch {
			case err != nil:
				slog.Error("audit save", "err", err)
			case p.review != nil && v.Timeline != nil && v.Timeline.KilledAt != nil:
				p.review.AuditSaved(v, id) // 설치 세션 · 건의 isolation{auditId, timeline}
			}
		}
		cancel()
	}
}
