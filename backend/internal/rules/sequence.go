package rules

import (
	"fmt"
	"log/slog"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/model"
)

// 연쇄 규칙(kind: sequence, 11/03) — 같은 컨테이너에서 windowSeconds 안에 단계가 순서대로 일어나면 걸린다.
//   - 순서는 파이프라인이 Observe 를 부른 순서, 창은 이벤트 시각(ev.Timestamp)으로 잰다. 타이머는 없다.
//   - 단계 사이에 다른 이벤트가 끼어도 된다. i 단계까지 마친 연쇄는 가장 늦게 시작한 것 하나만 남긴다.
//   - 완성되면 그 컨테이너 · 규칙의 상태를 비운다(같은 창 안에서 다시 걸리려면 처음부터).
//   - 판정은 이벤트 1개에 1건: 단일 규칙 판정과 연쇄 중 더 강한 쪽(rank), 동률이면 단일 규칙. 진 연쇄는 Sequence 에 주석으로.

const (
	seqMaxContainers = 1024 // 추적 컨테이너 상한 — 넘치면 정리, 그래도 차면 가장 오래 조용한 것부터 버린다
	seqDetailMax     = 160  // 단계 상세 글자 수 상한
	// seqIdle: 이만큼 진행이 없던 컨테이너에는 살아 있는 연쇄가 없다(창 ≤ 60초). 만료 정리도 이 간격으로(이벤트 시각) 한다
	seqIdle = MaxSequenceWindow * time.Second
)

// seqChain: 0..i 단계를 마친 연쇄 하나 — 시작 시각(0 단계 이벤트 시각)과 단계 기록
type seqChain struct {
	start time.Time
	steps []model.SequenceStep
}

// seqContainer: 한 컨테이너의 진행 중인 연쇄. chains[규칙 id][i] = 0..i 단계를 마친 연쇄(nil = 없음), i 는 마지막 단계 앞까지
type seqContainer struct {
	lastSeen time.Time // 마지막으로 연쇄가 생기거나 이어진 이벤트 시각
	chains   map[string][]*seqChain
}

// Observe: 실시간 파이프라인용 평가 — 상태 없는 Evaluate 에 연쇄 진행과 합치기를 더한다.
// 미리보기 · 제안 · 건 예외처럼 상태가 없어야 하는 곳은 Evaluate 를 그대로 쓴다.
func (e *Engine) Observe(ev model.Event) model.Verdict {
	v := e.Evaluate(ev)
	hv, ok := e.advance(ev)
	if !ok {
		return v // 이 이벤트로 완성된 연쇄 없음 → 단일 규칙 판정 그대로
	}
	if rank(hv) > rank(v) {
		return hv // 연쇄가 더 강하다 → 연쇄 판정(Sequence 포함)
	}
	v.Sequence = hv.Sequence // 단일 규칙이 같거나 더 강하다 → 판정은 그대로, 연쇄는 주석
	return v
}

// Forget: 컨테이너가 끝났거나 격리됐을 때 그 컨테이너의 연쇄 상태를 버린다.
func (e *Engine) Forget(containerID string) {
	e.seqMu.Lock()
	delete(e.seq, containerID)
	e.seqMu.Unlock()
}

// seqTracked: 연쇄 상태를 가진 컨테이너 수(테스트용)
func (e *Engine) seqTracked() int {
	e.seqMu.Lock()
	defer e.seqMu.Unlock()
	return len(e.seq)
}

// advance: 이 이벤트로 모든 연쇄 규칙을 한 칸씩 진행하고, 완성된 연쇄 중 가장 강한 것(동률이면 정책 순서 앞)의 판정을 돌려준다.
func (e *Engine) advance(ev model.Event) (model.Verdict, bool) {
	e.mu.RLock() // 잠금 순서 mu → seqMu
	defer e.mu.RUnlock()
	e.seqMu.Lock()
	defer e.seqMu.Unlock()

	now := ev.Timestamp
	if now.Sub(e.seqSwept) >= seqIdle {
		e.sweep(now)
	}
	var best model.Verdict
	found := false
	for _, r := range e.rules {
		if r.Kind != model.KindSequence || r.Disabled || len(r.steps) < MinSequenceSteps || !r.appliesTo(ev) {
			continue
		}
		steps, done := e.step(r, ev, now)
		if !done {
			continue
		}
		hv := r.sequenceVerdict(ev, steps)
		if !found || rank(hv) > rank(best) {
			best, found = hv, true
		}
	}
	return best, found
}

// step: 연쇄 규칙 r 의 단계를 뒤에서부터 본다 — 그래야 한 이벤트가 같은 연쇄의 두 단계를 채우지 못한다.
// 마지막 단계가 채워지면 그 컨테이너 · 규칙의 상태를 지우고 단계 기록을 돌려준다.
func (e *Engine) step(r compiled, ev model.Event, now time.Time) ([]model.SequenceStep, bool) {
	window := time.Duration(r.WindowSeconds) * time.Second
	last := len(r.steps) - 1
	var chains []*seqChain
	if c := e.seq[ev.ContainerID]; c != nil {
		chains = c.chains[r.ID]
	}
	for i := last; i >= 0; i-- {
		st := r.steps[i]
		if st.Kind != ev.Kind {
			continue
		}
		if _, _, ok := st.match(ev); !ok { // 단계의 directIp 덮어쓰기는 쓰지 않는다 — 판정 행동은 연쇄 규칙의 action
			continue
		}
		rec := stepRecord(ev)
		if i == 0 {
			// 첫 단계: 새 연쇄. 이미 있으면 늦게 시작한 쪽을 남긴다
			if chains == nil {
				chains = e.chainsFor(ev.ContainerID, r, now)
			}
			if cur := chains[0]; cur == nil || !now.Before(cur.start) {
				chains[0] = &seqChain{start: now, steps: []model.SequenceStep{rec}}
				e.seq[ev.ContainerID].lastSeen = now
			}
			continue
		}
		if chains == nil || chains[i-1] == nil {
			continue // 앞 단계를 마친 연쇄가 없다
		}
		prev := chains[i-1]
		if now.Sub(prev.start) > window {
			continue // 창 밖 — 이 연쇄로는 더 이어지지 않는다
		}
		steps := make([]model.SequenceStep, 0, len(prev.steps)+1)
		steps = append(append(steps, prev.steps...), rec)
		if i == last {
			c := e.seq[ev.ContainerID]
			delete(c.chains, r.ID)
			if len(c.chains) == 0 {
				delete(e.seq, ev.ContainerID)
			}
			return steps, true
		}
		if cur := chains[i]; cur == nil || !prev.start.Before(cur.start) {
			chains[i] = &seqChain{start: prev.start, steps: steps}
			e.seq[ev.ContainerID].lastSeen = now
		}
	}
	return nil, false
}

// chainsFor: 컨테이너 · 규칙의 연쇄 칸을 만든다. 추적 컨테이너가 상한이면 먼저 정리하고, 그래도 차 있으면 가장 오래 조용한 것을 버린다.
func (e *Engine) chainsFor(id string, r compiled, now time.Time) []*seqChain {
	if e.seq == nil {
		e.seq = map[string]*seqContainer{}
	}
	c := e.seq[id]
	if c == nil {
		if len(e.seq) >= seqMaxContainers {
			e.sweep(now)
		}
		if len(e.seq) >= seqMaxContainers {
			oldest := ""
			for k, v := range e.seq {
				if oldest == "" || v.lastSeen.Before(e.seq[oldest].lastSeen) {
					oldest = k
				}
			}
			delete(e.seq, oldest)
			slog.Warn("sequence state full; dropped the oldest container", "container", oldest, "limit", seqMaxContainers)
		}
		c = &seqContainer{lastSeen: now, chains: map[string][]*seqChain{}}
		e.seq[id] = c
	}
	chains := make([]*seqChain, len(r.steps)-1)
	c.chains[r.ID] = chains
	return chains
}

// sweep: seqIdle 넘게 진행이 없던 컨테이너를 지운다(그 안의 연쇄는 모두 창 밖이다). seqMu 를 쥔 채 부른다.
func (e *Engine) sweep(now time.Time) {
	e.seqSwept = now
	for id, c := range e.seq {
		if now.Sub(c.lastSeen) > seqIdle {
			delete(e.seq, id)
		}
	}
}

// stepRecord: 단계를 채운 이벤트 요약 — 상세는 seqDetailMax 글자로 자른다
func stepRecord(ev model.Event) model.SequenceStep {
	return model.SequenceStep{Kind: ev.Kind, Timestamp: ev.Timestamp, Comm: ev.Comm, Pid: ev.Pid, Detail: truncateRunes(ev.Detail(), seqDetailMax)}
}

func truncateRunes(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	return string([]rune(s)[:n-1]) + "…"
}

// sequenceVerdict: 완성된 연쇄의 판정. dryRun 은 단일 규칙과 같이 kill 에만 붙는다.
func (r compiled) sequenceVerdict(ev model.Event, steps []model.SequenceStep) model.Verdict {
	dry := r.Action == model.ActionKill && r.DryRun
	return model.Verdict{Event: ev, Matched: true, RuleID: r.ID, Action: r.Action, DryRun: dry,
		Reason:   sequenceReason(r.WindowSeconds, steps),
		Sequence: &model.SequenceHit{RuleID: r.ID, Action: r.Action, DryRun: dry, Steps: steps}}
}

// sequenceReason: "연쇄 3단계(10초 안): exec wget → connect 203.0.113.7:80 → open /root/.netrc · 2.4초" — exec 는 프로세스 이름, 나머지는 상세
func sequenceReason(window int, steps []model.SequenceStep) string {
	parts := make([]string, len(steps))
	for i, s := range steps {
		d := s.Detail
		if s.Kind == model.KindExec && s.Comm != "" {
			d = s.Comm
		}
		parts[i] = string(s.Kind) + " " + d
	}
	took := steps[len(steps)-1].Timestamp.Sub(steps[0].Timestamp).Seconds()
	return fmt.Sprintf("연쇄 %d단계(%d초 안): %s · %.1f초", len(steps), window, strings.Join(parts, " → "), took)
}
