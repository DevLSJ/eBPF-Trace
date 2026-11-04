package demo

import (
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/model"
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/rules"
)

// 「왜」 보충(11/04) — 시연 페이지 오른쪽 카드용. GET /api/demo 의 running · last 에 explain 으로 붙는다.
// 무엇(패키지 · 컨테이너 · 프로세스) · 판정 이벤트 원문 · 증거 · 격리 타임라인 · 건 id 는 기존 API(설치 세션 · 증거 · 정책)에 있으므로 넣지 않는다.
// 여기에는 그 API 로 바로 얻을 수 없는 것만 둔다:
//   - decidedBy: 세션 위반 중 이 실행의 결과를 정한 판정 하나(가장 강한 것, 같으면 이른 것) + 규칙 설명
//   - sequence: chain 시나리오의 연쇄 규칙 단계별 진행 — 연쇄가 먼저 격리돼 완성되지 않으면 판정 · 감사 로그에 sequence 가 없다
//
// 계산은 읽을 때마다 세션 사본과 지금 정책으로 한다(저장하지 않는다). 규칙 매칭 코드는 바꾸지 않고 rules.Engine.Evaluate 를 그대로 쓴다.

// ChainRuleID: chain 시나리오가 보여 주는 연쇄 규칙(기본 정책). 없으면 정책의 첫 sequence 규칙
const ChainRuleID = "chain-download-secrets"

// Explain: Run.explain
type Explain struct {
	// DecidedBy: 결과를 정한 판정. 위반이 없으면 null(통과)
	DecidedBy *Decider `json:"decidedBy"`
	// Sequence: chain 시나리오만. 정책에 연쇄 규칙이 없으면 null
	Sequence *SequenceProgress `json:"sequence"`
}

// Decider: 결과를 정한 판정 — 세션 violations 의 한 줄과 같은 값 + 규칙 설명
type Decider struct {
	RuleID      string       `json:"ruleId"`
	Description string       `json:"description"` // 지금 정책의 규칙 설명(규칙이 지워졌으면 "")
	Condition   string       `json:"condition"`   // 지금 정책의 조건 요약(RuleCondition, 규칙이 없으면 "")
	Action      model.Action `json:"action"`
	DryRun      bool         `json:"dryRun"`
	Enforced    bool         `json:"enforced"`
	Reason      string       `json:"reason"`
	Event       model.Event  `json:"event"` // 판정을 만든 이벤트 원문(kind · timestamp · comm · pid · args · path · dstIp · dstPort · dstHost · qtype)
	// Sequence: 이 판정에 연쇄가 붙었으면(이겼거나 주석) 그 규칙 id
	Sequence string `json:"sequence,omitempty"`
}

// SequenceProgress: 연쇄 규칙 한 개의 진행
type SequenceProgress struct {
	RuleID        string       `json:"ruleId"`
	Description   string       `json:"description"`
	Action        model.Action `json:"action"`
	DryRun        bool         `json:"dryRun"`
	Disabled      bool         `json:"disabled"`
	WindowSeconds int          `json:"windowSeconds"`
	// Completed: 판정에 이 연쇄의 sequence 가 기록됐다(모든 단계가 창 안에 이어짐)
	Completed bool           `json:"completed"`
	Steps     []StepProgress `json:"steps"`
}

// StepProgress: 단계 하나 — 조건 요약과 그 단계를 채운 이벤트
type StepProgress struct {
	Kind      model.Kind `json:"kind"`
	Condition string     `json:"condition"`
	// Matched: 이 단계를 채운 이벤트가 있다. 정상 이벤트는 저장하지 않으므로 미완성 연쇄는 위반으로 남은 이벤트로만 본다
	Matched bool                `json:"matched"`
	Event   *model.SequenceStep `json:"event"` // kind · timestamp · comm · pid · detail
	GapMs   *int64              `json:"gapMs"` // 앞 단계 이벤트에서 걸린 ms (첫 단계 · 미충족은 null)
}

// BuildExplain: 세션(GET /api/installs/{id} 와 같은 사본)과 지금 정책으로 explain 을 만든다
func BuildExplain(run Run, sess model.InstallSession, rs []rules.Rule) *Explain {
	ex := &Explain{DecidedBy: decidedBy(sess.Violations, rs)}
	if run.Scenario == "chain" {
		if r, ok := chainRule(rs); ok {
			ex.Sequence = sequenceProgress(r, sess.Violations)
		}
	}
	return ex
}

func ruleDesc(rs []rules.Rule, id string) string {
	for _, r := range rs {
		if r.ID == id {
			return r.Description
		}
	}
	return ""
}

// decidedBy: 가장 강한 판정(격리됨 > 격리 대상 > 경고), 같으면 이벤트가 이른 것
func decidedBy(vs []model.ViolationCount, rs []rules.Rule) *Decider {
	var best *model.Verdict
	for i := range vs {
		v := &vs[i].Verdict
		if best == nil {
			best = v
			continue
		}
		a, b := model.LevelOf(*v).Rank(), model.LevelOf(*best).Rank()
		if a > b || (a == b && v.Event.Timestamp.Before(best.Event.Timestamp)) {
			best = v
		}
	}
	if best == nil {
		return nil
	}
	d := &Decider{RuleID: best.RuleID, Description: ruleDesc(rs, best.RuleID), Condition: RuleCondition(rs, best.RuleID), Action: best.Action, DryRun: best.DryRun,
		Enforced: best.Enforced, Reason: best.Reason, Event: best.Event}
	if best.Sequence != nil {
		d.Sequence = best.Sequence.RuleID
	}
	return d
}

func chainRule(rs []rules.Rule) (rules.Rule, bool) {
	for _, r := range rs {
		if r.ID == ChainRuleID && r.Kind == model.KindSequence {
			return r, true
		}
	}
	for _, r := range rs {
		if r.Kind == model.KindSequence {
			return r, true
		}
	}
	return rules.Rule{}, false
}

// sequenceProgress: 판정에 이 연쇄의 sequence 가 있으면 그 기록 그대로(완성). 없으면 위반 이벤트를 시간순으로 단계에 차례로 맞춘다(창 안에서만)
func sequenceProgress(r rules.Rule, vs []model.ViolationCount) *SequenceProgress {
	p := &SequenceProgress{RuleID: r.ID, Description: r.Description, Action: r.Action, DryRun: r.DryRun, Disabled: r.Disabled,
		WindowSeconds: r.WindowSeconds, Steps: make([]StepProgress, len(r.Steps))}
	for i, st := range r.Steps {
		p.Steps[i] = StepProgress{Kind: st.Kind, Condition: condition(st)}
	}
	var got []model.SequenceStep
	for _, v := range vs {
		if v.Sequence != nil && v.Sequence.RuleID == r.ID && len(v.Sequence.Steps) == len(r.Steps) {
			got, p.Completed = v.Sequence.Steps, true
			break
		}
	}
	if !p.Completed {
		got = matchSteps(r, vs)
	}
	for i := range got {
		ev := got[i]
		p.Steps[i].Matched, p.Steps[i].Event = true, &ev
		if i > 0 {
			ms := ev.Timestamp.Sub(got[i-1].Timestamp).Milliseconds()
			p.Steps[i].GapMs = &ms
		}
	}
	return p
}

// matchSteps: 위반 이벤트(시간순)를 0 단계부터 차례로 맞춘다 — 단계 조건은 단일 규칙과 같은 매칭(rules.Engine.Evaluate)으로 본다
func matchSteps(r rules.Rule, vs []model.ViolationCount) []model.SequenceStep {
	evs := make([]model.Event, 0, len(vs))
	for _, v := range vs {
		evs = append(evs, v.Event)
	}
	slices.SortStableFunc(evs, func(a, b model.Event) int { return a.Timestamp.Compare(b.Timestamp) })
	window := time.Duration(r.WindowSeconds) * time.Second
	var out []model.SequenceStep
	for _, ev := range evs {
		i := len(out)
		if i == len(r.Steps) {
			break
		}
		if i > 0 && ev.Timestamp.Sub(out[0].Timestamp) > window {
			break
		}
		if stepMatches(r.Steps[i], ev) {
			out = append(out, model.SequenceStep{Kind: ev.Kind, Timestamp: ev.Timestamp, Comm: ev.Comm, Pid: ev.Pid, Detail: ev.Detail()})
		}
	}
	return out
}

// stepMatches: 단계 조건만 가진 임시 규칙 하나로 평가한다(컨테이너 범위 없음 · action 은 의미 없음)
func stepMatches(st rules.Rule, ev model.Event) bool {
	if st.Kind != ev.Kind {
		return false
	}
	st.ID, st.Action = "demo-step", model.ActionAlert
	return rules.New([]rules.Rule{st}).Evaluate(ev).Matched
}

// RuleCondition: 규칙 id 의 조건 요약 — 단일 규칙은 condition 그대로, 연쇄 규칙은 「10초 안: 단계 → 단계 → 단계」. 없는 규칙은 ""
func RuleCondition(rs []rules.Rule, id string) string {
	for _, r := range rs {
		if r.ID != id {
			continue
		}
		if r.Kind != model.KindSequence {
			return condition(r)
		}
		parts := make([]string, len(r.Steps))
		for i, st := range r.Steps {
			parts[i] = condition(st)
		}
		return fmt.Sprintf("%d초 안: %s", r.WindowSeconds, strings.Join(parts, " → "))
	}
	return ""
}

// condition: 단계 조건 요약(화면 문구) — exec「프로세스 curl · wget」· open「경로 …」· connect「포트 …」「내부망(…) 밖 연결」· dns「질의 …」
func condition(st rules.Rule) string {
	j := func(xs []string) string { return strings.Join(xs, " · ") }
	ports := func(ps []uint16) string {
		s := make([]string, len(ps))
		for i, p := range ps {
			s[i] = fmt.Sprint(p)
		}
		return j(s)
	}
	var parts []string
	add := func(ok bool, s string) {
		if ok {
			parts = append(parts, s)
		}
	}
	switch st.Kind {
	case model.KindExec:
		add(len(st.DenyComms) > 0, "프로세스 "+j(st.DenyComms))
		add(len(st.DenyArgs) > 0, "인자 "+j(st.DenyArgs))
	case model.KindOpen:
		add(len(st.DenyPaths) > 0, "경로 "+j(st.DenyPaths))
		add(len(st.AllowPaths) > 0, "예외 "+j(st.AllowPaths))
	case model.KindConnect:
		add(len(st.DenyPorts) > 0, "포트 "+ports(st.DenyPorts))
		add(len(st.DenyCIDRs) > 0, "대역 "+j(st.DenyCIDRs))
		add(len(st.DenyHosts) > 0, "도메인 "+j(st.DenyHosts))
		var allow []string
		if len(st.AllowPorts) > 0 {
			allow = append(allow, "포트 "+ports(st.AllowPorts))
		}
		if len(st.AllowHosts) > 0 {
			allow = append(allow, j(st.AllowHosts))
		}
		switch {
		case len(st.AllowCIDRs) > 0 && len(allow) == 0:
			parts = append(parts, "내부망("+j(st.AllowCIDRs)+") 밖 연결")
		case len(st.AllowCIDRs) > 0 || len(allow) > 0:
			parts = append(parts, "허용("+j(append(slices.Clone(st.AllowCIDRs), allow...))+") 밖 연결")
		}
		add(st.DirectIP != "", "도메인 조회 없는 IP 직접 연결("+st.DirectIP+")")
	case model.KindDNS:
		add(len(st.DenyHosts) > 0, "질의 "+j(st.DenyHosts))
		add(len(st.DenyQtypes) > 0, "질의 유형 "+j(st.DenyQtypes))
		add(st.MaxLabelLength > 0, fmt.Sprintf("라벨 %d자 초과", st.MaxLabelLength))
		add(st.MaxNameLength > 0, fmt.Sprintf("이름 %d자 초과", st.MaxNameLength))
		add(len(st.AllowHosts) > 0, "허용("+j(st.AllowHosts)+") 밖 질의")
	}
	return strings.Join(parts, " / ")
}
