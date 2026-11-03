package model

import "time"

// KindSequence: 연쇄 규칙(11/03)의 kind — 같은 컨테이너에서 창 안에 단계(exec · open · connect · dns)가 순서대로 일어나면 걸린다.
// 규칙에만 쓰는 kind 다. 이벤트 kind 가 아니므로 Kinds(이벤트 검증 · 감사 필터)에 넣지 않는다.
const KindSequence Kind = "sequence"

// SequenceHit: 완성된 연쇄 1건 — 판정(Verdict.Sequence)에 붙는다.
type SequenceHit struct {
	RuleID string         `json:"ruleId"`
	Action Action         `json:"action"`
	DryRun bool           `json:"dryRun,omitempty"`
	Steps  []SequenceStep `json:"steps"`
}

// SequenceStep: 연쇄의 한 단계를 채운 이벤트 요약. Detail 은 Event.Detail()(엔진이 길이를 자른다)
type SequenceStep struct {
	Kind      Kind      `json:"kind"`
	Timestamp time.Time `json:"timestamp"`
	Comm      string    `json:"comm"`
	Pid       uint32    `json:"pid"`
	Detail    string    `json:"detail"`
}
