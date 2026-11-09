package review

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"time"

	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/model"
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/rules"
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/store"
)

// 정책별 변경 이력 · 되돌리기(11/09, 정책 화면 분리).
// 변경 기록은 다룬 정책 id(ruleIds)와 정책 id 별 변경 전 · 후 정책 전체(before · after)를 함께 남긴다 —
// 정책 상세의 「변경 이력」 탭이 그 정책 것만 거르고, 「되돌리기」가 변경 전 값을 다시 쓴다.

const (
	defaultChangeLimit = 50
	maxChangeLimit     = 500
)

// ChangeQuery: GET /api/changes — 정책(ruleIds 에 있음) · 종류(완전 일치)로 거르고 최신순으로 Offset 부터 Limit 개
type ChangeQuery struct {
	RuleID string
	Kind   model.ChangeKind
	Offset int
	// Limit: 기본 50 · 상한 500 (ChangeLimit)
	Limit int
}

// ChangeLimit: 실제로 쓰는 쪽 크기 — 응답의 limit
func ChangeLimit(n int) int {
	if n <= 0 {
		return defaultChangeLimit
	}
	return min(n, maxChangeLimit)
}

// QueryChanges: 거른 기록(최신순 한 쪽)과 거른 뒤 전체 수. 정책으로 거르면 before · after 는 그 정책 값만 싣는다.
// ruleIds 는 늘 배열이다(정책과 무관한 기록 · 옛 행은 []).
func (s *Service) QueryChanges(q ChangeQuery) ([]model.Change, int) {
	limit, offset := ChangeLimit(q.Limit), max(q.Offset, 0)
	s.mu.Lock()
	defer s.mu.Unlock()
	out := []model.Change{}
	total := 0
	for i := len(s.changes) - 1; i >= 0; i-- {
		c := s.changes[i]
		if (q.RuleID != "" && !c.Touches(q.RuleID)) || (q.Kind != "" && c.Kind != q.Kind) {
			continue
		}
		total++
		if total <= offset || len(out) >= limit {
			continue
		}
		out = append(out, changeView(c, q.RuleID))
	}
	return out, total
}

// changeView: 응답용 사본. ruleID 가 있으면 before · after 를 그 정책 키만 남긴다(없으면 필드 없음)
func changeView(c model.Change, ruleID string) model.Change {
	v := c.Clone()
	if v.RuleIDs == nil {
		v.RuleIDs = []string{}
	}
	if ruleID != "" {
		v.Before, v.After = onlyKey(v.Before, ruleID), onlyKey(v.After, ruleID)
	}
	return v
}

func onlyKey(m map[string]json.RawMessage, k string) map[string]json.RawMessage {
	if v, ok := m[k]; ok {
		return map[string]json.RawMessage{k: v}
	}
	return nil
}

// PolicyMeta: 정책 목록의 최근 수정 — 그 정책을 다룬 마지막 변경 기록의 시각 · 처리자
type PolicyMeta struct {
	At time.Time
	By string
}

// PolicyMeta: 정책 id → 최근 수정. 변경 기록이 없는 정책(시드 · ruleIds 이전의 옛 기록뿐인 정책)은 없다
func (s *Service) PolicyMeta() map[string]PolicyMeta {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := map[string]PolicyMeta{}
	for _, c := range s.changes { // 오래된 순 — 나중 기록이 덮어쓴다
		for _, id := range c.RuleIDs {
			out[id] = PolicyMeta{At: c.At, By: c.By}
		}
	}
	return out
}

// RevertPolicy: POST /api/policies/{id}/revert — 정책 id 하나 전체를 변경 changeID 직전 값(before)으로 되돌린다.
// 사유 필수. 저장소에는 정책 upsert 와 되돌림 기록(policy_revert · revertOf)을 커밋 하나로 쓰고, 성공한 뒤에만 엔진을 리로드한다.
//   - 400: 사유 없음 · 500자 넘음 · changeId 없음
//   - 404: 변경 기록 없음 · 그 정책을 다룬 기록이 아님(옛 행 포함)
//   - 409: 시스템 규칙 · 변경 전에 정책이 없었음(만든 기록 — 지우려면 정책 삭제) · 변경 전 값 없음 · 지금 검사를 통과하지 않음 · 이미 그 값
func (s *Service) RevertPolicy(ctx context.Context, id, changeID, reason string) (rules.Rule, error) {
	reason, err := cleanReason(reason)
	if err != nil {
		return rules.Rule{}, err
	}
	if reason == "" {
		return rules.Rule{}, invalid("reason: 되돌리는 사유가 필요함")
	}
	if changeID == "" {
		return rules.Rule{}, invalid("changeId 가 필요함")
	}
	if rules.IsSystemRule(id) {
		return rules.Rule{}, conflict("%s 는 차단 목록에서 관리하는 시스템 규칙 — 차단 목록에서 바꾼다", id)
	}
	unlock := s.lockWrite()
	defer unlock()
	i := slices.IndexFunc(s.changes, func(c model.Change) bool { return c.ID == changeID })
	if i < 0 {
		return rules.Rule{}, notFound("변경 기록 없음")
	}
	src := s.changes[i]
	if !src.Touches(id) {
		return rules.Rule{}, notFound("정책 %s 의 변경 기록이 아님", id)
	}
	raw, ok := src.Before[id]
	if !ok {
		if _, made := src.After[id]; made {
			return rules.Rule{}, conflict("이 변경 전에는 정책 %s 이 없었음 — 지우려면 정책 삭제 사용", id)
		}
		return rules.Rule{}, conflict("이 변경에는 정책 %s 의 변경 전 값이 없음", id)
	}
	var restored rules.Rule
	if err := json.Unmarshal(raw, &restored); err != nil || restored.ID != id {
		return rules.Rule{}, conflict("정책 %s 의 변경 전 값을 읽을 수 없음", id)
	}
	if err := restored.Validate(); err != nil {
		return rules.Rule{}, conflict("변경 전 값이 지금 규칙 검사를 통과하지 않음: %v", err)
	}
	pols, err := s.o.Policies.ListPolicies(ctx)
	if err != nil {
		return rules.Rule{}, err
	}
	cur := policyMap(pols)
	if c, ok := cur[id]; ok && sameRule(c, restored) {
		return rules.Rule{}, conflict("정책 %s 은 이미 그 변경 전 값과 같음", id)
	}
	next := slices.Clone(pols)
	if j := slices.IndexFunc(next, func(r rules.Rule) bool { return r.ID == id }); j >= 0 {
		next[j] = restored
	} else {
		next = append(next, restored) // 지운 정책 — 저장소도 목록 끝에 붙인다(upsert)
	}
	chg := model.Change{ID: s.nextID("chg"), At: s.o.Now(), By: s.actor(ctx), Kind: model.ChangePolicyRevert,
		Summary: fmt.Sprintf("정책 %s 되돌림(%s 이전 값)", id, changeID), Reason: reason, RuleIDs: []string{id}, RevertOf: ptr(changeID)}
	chg.Before, chg.After = recordValues(cur, policyMap(next), chg.RuleIDs)
	if err := s.commitLocked(ctx, store.ReviewCommit{Policies: []rules.Rule{restored}, Changes: []model.Change{chg}}); err != nil {
		s.releaseID("chg")
		return rules.Rule{}, err
	}
	s.changes = append(s.changes, chg)
	s.o.Engine.Replace(s.engineRules(next, s.hostsLocked(s.blocklist)))
	return restored, nil
}

// ── 변경 전 · 후 값 ─────────────────────────────────────

func policyMap(rs []rules.Rule) map[string]rules.Rule {
	m := make(map[string]rules.Rule, len(rs))
	for _, r := range rs {
		m[r.ID] = r
	}
	return m
}

func ruleValue(r rules.Rule) json.RawMessage {
	b, _ := json.Marshal(r) // Rule 은 문자열 · 수 · 슬라이스뿐이라 실패하지 않는다
	return b
}

func sameRule(a, b rules.Rule) bool { return bytes.Equal(ruleValue(a), ruleValue(b)) }

// changedIDs: 앞뒤 값이 다른 정책 id(새로 · 빠짐 · 고침), 정렬 — YAML 교체처럼 다룬 정책을 미리 모를 때
func changedIDs(before, after map[string]rules.Rule) []string {
	var ids []string
	for id, b := range before {
		if a, ok := after[id]; !ok || !sameRule(a, b) {
			ids = append(ids, id)
		}
	}
	for id := range after {
		if _, ok := before[id]; !ok {
			ids = append(ids, id)
		}
	}
	slices.Sort(ids)
	return ids
}

// recordValues: ids 의 변경 전 · 후 정책 JSON. 그때 없던 정책은 키를 넣지 않고, 하나도 없으면 nil(필드 없음)
func recordValues(before, after map[string]rules.Rule, ids []string) (map[string]json.RawMessage, map[string]json.RawMessage) {
	pick := func(m map[string]rules.Rule) map[string]json.RawMessage {
		var out map[string]json.RawMessage
		for _, id := range ids {
			if r, ok := m[id]; ok {
				if out == nil {
					out = map[string]json.RawMessage{}
				}
				out[id] = ruleValue(r)
			}
		}
		return out
	}
	return pick(before), pick(after)
}

// sortedIDs: 정렬 · 중복 제거한 사본(nil 이면 nil)
func sortedIDs(ids []string) []string {
	if ids == nil {
		return nil
	}
	out := slices.Clone(ids)
	slices.Sort(out)
	return slices.Compact(out)
}
