package review

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/model"
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/rules"
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/store"
)

// ListProposals: 최신순
func (s *Service) ListProposals(state model.ProposalState) []model.Proposal {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := []model.Proposal{}
	for i := len(s.proposalIDs) - 1; i >= 0 && len(out) < 500; i-- {
		p := s.proposals[s.proposalIDs[i]]
		if state != "" && p.State != state {
			continue
		}
		out = append(out, p.Clone())
	}
	return out
}

func (s *Service) GetProposal(id string) (model.Proposal, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.proposals[id]
	if !ok {
		return model.Proposal{}, notFound("제안 없음")
	}
	return p.Clone(), nil
}

// ── 미리보기 ───────────────────────────────────────────

type PreviewRow struct {
	AuditID   int64       `json:"auditId"`
	Before    model.Level `json:"before"`
	After     model.Level `json:"after"`
	Container string      `json:"container"`
	RuleID    string      `json:"ruleId"`
}

type PreviewCounts struct {
	ToNormal  int `json:"toNormal"`
	ToBlocked int `json:"toBlocked"`
}

type Preview struct {
	Evaluated int           `json:"evaluated"`
	Changed   []PreviewRow  `json:"changed"`
	Counts    PreviewCounts `json:"counts"`
	// NextOnly: 과거 이벤트를 바꾸지 않는 변경(패키지 · 이미지 차단) — 「다음 설치 · 기동부터 적용」
	NextOnly []model.BlockRef `json:"nextOnly"`
}

const (
	previewScan    = 5000 // 최근 감사 로그 행
	previewChanged = 500  // 응답에 싣는 바뀐 행 (counts 는 전체)
)

// Preview: 제안을 적용한 규칙 사본과 지금 규칙으로 저장된 감사 로그 이벤트를 각각 다시 평가해,
// 탐지 결과가 달라지는 행만 돌려준다. 쓰기는 없다.
func (s *Service) Preview(ctx context.Context, id string) (Preview, error) {
	p, err := s.GetProposal(id)
	if err != nil {
		return Preview{}, err
	}
	cur := s.o.Engine.Rules()
	next, nextOnly := proposedRules(cur, p.Changes)
	out, err := s.reevaluate(ctx, cur, next)
	out.NextOnly = nextOnly
	return out, err
}

// PreviewRule: 정책 하나를 바꾼(목록에 없으면 더한) 규칙 사본으로 감사 로그를 다시 평가한다 — 정책 저장 전 확인(10/16). 쓰기는 없다.
func (s *Service) PreviewRule(ctx context.Context, r rules.Rule) (Preview, error) {
	if rules.IsSystemRule(r.ID) {
		return Preview{}, conflict("차단 목록에서 관리하는 시스템 규칙입니다")
	}
	if err := r.Validate(); err != nil {
		return Preview{}, invalid("%s", err.Error())
	}
	cur := s.o.Engine.Rules()
	next := slices.Clone(cur)
	if i := slices.IndexFunc(next, func(x rules.Rule) bool { return x.ID == r.ID }); i >= 0 {
		next[i] = r
	} else {
		next = append(next, r)
	}
	out, err := s.reevaluate(ctx, cur, next)
	out.NextOnly = []model.BlockRef{}
	return out, err
}

// reevaluate: 저장된 감사 로그(최근 previewScan 행)를 지금 규칙 · 다음 규칙으로 각각 평가해 결과가 달라지는 행만
func (s *Service) reevaluate(ctx context.Context, cur, next []rules.Rule) (Preview, error) {
	curE, nextE := rules.New(cur), rules.New(next)
	out := Preview{Changed: []PreviewRow{}}
	q := store.AuditQuery{Limit: store.MaxAuditLimit}
	for out.Evaluated < previewScan {
		rows, err := s.o.Audit.QueryAudit(ctx, q)
		if err != nil {
			return Preview{}, err
		}
		for _, a := range rows {
			out.Evaluated++
			before, bv := s.levelWith(curE, a.Event)
			after, av := s.levelWith(nextE, a.Event)
			if before == after {
				continue
			}
			if after == model.LevelNormal {
				out.Counts.ToNormal++
			}
			if blocking(after) && !blocking(before) {
				out.Counts.ToBlocked++
			}
			if len(out.Changed) < previewChanged {
				rid := bv.RuleID
				if rid == "" {
					rid = av.RuleID
				}
				out.Changed = append(out.Changed, PreviewRow{AuditID: a.ID, Before: before, After: after, Container: a.Event.ContainerName, RuleID: rid})
			}
		}
		if len(rows) < q.Limit {
			break
		}
		q.BeforeID = rows[len(rows)-1].ID
	}
	return out, nil
}

func blocking(l model.Level) bool { return l == model.LevelHeld || l == model.LevelKilled }

// levelWith: 다시 평가한 탐지 결과 — kill 은 전역 ENFORCE_KILL 과 규칙 dry-run 에 따라 격리됨 / 격리 대상
func (s *Service) levelWith(e *rules.Engine, ev model.Event) (model.Level, model.Verdict) {
	v := e.Evaluate(ev)
	switch {
	case !v.Matched:
		return model.LevelNormal, v
	case v.Action != model.ActionKill:
		return model.LevelAlert, v
	case v.DryRun || !s.o.EnforceKill:
		return model.LevelHeld, v
	default:
		return model.LevelKilled, v
	}
}

// proposedRules: 규칙 사본에 제안의 예외 · 도메인 차단을 반영한다. 패키지 · 이미지 차단은 nextOnly 로 따로 돌려준다.
func proposedRules(cur []rules.Rule, changes []model.ProposalChange) ([]rules.Rule, []model.BlockRef) {
	next := slices.Clone(cur)
	nextOnly := []model.BlockRef{}
	var hosts []string
	for _, r := range next {
		if r.ID == rules.SystemBlocklistHosts {
			hosts = slices.Clone(r.DenyHosts)
		}
	}
	addHost := false
	for _, ch := range changes {
		switch {
		case ch.Op == "block" && ch.List == model.ListHosts:
			if !slices.Contains(hosts, ch.Value) {
				hosts = append(hosts, ch.Value)
				addHost = true
			}
		case ch.Op == "block":
			nextOnly = append(nextOnly, model.BlockRef{List: ch.List, Value: ch.Value})
		case ch.Op == "except":
			if i := slices.IndexFunc(next, func(r rules.Rule) bool { return r.ID == ch.RuleID }); i >= 0 {
				next[i] = withValue(next[i], ch.Field, ch.Value)
			}
		}
	}
	if addHost {
		next = withSystemRule(next, hosts)
	}
	return next, nextOnly
}

// withSystemRule: 저장된 정책(시스템 규칙 제외) 뒤에 blocklist-hosts 를 붙인다.
func withSystemRule(policies []rules.Rule, hosts []string) []rules.Rule {
	out := make([]rules.Rule, 0, len(policies)+1)
	for _, r := range policies {
		if !rules.IsSystemRule(r.ID) {
			out = append(out, r)
		}
	}
	if sys, ok := rules.BlocklistHostsRule(hosts); ok {
		out = append(out, sys)
	}
	return out
}

// ── 적용 · 버림 ────────────────────────────────────────

// Apply: 제안을 한 번에 반영한다(모두 되거나 모두 안 됨).
//  1. 새 차단 목록 · 바뀐 정책 · 변경 이력 · 적용된 제안 · 닫힌 건을 사본으로 만든다(검증 실패면 아무것도 안 바뀜)
//  2. 저장소에 커밋 하나로 쓴다(Postgres 는 트랜잭션 하나) — 실패하면 캐시 · 엔진은 그대로
//  3. 성공한 뒤에만 캐시를 바꾸고 엔진을 리로드한다(Replace 는 실패하지 않음)
func (s *Service) Apply(ctx context.Context, id, reason string) (model.Proposal, model.Case, error) {
	reason, err := cleanReason(reason)
	if err != nil {
		return model.Proposal{}, model.Case{}, err
	}
	unlock := s.lockWrite()
	defer unlock()
	cur, ok := s.proposals[id]
	if !ok {
		return model.Proposal{}, model.Case{}, notFound("제안 없음")
	}
	if cur.State != model.ProposalDraft {
		return model.Proposal{}, model.Case{}, conflict("초안이 아닌 제안")
	}
	caseRec, ok := s.cases[cur.CaseID]
	if !ok {
		return model.Proposal{}, model.Case{}, conflict("제안의 건이 없음")
	}
	pols, err := s.o.Policies.ListPolicies(ctx)
	if err != nil {
		return model.Proposal{}, model.Case{}, err
	}
	now, by := s.o.Now(), s.actor(ctx)

	// 1. 사본 만들기
	nextBlock := slices.Clone(s.blocklist)
	nextPols := slices.Clone(pols)
	var adds []model.BlockEntry
	changed := map[string]bool{}
	for _, ch := range cur.Changes {
		switch ch.Op {
		case "block":
			if !model.ValidBlockList(ch.List) {
				return model.Proposal{}, model.Case{}, conflict("알 수 없는 차단 목록 %q", ch.List)
			}
			if slices.ContainsFunc(nextBlock, func(b model.BlockEntry) bool { return b.List == ch.List && b.Value == ch.Value }) {
				continue // 이미 차단됨 — 처음 차단한 기록을 그대로 둔다
			}
			e := model.BlockEntry{List: ch.List, Value: ch.Value, CaseID: ptr(cur.CaseID), At: now, By: by}
			nextBlock = append(nextBlock, e)
			adds = append(adds, e)
		case "except":
			i := slices.IndexFunc(nextPols, func(r rules.Rule) bool { return r.ID == ch.RuleID })
			if i < 0 || rules.IsSystemRule(ch.RuleID) {
				return model.Proposal{}, model.Case{}, conflict("규칙 %s 이 없어 적용할 수 없음 — 제안을 버리고 다시 판정하세요", ch.RuleID)
			}
			nextPols[i] = withValue(nextPols[i], ch.Field, ch.Value)
			changed[ch.RuleID] = true
		default:
			return model.Proposal{}, model.Case{}, conflict("알 수 없는 변경 %q", ch.Op)
		}
	}
	var upserts []rules.Rule
	for _, r := range nextPols {
		if changed[r.ID] {
			if err := r.Validate(); err != nil {
				return model.Proposal{}, model.Case{}, conflict("규칙 %s: %v", r.ID, err)
			}
			upserts = append(upserts, r)
		}
	}
	p := cur.Clone()
	p.State, p.AppliedAt, p.AppliedBy = model.ProposalApplied, &now, ptr(by)
	c := caseRec.Clone()
	c.Case.State, c.Case.ClosedAt = model.CaseClosed, &now
	chg := model.Change{ID: s.nextID("chg"), At: now, By: by, Kind: model.ChangeProposalApplied,
		CaseID: ptr(cur.CaseID), ProposalID: ptr(cur.ID), Summary: summarize(cur.Changes), Reason: reason}

	// 2. 커밋 하나
	commit := store.ReviewCommit{Cases: []model.CaseRecord{c}, Proposals: []model.Proposal{p},
		BlockAdd: adds, Policies: upserts, Changes: []model.Change{chg}}
	if err := s.commitLocked(ctx, commit); err != nil {
		s.releaseID("chg")
		return model.Proposal{}, model.Case{}, err
	}

	// 3. 캐시 · 엔진
	s.blocklist = nextBlock
	s.putProposal(&p)
	s.putCase(&c)
	s.changes = append(s.changes, chg)
	s.o.Engine.Replace(s.engineRules(nextPols, s.hostsLocked(nextBlock)))
	s.broadcastCase(&c)
	return p.Clone(), c.Clone().Case, nil
}

// Discard: 제안을 버리고 건을 변경 없이 닫는다. 사유를 남기려고 변경 이력(proposal_discarded)도 같은 커밋에 쓴다(W15).
func (s *Service) Discard(ctx context.Context, id, reason string) (model.Proposal, model.Case, error) {
	reason, err := cleanReason(reason)
	if err != nil {
		return model.Proposal{}, model.Case{}, err
	}
	unlock := s.lockWrite()
	defer unlock()
	cur, ok := s.proposals[id]
	if !ok {
		return model.Proposal{}, model.Case{}, notFound("제안 없음")
	}
	if cur.State != model.ProposalDraft {
		return model.Proposal{}, model.Case{}, conflict("초안이 아닌 제안")
	}
	now := s.o.Now()
	p := cur.Clone()
	p.State = model.ProposalDiscarded
	chg := model.Change{ID: s.nextID("chg"), At: now, By: s.actor(ctx), Kind: model.ChangeProposalDiscarded,
		CaseID: ptr(p.CaseID), ProposalID: ptr(p.ID), Summary: "제안 버림 — 변경 없이 건 종결", Reason: reason}
	var commit store.ReviewCommit
	commit.Proposals = []model.Proposal{p}
	commit.Changes = []model.Change{chg}
	var c model.CaseRecord
	if x, ok := s.cases[p.CaseID]; ok {
		c = x.Clone()
		c.Case.State, c.Case.ClosedAt = model.CaseClosed, &now
		commit.Cases = []model.CaseRecord{c}
	}
	if err := s.commitLocked(ctx, commit); err != nil {
		s.releaseID("chg")
		return model.Proposal{}, model.Case{}, err
	}
	s.putProposal(&p)
	s.changes = append(s.changes, chg)
	if c.Case.ID != "" {
		s.putCase(&c)
		s.broadcastCase(&c)
	}
	return p.Clone(), c.Clone().Case, nil
}

// summarize: 변경 이력 한 줄 — "패키지 pip:reqeusts 차단 · 도메인 1개 차단 · 예외 2개 추가"
func summarize(changes []model.ProposalChange) string {
	var pk, im, hosts, exc []string
	for _, ch := range changes {
		switch {
		case ch.Op == "block" && ch.List == model.ListPackages:
			pk = append(pk, ch.Value)
		case ch.Op == "block" && ch.List == model.ListImages:
			im = append(im, ch.Value)
		case ch.Op == "block" && ch.List == model.ListHosts:
			hosts = append(hosts, ch.Value)
		case ch.Op == "except":
			exc = append(exc, ch.RuleID)
		}
	}
	var parts []string
	if len(pk) > 0 {
		parts = append(parts, "패키지 "+strings.Join(pk, ", ")+" 차단")
	}
	if len(im) > 0 {
		parts = append(parts, "이미지 "+strings.Join(im, ", ")+" 차단")
	}
	if len(hosts) > 0 {
		parts = append(parts, fmt.Sprintf("도메인 %d개 차단", len(hosts)))
	}
	if len(exc) > 0 {
		slices.Sort(exc)
		parts = append(parts, fmt.Sprintf("예외 %d개 추가(%s)", len(exc), strings.Join(slices.Compact(exc), ", ")))
	}
	if len(parts) == 0 {
		return "변경 없음 — 건 종결"
	}
	return strings.Join(parts, " · ")
}
