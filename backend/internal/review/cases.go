package review

import (
	"context"
	"fmt"
	"net/netip"
	"slices"
	"strings"

	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/model"
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/rules"
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/store"
)

type CaseQuery struct {
	State  model.CaseState
	Source model.CaseSource
}

// ListCases: 최신순
func (s *Service) ListCases(q CaseQuery) []model.Case {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := []model.Case{}
	for i := len(s.caseIDs) - 1; i >= 0 && len(out) < 500; i-- {
		c := s.cases[s.caseIDs[i]]
		if (q.State != "" && c.Case.State != q.State) || (q.Source != "" && c.Case.Source != q.Source) {
			continue
		}
		out = append(out, c.Clone().Case)
	}
	return out
}

func (s *Service) GetCase(id string) (model.Case, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.cases[id]
	if !ok {
		return model.Case{}, notFound("건 없음")
	}
	return c.Clone().Case, nil
}

// Decide: 판정을 남기고 제안 초안을 만든다. 이미 판정된 건은 409.
func (s *Service) Decide(ctx context.Context, id string, decision model.Decision, note string) (model.Case, model.Proposal, error) {
	if decision != model.DecisionMalicious && decision != model.DecisionFalsePositive {
		return model.Case{}, model.Proposal{}, invalid("decision: malicious | false_positive")
	}
	if len(note) > 2000 {
		return model.Case{}, model.Proposal{}, invalid("note: 2000자 이하")
	}
	unlock := s.lockWrite()
	defer unlock()
	cur, ok := s.cases[id]
	if !ok {
		return model.Case{}, model.Proposal{}, notFound("건 없음")
	}
	if cur.Case.Decision != model.DecisionPending || cur.Case.State != model.CaseOpen {
		return model.Case{}, model.Proposal{}, conflict("이미 판정된 건")
	}
	now := s.o.Now()
	p := model.Proposal{
		ID: s.nextID("prop"), CaseID: id, Decision: decision, State: model.ProposalDraft,
		CreatedAt: now, CreatedBy: s.o.Actor, Changes: []model.ProposalChange{}, Notes: []string{},
	}
	if decision == model.DecisionMalicious {
		s.maliciousChanges(cur, &p)
	} else {
		s.falsePositiveChanges(cur, &p)
	}
	c := cur.Clone()
	c.Case.State, c.Case.Decision = model.CaseDecided, decision
	c.Case.DecidedAt, c.Case.DecidedBy, c.Case.Note = &now, ptr(s.o.Actor), note
	c.Case.ProposalID = ptr(p.ID)
	if err := s.commitLocked(ctx, store.ReviewCommit{Cases: []model.CaseRecord{c}, Proposals: []model.Proposal{p}}); err != nil {
		s.releaseID("prop")
		return model.Case{}, model.Proposal{}, err
	}
	s.putCase(&c)
	s.putProposal(&p)
	s.broadcastCase(&c)
	return c.Clone().Case, p.Clone(), nil
}

func addChange(p *model.Proposal, ch model.ProposalChange) {
	if !slices.Contains(p.Changes, ch) {
		p.Changes = append(p.Changes, ch)
	}
}

func addNote(p *model.Proposal, n string) {
	if !slices.Contains(p.Notes, n) {
		p.Notes = append(p.Notes, n)
	}
}

// maliciousChanges: 설치 건 = 패키지 차단, 런타임 건 = 이미지 차단. 둘 다 위반 통신의 도메인 차단.
// IP 만 있고 도메인이 없는 통신은 도메인 차단을 만들지 않는다.
func (s *Service) maliciousChanges(c *model.CaseRecord, p *model.Proposal) {
	switch c.Case.Source {
	case model.CaseInstall:
		var pkgs []string
		mgr := ""
		if c.Case.InstallID != nil {
			if x, ok := s.installs[*c.Case.InstallID]; ok {
				pkgs, mgr = x.Packages, x.Manager
			}
		}
		for _, raw := range pkgs {
			if key, err := NormalizePackage(mgr, raw); err == nil {
				addChange(p, model.ProposalChange{Op: "block", List: model.ListPackages, Value: key})
			}
		}
		if len(pkgs) == 0 && c.Case.Package != "" {
			addChange(p, model.ProposalChange{Op: "block", List: model.ListPackages, Value: c.Case.Package})
		}
	case model.CaseScan: // 공급망 검사에서 올린 패키지(10/16)
		if c.Case.Package != "" {
			addChange(p, model.ProposalChange{Op: "block", List: model.ListPackages, Value: c.Case.Package})
		}
	case model.CaseRuntime:
		if c.Case.Image != "" {
			addChange(p, model.ProposalChange{Op: "block", List: model.ListImages, Value: c.Case.Image})
		}
	}
	cur := s.o.Engine.Rules()
	for _, v := range c.Evidence {
		e := v.Event
		if e.Kind != model.KindConnect {
			continue
		}
		host := strings.ToLower(strings.TrimSuffix(e.DstHost, "."))
		switch {
		case host == "":
			addNote(p, fmt.Sprintf("%s 은 도메인을 몰라 도메인 차단을 만들지 않았습니다", e.DstIP))
		case !rules.ValidHost(host):
			addNote(p, fmt.Sprintf("도메인 %q 은 형식이 맞지 않아 차단하지 않았습니다", e.DstHost))
		default:
			// 어느 규칙의 allowHosts 에 있는(접미사 일치 포함) 도메인은 막지 않는다 — 레지스트리 · GitHub 를 전 컨테이너에서 끊지 않게 (결정 2026-10-15)
			if rid, pat, ok := allowedBy(cur, host); ok {
				addNote(p, fmt.Sprintf("도메인 %s 은 규칙 %s 의 허용 도메인(%s)이라 차단하지 않았습니다", host, rid, pat))
				continue
			}
			addChange(p, model.ProposalChange{Op: "block", List: model.ListHosts, Value: host})
		}
	}
}

// allowedBy: host 를 allowHosts 로 허용하는 규칙이 있으면 그 규칙 id 와 패턴
func allowedBy(rs []rules.Rule, host string) (ruleID, pattern string, ok bool) {
	for _, r := range rs {
		for _, h := range r.AllowHosts {
			if rules.HostMatches(h, host) {
				return r.ID, h, true
			}
		}
	}
	return "", "", false
}

// falsePositiveChanges: 걸린 규칙마다 가장 좁은 예외를 만든다.
// 예외를 넣은 규칙 사본으로 그 이벤트를 다시 평가해, 다른 규칙이 또 걸리면 그 규칙의 예외도 더한다.
// 예외로 풀리지 않는 규칙(실행 규칙, 금지 목록 deny*, 시스템 규칙)은 변경 없이 안내만 남긴다.
func (s *Service) falsePositiveChanges(c *model.CaseRecord, p *model.Proposal) {
	work := s.o.Engine.Rules()
	// hadHosts: 제안 전에 allowHosts 가 있던 규칙 — 없던 규칙에 allowHosts 를 넣으면 그 규칙의
	// DNS 미확인 연결이 모두 통과(fail-open)하므로 allowCidrs IP/32 로 대신한다 (결정 2026-10-15)
	hadHosts := map[string]bool{}
	for _, r := range work {
		hadHosts[r.ID] = len(r.AllowHosts) > 0
	}
	for _, ev := range c.Evidence {
		if ev.RuleID == model.RuleBlockedImage {
			addNote(p, "이미지 차단은 예외가 아니라 차단 목록에서 해제합니다")
			continue
		}
		for range len(work) + 1 {
			v := rules.New(work).Evaluate(ev.Event)
			if !v.Matched {
				break
			}
			if rules.IsSystemRule(v.RuleID) {
				addNote(p, fmt.Sprintf("도메인 %s 은 차단 목록에 있습니다 — 차단 목록에서 해제하세요", ev.Event.DstHost))
				break
			}
			i := slices.IndexFunc(work, func(r rules.Rule) bool { return r.ID == v.RuleID })
			field, value, ok := narrowestException(work[i].Kind, ev.Event, hadHosts[v.RuleID])
			if !ok {
				addNote(p, fmt.Sprintf("실행 규칙 %s 은 자동 예외를 만들지 않습니다 — 정책 탭에서 직접 수정하세요", v.RuleID))
				break
			}
			trial := slices.Clone(work)
			trial[i] = withValue(trial[i], field, value)
			if again := rules.New(trial).Evaluate(ev.Event); again.Matched && again.RuleID == v.RuleID {
				addNote(p, fmt.Sprintf("규칙 %s 은 금지 목록에 걸려 예외로 풀 수 없습니다 — 정책 탭에서 직접 수정하세요", v.RuleID))
				break
			}
			work = trial
			addChange(p, model.ProposalChange{Op: "except", RuleID: v.RuleID, Field: field, Value: value})
		}
	}
}

// narrowestException: 파일 → allowPaths 경로,
// 통신 → 규칙에 원래 allowHosts 가 있고 도메인을 알면 allowHosts, 그 밖은 allowCidrs IP/32(/128)
func narrowestException(kind model.Kind, e model.Event, ruleHasHosts bool) (field, value string, ok bool) {
	switch kind {
	case model.KindOpen:
		if e.Path != "" {
			return "allowPaths", e.Path, true
		}
	case model.KindConnect:
		if h := strings.ToLower(strings.TrimSuffix(e.DstHost, ".")); ruleHasHosts && h != "" && rules.ValidHost(h) {
			return "allowHosts", h, true
		}
		if a, err := netip.ParseAddr(e.DstIP); err == nil {
			a = a.Unmap()
			return "allowCidrs", netip.PrefixFrom(a, a.BitLen()).String(), true
		}
	}
	return "", "", false
}

// withValue: 규칙 필드에 값을 더한 사본 (이미 있으면 그대로)
func withValue(r rules.Rule, field, value string) rules.Rule {
	add := func(xs []string) []string {
		if slices.Contains(xs, value) {
			return xs
		}
		return append(slices.Clone(xs), value)
	}
	switch field {
	case "allowPaths":
		r.AllowPaths = add(r.AllowPaths)
	case "allowHosts":
		r.AllowHosts = add(r.AllowHosts)
	case "allowCidrs":
		r.AllowCIDRs = add(r.AllowCIDRs)
	}
	return r
}

// FromScan: 공급망 검사 「차단 목록에 올리기」(10/16) — 검사마다 건 하나(source scan)를 열고 악성으로 판정해 패키지 차단 제안을 만든다.
// 이미 올렸으면 그 건 · 제안을 돌려준다. 적용은 정책 화면의 미리보기 → 적용(사람)
func (s *Service) FromScan(ctx context.Context, sc model.Scan) (model.Case, model.Proposal, error) {
	key, err := NormalizePackage(sc.Target.Manager, sc.Target.Name)
	if err != nil {
		return model.Case{}, model.Proposal{}, invalid("%s", err.Error())
	}
	unlock := s.lockWrite()
	var found *model.CaseRecord
	for _, id := range s.caseIDs {
		if c := s.cases[id]; c.Case.ScanID != nil && *c.Case.ScanID == sc.ID {
			found = c
		}
	}
	if found != nil && found.Case.ProposalID != nil {
		c, p := found.Clone().Case, s.proposals[*found.Case.ProposalID].Clone()
		unlock()
		return c, p, nil
	}
	if found == nil {
		rules := []string{}
		for _, f := range sc.Findings {
			if f.Category == "threat" && !slices.Contains(rules, f.Rule) {
				rules = append(rules, f.Rule)
			}
		}
		lvl := model.LevelAlert
		if sc.Verdict == "malicious" {
			lvl = model.LevelKilled
		}
		c := model.CaseRecord{Case: model.Case{
			ID: s.nextID("case"), Source: model.CaseScan, ScanID: ptr(sc.ID), Label: sc.Target.Label, Package: key,
			OpenedAt: s.o.Now(), Level: lvl, Violations: sc.Threats, RuleIDs: rules, State: model.CaseOpen, Decision: model.DecisionPending,
		}, Evidence: []model.ViolationCount{}}
		if err := s.commitLocked(ctx, store.ReviewCommit{Cases: []model.CaseRecord{c}}); err != nil {
			s.releaseID("case")
			unlock()
			return model.Case{}, model.Proposal{}, err
		}
		s.putCase(&c)
		found = &c
	}
	id := found.Case.ID
	unlock()
	note := "공급망 검사 " + sc.ID
	if sc.Risk != nil {
		note += fmt.Sprintf(" — 위험 점수 %.1f", sc.Risk.Score)
	}
	return s.Decide(ctx, id, model.DecisionMalicious, note)
}
