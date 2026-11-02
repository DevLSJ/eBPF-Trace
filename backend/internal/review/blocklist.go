package review

import (
	"context"
	"log/slog"

	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/model"
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/rules"
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/store"
)

// Blocklist: GET /api/blocklist
func (s *Service) Blocklist() model.Blocklist {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := model.Blocklist{Packages: []model.BlockEntry{}, Images: []model.BlockEntry{}, Hosts: []model.BlockEntry{}}
	for _, b := range s.blocklist {
		switch b.List {
		case model.ListPackages:
			out.Packages = append(out.Packages, b)
		case model.ListImages:
			out.Images = append(out.Images, b)
		case model.ListHosts:
			out.Hosts = append(out.Hosts, b)
		}
	}
	return out
}

type CheckResult struct {
	Blocked bool    `json:"blocked"`
	Value   string  `json:"value"`
	CaseID  *string `json:"caseId"`
}

// CheckPackage: sg-install 사전 확인 — 정규화한 「매니저:이름」이 차단 목록에 있는지
func (s *Service) CheckPackage(manager, pkg string) (CheckResult, error) {
	key, err := NormalizePackage(manager, pkg)
	if err != nil {
		return CheckResult{}, invalid("%s", err.Error())
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, b := range s.blocklist {
		if b.List == model.ListPackages && b.Value == key {
			return CheckResult{Blocked: true, Value: key, CaseID: b.CaseID}, nil
		}
	}
	return CheckResult{Value: key}, nil
}

func (s *Service) hostsLocked(bl []model.BlockEntry) []string {
	var hosts []string
	for _, b := range bl {
		if b.List == model.ListHosts {
			hosts = append(hosts, b.Value)
		}
	}
	return hosts
}

// RemoveBlock: DELETE /api/blocklist/{list}/{value} — 차단 해제 + 변경 이력
func (s *Service) RemoveBlock(ctx context.Context, list, value, reason string) error {
	if !model.ValidBlockList(list) {
		return invalid("list: packages | images | hosts")
	}
	reason, err := cleanReason(reason)
	if err != nil {
		return err
	}
	unlock := s.lockWrite()
	defer unlock()
	idx := -1
	for i, b := range s.blocklist {
		if b.List == list && b.Value == value {
			idx = i
		}
	}
	if idx < 0 {
		return notFound("차단 목록에 없음")
	}
	entry := s.blocklist[idx]
	next := append(append([]model.BlockEntry{}, s.blocklist[:idx]...), s.blocklist[idx+1:]...)
	var pols []rules.Rule
	if list == model.ListHosts {
		var err error
		if pols, err = s.o.Policies.ListPolicies(ctx); err != nil {
			return err
		}
	}
	label := map[string]string{model.ListPackages: "패키지", model.ListImages: "이미지", model.ListHosts: "도메인"}[list]
	chg := model.Change{ID: s.nextID("chg"), At: s.o.Now(), By: s.actor(ctx), Kind: model.ChangeBlocklistRemove,
		CaseID: entry.CaseID, Summary: label + " " + value + " 차단 해제", Reason: reason}
	if err := s.commitLocked(ctx, store.ReviewCommit{BlockRemove: []model.BlockRef{{List: list, Value: value}}, Changes: []model.Change{chg}}); err != nil {
		s.releaseID("chg")
		return err
	}
	s.blocklist = next
	s.changes = append(s.changes, chg)
	if list == model.ListHosts {
		s.o.Engine.Replace(s.engineRules(pols, s.hostsLocked(next)))
	}
	return nil
}

// ListChanges: 최신순, 기본 50 · 상한 500
func (s *Service) ListChanges(limit int) []model.Change {
	if limit <= 0 {
		limit = 50
	}
	limit = min(limit, 500)
	s.mu.Lock()
	defer s.mu.Unlock()
	out := []model.Change{}
	for i := len(s.changes) - 1; i >= 0 && len(out) < limit; i-- {
		out = append(out, s.changes[i])
	}
	return out
}

// engineRules: 엔진에 넣을 규칙 = 저장된 정책 + 차단 도메인으로 만든 시스템 규칙
// 같은 id 가 저장소에 있더라도(이전 버전 등) 저장된 것은 버리고 차단 목록에서 다시 만든다 — 기준은 차단 목록 하나.
func (s *Service) engineRules(policies []rules.Rule, hosts []string) []rules.Rule {
	return withSystemRule(policies, hosts)
}

// Reload: 저장소의 정책과 차단 목록으로 엔진을 다시 만든다.
func (s *Service) Reload(ctx context.Context) error {
	pols, err := s.o.Policies.ListPolicies(ctx)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.o.Engine.Replace(s.engineRules(pols, s.hostsLocked(s.blocklist)))
	return nil
}

// RecordChange: 정책 · 차단 목록을 바꾸지 않는 작업의 변경 이력 한 줄(시연 실행 demo_run, 10/30). 처리자는 요청자
func (s *Service) RecordChange(ctx context.Context, kind model.ChangeKind, summary string) error {
	unlock := s.lockWrite()
	defer unlock()
	chg := model.Change{ID: s.nextID("chg"), At: s.o.Now(), By: s.actor(ctx), Kind: kind, Summary: summary}
	if err := s.commitLocked(ctx, store.ReviewCommit{Changes: []model.Change{chg}}); err != nil {
		s.releaseID("chg")
		return err
	}
	s.changes = append(s.changes, chg)
	return nil
}

// PolicyWrite: 정책 API 의 쓰기(write)를 제안 적용과 같은 잠금 안에서 하고, 엔진 리로드 후 변경 이력을 남긴다.
func (s *Service) PolicyWrite(ctx context.Context, kind model.ChangeKind, summary string, write func(context.Context) error) error {
	unlock := s.lockWrite()
	defer unlock()
	if err := write(ctx); err != nil {
		return err
	}
	pols, err := s.o.Policies.ListPolicies(ctx)
	if err != nil {
		return err
	}
	s.o.Engine.Replace(s.engineRules(pols, s.hostsLocked(s.blocklist)))
	chg := model.Change{ID: s.nextID("chg"), At: s.o.Now(), By: s.actor(ctx), Kind: kind, Summary: summary}
	if err := s.commitLocked(ctx, store.ReviewCommit{Changes: []model.Change{chg}}); err != nil {
		// 정책은 이미 저장 · 적용됐다 — 이력만 못 남긴 것이므로 요청은 성공으로 둔다
		s.releaseID("chg")
		slog.Error("change record", "kind", kind, "err", err)
		return nil
	}
	s.changes = append(s.changes, chg)
	return nil
}
