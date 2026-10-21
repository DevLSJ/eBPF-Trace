package review

import (
	"context"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"time"

	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/model"
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/rules"
)

// ── 판정 미리보기 (W15) ─────────────────────────────────
// POST /api/cases/{id}/preview {decision} — 확인 대화상자의 「함께 일어나는 일」.
// Decide 와 같은 함수(draftChanges)로 제안의 변경을 만들고, 저장 · id 번호 · 알림 없이 영향 요약만 붙여 돌려준다.

// Effect kind — 화면은 text 를 그대로 보여 주고, kind · count 로 아이콘 · 강조를 고른다
const (
	EffectBlocklist      = "blocklist"       // 차단 목록 +N (패키지 a · 이미지 b · 도메인 c), count = N
	EffectAlreadyBlocked = "already_blocked" // 이미 차단 목록에 있어 그대로 두는 값, count
	EffectPackage        = "package"         // 패키지 하나: 다음 sg-install 부터 설치 전 거부
	EffectImage          = "image"           // 이미지 하나: 같은 이미지 실행 중 컨테이너 수(count, 모르면 없음) — 다음 시작 때 격리
	EffectHost           = "host"            // 도메인 차단: 적용 즉시 시스템 규칙으로 집행
	EffectException      = "exception"       // 오탐 예외 하나: 규칙 · 필드 · 값 · 범위
	EffectNone           = "none"            // 자동으로 만들 변경이 없음
	EffectNote           = "note"            // 제안 안내(notes) 그대로
	EffectNext           = "next"            // 판정 뒤 흐름(마지막 줄)
)

type Effect struct {
	Kind  string `json:"kind"`
	Text  string `json:"text"`
	Count *int   `json:"count,omitempty"`
}

type DecisionPreview struct {
	CaseID   string                 `json:"caseId"`
	Decision model.Decision         `json:"decision"`
	Changes  []model.ProposalChange `json:"changes"`
	Notes    []string               `json:"notes"`
	Effects  []Effect               `json:"effects"`
}

const listContainersTimeout = 3 * time.Second

var listLabel = map[string]string{model.ListPackages: "패키지", model.ListImages: "이미지", model.ListHosts: "도메인"}

// PreviewDecision: 판정하면 생길 제안(변경 · 안내)과 영향 요약. 쓰기는 없다. 판정 · 종결 건은 409
func (s *Service) PreviewDecision(ctx context.Context, id string, decision model.Decision) (DecisionPreview, error) {
	if err := validDecision(decision); err != nil {
		return DecisionPreview{}, err
	}
	s.mu.Lock()
	cur, err := s.decidableLocked(id)
	if err != nil {
		s.mu.Unlock()
		return DecisionPreview{}, err
	}
	changes, notes := s.draftChanges(cur, decision)
	blocked := map[model.BlockRef]bool{}
	for _, b := range s.blocklist {
		blocked[model.BlockRef{List: b.List, Value: b.Value}] = true
	}
	s.mu.Unlock()

	out := DecisionPreview{CaseID: id, Decision: decision, Changes: changes, Notes: notes}
	if decision == model.DecisionMalicious {
		out.Effects = s.blockEffects(ctx, changes, blocked)
	} else {
		out.Effects = exceptionEffects(s.o.Engine.Rules(), changes)
	}
	for _, n := range notes {
		out.Effects = append(out.Effects, Effect{Kind: EffectNote, Text: n})
	}
	out.Effects = append(out.Effects, Effect{Kind: EffectNext, Text: "판정하면 제안 초안이 생깁니다 — 아직 아무것도 바뀌지 않으며, 정책 화면에서 미리보기 후 적용합니다"})
	return out, nil
}

// blockEffects: 악성 — 새로 늘어날 차단(적용이 건너뛰는 이미 차단된 값은 따로), 패키지 · 이미지 · 도메인별 결과
func (s *Service) blockEffects(ctx context.Context, changes []model.ProposalChange, blocked map[model.BlockRef]bool) []Effect {
	var fresh, already []model.ProposalChange
	for _, ch := range changes {
		if ch.Op != "block" {
			continue
		}
		if blocked[model.BlockRef{List: ch.List, Value: ch.Value}] {
			already = append(already, ch)
		} else {
			fresh = append(fresh, ch)
		}
	}
	var out []Effect
	if len(fresh) > 0 {
		out = append(out, Effect{Kind: EffectBlocklist, Count: ptr(len(fresh)),
			Text: fmt.Sprintf("차단 목록 +%d (%s)", len(fresh), countByList(fresh))})
	}
	if len(already) > 0 {
		var vals []string
		for _, ch := range already {
			vals = append(vals, listLabel[ch.List]+" "+ch.Value)
		}
		out = append(out, Effect{Kind: EffectAlreadyBlocked, Count: ptr(len(already)),
			Text: fmt.Sprintf("이미 차단 목록에 있는 %d개(%s)는 그대로 둡니다", len(already), strings.Join(vals, ", "))})
	}
	if len(fresh) == 0 {
		out = append(out, Effect{Kind: EffectNone, Text: "새로 차단할 대상이 없습니다 — 적용하면 건만 종결합니다"})
		return out
	}
	var hosts []string
	var running map[string]int
	var runErr error
	for _, ch := range fresh {
		switch ch.List {
		case model.ListPackages:
			out = append(out, Effect{Kind: EffectPackage, Text: fmt.Sprintf("다음 sg-install 부터 %s 는 설치 전에 거부됩니다(컨테이너를 띄우지 않음)", ch.Value)})
		case model.ListImages:
			if running == nil && runErr == nil {
				running, runErr = s.runningByImage(ctx)
			}
			if runErr != nil {
				out = append(out, Effect{Kind: EffectImage, Text: fmt.Sprintf("이미지 %s — 실행 중 컨테이너 수를 확인하지 못했습니다. 적용하면 이 이미지로 시작하는 컨테이너는 격리됩니다", ch.Value)})
				continue
			}
			n := running[ch.Value]
			out = append(out, Effect{Kind: EffectImage, Count: ptr(n),
				Text: fmt.Sprintf("같은 이미지(%s)를 쓰는 실행 중 컨테이너 %d개 — 적용하면 다음 시작 때 격리됩니다(지금 실행은 그대로)", ch.Value, n)})
		case model.ListHosts:
			hosts = append(hosts, ch.Value)
		}
	}
	if len(hosts) > 0 {
		out = append(out, Effect{Kind: EffectHost, Count: ptr(len(hosts)),
			Text: fmt.Sprintf("도메인 %d개(%s)는 적용 즉시 시스템 규칙 %s 로 차단됩니다(런타임 · 설치 모두)", len(hosts), strings.Join(hosts, ", "), rules.SystemBlocklistHosts)})
	}
	return out
}

func countByList(chs []model.ProposalChange) string {
	var parts []string
	for _, l := range model.BlockLists {
		n := 0
		for _, ch := range chs {
			if ch.List == l {
				n++
			}
		}
		if n > 0 {
			parts = append(parts, fmt.Sprintf("%s %d", listLabel[l], n))
		}
	}
	return strings.Join(parts, " · ")
}

// errNoLister: Options.Containers 없음(테스트 · Docker 없는 실행)
var errNoLister = fmt.Errorf("container lister not configured")

// runningByImage: 이미지 → 실행 중 컨테이너 수 (Docker API, 잠금 밖에서)
func (s *Service) runningByImage(ctx context.Context) (map[string]int, error) {
	if s.o.Containers == nil {
		return nil, errNoLister
	}
	ctx, cancel := context.WithTimeout(ctx, listContainersTimeout)
	defer cancel()
	cs, err := s.o.Containers.List(ctx)
	if err != nil {
		slog.Warn("decision preview: list containers", "err", err)
		return nil, err
	}
	out := map[string]int{}
	for _, c := range cs {
		if c.Running {
			out[c.Image]++
		}
	}
	return out, nil
}

// exceptionEffects: 오탐 — 예외마다 규칙 · 필드 · 값 · 범위(규칙의 containers, 비면 모든 컨테이너)
func exceptionEffects(cur []rules.Rule, changes []model.ProposalChange) []Effect {
	var out []Effect
	for _, ch := range changes {
		if ch.Op != "except" {
			continue
		}
		scope := "모든 컨테이너"
		if i := slices.IndexFunc(cur, func(r rules.Rule) bool { return r.ID == ch.RuleID }); i >= 0 && len(cur[i].Containers) > 0 {
			scope = "컨테이너 " + strings.Join(cur[i].Containers, ", ")
		}
		out = append(out, Effect{Kind: EffectException,
			Text: fmt.Sprintf("규칙 %s 예외 추가 — %s 에 %s (범위: %s). 적용 즉시 엔진에 반영됩니다", ch.RuleID, ch.Field, ch.Value, scope)})
	}
	if len(out) == 0 {
		out = append(out, Effect{Kind: EffectNone, Text: "자동으로 만들 예외가 없습니다 — 정책 탭에서 직접 고칩니다"})
	}
	return out
}
