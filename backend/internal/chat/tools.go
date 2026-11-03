package chat

import (
	"cmp"
	"context"
	"fmt"
	"net/url"
	"slices"
	"strings"
	"unicode"

	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/model"
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/rules"
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/store"
)

// 읽기 전용 도구: 조회 결과 → 한국어 사실 문장(모델에 넣는 것) + 확정 값(facts) + 관련 화면(links).
// 쓰기 메서드는 부르지 않는다.

var (
	levelText  = map[model.Level]string{model.LevelKilled: "격리됨", model.LevelHeld: "격리 대상(컨테이너 살아 있음)", model.LevelAlert: "경고", model.LevelNormal: "정상"}
	sourceText = map[model.CaseSource]string{model.CaseInstall: "설치 검사", model.CaseRuntime: "런타임", model.CaseScan: "공급망 검사"}
	kindText   = map[model.Kind]string{model.KindExec: "실행", model.KindOpen: "파일 열기", model.KindConnect: "연결", model.KindDNS: "도메인 조회"}
	verdictTxt = map[string]string{"malicious": "악성 의심", "vulnerable": "취약점 있음", "caution": "주의", "clean": "위협 없음"}
	rangeText  = map[string]string{"1h": "1시간", "24h": "24시간", "7d": "7일"}
)

const (
	listCases    = 5  // 사실 문장 · facts 에 넣는 건 수
	listLinks    = 3  // 관련 화면 링크 수
	auditLimit   = 50 // 컨테이너 한 개 위반 기록 조회 상한
	clipDetail   = 120
	listExamples = 3
)

func toolIntent(tool string) Intent {
	switch tool {
	case ToolPending:
		return IntentPending
	case ToolAudit:
		return IntentWhy
	case ToolSummary:
		return IntentSummary
	case ToolLatestScan, ToolScan:
		return IntentScan
	case ToolBlocklist:
		return IntentBlocklist
	case ToolPolicy:
		return IntentPolicy
	}
	return IntentUnknown
}

// RunTool: 도구 하나를 실행한다. 의존성이 없으면 「읽을 수 없음」 문장으로 답하고, 저장소 오류만 error 로 돌려준다
func (s *Service) RunTool(ctx context.Context, tool string, args map[string]string) (Facts, []Link, error) {
	f := Facts{Intent: toolIntent(tool), Tool: tool, Sentences: []string{}}
	var links []Link
	var err error
	switch tool {
	case ToolPending:
		links = s.pending(&f)
	case ToolAudit:
		links, err = s.searchAudit(ctx, &f, args["container"], args["rule"])
	case ToolSummary:
		links, err = s.summary(ctx, &f, args["range"])
	case ToolLatestScan, ToolScan:
		links = s.scan(&f, args["id"])
	case ToolBlocklist:
		links = s.blocklist(&f)
	case ToolPolicy:
		links, err = s.policy(ctx, &f, args["id"])
	default:
		f.Intent = IntentUnknown
		f.Sentences = append(f.Sentences, "질문에 맞는 기록을 고르지 못했습니다.")
	}
	if links == nil {
		links = []Link{}
	}
	return f, links, err
}

func (s *Service) cases() []model.Case {
	if s.o.Review == nil {
		return nil
	}
	return s.o.Review.Cases()
}

func unavailable(f *Facts, what string) {
	f.Sentences = append(f.Sentences, "이 서버에서는 "+what+" 기록을 읽을 수 없습니다.")
}

// --- pending_cases ---

func (s *Service) pending(f *Facts) []Link {
	if s.o.Review == nil {
		unavailable(f, "판정 대기")
		return nil
	}
	open := []model.Case{}
	for _, c := range s.o.Review.Cases() {
		if c.State == model.CaseOpen {
			open = append(open, c)
		}
	}
	f.Status = fmt.Sprintf("판정 대기 %d건", len(open))
	if len(open) == 0 {
		f.Sentences = append(f.Sentences, "지금 판정 대기 건은 없습니다. 새 격리 · 경고가 생기면 대시보드 맨 위에 올라옵니다.")
		return []Link{{"대시보드", "/"}}
	}
	f.Sentences = append(f.Sentences, fmt.Sprintf("판정 대기 건은 %d개입니다.", len(open)))
	links := []Link{}
	for i, c := range open {
		if i >= listCases {
			f.Sentences = append(f.Sentences, fmt.Sprintf("나머지 %d건은 대시보드에서 볼 수 있습니다.", len(open)-listCases))
			break
		}
		f.Sentences = append(f.Sentences, fmt.Sprintf("%d. %s", i+1, caseSentence(c)))
		f.Cases = append(f.Cases, caseFact(c))
		if i < listLinks {
			links = append(links, Link{caseName(c) + " 판정하기", caseHref(c)})
		}
	}
	f.Sentences = append(f.Sentences, "판정은 각 건을 열어 공격 체인을 본 뒤 「악성 확정」 또는 「오탐」으로 하고, 판정하면 정책에서 미리보기 뒤 적용합니다.")
	return links
}

func caseName(c model.Case) string { return cmp.Or(c.Label, c.Container, c.ID) }

func caseSentence(c model.Case) string {
	name := caseName(c)
	if c.Container != "" && c.Container != name {
		name += "(컨테이너 " + c.Container + ")"
	}
	s := fmt.Sprintf("%s %s: %s, 위반 %d건", sourceText[c.Source], name, levelText[c.Level], c.Violations)
	if len(c.RuleIDs) > 0 {
		s += ", 걸린 정책 " + strings.Join(c.RuleIDs, ", ")
	}
	return s + "."
}

func caseHref(c model.Case) string {
	switch {
	case c.Source == model.CaseInstall && c.InstallID != nil:
		return "/installs?id=" + url.QueryEscape(*c.InstallID)
	case c.Source == model.CaseScan && c.ScanID != nil:
		return "/scans?id=" + url.QueryEscape(*c.ScanID)
	case c.Container != "":
		return "/topology?container=" + url.QueryEscape(c.Container)
	}
	return "/"
}

func decisionText(c model.Case) string {
	word := map[model.Decision]string{model.DecisionMalicious: "악성 확정", model.DecisionFalsePositive: "오탐"}[c.Decision]
	switch {
	case c.State == model.CaseOpen:
		return "판정 대기"
	case c.State == model.CaseClosed:
		return cmp.Or(word, "판정") + " · 종결"
	}
	return cmp.Or(word, "판정") + "(제안 적용 전)"
}

func caseFact(c model.Case) CaseFact {
	return CaseFact{
		ID: c.ID, Source: c.Source, Label: c.Label, Container: c.Container,
		Level: c.Level, LevelText: levelText[c.Level], State: c.State, Decision: c.Decision, DecisionText: decisionText(c),
		Violations: c.Violations, RuleIDs: slices.Clone(c.RuleIDs), Href: caseHref(c),
	}
}

// --- search_audit ---

func (s *Service) searchAudit(ctx context.Context, f *Facts, container, rule string) ([]Link, error) {
	container, rule = strings.TrimSpace(container), strings.TrimSpace(rule)
	if s.o.Audit == nil {
		unavailable(f, "감사 로그")
		return nil, nil
	}
	if container == "" && rule == "" {
		f.Sentences = append(f.Sentences, "찾을 컨테이너 이름이나 정책 id 가 없습니다.")
		return []Link{{"감사 로그", "/audit"}}, nil
	}
	rows, err := s.o.Audit.QueryAudit(ctx, store.AuditQuery{Container: container, RuleID: rule, Limit: auditLimit})
	if err != nil {
		return nil, err
	}
	who := quote(cmp.Or(container, rule), 64)
	if len(rows) == 0 {
		f.Sentences = append(f.Sentences, who+" 에 대한 위반 기록을 찾지 못했습니다. 이름을 확인해 주세요.")
		return []Link{{"감사 로그", "/audit"}}, nil
	}
	name := rows[0].Event.ContainerName
	subject := "컨테이너 " + name
	if container == "" {
		subject = "정책 " + rule
	}
	n := fmt.Sprintf("%d건", len(rows))
	if len(rows) >= auditLimit {
		n = fmt.Sprintf("%d건 이상(최근 %d건까지 봄)", auditLimit, auditLimit)
	}
	f.Sentences = append(f.Sentences, fmt.Sprintf("%s 의 위반 기록은 %s입니다.", subject, n))

	type cnt struct {
		id string
		n  int
	}
	byRule := map[string]int{}
	order := []string{}
	enforced, held, failed := false, false, false
	for _, a := range rows {
		if byRule[a.RuleID] == 0 {
			order = append(order, a.RuleID)
		}
		byRule[a.RuleID]++
		switch {
		case a.Enforced:
			enforced = true
		case a.EnforceError != "":
			failed = true
		case a.Action == model.ActionKill:
			held = true
		}
	}
	rs := make([]cnt, 0, len(order))
	for _, id := range order {
		rs = append(rs, cnt{id, byRule[id]})
	}
	slices.SortStableFunc(rs, func(a, b cnt) int { return cmp.Compare(b.n, a.n) })
	parts := make([]string, len(rs))
	for i, r := range rs {
		parts[i] = fmt.Sprintf("%s(%d건)", r.id, r.n)
	}
	f.Sentences = append(f.Sentences, "걸린 정책은 "+strings.Join(parts, ", ")+"입니다.")
	switch {
	case enforced:
		f.Sentences = append(f.Sentences, "실제로 컨테이너를 종료(격리)한 기록이 있습니다.")
	case failed:
		f.Sentences = append(f.Sentences, "컨테이너 종료를 시도했지만 실패한 기록이 있습니다.")
	case held:
		f.Sentences = append(f.Sentences, "격리 대상이지만 dry-run(또는 ENFORCE_KILL=false)이라 컨테이너는 종료하지 않았습니다.")
	default:
		f.Sentences = append(f.Sentences, "경고만 났고 컨테이너는 종료하지 않았습니다.")
	}
	seen := map[string]bool{}
	k := 0
	for _, a := range rows {
		if seen[a.RuleID] || k >= listExamples {
			continue
		}
		seen[a.RuleID] = true
		k++
		s := fmt.Sprintf("예시 %d: %s %s %s — 정책 %s", k, a.Event.Timestamp.Format("2006-01-02 15:04:05"), kindText[a.Event.Kind], quote(a.Event.Detail(), clipDetail), a.RuleID)
		if a.Reason != "" {
			s += ", 사유 " + quote(a.Reason, 80)
		}
		if container == "" && a.Event.ContainerName != "" {
			s += ", 컨테이너 " + a.Event.ContainerName
		}
		f.Sentences = append(f.Sentences, s+".")
	}

	if container == "" {
		return []Link{{"감사 로그에서 보기", "/audit?rule=" + url.QueryEscape(rule)}, {rule + " 정책", "/policies?id=" + url.QueryEscape(rule)}}, nil
	}
	links := []Link{{"감사 로그에서 보기", "/audit?container=" + url.QueryEscape(name)}}
	if c, ok := s.caseOf(name); ok {
		f.Cases = []CaseFact{caseFact(c)}
		f.Status = decisionText(c)
		links = append(links, Link{caseName(c) + " 건 보기", caseHref(c)})
	} else {
		links = append(links, Link{"토폴로지", "/topology?container=" + url.QueryEscape(name)})
	}
	return links, nil
}

// caseOf: 그 컨테이너의 건 — 열린 건 우선, 없으면 가장 최근 건
func (s *Service) caseOf(container string) (model.Case, bool) {
	var last *model.Case
	for _, c := range s.cases() {
		if c.Container != container {
			continue
		}
		if c.State == model.CaseOpen {
			return c, true
		}
		if last == nil || c.OpenedAt.After(last.OpenedAt) {
			last = &c
		}
	}
	if last != nil {
		return *last, true
	}
	return model.Case{}, false
}

// --- summary ---

func (s *Service) summary(ctx context.Context, f *Facts, rng string) ([]Link, error) {
	if s.o.Summary == nil {
		unavailable(f, "종합")
		return nil, nil
	}
	if _, ok := rangeText[rng]; !ok {
		rng = "24h"
	}
	sm, err := s.o.Summary.Build(ctx, rng)
	if err != nil {
		return nil, err
	}
	c, v := sm.Collected, sm.Violations
	f.Sentences = append(f.Sentences,
		fmt.Sprintf("최근 %s 동안 수집한 eBPF 이벤트는 %d건(실행 %d · 파일 열기 %d · 연결 %d)입니다.", rangeText[rng], c.Total, c.ByKind.Exec, c.ByKind.Open, c.ByKind.Connect),
		fmt.Sprintf("위반은 %d건(격리 %d · 격리 대상 %d · 경고 %d)입니다.", v.Total, v.Killed, v.Held, v.Alert))
	links := []Link{{"종합 보기", "/?range=" + rng}}
	if len(sm.TopRules) == 0 {
		f.Sentences = append(f.Sentences, "이 기간에 걸린 정책은 없습니다.")
	} else {
		parts := []string{}
		for i, t := range sm.TopRules {
			if i >= 3 {
				break
			}
			parts = append(parts, fmt.Sprintf("%s(%d건)", t.RuleID, t.Count))
			links = append(links, Link{t.RuleID + " 정책", "/policies?id=" + url.QueryEscape(t.RuleID)})
		}
		f.Sentences = append(f.Sentences, "가장 많이 걸린 정책은 "+strings.Join(parts, ", ")+"입니다.")
	}
	if len(sm.TopContainers) > 0 {
		parts := []string{}
		for i, t := range sm.TopContainers {
			if i >= 3 {
				break
			}
			parts = append(parts, fmt.Sprintf("%s(%d건)", t.Container, t.Count))
		}
		f.Sentences = append(f.Sentences, "위반이 많은 컨테이너는 "+strings.Join(parts, ", ")+"입니다.")
	}
	in := sm.Installs
	f.Sentences = append(f.Sentences,
		fmt.Sprintf("설치 검사는 %d건(통과 %d · 격리 %d · 경고 %d · 설치 전 거부 %d · 실패 %d · 진행 중 %d)입니다.", in.Total, in.Passed, in.Isolated, in.Warned, in.Refused, in.Failed, in.Running),
		fmt.Sprintf("차단 목록은 패키지 %d · 이미지 %d · 도메인 %d개입니다.", sm.Blocklist.Packages, sm.Blocklist.Images, sm.Blocklist.Hosts))
	return links, nil
}

// --- latest_scan · scan(id) ---

func (s *Service) scan(f *Facts, id string) []Link {
	if s.o.Scans == nil {
		unavailable(f, "공급망 검사")
		return nil
	}
	id = strings.TrimSpace(id)
	if id == "" {
		list := slices.Clone(s.o.Scans.List())
		if len(list) == 0 {
			f.Sentences = append(f.Sentences, "아직 공급망 검사가 없습니다. 공급망 검사 화면에서 패키지 이름 · 저장소 주소 · 파일로 시작하세요.")
			return []Link{{"공급망 검사", "/scans"}}
		}
		slices.SortStableFunc(list, func(a, b model.Scan) int { return b.StartedAt.Compare(a.StartedAt) })
		id = list[0].ID
	}
	sc, ok := s.o.Scans.Get(id)
	if !ok {
		f.Sentences = append(f.Sentences, "공급망 검사 "+quote(id, 32)+" 을(를) 찾지 못했습니다.")
		return []Link{{"공급망 검사", "/scans"}}
	}
	threats, caps, vulns := sc.Threats, sc.Capabilities, sc.VulnCount
	if threats == 0 && caps == 0 {
		for _, x := range sc.Findings {
			if x.Category == "threat" {
				threats++
			} else {
				caps++
			}
		}
	}
	if vulns == 0 {
		for _, v := range sc.Vulns {
			vulns += max(v.Count, 1)
		}
	}
	fact := &ScanFact{ID: sc.ID, Label: sc.Target.Label, Status: sc.Status, Verdict: sc.Verdict, Threats: threats, Capabilities: caps, Vulns: vulns}
	if sc.Risk != nil {
		sv := sc.Risk.Score
		fact.Score = &sv
	}
	f.Sentences = append(f.Sentences, fmt.Sprintf("공급망 검사 %s 의 대상은 %s 입니다.", sc.ID, quote(sc.Target.Label, 120)))
	switch sc.Status {
	case "running":
		fact.VerdictText = "검사 중"
		f.Sentences = append(f.Sentences, "아직 검사 중입니다.")
	case "failed":
		fact.VerdictText = "검사 실패"
		f.Sentences = append(f.Sentences, "검사가 실패했습니다. 오류: "+quote(sc.Error, 120)+".")
	default:
		fact.VerdictText = cmp.Or(verdictTxt[sc.Verdict], sc.Verdict)
		r := "결과는 " + fact.VerdictText
		if sc.Risk != nil {
			r += fmt.Sprintf("(위험 점수 %.1f", sc.Risk.Score)
			if sc.Risk.Label != "" {
				r += " · " + sc.Risk.Label
			}
			r += ")"
		}
		f.Sentences = append(f.Sentences, r+"입니다.",
			fmt.Sprintf("위협 코드 %d곳, 위험 기능 %d곳, 알려진 취약점 %d건이 나왔습니다.", threats, caps, vulns))
		k := 0
		for _, x := range sc.Findings {
			if x.Category != "threat" || k >= listExamples {
				continue
			}
			k++
			s := fmt.Sprintf("위협 %d: %s — %s:%d", k, x.Rule, x.File, x.Line)
			if x.Message != "" {
				s += " " + quote(x.Message, 100)
			}
			f.Sentences = append(f.Sentences, s+".")
		}
		if threats > 0 {
			f.Sentences = append(f.Sentences, "위협 줄은 검사 결과의 코드 보기에서 빨갛게 표시됩니다.")
		}
	}
	f.Scan, f.Status = fact, fact.VerdictText
	return []Link{{"검사 결과 보기", "/scans?id=" + url.QueryEscape(sc.ID)}}
}

// --- blocklist ---

func (s *Service) blocklist(f *Facts) []Link {
	if s.o.Review == nil {
		unavailable(f, "차단 목록")
		return nil
	}
	bl := s.o.Review.Blocklist()
	part := func(name string, es []model.BlockEntry) string {
		if len(es) == 0 {
			return name + " 0개"
		}
		vs := []string{}
		for i, e := range es {
			if i >= 5 {
				vs = append(vs, "…")
				break
			}
			vs = append(vs, clip(e.Value, 64))
		}
		return fmt.Sprintf("%s %d개(%s)", name, len(es), strings.Join(vs, ", "))
	}
	f.Sentences = append(f.Sentences,
		"차단 목록에는 "+part("패키지", bl.Packages)+", "+part("이미지", bl.Images)+", "+part("도메인", bl.Hosts)+"가 있습니다.",
		"패키지는 다시 설치하면 컨테이너 없이 설치 전에 거부되고, 이미지는 기동 즉시 격리되며, 도메인은 시스템 규칙 blocklist-hosts 로 막습니다.")
	return []Link{{"차단 목록(정책 화면)", "/policies"}}
}

// --- policy(id) ---

func (s *Service) policy(ctx context.Context, f *Facts, id string) ([]Link, error) {
	if s.o.Policies == nil {
		unavailable(f, "정책")
		return nil, nil
	}
	ps, err := s.o.Policies.ListPolicies(ctx)
	if err != nil {
		return nil, err
	}
	i := slices.IndexFunc(ps, func(r rules.Rule) bool { return r.ID == id })
	if i < 0 {
		ids := []string{}
		for j, r := range ps {
			if j >= 10 {
				ids = append(ids, "…")
				break
			}
			ids = append(ids, r.ID)
		}
		f.Sentences = append(f.Sentences, "정책 "+quote(id, 64)+" 을(를) 찾지 못했습니다.", "있는 정책은 "+strings.Join(ids, ", ")+"입니다.")
		return []Link{{"정책", "/policies"}}, nil
	}
	r := ps[i]
	act := "경고(alert)합니다"
	if r.Action == model.ActionKill {
		act = "컨테이너를 격리(kill)합니다"
	}
	f.Sentences = append(f.Sentences, fmt.Sprintf("정책 %s 은(는) %s(%s) 규칙이고, 위반하면 %s.", r.ID, kindText[r.Kind], r.Kind, act))
	if r.Description != "" {
		f.Sentences = append(f.Sentences, "설명: "+quote(r.Description, 160)+".")
	}
	if r.Disabled {
		f.Sentences = append(f.Sentences, "지금 꺼져 있어 평가하지 않습니다.")
	}
	if r.DryRun && r.Action == model.ActionKill {
		f.Sentences = append(f.Sentences, "dry-run 이라 격리하지 않고 경고만 합니다.")
	}
	if len(r.Containers) > 0 {
		f.Sentences = append(f.Sentences, "적용 대상 컨테이너: "+quoteList(r.Containers)+".")
	} else {
		f.Sentences = append(f.Sentences, "모든 컨테이너에 적용됩니다.")
	}
	ports := func(ps []uint16) []string {
		out := make([]string, len(ps))
		for i, p := range ps {
			out[i] = fmt.Sprint(p)
		}
		return out
	}
	for _, fld := range []struct {
		name string
		vs   []string
	}{
		{"막는 프로그램", r.DenyComms}, {"막는 명령 인자", r.DenyArgs}, {"막는 경로", r.DenyPaths}, {"예외 경로", r.AllowPaths},
		{"허용 포트", ports(r.AllowPorts)}, {"허용 대역", r.AllowCIDRs}, {"막는 포트", ports(r.DenyPorts)}, {"막는 대역", r.DenyCIDRs},
		{"허용 도메인", r.AllowHosts}, {"막는 도메인", r.DenyHosts}, {"막는 질의 유형", r.DenyQtypes},
	} {
		if len(fld.vs) > 0 {
			f.Sentences = append(f.Sentences, fld.name+": "+quoteList(fld.vs)+".")
		}
	}
	if r.MaxLabelLength > 0 {
		f.Sentences = append(f.Sentences, fmt.Sprintf("DNS 라벨 길이 상한: %d자.", r.MaxLabelLength))
	}
	if r.MaxNameLength > 0 {
		f.Sentences = append(f.Sentences, fmt.Sprintf("DNS 이름 길이 상한: %d자.", r.MaxNameLength))
	}
	if r.DirectIP != "" {
		f.Sentences = append(f.Sentences, "도메인 조회 없이 IP 로 바로 붙는 연결은 "+map[string]string{"allow": "통과", "alert": "경고", "kill": "격리"}[r.DirectIP]+" 처리합니다.")
	}
	if s.o.Audit != nil {
		rows, err := s.o.Audit.QueryAudit(ctx, store.AuditQuery{RuleID: r.ID, Limit: 200})
		if err != nil {
			return nil, err
		}
		if len(rows) >= 200 {
			f.Sentences = append(f.Sentences, "최근 기록에서 200건 넘게 걸렸습니다.")
		} else {
			f.Sentences = append(f.Sentences, fmt.Sprintf("최근 기록에서 %d건 걸렸습니다.", len(rows)))
		}
	}
	return []Link{{r.ID + " 정책", "/policies?id=" + url.QueryEscape(r.ID)}, {"감사 로그에서 보기", "/audit?rule=" + url.QueryEscape(r.ID)}}, nil
}

// --- 문자열 다듬기: 관찰된 값(명령줄 · 경로 · 메시지)은 공격자가 만든 것일 수 있다 → 한 줄로, 짧게, 「」 안에 ---

func clip(s string, n int) string {
	s = strings.Map(func(r rune) rune {
		switch {
		case r == '「' || r == '」':
			return '\''
		case unicode.IsControl(r):
			return ' '
		}
		return r
	}, s)
	s = strings.Join(strings.Fields(s), " ")
	if rs := []rune(s); len(rs) > n {
		return string(rs[:n]) + "…"
	}
	return s
}

func quote(s string, n int) string { return "「" + clip(s, n) + "」" }

func quoteList(vs []string) string {
	out := []string{}
	for i, v := range vs {
		if i >= 8 {
			out = append(out, fmt.Sprintf("외 %d개", len(vs)-8))
			break
		}
		out = append(out, quote(v, 60))
	}
	return strings.Join(out, ", ")
}
