// Package rules evaluates normalized kernel events against the active policy set.
package rules

import (
	"fmt"
	"net/netip"
	"path"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/model"
)

type compiled struct {
	Rule
	allow []netip.Prefix
	deny  []netip.Prefix
	steps []compiled // sequence 규칙의 단계(11/03) — 단일 규칙과 같은 match 를 쓴다
}

// Engine: 정책을 원자적으로 교체(리로드)할 수 있는 평가기. 동시 호출 안전.
// 연쇄 규칙 상태(seq*)는 seqMu 가 지킨다. 둘 다 쥘 때는 mu → seqMu 순서로만 잡는다.
type Engine struct {
	mu    sync.RWMutex
	rules []compiled

	seqMu    sync.Mutex
	seq      map[string]*seqContainer // 컨테이너 ID → 진행 중인 연쇄
	seqSwept time.Time                // 마지막 만료 정리(이벤트 시각)
}

func New(rules []Rule) *Engine {
	e := &Engine{}
	e.Replace(rules)
	return e
}

// Replace: 정책 저장 후 엔진 리로드. 호출 전에 Validate를 통과한 규칙만 넘긴다. 진행 중인 연쇄 상태는 모두 버린다.
func (e *Engine) Replace(rules []Rule) {
	cs := make([]compiled, 0, len(rules))
	for _, r := range rules {
		cs = append(cs, compile(r))
	}
	e.mu.Lock()
	e.rules = cs
	e.seqMu.Lock() // 잠금 순서 mu → seqMu
	e.seq, e.seqSwept = nil, time.Time{}
	e.seqMu.Unlock()
	e.mu.Unlock()
}

// compile: 대역 문자열을 미리 파싱한다. sequence 규칙은 단계마다 같은 일을 한다.
func compile(r Rule) compiled {
	c := compiled{Rule: r}
	for _, s := range r.AllowCIDRs {
		if p, err := parsePrefix(s); err == nil {
			c.allow = append(c.allow, p)
		}
	}
	for _, s := range r.DenyCIDRs {
		if p, err := parsePrefix(s); err == nil {
			c.deny = append(c.deny, p)
		}
	}
	for _, st := range r.Steps {
		c.steps = append(c.steps, compile(st))
	}
	return c
}

func (e *Engine) Rules() []Rule {
	e.mu.RLock()
	defer e.mu.RUnlock()
	out := make([]Rule, len(e.rules))
	for i, c := range e.rules {
		out[i] = c.Rule
	}
	return out
}

// Evaluate: 매칭되는 규칙 중 가장 강한 대응(kill > kill dry-run > alert)을 판정으로 낸다.
func (e *Engine) Evaluate(ev model.Event) model.Verdict {
	e.mu.RLock()
	defer e.mu.RUnlock()

	best := model.Verdict{Event: ev}
	for _, r := range e.rules {
		if r.Disabled || r.Kind != ev.Kind || !r.appliesTo(ev) {
			continue
		}
		reason, override, ok := r.match(ev)
		if !ok {
			continue
		}
		// override: 조건이 자기 행동을 정하는 경우(directIp) 규칙의 action 대신 그 값을 쓴다
		action := r.Action
		if override != "" {
			action = override
		}
		v := model.Verdict{Event: ev, Matched: true, RuleID: r.ID, Action: action, Reason: reason,
			DryRun: action == model.ActionKill && r.DryRun}
		if rank(v) > rank(best) {
			best = v
		}
	}
	return best
}

func rank(v model.Verdict) int {
	switch {
	case !v.Matched:
		return 0
	case v.Action == model.ActionKill && !v.DryRun:
		return 3
	case v.Action == model.ActionKill:
		return 2
	default:
		return 1
	}
}

func (r compiled) appliesTo(ev model.Event) bool {
	if len(r.Containers) == 0 {
		return true
	}
	for _, g := range r.Containers {
		if ok, _ := path.Match(g, ev.ContainerName); ok {
			return true
		}
		if ok, _ := path.Match(g, ev.ImageName); ok {
			return true
		}
	}
	return false
}

// match: (이유, 행동 덮어쓰기, 걸림). 덮어쓰기가 "" 이면 규칙의 action 을 쓴다.
func (r compiled) match(ev model.Event) (string, model.Action, bool) {
	switch ev.Kind {
	case model.KindExec:
		reason, ok := r.matchExec(ev)
		return reason, "", ok
	case model.KindOpen:
		reason, ok := r.matchOpen(ev)
		return reason, "", ok
	case model.KindConnect:
		return r.matchConnect(ev)
	case model.KindDNS:
		reason, ok := r.matchDNS(ev)
		return reason, "", ok
	}
	return "", "", false
}

// matchDNS(10/30): ① denyHosts → ② allowHosts(통과) → ③ denyQtypes → ④ 라벨 길이 → ⑤ 이름 길이 → ⑥ allowHosts 가 있는데 일치 안 함.
// ⑥ 에서 점 없는 이름 · *.arpa · *.local · *.internal 은 뺀다. 포트 · 대역 · directIp 는 dns 에 적용하지 않는다.
func (r compiled) matchDNS(ev model.Event) (string, bool) {
	name := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(ev.DstHost), "."))
	if name == "" {
		return "", false
	}
	qtype := strings.ToUpper(strings.TrimSpace(ev.Qtype))
	label := model.DNSDetail(name, qtype)
	for _, h := range r.DenyHosts {
		if HostMatches(h, name) {
			return "금지 도메인 질의: " + label, true
		}
	}
	for _, h := range r.AllowHosts {
		if HostMatches(h, name) {
			return "", false
		}
	}
	if qtype != "" && slices.Contains(r.DenyQtypes, qtype) {
		return "금지 질의 유형: " + label, true
	}
	if r.MaxLabelLength > 0 {
		if n := longestLabel(name); n > r.MaxLabelLength {
			return fmt.Sprintf("긴 DNS 라벨(유출 의심): %s (라벨 %d자 > %d)", name, n, r.MaxLabelLength), true
		}
	}
	if r.MaxNameLength > 0 && len(name) > r.MaxNameLength {
		return fmt.Sprintf("긴 DNS 이름(유출 의심): %s (%d자 > %d)", name, len(name), r.MaxNameLength), true
	}
	if len(r.AllowHosts) > 0 && !dnsAllowlistExempt(name) {
		return "허용 목록 밖 도메인 질의: " + label, true
	}
	return "", false
}

// longestLabel: 점으로 나눈 라벨 중 가장 긴 것의 길이
func longestLabel(name string) int {
	n := 0
	for _, l := range strings.Split(name, ".") {
		n = max(n, len(l))
	}
	return n
}

// dnsAllowlistExempt: 허용 목록 밖 판정에서 빼는 이름 — 점 없는 단일 라벨(컨테이너 · 호스트 이름) · 역조회(*.arpa) · mDNS(*.local) · 사내(*.internal)
func dnsAllowlistExempt(name string) bool {
	if !strings.Contains(name, ".") {
		return true
	}
	for _, s := range []string{".arpa", ".local", ".internal"} {
		if strings.HasSuffix(name, s) {
			return true
		}
	}
	return false
}

func (r compiled) matchExec(ev model.Event) (string, bool) {
	// comm은 16바이트로 잘리므로 argv[0]의 basename도 함께 비교한다
	argv0 := ev.Args
	if i := strings.IndexByte(argv0, ' '); i >= 0 {
		argv0 = argv0[:i]
	}
	argv0 = path.Base(argv0)
	for _, c := range r.DenyComms {
		if ev.Comm == c || argv0 == c {
			return "금지 프로세스 실행: " + c, true
		}
	}
	for _, a := range r.DenyArgs {
		if strings.Contains(ev.Args, a) {
			return "금지 인자 패턴: " + a, true
		}
	}
	return "", false
}

func (r compiled) matchOpen(ev model.Event) (string, bool) {
	for _, p := range r.AllowPaths {
		if pathMatch(p, ev.Path) {
			return "", false
		}
	}
	for _, p := range r.DenyPaths {
		if pathMatch(p, ev.Path) {
			return "민감 파일 접근: " + ev.Path, true
		}
	}
	return "", false
}

// IsPublicAddr: 인터넷으로 나가는 주소인지 — 루프백 · 링크로컬 · 사설(10/8 · 172.16/12 · 192.168/16 · fc00::/7) · unspecified 는 아니다.
// 파싱이 안 되면 false. 직접 IP 연결 판정과 pipeline 의 DNS 유예 대상 선별이 같은 기준을 쓴다.
func IsPublicAddr(ip string) bool {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	a = a.Unmap()
	return !(a.IsLoopback() || a.IsLinkLocalUnicast() || a.IsLinkLocalMulticast() || a.IsPrivate() || a.IsUnspecified())
}

// pathMatch: glob 문자(*?[)가 있으면 glob, 아니면 prefix 비교
func pathMatch(pattern, p string) bool {
	if strings.ContainsAny(pattern, "*?[") {
		ok, _ := path.Match(pattern, p)
		return ok
	}
	return strings.HasPrefix(p, pattern)
}

// matchConnect: 금지 목록 → 허용 목록(OR) → 직접 IP 연결(directIp) → 허용 목록 밖 순으로 본다.
func (r compiled) matchConnect(ev model.Event) (string, model.Action, bool) {
	addr, err := netip.ParseAddr(ev.DstIP)
	if err != nil {
		return "", "", false
	}
	addr = addr.Unmap()
	dst := ev.DstIP + ":" + strconv.Itoa(int(ev.DstPort))
	if ev.DstHost != "" {
		dst += " (" + ev.DstHost + ")"
	}
	if slices.Contains(r.DenyPorts, ev.DstPort) {
		return "금지 포트 연결: " + dst, "", true
	}
	for _, p := range r.deny {
		if p.Contains(addr) {
			return "금지 대역 연결: " + dst, "", true
		}
	}
	for _, h := range r.DenyHosts {
		if HostMatches(h, ev.DstHost) {
			return "금지 도메인 연결: " + dst, "", true
		}
	}
	// 허용 목록은 OR: 허용 포트이거나 허용 대역이거나 허용 도메인이면 통과
	if slices.Contains(r.AllowPorts, ev.DstPort) {
		return "", "", false
	}
	for _, p := range r.allow {
		if p.Contains(addr) {
			return "", "", false
		}
	}
	for _, h := range r.AllowHosts {
		if HostMatches(h, ev.DstHost) {
			return "", "", false
		}
	}
	// 직접 IP 연결: trace_dns 가 돌고 있는데(DNSTraced) 도메인 없이 공인 주소로 바로 붙었다 — 규칙의 directIp 대로.
	// 사설 · 루프백 · 링크로컬 목적지는 직접 연결로 보지 않는다. trace_dns 가 꺼져 있으면(DNSTraced=false) 아래 fail-open 으로 간다.
	if r.DirectIP != "" && ev.DstHost == "" && ev.DNSTraced && IsPublicAddr(ev.DstIP) {
		if r.DirectIP == DirectIPAllow {
			return "", "", false
		}
		return "도메인 조회 없는 IP 직접 연결: " + dst, model.Action(r.DirectIP), true
	}
	// directIp 만 있고 allowHosts 가 없는 규칙(예: runtime-direct-ip)은 직접 IP 연결 전용이다 —
	// 도메인을 아는 연결 · DNS 추적이 꺼진 연결 · 사설 목적지는 이 규칙이 판정하지 않는다(허용 목록은 예외 지정용).
	if r.DirectIP != "" && len(r.AllowHosts) == 0 {
		return "", "", false
	}
	if len(r.AllowPorts) == 0 && len(r.allow) == 0 && len(r.AllowHosts) == 0 {
		return "", "", false
	}
	// 도메인 허용 목록이 있는데 목적지 도메인을 모르면(DNS 미확인 — trace_dns 미탑재 커널 · directIp 미설정)
	// 도메인 기준을 판단할 수 없으므로 이 연결로는 격리하지 않는다(fail-open). directIp 를 두면 위에서 실제로 판단한다.
	if len(r.AllowHosts) > 0 && ev.DstHost == "" {
		return "", "", false
	}
	return "허용 목록 밖 외부 연결: " + dst, "", true
}
