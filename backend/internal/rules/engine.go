// Package rules evaluates normalized kernel events against the active policy set.
package rules

import (
	"net/netip"
	"path"
	"slices"
	"strconv"
	"strings"
	"sync"

	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/model"
)

type compiled struct {
	Rule
	allow []netip.Prefix
	deny  []netip.Prefix
}

// Engine: 정책을 원자적으로 교체(리로드)할 수 있는 평가기. 동시 호출 안전.
type Engine struct {
	mu    sync.RWMutex
	rules []compiled
}

func New(rules []Rule) *Engine {
	e := &Engine{}
	e.Replace(rules)
	return e
}

// Replace: 정책 저장 후 엔진 리로드. 호출 전에 Validate를 통과한 규칙만 넘긴다.
func (e *Engine) Replace(rules []Rule) {
	cs := make([]compiled, 0, len(rules))
	for _, r := range rules {
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
		cs = append(cs, c)
	}
	e.mu.Lock()
	e.rules = cs
	e.mu.Unlock()
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
		reason, ok := r.match(ev)
		if !ok {
			continue
		}
		v := model.Verdict{Event: ev, Matched: true, RuleID: r.ID, Action: r.Action, Reason: reason,
			DryRun: r.Action == model.ActionKill && r.DryRun}
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

func (r compiled) match(ev model.Event) (string, bool) {
	switch ev.Kind {
	case model.KindExec:
		return r.matchExec(ev)
	case model.KindOpen:
		return r.matchOpen(ev)
	case model.KindConnect:
		return r.matchConnect(ev)
	}
	return "", false
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

// pathMatch: glob 문자(*?[)가 있으면 glob, 아니면 prefix 비교
func pathMatch(pattern, p string) bool {
	if strings.ContainsAny(pattern, "*?[") {
		ok, _ := path.Match(pattern, p)
		return ok
	}
	return strings.HasPrefix(p, pattern)
}

func (r compiled) matchConnect(ev model.Event) (string, bool) {
	addr, err := netip.ParseAddr(ev.DstIP)
	if err != nil {
		return "", false
	}
	addr = addr.Unmap()
	dst := ev.DstIP + ":" + strconv.Itoa(int(ev.DstPort))
	if ev.DstHost != "" {
		dst += " (" + ev.DstHost + ")"
	}
	if slices.Contains(r.DenyPorts, ev.DstPort) {
		return "금지 포트 연결: " + dst, true
	}
	for _, p := range r.deny {
		if p.Contains(addr) {
			return "금지 대역 연결: " + dst, true
		}
	}
	for _, h := range r.DenyHosts {
		if HostMatches(h, ev.DstHost) {
			return "금지 도메인 연결: " + dst, true
		}
	}
	if len(r.AllowPorts) == 0 && len(r.allow) == 0 && len(r.AllowHosts) == 0 {
		return "", false
	}
	// 허용 목록은 OR: 허용 포트이거나 허용 대역이거나 허용 도메인이면 통과
	if slices.Contains(r.AllowPorts, ev.DstPort) {
		return "", false
	}
	for _, p := range r.allow {
		if p.Contains(addr) {
			return "", false
		}
	}
	for _, h := range r.AllowHosts {
		if HostMatches(h, ev.DstHost) {
			return "", false
		}
	}
	// 도메인 허용 목록이 있는데 목적지 도메인을 모르면(DNS 미확인 — trace_dns 미탑재 커널 등)
	// 도메인 기준을 판단할 수 없으므로 이 연결로는 격리하지 않는다(fail-open). trace_dns 가 뜨면 실제로 판단한다.
	if len(r.AllowHosts) > 0 && ev.DstHost == "" {
		return "", false
	}
	return "허용 목록 밖 외부 연결: " + dst, true
}
