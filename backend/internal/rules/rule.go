package rules

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/model"
)

// Rule: 정책 1건. 프론트 정책 편집기가 YAML/JSON 양쪽으로 다룬다.
type Rule struct {
	// ID · Action 은 규칙에 늘 있고(Validate), 연쇄 규칙의 단계(Steps)에만 없다 — omitempty 는 단계를 내보낼 때 빈 키를 빼려는 것
	ID          string       `yaml:"id,omitempty" json:"id,omitempty"`
	Description string       `yaml:"description,omitempty" json:"description,omitempty"`
	Kind        model.Kind   `yaml:"kind" json:"kind"`
	Action      model.Action `yaml:"action,omitempty" json:"action,omitempty"`
	// DryRun: kill 정책이라도 종료하지 않고 알림만 (오탐 시 컨테이너 보호)
	DryRun   bool `yaml:"dryRun,omitempty" json:"dryRun,omitempty"`
	Disabled bool `yaml:"disabled,omitempty" json:"disabled,omitempty"`
	// Containers: 적용 대상 컨테이너 이름·이미지 glob. 비우면 전체.
	Containers []string `yaml:"containers,omitempty" json:"containers,omitempty"`

	// exec
	DenyComms []string `yaml:"denyComms,omitempty" json:"denyComms,omitempty"`
	DenyArgs  []string `yaml:"denyArgs,omitempty" json:"denyArgs,omitempty"`
	// open
	DenyPaths  []string `yaml:"denyPaths,omitempty" json:"denyPaths,omitempty"`
	AllowPaths []string `yaml:"allowPaths,omitempty" json:"allowPaths,omitempty"`
	// connect — allow*(포트 또는 대역, OR)가 있으면 그 밖은 위반, deny* 는 항상 위반
	AllowPorts []uint16 `yaml:"allowPorts,omitempty" json:"allowPorts,omitempty"`
	AllowCIDRs []string `yaml:"allowCidrs,omitempty" json:"allowCidrs,omitempty"`
	DenyPorts  []uint16 `yaml:"denyPorts,omitempty" json:"denyPorts,omitempty"`
	DenyCIDRs  []string `yaml:"denyCidrs,omitempty" json:"denyCidrs,omitempty"`
	// 도메인: 같은 컨테이너의 DNS 응답(trace_dns)으로 알아낸 목적지 이름과 비교. "pypi.org" 는 pypi.org 와 *.pypi.org 에 맞는다.
	AllowHosts []string `yaml:"allowHosts,omitempty" json:"allowHosts,omitempty"`
	DenyHosts  []string `yaml:"denyHosts,omitempty" json:"denyHosts,omitempty"`
	// DirectIP: trace_dns 가 켜져 있는데 도메인 조회 없이 공인 IP 로 바로 붙는 연결(C2 · 유출에 흔함)의 처리.
	// "" = 옛 동작(allowHosts 가 있으면 fail-open) | allow = 통과 | alert · kill = 위반, 이 값이 규칙의 action 을 덮어쓴다.
	// trace_dns 가 꺼져 있으면(DNSTraced=false) 판단할 수 없으므로 언제나 fail-open 이다. connect 규칙에서만 의미가 있다.
	DirectIP string `yaml:"directIp,omitempty" json:"directIp,omitempty"`

	// dns(10/30) — 질의 이름은 allowHosts · denyHosts(접미사 일치, connect 와 같은 함수)로, 질의 유형은 denyQtypes(대문자)로,
	// 유출 패턴은 라벨 · 이름 길이 상한으로 본다. dns 규칙에서만 쓰고, dns 규칙에는 포트 · 대역 · directIp 를 쓰지 않는다.
	DenyQtypes     []string `yaml:"denyQtypes,omitempty" json:"denyQtypes,omitempty"`
	MaxNameLength  int      `yaml:"maxNameLength,omitempty" json:"maxNameLength,omitempty"`   // 1..253
	MaxLabelLength int      `yaml:"maxLabelLength,omitempty" json:"maxLabelLength,omitempty"` // 1..63

	// sequence(11/03) — 같은 컨테이너에서 windowSeconds 안에 Steps 가 순서대로 일어나면 걸린다(사이에 다른 이벤트 허용).
	// 단계는 kind(exec · open · connect · dns) + 그 kind 의 조건 필드만 쓴다(단일 규칙과 같은 조건 문법 · 같은 매칭 함수).
	// 최상위에는 조건 필드를 쓰지 않는다. sequence 가 아닌 규칙에는 둘 다 쓰지 않는다.
	WindowSeconds int    `yaml:"windowSeconds,omitempty" json:"windowSeconds,omitempty"` // 1..60
	Steps         []Rule `yaml:"steps,omitempty" json:"steps,omitempty"`
}

// DirectIP 값
const (
	DirectIPAllow = "allow"
	DirectIPAlert = "alert"
	DirectIPKill  = "kill"
)

var hostPattern = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$`)

// HostMatches: pattern 이 host 와 같거나 host 의 상위 도메인이면 true (대소문자·끝의 점 무시)
func HostMatches(pattern, host string) bool {
	h := strings.ToLower(strings.TrimSuffix(host, "."))
	pt := strings.ToLower(strings.TrimSuffix(pattern, "."))
	return h != "" && (h == pt || strings.HasSuffix(h, "."+pt))
}

var idPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)

// qtypePattern: denyQtypes 값 — IG 열거 그대로 대문자(A · AAAA · TXT · ALL …)
var qtypePattern = regexp.MustCompile(`^[A-Z][A-Z0-9]{0,15}$`)

// DNS 이름 길이 상한(RFC 1035): 이름 253자 · 라벨 63자
const (
	MaxDNSName  = 253
	MaxDNSLabel = 63
)

// 연쇄 규칙 범위(11/03)
const (
	MinSequenceSteps  = 2
	MaxSequenceSteps  = 5
	MaxSequenceWindow = 60 // 초
)

// Validate: 저장 전에 규칙이 평가 가능한지 확인한다.
func (r Rule) Validate() error {
	var errs []error
	if !idPattern.MatchString(r.ID) {
		errs = append(errs, fmt.Errorf("id %q: 소문자·숫자·하이픈 1~63자", r.ID))
	}
	// V1: 규칙 kind 는 이벤트 kind 4개 + sequence
	if !r.Kind.Valid() && r.Kind != model.KindSequence {
		errs = append(errs, fmt.Errorf("kind %q: exec | open | connect | dns | sequence", r.Kind))
	}
	if !r.Action.Valid() {
		errs = append(errs, fmt.Errorf("action %q: alert | kill", r.Action))
	}
	for _, g := range r.Containers {
		if _, err := path.Match(g, ""); err != nil {
			errs = append(errs, fmt.Errorf("containers %q: %w", g, err))
		}
	}
	if r.Kind == model.KindSequence {
		errs = append(errs, r.validateSequence()...)
		return errors.Join(errs...)
	}
	// V5: steps · windowSeconds 는 sequence 규칙에서만
	if len(r.Steps) > 0 || r.WindowSeconds != 0 {
		errs = append(errs, fmt.Errorf("steps · windowSeconds 는 sequence 규칙에서만"))
	}
	errs = append(errs, r.validateConditions()...)
	return errors.Join(errs...)
}

// validateSequence: 연쇄 규칙의 단계 수 · 창 · 최상위 조건 금지 · 각 단계(kind · 헤더 필드 금지 · 조건)를 본다.
func (r Rule) validateSequence() []error {
	var errs []error
	// V2: 단계 2~5개
	if n := len(r.Steps); n < MinSequenceSteps || n > MaxSequenceSteps {
		errs = append(errs, fmt.Errorf("steps: 단계 %d~%d개 (지금 %d개)", MinSequenceSteps, MaxSequenceSteps, n))
	}
	// V3: 창 1~60초 필수
	if r.WindowSeconds < 1 || r.WindowSeconds > MaxSequenceWindow {
		errs = append(errs, fmt.Errorf("windowSeconds %d: 1~%d", r.WindowSeconds, MaxSequenceWindow))
	}
	// V4: 조건은 단계에만
	if r.hasConditions() {
		errs = append(errs, fmt.Errorf("sequence 규칙 최상위에는 조건을 쓸 수 없음 — 조건은 steps 에"))
	}
	for i, s := range r.Steps {
		// V6: 단계 kind 는 이벤트 kind 4개만(중첩 sequence 금지)
		if !s.Kind.Valid() {
			errs = append(errs, fmt.Errorf("steps[%d]: kind %q: exec | open | connect | dns", i, s.Kind))
			continue
		}
		// V7: 단계에는 kind 와 조건만
		if s.ID != "" || s.Description != "" || s.Action != "" || s.DryRun || s.Disabled || len(s.Containers) > 0 || len(s.Steps) > 0 || s.WindowSeconds != 0 {
			errs = append(errs, fmt.Errorf("steps[%d]: 단계에는 kind 와 조건만 — id · description · action · dryRun · disabled · containers · steps · windowSeconds 는 쓸 수 없음", i))
		}
		// V8: 조건은 단일 규칙과 같은 검사(형식 · 「조건이 없음」)
		for _, err := range s.validateConditions() {
			errs = append(errs, fmt.Errorf("steps[%d]: %w", i, err))
		}
	}
	return errs
}

// hasConditions: 조건 필드(exec · open · connect · dns 어느 것이든)가 하나라도 있는지
func (r Rule) hasConditions() bool {
	return len(r.DenyComms)+len(r.DenyArgs)+len(r.DenyPaths)+len(r.AllowPaths)+
		len(r.AllowPorts)+len(r.AllowCIDRs)+len(r.DenyPorts)+len(r.DenyCIDRs)+len(r.AllowHosts)+len(r.DenyHosts)+
		len(r.DenyQtypes) > 0 || r.DirectIP != "" || r.MaxNameLength != 0 || r.MaxLabelLength != 0
}

// validateConditions: kind 별 조건 필드의 형식과 조건 유무 — 단일 규칙과 연쇄 규칙의 단계가 함께 쓴다.
func (r Rule) validateConditions() []error {
	var errs []error
	for _, c := range append(append([]string{}, r.AllowCIDRs...), r.DenyCIDRs...) {
		if _, err := parsePrefix(c); err != nil {
			errs = append(errs, fmt.Errorf("cidr %q: %w", c, err))
		}
	}
	for _, h := range append(append([]string{}, r.AllowHosts...), r.DenyHosts...) {
		if !hostPattern.MatchString(strings.ToLower(strings.TrimSuffix(h, "."))) {
			errs = append(errs, fmt.Errorf("host %q: 도메인 이름 형식이 아님", h))
		}
	}
	switch r.DirectIP {
	case "", DirectIPAllow, DirectIPAlert, DirectIPKill:
	default:
		errs = append(errs, fmt.Errorf("directIp %q: allow | alert | kill (또는 비움)", r.DirectIP))
	}
	for _, q := range r.DenyQtypes {
		if !qtypePattern.MatchString(q) {
			errs = append(errs, fmt.Errorf("denyQtypes %q: 대문자 질의 유형(A · AAAA · TXT · ALL …)", q))
		}
	}
	if r.MaxNameLength < 0 || r.MaxNameLength > MaxDNSName {
		errs = append(errs, fmt.Errorf("maxNameLength %d: 1~%d", r.MaxNameLength, MaxDNSName))
	}
	if r.MaxLabelLength < 0 || r.MaxLabelLength > MaxDNSLabel {
		errs = append(errs, fmt.Errorf("maxLabelLength %d: 1~%d", r.MaxLabelLength, MaxDNSLabel))
	}
	dnsOnly := len(r.DenyQtypes) + r.MaxNameLength + r.MaxLabelLength
	if r.Kind == model.KindDNS {
		if len(r.AllowPorts)+len(r.AllowCIDRs)+len(r.DenyPorts)+len(r.DenyCIDRs) > 0 || r.DirectIP != "" {
			errs = append(errs, fmt.Errorf("dns 규칙에는 포트 · 대역 · directIp 조건을 쓸 수 없음"))
		}
	} else if dnsOnly != 0 {
		errs = append(errs, fmt.Errorf("denyQtypes · maxNameLength · maxLabelLength 는 dns 규칙에서만"))
	}
	var conds int
	switch r.Kind {
	case model.KindExec:
		conds = len(r.DenyComms) + len(r.DenyArgs)
	case model.KindOpen:
		conds = len(r.DenyPaths)
	case model.KindConnect:
		conds = len(r.AllowPorts) + len(r.AllowCIDRs) + len(r.DenyPorts) + len(r.DenyCIDRs) + len(r.AllowHosts) + len(r.DenyHosts)
		if r.DirectIP != "" {
			conds++ // 직접 IP 연결 처리 자체가 조건 하나
		}
	case model.KindDNS:
		conds = len(r.AllowHosts) + len(r.DenyHosts) + len(r.DenyQtypes)
		if r.MaxNameLength > 0 {
			conds++
		}
		if r.MaxLabelLength > 0 {
			conds++
		}
	}
	if r.Kind.Valid() && conds == 0 {
		errs = append(errs, fmt.Errorf("%s 규칙에 조건이 없음", r.Kind))
	}
	return errs
}

// parsePrefix: "10.0.0.0/8" 또는 단일 IP "1.2.3.4"를 받는다.
func parsePrefix(s string) (netip.Prefix, error) {
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		return p.Masked(), err
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, err
	}
	return netip.PrefixFrom(a, a.BitLen()), nil
}

type policyFile struct {
	Rules []Rule `yaml:"rules"`
}

// LoadFile: 기본 정책 YAML(policies/default.yaml)을 읽는다.
func LoadFile(p string) ([]Rule, error) {
	b, err := os.ReadFile(p)
	if err != nil {
		return nil, err
	}
	return ParseYAML(b)
}

func ParseYAML(b []byte) ([]Rule, error) {
	var f policyFile
	if err := yaml.Unmarshal(b, &f); err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	for _, r := range f.Rules {
		if err := r.Validate(); err != nil {
			return nil, fmt.Errorf("rule %q: %w", r.ID, err)
		}
		if seen[r.ID] {
			return nil, fmt.Errorf("rule %q: 중복 id", r.ID)
		}
		seen[r.ID] = true
	}
	return f.Rules, nil
}

// SystemBlocklistHosts: 차단 목록의 도메인으로 만들어지는 시스템 규칙 id (connect · kill · denyHosts).
// 저장소에 두지 않고 엔진을 리로드할 때마다 차단 목록에서 합성한다. 정책 API 로 만들거나 고치거나 지울 수 없다(409).
const SystemBlocklistHosts = "blocklist-hosts"

// IsSystemRule: 정책 API 로 다룰 수 없는 규칙인지
func IsSystemRule(id string) bool { return id == SystemBlocklistHosts }

// BlocklistHostsRule: 차단 도메인 목록으로 시스템 규칙을 만든다. 목록이 비면 규칙도 없다(조건 없는 규칙은 무효).
func BlocklistHostsRule(hosts []string) (Rule, bool) {
	if len(hosts) == 0 {
		return Rule{}, false
	}
	return Rule{
		ID:          SystemBlocklistHosts,
		Description: "차단 목록에서 관리 — 악성 판정으로 차단한 도메인",
		Kind:        model.KindConnect,
		Action:      model.ActionKill,
		DenyHosts:   append([]string(nil), hosts...),
	}, true
}

// ValidHost: allowHosts · denyHosts 에 넣을 수 있는 도메인 이름인지
func ValidHost(h string) bool {
	return hostPattern.MatchString(strings.ToLower(strings.TrimSuffix(h, ".")))
}

// ValidCIDR: allowCidrs · denyCidrs 값 형식인지
func ValidCIDR(s string) bool {
	_, err := parsePrefix(s)
	return err == nil
}
