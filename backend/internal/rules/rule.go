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
	ID          string       `yaml:"id" json:"id"`
	Description string       `yaml:"description,omitempty" json:"description,omitempty"`
	Kind        model.Kind   `yaml:"kind" json:"kind"`
	Action      model.Action `yaml:"action" json:"action"`
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

// Validate: 저장 전에 규칙이 평가 가능한지 확인한다.
func (r Rule) Validate() error {
	var errs []error
	if !idPattern.MatchString(r.ID) {
		errs = append(errs, fmt.Errorf("id %q: 소문자·숫자·하이픈 1~63자", r.ID))
	}
	if !r.Kind.Valid() {
		errs = append(errs, fmt.Errorf("kind %q: exec | open | connect | dns", r.Kind))
	}
	if !r.Action.Valid() {
		errs = append(errs, fmt.Errorf("action %q: alert | kill", r.Action))
	}
	for _, g := range r.Containers {
		if _, err := path.Match(g, ""); err != nil {
			errs = append(errs, fmt.Errorf("containers %q: %w", g, err))
		}
	}
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
	return errors.Join(errs...)
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
