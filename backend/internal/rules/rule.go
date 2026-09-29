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
}

var idPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)

// Validate: 저장 전에 규칙이 평가 가능한지 확인한다.
func (r Rule) Validate() error {
	var errs []error
	if !idPattern.MatchString(r.ID) {
		errs = append(errs, fmt.Errorf("id %q: 소문자·숫자·하이픈 1~63자", r.ID))
	}
	if !r.Kind.Valid() {
		errs = append(errs, fmt.Errorf("kind %q: exec | open | connect", r.Kind))
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
	var conds int
	switch r.Kind {
	case model.KindExec:
		conds = len(r.DenyComms) + len(r.DenyArgs)
	case model.KindOpen:
		conds = len(r.DenyPaths)
	case model.KindConnect:
		conds = len(r.AllowPorts) + len(r.AllowCIDRs) + len(r.DenyPorts) + len(r.DenyCIDRs)
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
