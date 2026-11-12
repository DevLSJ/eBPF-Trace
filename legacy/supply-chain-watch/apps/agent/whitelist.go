package main

import (
	_ "embed"
	"fmt"
	"net/netip"
	"path"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"
)

//go:embed whitelist.default.yaml
var defaultWhitelistYAML []byte

// Whitelist — 1차 필터 + 룰 분류 규칙 (docs/13 §6). gateway의 cmd.whitelist_update로 교체 가능(R-6).
type Whitelist struct {
	ServiceComms     []string `yaml:"service_comms" json:"service_comms"`
	ShellNames       []string `yaml:"shell_names" json:"shell_names"`
	ToolNames        []string `yaml:"tool_names" json:"tool_names"`
	BenignComms      []string `yaml:"benign_comms" json:"benign_comms"`
	AllowedDestCIDRs []string `yaml:"allowed_dest_cidrs" json:"allowed_dest_cidrs"`
	AllowedDestPorts []uint16 `yaml:"allowed_dest_ports" json:"allowed_dest_ports"`

	mu       sync.RWMutex
	service  map[string]bool
	shell    map[string]bool
	tool     map[string]bool
	benign   map[string]bool
	cidrs    []netip.Prefix
	ports    map[uint16]bool
}

func loadDefaultWhitelist() (*Whitelist, error) {
	var w Whitelist
	if err := yaml.Unmarshal(defaultWhitelistYAML, &w); err != nil {
		return nil, fmt.Errorf("parse default whitelist: %w", err)
	}
	if err := w.compile(); err != nil {
		return nil, err
	}
	return &w, nil
}

func set(items []string) map[string]bool {
	m := make(map[string]bool, len(items))
	for _, s := range items {
		m[s] = true
	}
	return m
}

func (w *Whitelist) compile() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.service = set(w.ServiceComms)
	w.shell = set(w.ShellNames)
	w.tool = set(w.ToolNames)
	w.benign = set(w.BenignComms)
	w.ports = make(map[uint16]bool, len(w.AllowedDestPorts))
	for _, p := range w.AllowedDestPorts {
		w.ports[p] = true
	}
	w.cidrs = w.cidrs[:0]
	for _, c := range w.AllowedDestCIDRs {
		pfx, err := netip.ParsePrefix(c)
		if err != nil {
			return fmt.Errorf("bad CIDR %q: %w", c, err)
		}
		w.cidrs = append(w.cidrs, pfx)
	}
	return nil
}

// replaceFrom — gateway 동적 갱신본의 설정 필드를 복사하고 다시 컴파일한다(뮤텍스는 복사하지 않음).
func (w *Whitelist) replaceFrom(src *Whitelist) error {
	w.mu.Lock()
	w.ServiceComms = src.ServiceComms
	w.ShellNames = src.ShellNames
	w.ToolNames = src.ToolNames
	w.BenignComms = src.BenignComms
	w.AllowedDestCIDRs = src.AllowedDestCIDRs
	w.AllowedDestPorts = src.AllowedDestPorts
	w.mu.Unlock()
	return w.compile()
}

func base(filename string) string { return path.Base(filename) }

// classifyExec: EXEC 이벤트의 룰 ID를 반환한다. 빈 문자열이면 양성(전송 안 함).
func (w *Whitelist) classifyExec(comm, filename string) string {
	w.mu.RLock()
	defer w.mu.RUnlock()
	b := base(filename)
	switch {
	case w.shell[b] && w.service[comm]:
		return "PROC_CHAIN_SUSPECT" // 앱 런타임이 셸을 스폰
	case w.tool[b]:
		return "TOOL_EXEC_IN_CONTAINER" // curl/nc 등 공격 도구 실행
	case strings.HasPrefix(filename, "/tmp/") || strings.HasPrefix(filename, "/dev/shm/"):
		return "TMP_EXEC"
	default:
		return "" // 양성(런타임·헬스체크 등) → 버림
	}
}

// classifyConnect: CONN 이벤트의 룰 ID를 반환한다. 허용 목적지면 빈 문자열.
func (w *Whitelist) classifyConnect(dst netip.Addr, port uint16) string {
	w.mu.RLock()
	defer w.mu.RUnlock()
	if w.ports[port] {
		return ""
	}
	for _, pfx := range w.cidrs {
		if pfx.Contains(dst) {
			return ""
		}
	}
	return "NET_UNALLOWED_CONNECT"
}
