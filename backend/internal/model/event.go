// Package model holds the types shared by ingestion, rules, API and the
// WebSocket stream. The JSON shape is the contract for frontend/src/lib/types.ts.
package model

import (
	"strconv"
	"time"
)

// Kind: 어떤 시스템콜에서 온 이벤트인지
type Kind string

const (
	KindExec    Kind = "exec"    // trace_exec (execve)
	KindOpen    Kind = "open"    // trace_open (openat)
	KindConnect Kind = "connect" // trace_tcp --connect-only (sys_connect)
)

var Kinds = []Kind{KindExec, KindOpen, KindConnect}

func (k Kind) Valid() bool {
	for _, v := range Kinds {
		if k == v {
			return true
		}
	}
	return false
}

// Action: 정책 위반 시 수행할 대응
type Action string

const (
	ActionAlert Action = "alert"
	ActionKill  Action = "kill"
)

func (a Action) Valid() bool { return a == ActionAlert || a == ActionKill }

// Event: 가젯 이벤트를 백엔드 내부 표준형으로 정규화한 것
type Event struct {
	Kind          Kind      `json:"kind"`
	Timestamp     time.Time `json:"timestamp"`
	ContainerID   string    `json:"containerId"`
	ContainerName string    `json:"containerName"`
	ImageName     string    `json:"imageName"`
	Comm          string    `json:"comm"`
	Pid           uint32    `json:"pid"`
	// Kind별 상세
	Args    string `json:"args,omitempty"`    // exec
	Path    string `json:"path,omitempty"`    // open (fname)
	DstIP   string `json:"dstIp,omitempty"`   // connect
	DstPort uint16 `json:"dstPort,omitempty"` // connect
}

// Detail: 이벤트 종류별 핵심 값 한 줄 (피드·감사로그 표시용)
func (e Event) Detail() string {
	switch e.Kind {
	case KindExec:
		if e.Args != "" {
			return e.Args
		}
		return e.Comm
	case KindOpen:
		return e.Path
	case KindConnect:
		return e.DstIP + ":" + strconv.Itoa(int(e.DstPort))
	}
	return ""
}

// Verdict: 규칙 평가 결과
type Verdict struct {
	Event   Event  `json:"event"`
	Matched bool   `json:"matched"`
	RuleID  string `json:"ruleId,omitempty"`
	Action  Action `json:"action,omitempty"`
	Reason  string `json:"reason,omitempty"`
	// DryRun: 정책이 kill이지만 dry-run(정책 또는 전역 ENFORCE_KILL=false)이라 종료하지 않음
	DryRun bool `json:"dryRun,omitempty"`
	// Enforced: 실제로 컨테이너 종료를 수행(성공)했는지
	Enforced bool `json:"enforced,omitempty"`
	// EnforceError: 종료 시도가 실패한 경우 사유
	EnforceError string `json:"enforceError,omitempty"`
}

// AuditEntry: 저장된 위반 판정 (PostgreSQL audit_log)
type AuditEntry struct {
	ID int64 `json:"id"`
	Verdict
}
