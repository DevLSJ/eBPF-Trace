// Package model holds the types shared by ingestion, rules, API and the
// WebSocket stream. The JSON shape is the contract for frontend/src/lib/types.ts.
package model

import (
	"encoding/json"
	"strconv"
	"time"
)

// Kind: 어떤 시스템콜에서 온 이벤트인지
type Kind string

const (
	KindExec    Kind = "exec"    // trace_exec (execve)
	KindOpen    Kind = "open"    // trace_open (openat)
	KindConnect Kind = "connect" // trace_tcp --connect-only (sys_connect)
	// KindDNS: trace_dns 응답. 정책 평가 대상이 아니라 connect 이벤트의 목적지 도메인(DstHost)을 채우는 내부 이벤트.
	KindDNS Kind = "dns"
	// KindStart · KindExit: Docker 컨테이너 시작 · 종료 (docker-events). 정책 평가 대상이 아닌 내부 이벤트 —
	// 시작은 차단 이미지 확인, 종료는 설치 세션의 containerExitedAt 에 쓴다. ImageName 이 채워져 온다.
	KindStart Kind = "start"
	KindExit  Kind = "exit"
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
	// DstHost: 같은 컨테이너가 직전에 조회한 DNS 응답으로 알아낸 목적지 도메인 (모르면 빈 문자열)
	DstHost string `json:"dstHost,omitempty"` // connect
	// DNSTraced: 이 connect 이벤트가 올 때 trace_dns 가 실제로 돌고 있었는지. true 인데 DstHost 가 비면
	// 「도메인 조회 없는 IP 직접 연결」이고, false 면 판단 불가(fail-open). 가젯 소스는 trace_dns 로드 여부, mock 은 항상 true.
	// JSON 은 connect 에만, false 도 명시해서 낸다(W20, MarshalJSON). 필드가 없으면 옛 기록이다.
	DNSTraced bool `json:"dnsTraced,omitempty"` // connect
	// DNS 응답 (KindDNS 내부 이벤트 전용, JSON 으로 내보내지 않음)
	DNSName  string   `json:"-"`
	DNSAddrs []string `json:"-"`
	// dnsUnrecorded: 저장된 connect 기록에 dnsTraced 가 없었다(필드가 생기기 전 옛 기록). 다시 내보낼 때도 생략해
	// 화면이 「기록 없음」으로 보이게 한다. 이 프로세스가 만든 이벤트는 늘 false(= 기록 있음).
	dnsUnrecorded bool
}

// eventJSON: Event 의 기본 JSON 모양(메서드 없는 같은 구조) — MarshalJSON · UnmarshalJSON 재귀를 끊는다
type eventJSON Event

// MarshalJSON: dnsTraced 를 connect 이벤트에만, false 도 명시해서 낸다. 다른 종류에는 필드가 없다.
func (e Event) MarshalJSON() ([]byte, error) {
	w := struct {
		eventJSON
		DNSTraced *bool `json:"dnsTraced,omitempty"` // 바깥 필드가 안쪽(omitempty bool)을 가린다
	}{eventJSON: eventJSON(e)}
	if e.Kind == KindConnect && !e.dnsUnrecorded {
		v := e.DNSTraced
		w.DNSTraced = &v
	}
	return json.Marshal(w)
}

// UnmarshalJSON: 저장(PG jsonb · Redis)에서 읽을 때 connect 기록에 dnsTraced 가 없었는지 기억한다.
// 없으면 DNSTraced=false(규칙 평가는 fail-open 그대로)이고 다시 내보낼 때도 생략한다.
func (e *Event) UnmarshalJSON(b []byte) error {
	var w struct {
		eventJSON
		DNSTraced *bool `json:"dnsTraced"`
	}
	if err := json.Unmarshal(b, &w); err != nil {
		return err
	}
	*e = Event(w.eventJSON)
	e.DNSTraced = w.DNSTraced != nil && *w.DNSTraced
	e.dnsUnrecorded = e.Kind == KindConnect && w.DNSTraced == nil
	return nil
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
		d := e.DstIP + ":" + strconv.Itoa(int(e.DstPort))
		if e.DstHost != "" {
			d += " (" + e.DstHost + ")"
		}
		return d
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
	// CaseID · Install: 이 판정이 묶인 건 · 설치 세션 (없으면 null). 감사 로그 행에도 그대로 남는다.
	CaseID  *string     `json:"caseId"`
	Install *InstallRef `json:"install"`
}

// AuditEntry: 저장된 위반 판정 (PostgreSQL audit_log)
type AuditEntry struct {
	ID int64 `json:"id"`
	Verdict
}
