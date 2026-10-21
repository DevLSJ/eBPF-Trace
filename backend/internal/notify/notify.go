// Package notify 는 격리 · 경고 · 건 열림 · 제안 대기를 범용 웹훅(JSON POST)과 Slack incoming webhook 으로 보낸다.
//
// 호출자는 절대 막히지 않는다 — Notify 는 큐에 넣고 바로 돌아오고, 채널마다 하나의 워커가 순서대로 보낸다.
// 실패하면 지수 백오프(1s · 4s · 16s)로 3번 더 시도하고, 큐(256)가 차면 가장 오래된 것을 버리고 센다.
// 같은 컨테이너 · 같은 규칙의 위반 알림은 60초 안에 한 번만 보내고, 합쳐진 수를 다음 알림의 suppressed 에 넣는다.
//
// 다른 패키지는 이 패키지를 모른다 — main 에서 New 로 만들고 pipeline · review 에 Notifier 로 넘긴다.
package notify

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/model"
)

// Kind: 알림 종류 (JSON kind 값 그대로)
type Kind string

const (
	KindViolation       Kind = "violation"        // 격리 · 경고 (판정 한 건)
	KindCaseOpened      Kind = "case.opened"      // 건이 새로 열림
	KindProposalPending Kind = "proposal.pending" // 제안 초안이 적용 대기
	KindTest            Kind = "test"             // 「테스트 발송」
)

// Message: 채널에 보내는 한 건. 웹훅은 이 구조를 JSON 그대로 받고, Slack 은 Title · Text · Link 로 블록을 만든다.
// Link 는 대시보드 경로("/installs?id=…")로 두면 보낼 때 PUBLIC_URL 을 앞에 붙인다.
type Message struct {
	Kind  Kind      `json:"kind"`
	At    time.Time `json:"at"`
	Title string    `json:"title"`
	Text  string    `json:"text,omitempty"`
	Link  string    `json:"link,omitempty"`
	// Suppressed: 이 알림 앞에서 디바운스로 합쳐진(보내지 않은) 같은 컨테이너 · 규칙의 위반 수
	Suppressed int `json:"suppressed,omitempty"`

	Violation *Violation       `json:"violation,omitempty"`
	Case      *CaseOpened      `json:"case,omitempty"`
	Proposal  *ProposalPending `json:"proposal,omitempty"`
}

// Violation: 격리 · 경고 상세
type Violation struct {
	Container   string    `json:"container"`
	ContainerID string    `json:"containerId,omitempty"`
	Image       string    `json:"image,omitempty"`
	RuleID      string    `json:"ruleId"`
	Verdict     string    `json:"verdict"` // kill | alert | dry-run
	Reason      string    `json:"reason,omitempty"`
	Detail      string    `json:"detail,omitempty"` // 이벤트 핵심 값 한 줄 (명령 · 경로 · 목적지)
	At          time.Time `json:"at"`
	CaseID      string    `json:"caseId,omitempty"`
	InstallID   string    `json:"installId,omitempty"`
	// EnforceError: kill 을 시도했으나 실패한 사유 (있을 때만)
	EnforceError string `json:"enforceError,omitempty"`
}

// CaseOpened: 건 열림 상세
type CaseOpened struct {
	ID         string           `json:"id"`
	Source     model.CaseSource `json:"source"` // install | runtime | scan
	Label      string           `json:"label"`
	Container  string           `json:"container,omitempty"`
	Image      string           `json:"image,omitempty"`
	Level      model.Level      `json:"level,omitempty"`
	Violations int              `json:"violations"`
	RuleIDs    []string         `json:"ruleIds,omitempty"`
}

// ProposalPending: 제안 대기 상세
type ProposalPending struct {
	ID       string         `json:"id"`
	CaseID   string         `json:"caseId"`
	Decision model.Decision `json:"decision"` // malicious | false_positive
	Summary  string         `json:"summary"`
	Changes  int            `json:"changes"`
}

// Notifier: pipeline · review 가 의존하는 최소 인터페이스. 호출은 즉시 돌아온다(비동기).
type Notifier interface {
	Notify(ctx context.Context, m Message)
}

// ChannelStatus: 채널 하나의 집계
type ChannelStatus struct {
	Name      string     `json:"name"` // webhook | slack
	Host      string     `json:"host"` // URL 의 호스트만 (토큰 · 경로는 내보내지 않는다)
	Sent      int64      `json:"sent"`
	Failed    int64      `json:"failed"` // 재시도까지 모두 실패해 포기한 수
	Dropped   int64      `json:"dropped"`
	LastError string     `json:"lastError,omitempty"`
	LastAt    *time.Time `json:"lastAt,omitempty"` // 마지막으로 성공한 시각
	Queued    int        `json:"queued"`
}

// Status: /api/info 와 「서버 설정」 화면에 쓰는 값
type Status struct {
	Enabled    bool            `json:"enabled"`
	Channels   []ChannelStatus `json:"channels"`
	Sent       int64           `json:"sent"`
	Failed     int64           `json:"failed"`
	Dropped    int64           `json:"dropped"`
	Suppressed int64           `json:"suppressed"` // 디바운스로 보내지 않은 위반 수 누계
	LastError  string          `json:"lastError,omitempty"`
}

// Nop: 비활성 구현 — 아무것도 하지 않는다.
type Nop struct{}

func (Nop) Notify(context.Context, Message) {}
func (Nop) Status() Status                  { return Status{Enabled: false, Channels: []ChannelStatus{}} }

// ── 메시지 만들기 ───────────────────────────────────────────

// VerdictLabel: kill | alert | dry-run
func VerdictLabel(v model.Verdict) string {
	switch {
	case v.Action == model.ActionKill && v.DryRun:
		return "dry-run"
	case v.Action == model.ActionKill:
		return "kill"
	default:
		return "alert"
	}
}

// FromVerdict: 위반 판정 → violation 메시지. Matched 가 아니면 보낼 것이 없으므로 ok=false.
func FromVerdict(v model.Verdict) (Message, bool) {
	if !v.Matched {
		return Message{}, false
	}
	ev := v.Event
	label := VerdictLabel(v)
	head := map[string]string{"kill": "격리", "alert": "경고", "dry-run": "격리 대상(dry-run)"}[label]
	if label == "kill" && !v.Enforced && v.EnforceError != "" {
		head = "격리 실패"
	}
	vio := &Violation{
		Container: ev.ContainerName, ContainerID: shortID(ev.ContainerID), Image: ev.ImageName,
		RuleID: v.RuleID, Verdict: label, Reason: v.Reason, Detail: ev.Detail(), At: ev.Timestamp,
		EnforceError: v.EnforceError,
	}
	link := "/topology?container=" + url.QueryEscape(ev.ContainerName)
	if v.Install != nil {
		vio.InstallID = v.Install.ID
		link = "/installs?id=" + url.QueryEscape(v.Install.ID)
	}
	if v.CaseID != nil {
		vio.CaseID = *v.CaseID
	}
	text := fmt.Sprintf("규칙 %s · %s", v.RuleID, v.Reason)
	if d := ev.Detail(); d != "" {
		text += "\n" + string(ev.Kind) + ": " + d
	}
	if v.EnforceError != "" {
		text += "\n종료 실패: " + v.EnforceError
	}
	return Message{
		Kind: KindViolation, At: ev.Timestamp,
		Title: fmt.Sprintf("[SupplyGuard] %s: %s", head, ev.ContainerName),
		Text:  text, Link: link, Violation: vio,
	}, true
}

// FromCase: 건 열림 → case.opened 메시지
func FromCase(c model.Case) Message {
	link := "/topology?container=" + url.QueryEscape(c.Container)
	switch {
	case c.Source == model.CaseInstall && c.InstallID != nil:
		link = "/installs?id=" + url.QueryEscape(*c.InstallID)
	case c.Source == model.CaseScan && c.ScanID != nil:
		link = "/scans?id=" + url.QueryEscape(*c.ScanID)
	}
	src := map[model.CaseSource]string{model.CaseInstall: "설치", model.CaseRuntime: "런타임", model.CaseScan: "공급망 검사"}[c.Source]
	return Message{
		Kind: KindCaseOpened, At: c.OpenedAt,
		Title: fmt.Sprintf("[SupplyGuard] 건 열림(%s): %s", src, c.Label),
		Text:  fmt.Sprintf("건 %s · 위반 %d건 · 규칙 %s", c.ID, c.Violations, strings.Join(c.RuleIDs, ", ")),
		Link:  link,
		Case: &CaseOpened{
			ID: c.ID, Source: c.Source, Label: c.Label, Container: c.Container, Image: c.Image,
			Level: c.Level, Violations: c.Violations, RuleIDs: c.RuleIDs,
		},
	}
}

// FromProposal: 제안 초안 → proposal.pending 메시지. summary 가 비면 변경 목록으로 만든다.
func FromProposal(p model.Proposal, summary string) Message {
	if summary == "" {
		summary = summarizeChanges(p)
	}
	kind := map[model.Decision]string{model.DecisionMalicious: "악성", model.DecisionFalsePositive: "오탐"}[p.Decision]
	return Message{
		Kind: KindProposalPending, At: p.CreatedAt,
		Title: fmt.Sprintf("[SupplyGuard] 제안 대기(%s): %s", kind, p.ID),
		Text:  fmt.Sprintf("건 %s · %s", p.CaseID, summary),
		Link:  "/policies?proposal=" + url.QueryEscape(p.ID),
		Proposal: &ProposalPending{
			ID: p.ID, CaseID: p.CaseID, Decision: p.Decision, Summary: summary, Changes: len(p.Changes),
		},
	}
}

// TestMessage: 「테스트 발송」
func TestMessage(now time.Time) Message {
	return Message{Kind: KindTest, At: now, Title: "[SupplyGuard] 테스트 발송", Text: "알림 채널 연결 확인", Link: "/"}
}

func summarizeChanges(p model.Proposal) string {
	if len(p.Changes) == 0 {
		return "자동 변경 없음"
	}
	parts := make([]string, 0, len(p.Changes))
	for _, ch := range p.Changes {
		switch ch.Op {
		case "block":
			parts = append(parts, fmt.Sprintf("%s 차단 %s", ch.List, ch.Value))
		case "except":
			parts = append(parts, fmt.Sprintf("%s 예외 %s=%s", ch.RuleID, ch.Field, ch.Value))
		default:
			parts = append(parts, ch.Op+" "+ch.Value)
		}
	}
	return strings.Join(parts, ", ")
}

func shortID(id string) string {
	if len(id) > 12 {
		return id[:12]
	}
	return id
}

// hostOf: 로그 · Status 에 쓰는 URL 의 호스트 부분 (토큰 · 경로 제외)
func hostOf(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return "(invalid)"
	}
	return u.Host
}
