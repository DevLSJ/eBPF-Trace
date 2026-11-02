package model

import (
	"slices"
	"time"
)

// 설치 세션 · 건 · 제안 · 차단 목록 · 변경 이력 — Claude Docs 「API 계약」 탭의 데이터 모양 그대로.
// nullable 값은 포인터로 두어 JSON 에 null 로 나간다.

// RuleBlockedImage: 차단 이미지로 시작한 컨테이너를 격리한 판정의 규칙 id (정책 규칙이 아니라 차단 목록에서 온다)
const RuleBlockedImage = "blocked-image"

// Level: 탐지 결과(화면 표기) — normal · alert · held(격리 대상, 종료 안 함) · killed(격리됨)
type Level string

const (
	LevelNormal Level = "normal"
	LevelAlert  Level = "alert"
	LevelHeld   Level = "held"
	LevelKilled Level = "killed"
)

func (l Level) Rank() int {
	switch l {
	case LevelAlert:
		return 1
	case LevelHeld:
		return 2
	case LevelKilled:
		return 3
	}
	return 0
}

// LevelOf: 저장 · 전송된 판정의 탐지 결과 (목업 levelOf 와 같은 규칙)
func LevelOf(v Verdict) Level {
	switch {
	case !v.Matched:
		return LevelNormal
	case v.Action != ActionKill:
		return LevelAlert
	case v.Enforced:
		return LevelKilled
	default:
		return LevelHeld
	}
}

// InstallRef: 감사 로그 행 · 판정에 붙는 설치 세션 표시
type InstallRef struct {
	ID    string `json:"id"`
	Label string `json:"label"`
}

type InstallStatus string

const (
	InstallRunning  InstallStatus = "running"
	InstallPassed   InstallStatus = "passed"
	InstallIsolated InstallStatus = "isolated"
	InstallWarned   InstallStatus = "warned"
	InstallFailed   InstallStatus = "failed"
	InstallUnknown  InstallStatus = "unknown"
	InstallRefused  InstallStatus = "refused"
)

func (s InstallStatus) Valid() bool {
	switch s {
	case InstallRunning, InstallPassed, InstallIsolated, InstallWarned, InstallFailed, InstallUnknown, InstallRefused:
		return true
	}
	return false
}

// Managers: sg-install 이 지원하는 패키지 매니저
var Managers = []string{"pip", "npm", "cargo"}

func ValidManager(m string) bool {
	for _, x := range Managers {
		if m == x {
			return true
		}
	}
	return false
}

type BlockRef struct {
	List  string `json:"list"`
	Value string `json:"value"`
}

// ViolationCount: 같은 위반(규칙 · 종류 · 상세)을 묶은 것 — Verdict 그대로 + count
type ViolationCount struct {
	Verdict
	Count int `json:"count"`
}

type HostActivity struct {
	Host  string `json:"host"`
	IP    string `json:"ip"`
	Port  uint16 `json:"port"`
	Count int    `json:"count"`
	Level Level  `json:"level"`
}

type ProgramActivity struct {
	Comm  string `json:"comm"`
	Args  string `json:"args"`
	Count int    `json:"count"`
	Level Level  `json:"level"`
}

type Activity struct {
	Kinds    map[Kind]int      `json:"kinds"`
	Hosts    []HostActivity    `json:"hosts"`
	Programs []ProgramActivity `json:"programs"`
}

type InstallSession struct {
	ID                string           `json:"id"`
	Manager           string           `json:"manager"`
	Packages          []string         `json:"packages"`
	Container         string           `json:"container"`
	ContainerID       string           `json:"containerId"`
	Image             string           `json:"image"`
	StartedAt         time.Time        `json:"startedAt"`
	FinishedAt        *time.Time       `json:"finishedAt"`
	ExitCode          *int             `json:"exitCode"`
	ContainerExitedAt *time.Time       `json:"containerExitedAt"`
	Status            InstallStatus    `json:"status"`
	RefusedBy         *BlockRef        `json:"refusedBy"`
	CaseID            *string          `json:"caseId"`
	Violations        []ViolationCount `json:"violations"`
	// ViolationCount: 위반 수 합(violations 의 count 합) — 목록 화면용
	ViolationCount int      `json:"violationCount"`
	Activity       Activity `json:"activity"`
	// Demo: 시연 실행(POST /api/demo/run, 10/30)이 만든 세션
	Demo bool `json:"demo,omitempty"`
	// Isolation: 격리 세션의 첫 kill 판정(감사 로그 id · 타임라인, 10/30). 격리되지 않았으면 없다
	Isolation *Isolation `json:"isolation,omitempty"`
}

// Isolation: 격리 타임라인이 붙는 곳 — 설치 세션 · 건의 첫 실제 kill 판정
type Isolation struct {
	AuditID  int64    `json:"auditId"`
	Timeline Timeline `json:"timeline"`
}

func (i *Isolation) clone() *Isolation {
	if i == nil {
		return nil
	}
	c := *i
	c.Timeline = *i.Timeline.Clone()
	return &c
}

func (s InstallSession) Label() string {
	l := s.Manager
	for _, p := range s.Packages {
		l += " " + p
	}
	return l
}

// Clone: 잠금 밖에서 JSON 으로 내보내거나 저장할 사본
func (s InstallSession) Clone() InstallSession {
	c := s
	c.Packages = slices.Clone(s.Packages)
	c.Violations = slices.Clone(s.Violations)
	c.Activity.Kinds = make(map[Kind]int, len(s.Activity.Kinds))
	for k, v := range s.Activity.Kinds {
		c.Activity.Kinds[k] = v
	}
	c.Activity.Hosts = slices.Clone(s.Activity.Hosts)
	c.Activity.Programs = slices.Clone(s.Activity.Programs)
	c.Isolation = s.Isolation.clone()
	return c
}

type CaseSource string

const (
	CaseInstall CaseSource = "install"
	CaseRuntime CaseSource = "runtime"
	CaseScan    CaseSource = "scan" // 공급망 검사에서 「차단 목록에 올리기」(10/16)
)

type CaseState string

const (
	CaseOpen    CaseState = "open"
	CaseDecided CaseState = "decided"
	CaseClosed  CaseState = "closed"
)

type Decision string

const (
	DecisionPending       Decision = "pending"
	DecisionMalicious     Decision = "malicious"
	DecisionFalsePositive Decision = "false_positive"
)

type Case struct {
	ID         string     `json:"id"`
	Source     CaseSource `json:"source"`
	InstallID  *string    `json:"installId"`
	ScanID     *string    `json:"scanId,omitempty"`
	Container  string     `json:"container"`
	Label      string     `json:"label"` // 화면 표기: 설치 건 = 입력 그대로(「pip ./reqeusts」), 런타임 건 = 컨테이너 이름
	Image      string     `json:"image"`
	Package    string     `json:"package,omitempty"` // 차단 목록 키(pip:reqeusts) — runtime 건은 없음
	OpenedAt   time.Time  `json:"openedAt"`
	Level      Level      `json:"level"`
	Violations int        `json:"violations"`
	RuleIDs    []string   `json:"ruleIds"`
	State      CaseState  `json:"state"`
	Decision   Decision   `json:"decision"`
	DecidedAt  *time.Time `json:"decidedAt"`
	DecidedBy  *string    `json:"decidedBy"`
	Note       string     `json:"note"`
	ProposalID *string    `json:"proposalId"`
	ClosedAt   *time.Time `json:"closedAt"`
	// Isolation: 이 건의 첫 실제 kill 판정(감사 로그 id · 타임라인, 10/30). 격리가 없었으면 없다
	Isolation *Isolation `json:"isolation,omitempty"`
}

// CaseRecord: 저장용 — 건 + 제안을 만들 때 쓰는 위반 증거(화면 응답에는 Case 만 나간다)
type CaseRecord struct {
	Case     Case             `json:"case"`
	Evidence []ViolationCount `json:"evidence"`
}

func (r CaseRecord) Clone() CaseRecord {
	c := r
	c.Case.RuleIDs = slices.Clone(r.Case.RuleIDs)
	c.Evidence = slices.Clone(r.Evidence)
	c.Case.Isolation = r.Case.Isolation.clone()
	return c
}

type ProposalState string

const (
	ProposalDraft     ProposalState = "draft"
	ProposalApplied   ProposalState = "applied"
	ProposalDiscarded ProposalState = "discarded"
)

// ProposalChange: {op:block, list, value} 또는 {op:except, ruleId, field, value}
type ProposalChange struct {
	Op     string `json:"op"`
	List   string `json:"list,omitempty"`
	RuleID string `json:"ruleId,omitempty"`
	Field  string `json:"field,omitempty"`
	Value  string `json:"value"`
}

type Proposal struct {
	ID        string           `json:"id"`
	CaseID    string           `json:"caseId"`
	Decision  Decision         `json:"decision"`
	State     ProposalState    `json:"state"`
	CreatedAt time.Time        `json:"createdAt"`
	CreatedBy string           `json:"createdBy"`
	AppliedAt *time.Time       `json:"appliedAt"`
	AppliedBy *string          `json:"appliedBy"`
	Changes   []ProposalChange `json:"changes"`
	// Notes: 자동으로 만들지 못한 변경 안내 (예: 실행 규칙은 정책 탭에서 직접 수정)
	Notes []string `json:"notes"`
}

func (p Proposal) Clone() Proposal {
	c := p
	c.Changes = slices.Clone(p.Changes)
	c.Notes = slices.Clone(p.Notes)
	return c
}

// 차단 목록 이름
const (
	ListPackages = "packages"
	ListImages   = "images"
	ListHosts    = "hosts"
)

var BlockLists = []string{ListPackages, ListImages, ListHosts}

func ValidBlockList(l string) bool {
	return l == ListPackages || l == ListImages || l == ListHosts
}

type BlockEntry struct {
	List   string    `json:"-"`
	Value  string    `json:"value"`
	CaseID *string   `json:"caseId"`
	At     time.Time `json:"at"`
	By     string    `json:"by"`
}

type Blocklist struct {
	Packages []BlockEntry `json:"packages"`
	Images   []BlockEntry `json:"images"`
	Hosts    []BlockEntry `json:"hosts"`
}

type ChangeKind string

const (
	ChangeProposalApplied ChangeKind = "proposal_applied"
	ChangePolicyEdit      ChangeKind = "policy_edit"
	ChangePolicyReplace   ChangeKind = "policy_replace"
	// ChangeBlocklistRemove: DELETE /api/blocklist — 계약의 「차단 해제, Change 기록」
	ChangeBlocklistRemove ChangeKind = "blocklist_remove"
	// ChangeProposalDiscarded: POST /api/proposals/{id}/discard — 변경 없이 건 종결(W15, 사유를 남기려고 기록)
	ChangeProposalDiscarded ChangeKind = "proposal_discarded"
	// ChangeDemoRun: POST /api/demo/run — 시연 실행(10/30). 요약 「시연 실행: <scenario>」
	ChangeDemoRun ChangeKind = "demo_run"
)

// MaxReasonRunes: 적용 · 버림 · 차단 해제 사유(Change.reason)의 상한(문자 수, W15)
const MaxReasonRunes = 500

type Change struct {
	ID         string     `json:"id"`
	At         time.Time  `json:"at"`
	By         string     `json:"by"`
	Kind       ChangeKind `json:"kind"`
	CaseID     *string    `json:"caseId"`
	ProposalID *string    `json:"proposalId"`
	Summary    string     `json:"summary"`
	// Reason: 확인 대화상자의 사유(선택, 500자) — 적용 · 버림 · 차단 해제. 판정 사유는 건 메모(Case.note). 없으면 ""
	Reason string `json:"reason"`
}

// Osv: GET /api/osv 응답
type Osv struct {
	Ecosystem string    `json:"ecosystem"`
	Name      string    `json:"name"`
	Vulns     int       `json:"vulns"`
	IDs       []string  `json:"ids"`
	QueriedAt time.Time `json:"queriedAt"`
	Source    string    `json:"source"`
	Error     *string   `json:"error"`
}
