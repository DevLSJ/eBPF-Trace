// Package chat: AI 도우미(10/16 결정) — POST /api/chat 의 질문 → 의도 분류 → 읽기 전용 조회 → 한국어 사실 문장 → 로컬 Ollama 답 스트리밍.
//
// 틀리면 안 되는 값(판정 상태 · 관련 화면 링크)은 모델이 아니라 서버가 붙인다(실측: qwen2.5:3b 가 판정 상태를 지어냄).
// 모델에는 원시 JSON 이 아니라 한국어 사실 문장만 넣는다(실측: 원시 JSON 이면 「데이터 없음」으로 틀림).
// 질문 원문은 저장 · 로그하지 않는다(로그에는 의도 · 도구 · 소요 시간만).
package chat

import (
	"context"
	"errors"

	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/model"
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/rules"
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/store"
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/summary"
)

const (
	// MaxQuestion: 질문 길이 상한(글자 수, rune)
	MaxQuestion = 500
	// MaxHistory: 모델에 넘기는 대화 문맥(클라이언트가 보낸 것 중 최근 턴 수)
	MaxHistory = 6
	// maxTurnText: 문맥 한 턴의 글자 상한(앞 답이 길어도 프롬프트가 불지 않게)
	maxTurnText = 1000
)

var (
	ErrEmpty   = errors.New("질문이 비어 있습니다")
	ErrTooLong = errors.New("질문은 500자까지입니다")
	ErrBusy    = errors.New("다른 질문에 답하는 중입니다. 잠시 뒤 다시 물어 주세요")
)

// MsgModelDown: Ollama 가 꺼져 있거나 모델이 없을 때 error 이벤트 문구
const MsgModelDown = "AI 모델이 준비되지 않았습니다(OLLAMA_URL)"

// Request: POST /api/chat 본문
type Request struct {
	Question string `json:"question"`
	// Page: 지금 보는 화면 경로(「/installs」, 목업은 「#/installs?id=…」도 받는다) — 화면 설명 의도에 쓴다
	Page    string `json:"page"`
	History []Turn `json:"history"`
}

// Turn: 클라이언트가 보낸 앞 대화 한 턴. role 은 user | assistant 만 받는다
type Turn struct {
	Role string `json:"role"`
	Text string `json:"text"`
}

// Link: 관련 화면(서버가 붙임). href 는 React 경로(BrowserRouter) — 목업은 앞에 「#」를 붙여 쓴다
type Link struct {
	Label string `json:"label"`
	Href  string `json:"href"`
}

type Intent string

const (
	IntentPage      Intent = "page"      // 화면 설명 — 모델 없이 고정 문구
	IntentPending   Intent = "pending"   // 판정 대기 요약
	IntentWhy       Intent = "why"       // 컨테이너가 왜 격리 · 경고됐나
	IntentScan      Intent = "scan"      // 공급망 검사 결과
	IntentBlocklist Intent = "blocklist" // 차단 목록
	IntentPolicy    Intent = "policy"    // 정책 하나 설명
	IntentSummary   Intent = "summary"   // 기간 종합 · 가장 많이 걸린 정책
	IntentUsage     Intent = "usage"     // 사용법(명령 · 화면 조작) — 모델 없이 고정 문구
	IntentUnknown   Intent = "unknown"   // 규칙으로 못 고름 → 모델 도구 호출 1회
)

// 도구 이름(모델 도구 호출과 규칙 분류가 같은 이름을 쓴다)
const (
	ToolPending    = "pending_cases"
	ToolAudit      = "search_audit"
	ToolSummary    = "summary"
	ToolLatestScan = "latest_scan"
	ToolScan       = "scan"
	ToolBlocklist  = "blocklist"
	ToolPolicy     = "policy"
)

// CaseFact: 서버가 확정한 건의 판정 상태 — 모델이 무엇이라 말하든 화면은 이 값을 보인다
type CaseFact struct {
	ID           string           `json:"id"`
	Source       model.CaseSource `json:"source"`
	Label        string           `json:"label"`
	Container    string           `json:"container"`
	Level        model.Level      `json:"level"`
	LevelText    string           `json:"levelText"`
	State        model.CaseState  `json:"state"`
	Decision     model.Decision   `json:"decision"`
	DecisionText string           `json:"decisionText"`
	Violations   int              `json:"violations"`
	RuleIDs      []string         `json:"ruleIds"`
	Href         string           `json:"href"`
}

// ScanFact: 서버가 확정한 공급망 검사 결과
type ScanFact struct {
	ID           string   `json:"id"`
	Label        string   `json:"label"`
	Status       string   `json:"status"`
	Verdict      string   `json:"verdict,omitempty"`
	VerdictText  string   `json:"verdictText"`
	Score        *float64 `json:"score"`
	Threats      int      `json:"threats"`
	Capabilities int      `json:"capabilities"`
	Vulns        int      `json:"vulns"`
}

// Facts: facts 이벤트 — 조회 결과의 확정 값. Sentences 는 모델에 넣은 사실 문장 그대로(모델이 꺼져 있으면 화면이 이것을 답으로 보인다)
type Facts struct {
	Intent    Intent     `json:"intent"`
	Tool      string     `json:"tool,omitempty"`
	Status    string     `json:"status,omitempty"` // 한 줄 확정 상태(「판정 대기 2건」 · 「판정 대기」 · 「악성 의심」…)
	Sentences []string   `json:"sentences"`
	Cases     []CaseFact `json:"cases,omitempty"`
	Scan      *ScanFact  `json:"scan,omitempty"`
}

// --- 읽기 전용 의존성(인터페이스로 받아 테스트에서 바꿔 끼운다) ---

// Review: 건 · 차단 목록 읽기. main 의 reviewView(summary 용)가 이미 만족한다
type Review interface {
	Cases() []model.Case
	Blocklist() model.Blocklist
}

// Audit: 감사 로그 조회(store.AuditStore 의 읽기 쪽)
type Audit interface {
	QueryAudit(ctx context.Context, q store.AuditQuery) ([]model.AuditEntry, error)
}

// Summary: 기간 종합(summary.Service)
type Summary interface {
	Build(ctx context.Context, rng string) (summary.Summary, error)
}

// Scans: 공급망 검사 목록 · 한 건(scan.Service)
type Scans interface {
	List() []model.Scan
	Get(id string) (model.Scan, bool)
}

// Policies: 정책 목록(store.PolicyStore 의 읽기 쪽)
type Policies interface {
	ListPolicies(ctx context.Context) ([]rules.Rule, error)
}

// Emit: SSE 이벤트 하나를 보낸다(token · facts · links · done · error). 쓰기 실패(연결 끊김)면 error 를 돌려 생성을 멈춘다
type Emit func(event string, data any) error
