// Package review keeps install sessions, cases (사람이 판정할 묶음), proposals,
// the blocklist and the change history — the 「API 계약」 workflow behind
// /api/installs · /api/cases · /api/proposals · /api/blocklist · /api/changes.
//
// 메모리 캐시가 기준이고 저장소(Memory · Postgres)에 써 둔다. 상태 변경은 잠금 하나(mu)로 직렬화한다.
// 화면 · CLI 의 쓰기는 저장소 커밋이 성공한 뒤에만 캐시에 반영한다(모두 되거나 모두 안 됨).
// 파이프라인이 매 이벤트마다 부르는 Observe 는 캐시만 바꾸고, 저장은 Run 의 주기적 flush 가 맡는다.
package review

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/dockerapi"
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/model"
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/notify"
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/rules"
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/store"
)

// Broadcaster: ws.Hub — {type:"case", data: Case}
type Broadcaster interface {
	Broadcast(msgType string, data any)
}

type Options struct {
	Store    store.ReviewStore
	Policies store.PolicyStore
	Audit    store.AuditStore
	Engine   *rules.Engine
	Hub      Broadcaster
	// Actor: 처리자 이름 (ACTOR_NAME, 기본 「보안 담당자」)
	Actor string
	// ActorFrom: 요청자 이름 (로그인 계정 표시 이름 · CLI 는 "cli"). nil 이거나 빈 값이면 Actor
	ActorFrom func(context.Context) string
	// EnforceKill: 미리보기에서 kill 판정을 killed(격리됨) / held(격리 대상)로 나눌 때 쓴다
	EnforceKill bool
	Now         func() time.Time
	// OnInstallStart: 설치 세션이 기록된 뒤 부른다 (mock 이벤트 소스가 설치를 흉내 낼 때)
	OnInstallStart func(model.InstallSession)
	// FlushInterval: Observe 로 바뀐 세션 · 건을 저장소에 쓰는 주기 (기본 1초)
	FlushInterval time.Duration
	// Notifier: 외부 알림(10/20). 판정 뒤 제안 대기 · 공급망 검사 건 열림을 보낸다. 설치 · 런타임 위반은 pipeline 이 위반 알림으로 보낸다(중복 방지). nil 이면 안 보냄
	Notifier notify.Notifier
	// Containers: 지금 실행 중인 컨테이너(dockerapi.Client). 판정 미리보기의 「같은 이미지 컨테이너 N개」(W15). nil 이면 수를 모른다고 표시
	Containers ContainerLister
}

// ContainerLister: dockerapi.Client.List
type ContainerLister interface {
	List(ctx context.Context) ([]dockerapi.Container, error)
}

// 계약 상수
const (
	SandboxPrefix   = "sg-install-"
	UnknownAfter    = 10 * time.Minute
	DefaultActor    = "보안 담당자"
	maxViolations   = 200 // 세션당 서로 다른 위반 수
	maxEvidence     = 100 // 건당 서로 다른 위반 증거 수
	maxActivityRows = 200 // 세션당 호스트 · 프로그램 행 수
)

type Service struct {
	o Options

	wmu sync.Mutex // 저장소 쓰기 순서 (항상 wmu → mu 순으로 잡는다)
	mu  sync.Mutex

	installs    map[string]*model.InstallSession
	installIDs  []string          // 만든 순서
	byContainer map[string]string // 컨테이너 이름 → 세션 id

	cases   map[string]*model.CaseRecord
	caseIDs []string

	proposals   map[string]*model.Proposal
	proposalIDs []string

	blocklist []model.BlockEntry
	changes   []model.Change

	seq map[string]int // id 접두어 → 마지막 번호

	dirtyInstalls map[string]bool
	dirtyCases    map[string]bool
}

// actor: 이 요청의 처리자 — 판정 · 제안 작성 · 적용 · 차단 해제 · 정책 변경 기록에 남는다.
// 요청자(ActorFrom: 로그인 계정 표시 이름 · Bearer CLI 는 "cli")가 있으면 그 이름, 없으면 ACTOR_NAME
func (s *Service) actor(ctx context.Context) string {
	if s.o.ActorFrom != nil {
		if name := strings.TrimSpace(s.o.ActorFrom(ctx)); name != "" {
			return name
		}
	}
	return s.o.Actor
}

func New(o Options) *Service {
	if o.Now == nil {
		o.Now = func() time.Time { return time.Now().UTC() }
	}
	if strings.TrimSpace(o.Actor) == "" {
		o.Actor = DefaultActor
	}
	if o.FlushInterval <= 0 {
		o.FlushInterval = time.Second
	}
	return &Service{
		o:             o,
		installs:      map[string]*model.InstallSession{},
		byContainer:   map[string]string{},
		cases:         map[string]*model.CaseRecord{},
		proposals:     map[string]*model.Proposal{},
		seq:           map[string]int{},
		dirtyInstalls: map[string]bool{},
		dirtyCases:    map[string]bool{},
	}
}

// ── 오류 ───────────────────────────────────────────────

type ErrKind int

const (
	KindInvalid  ErrKind = iota + 1 // 400
	KindNotFound                    // 404
	KindConflict                    // 409
)

type Error struct {
	Kind ErrKind
	Msg  string
}

func (e *Error) Error() string { return e.Msg }

func invalid(f string, a ...any) error  { return &Error{KindInvalid, fmt.Sprintf(f, a...)} }
func notFound(f string, a ...any) error { return &Error{KindNotFound, fmt.Sprintf(f, a...)} }
func conflict(f string, a ...any) error { return &Error{KindConflict, fmt.Sprintf(f, a...)} }

// ErrorKind: API 가 상태 코드를 고를 때 쓴다 (0 = 서버 오류)
func ErrorKind(err error) ErrKind {
	var e *Error
	if errors.As(err, &e) {
		return e.Kind
	}
	return 0
}

// ── 시작 · 저장 ────────────────────────────────────────

// Load: 저장소에서 전체 상태를 읽어 캐시와 id 번호를 채운다. 엔진 리로드는 하지 않는다(Reload).
func (s *Service) Load(ctx context.Context) error {
	snap, err := s.o.Store.LoadReview(ctx)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, x := range snap.Installs {
		x := x.Clone()
		s.putInstall(&x)
		s.bump("ins", x.ID)
	}
	for _, x := range snap.Cases {
		x := x.Clone()
		s.putCase(&x)
		s.bump("case", x.Case.ID)
	}
	for _, x := range snap.Proposals {
		x := x.Clone()
		s.putProposal(&x)
		s.bump("prop", x.ID)
	}
	s.blocklist = snap.Blocklist
	s.changes = snap.Changes
	for _, c := range s.changes {
		s.bump("chg", c.ID)
	}
	return nil
}

func (s *Service) bump(prefix, id string) {
	n, err := strconv.Atoi(strings.TrimPrefix(id, prefix+"-"))
	if err == nil && n > s.seq[prefix] {
		s.seq[prefix] = n
	}
}

// nextID: 잠금 안에서. 커밋이 실패하면 releaseID 로 되돌린다.
func (s *Service) nextID(prefix string) string {
	s.seq[prefix]++
	return fmt.Sprintf("%s-%04d", prefix, s.seq[prefix])
}

func (s *Service) releaseID(prefix string) { s.seq[prefix]-- }

func (s *Service) putInstall(x *model.InstallSession) {
	if _, ok := s.installs[x.ID]; !ok {
		s.installIDs = append(s.installIDs, x.ID)
	}
	s.installs[x.ID] = x
	if x.Container != "" {
		s.byContainer[x.Container] = x.ID
	}
}

func (s *Service) putCase(x *model.CaseRecord) {
	if _, ok := s.cases[x.Case.ID]; !ok {
		s.caseIDs = append(s.caseIDs, x.Case.ID)
	}
	s.cases[x.Case.ID] = x
}

func (s *Service) putProposal(x *model.Proposal) {
	if _, ok := s.proposals[x.ID]; !ok {
		s.proposalIDs = append(s.proposalIDs, x.ID)
	}
	s.proposals[x.ID] = x
}

// Run: Observe 로 바뀐 세션 · 건을 주기적으로 저장한다. ctx 가 끝나면 마지막으로 한 번 더 쓴다.
func (s *Service) Run(ctx context.Context) {
	t := time.NewTicker(s.o.FlushInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			fctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			s.Flush(fctx)
			cancel()
			return
		case <-t.C:
			s.Flush(ctx)
		}
	}
}

// Flush: 밀린 세션 · 건 쓰기. 실패하면 다음 주기에 다시 쓴다.
func (s *Service) Flush(ctx context.Context) {
	s.wmu.Lock()
	defer s.wmu.Unlock()
	s.mu.Lock()
	var c store.ReviewCommit
	for id := range s.dirtyInstalls {
		c.Installs = append(c.Installs, s.installs[id].Clone())
	}
	for id := range s.dirtyCases {
		c.Cases = append(c.Cases, s.cases[id].Clone())
	}
	s.dirtyInstalls, s.dirtyCases = map[string]bool{}, map[string]bool{}
	s.mu.Unlock()
	if c.Empty() {
		return
	}
	if err := s.o.Store.CommitReview(ctx, c); err != nil {
		slog.Error("review flush", "err", err)
		s.mu.Lock()
		for _, x := range c.Installs {
			s.dirtyInstalls[x.ID] = true
		}
		for _, x := range c.Cases {
			s.dirtyCases[x.Case.ID] = true
		}
		s.mu.Unlock()
	}
}

// commitLocked: wmu · mu 를 잡은 상태에서 부른다. 같은 id 의 밀린 쓰기는 이번 커밋에 포함되므로 지운다.
func (s *Service) commitLocked(ctx context.Context, c store.ReviewCommit) error {
	if err := s.o.Store.CommitReview(ctx, c); err != nil {
		return err
	}
	for _, x := range c.Installs {
		delete(s.dirtyInstalls, x.ID)
	}
	for _, x := range c.Cases {
		delete(s.dirtyCases, x.Case.ID)
	}
	return nil
}

func (s *Service) lockWrite() func() {
	s.wmu.Lock()
	s.mu.Lock()
	return func() {
		s.mu.Unlock()
		s.wmu.Unlock()
	}
}

func (s *Service) broadcastCase(c *model.CaseRecord) {
	if s.o.Hub != nil {
		s.o.Hub.Broadcast("case", c.Case)
	}
}

func ptr[T any](v T) *T { return &v }

// cleanReason: 적용 · 버림 · 차단 해제 사유 — 앞뒤 공백을 떼고 500자(문자 수) 이하만
func cleanReason(r string) (string, error) {
	r = strings.TrimSpace(r)
	if utf8.RuneCountInString(r) > model.MaxReasonRunes {
		return "", invalid("reason: %d자 이하", model.MaxReasonRunes)
	}
	return r, nil
}
