package review

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/model"
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/rules"
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/store"
)

// flakyStore: 저장소 커밋을 원하는 때에 실패시킨다 (적용 원자성 확인용)
type flakyStore struct {
	*store.Memory
	mu   sync.Mutex
	fail bool
}

func (f *flakyStore) setFail(v bool) {
	f.mu.Lock()
	f.fail = v
	f.mu.Unlock()
}

func (f *flakyStore) CommitReview(ctx context.Context, c store.ReviewCommit) error {
	f.mu.Lock()
	fail := f.fail
	f.mu.Unlock()
	if fail {
		return errors.New("db down")
	}
	return f.Memory.CommitReview(ctx, c)
}

type fakeHub struct {
	mu    sync.Mutex
	cases []model.Case
}

func (h *fakeHub) Broadcast(t string, d any) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if c, ok := d.(model.Case); ok && t == "case" {
		h.cases = append(h.cases, c)
	}
}

var testRules = []rules.Rule{
	{ID: "sensitive-files", Kind: model.KindOpen, Action: model.ActionKill, DenyPaths: []string{"/etc/shadow", "/root/.ssh/"}},
	{ID: "no-shell-download", Kind: model.KindExec, Action: model.ActionKill, DenyComms: []string{"curl"}},
	{ID: "reverse-shell-ports", Kind: model.KindConnect, Action: model.ActionKill, DenyPorts: []uint16{4444}},
	{ID: "egress-allowlist", Kind: model.KindConnect, Action: model.ActionAlert, AllowPorts: []uint16{80, 443, 53},
		AllowCIDRs: []string{"10.0.0.0/8"}},
	{ID: "sandbox-egress", Kind: model.KindConnect, Action: model.ActionKill, Containers: []string{"sg-install-*"},
		AllowHosts: []string{"pypi.org", "pythonhosted.org"}},
}

type env struct {
	svc    *Service
	store  *flakyStore
	engine *rules.Engine
	hub    *fakeHub
	now    time.Time
}

func newEnv(t *testing.T) *env {
	t.Helper()
	mem := store.NewMemory()
	if err := mem.ReplacePolicies(t.Context(), testRules); err != nil {
		t.Fatal(err)
	}
	e := &env{store: &flakyStore{Memory: mem}, engine: rules.New(testRules), hub: &fakeHub{},
		now: time.Date(2026, 10, 15, 9, 0, 0, 0, time.UTC)}
	e.svc = New(Options{Store: e.store, Policies: mem, Audit: mem, Engine: e.engine, Hub: e.hub,
		EnforceKill: true, Now: func() time.Time { return e.now }})
	if err := e.svc.Load(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.Reload(t.Context()); err != nil {
		t.Fatal(err)
	}
	return e
}

const sandboxCID = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

// observe: 파이프라인처럼 엔진 평가 → (kill 이면 격리됨으로 표시) → Observe → 감사 로그 저장
func (e *env) observe(t *testing.T, ev model.Event) model.Verdict {
	t.Helper()
	if ev.Timestamp.IsZero() {
		ev.Timestamp = e.now
	}
	v := e.engine.Evaluate(ev)
	if v.Matched && v.Action == model.ActionKill && !v.DryRun {
		v.Enforced = true
	}
	e.svc.Observe(&v)
	if v.Matched {
		if _, err := e.store.SaveAudit(t.Context(), v); err != nil {
			t.Fatal(err)
		}
	}
	return v
}

func sandboxEv(container string) model.Event {
	return model.Event{ContainerID: sandboxCID, ContainerName: container, ImageName: "python:3.12-slim", Comm: "python3"}
}

// maliciousInstallCase: 악성 설치 세션 하나 → 건 1개 → 악성 판정 → 제안 초안
func (e *env) maliciousInstallCase(t *testing.T) (model.Case, model.Proposal) {
	t.Helper()
	ctx := t.Context()
	s, err := e.svc.StartInstall(ctx, StartInput{Manager: "pip", Packages: []string{"./reqeusts"}, Container: "sg-install-pip-1", Image: "python:3.12-slim"})
	if err != nil {
		t.Fatal(err)
	}
	ev := sandboxEv(s.Container)
	ev.Kind, ev.DstIP, ev.DstPort, ev.DstHost = model.KindConnect, "203.0.113.7", 8081, "cdn.reqeusts-update.test"
	v := e.observe(t, ev)
	if v.CaseID == nil {
		t.Fatalf("violation must open a case: %+v", v)
	}
	c, p, err := e.svc.Decide(ctx, *v.CaseID, model.DecisionMalicious, "")
	if err != nil {
		t.Fatal(err)
	}
	return c, p
}

func ruleByID(rs []rules.Rule, id string) (rules.Rule, bool) {
	for _, r := range rs {
		if r.ID == id {
			return r, true
		}
	}
	return rules.Rule{}, false
}
