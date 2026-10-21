package review

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/dockerapi"
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/model"
)

// W15 판정 미리보기: 저장 없이, Decide 가 만들 제안의 변경과 영향 요약을 돌려준다.

type fakeContainers struct {
	list []dockerapi.Container
	err  error
}

func (f fakeContainers) List(context.Context) ([]dockerapi.Container, error) { return f.list, f.err }

func effectOf(pv DecisionPreview, kind string) (Effect, bool) {
	for _, x := range pv.Effects {
		if x.Kind == kind {
			return x, true
		}
	}
	return Effect{}, false
}

// installCase: 악성 설치 세션 하나 → 열린 건(판정 전)
func (e *env) installCase(t *testing.T) model.Case {
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
		t.Fatal("violation must open a case")
	}
	c, _ := e.svc.GetCase(*v.CaseID)
	return c
}

// 악성: 미리보기의 changes · notes = Decide 가 만든 제안. 미리보기는 건 · 제안 · id 번호를 바꾸지 않는다.
func TestPreviewDecisionMaliciousMatchesDecide(t *testing.T) {
	e := newEnv(t)
	ctx := t.Context()
	c := e.installCase(t)

	pv, err := e.svc.PreviewDecision(ctx, c.ID, model.DecisionMalicious)
	if err != nil {
		t.Fatal(err)
	}
	if after, _ := e.svc.GetCase(c.ID); !reflect.DeepEqual(after, c) {
		t.Fatalf("preview must not change the case:\n%+v\n%+v", c, after)
	}
	if n := len(e.svc.ListProposals("")); n != 0 {
		t.Fatalf("preview must not create a proposal: %d", n)
	}
	if pv.CaseID != c.ID || pv.Decision != model.DecisionMalicious {
		t.Fatalf("preview head: %+v", pv)
	}
	want := []model.ProposalChange{
		{Op: "block", List: model.ListPackages, Value: "pip:reqeusts"},
		{Op: "block", List: model.ListHosts, Value: "cdn.reqeusts-update.test"},
	}
	if !reflect.DeepEqual(pv.Changes, want) {
		t.Fatalf("changes: %+v", pv.Changes)
	}
	bl, ok := effectOf(pv, EffectBlocklist)
	if !ok || bl.Count == nil || *bl.Count != 2 || !strings.Contains(bl.Text, "+2") || !strings.Contains(bl.Text, "패키지 1") || !strings.Contains(bl.Text, "도메인 1") {
		t.Fatalf("blocklist effect: %+v", pv.Effects)
	}
	if x, ok := effectOf(pv, EffectPackage); !ok || !strings.Contains(x.Text, "pip:reqeusts") {
		t.Fatalf("package effect: %+v", pv.Effects)
	}
	if _, ok := effectOf(pv, EffectHost); !ok {
		t.Fatalf("host effect: %+v", pv.Effects)
	}
	if pv.Effects[len(pv.Effects)-1].Kind != EffectNext {
		t.Fatalf("last effect must explain the draft: %+v", pv.Effects)
	}

	_, p, err := e.svc.Decide(ctx, c.ID, model.DecisionMalicious, "")
	if err != nil {
		t.Fatal(err)
	}
	if p.ID != "prop-0001" {
		t.Fatalf("preview must not consume ids: %s", p.ID)
	}
	if !reflect.DeepEqual(p.Changes, pv.Changes) || !reflect.DeepEqual(p.Notes, pv.Notes) {
		t.Fatalf("preview ≠ decide:\npreview %+v %+v\ndecide  %+v %+v", pv.Changes, pv.Notes, p.Changes, p.Notes)
	}

	// 판정한 건 · 종결 건은 409
	if _, err := e.svc.PreviewDecision(ctx, c.ID, model.DecisionMalicious); ErrorKind(err) != KindConflict {
		t.Fatalf("decided case: %v", err)
	}
	if _, _, err := e.svc.Apply(ctx, p.ID, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.PreviewDecision(ctx, c.ID, model.DecisionFalsePositive); ErrorKind(err) != KindConflict {
		t.Fatalf("closed case: %v", err)
	}
}

// 오탐: 예외로 추가될 규칙 · 필드 · 값 · 범위. changes = Decide 결과
func TestPreviewDecisionFalsePositiveMatchesDecide(t *testing.T) {
	e := newEnv(t)
	ctx := t.Context()
	c := e.installCase(t)

	pv, err := e.svc.PreviewDecision(ctx, c.ID, model.DecisionFalsePositive)
	if err != nil {
		t.Fatal(err)
	}
	if len(pv.Changes) == 0 {
		t.Fatalf("false positive must propose an exception: %+v", pv)
	}
	x, ok := effectOf(pv, EffectException)
	if !ok || !strings.Contains(x.Text, "sandbox-egress") || !strings.Contains(x.Text, "sg-install-*") {
		t.Fatalf("exception effect must name the rule and its scope: %+v", pv.Effects)
	}
	if _, ok := effectOf(pv, EffectBlocklist); ok {
		t.Fatalf("false positive must not touch the blocklist: %+v", pv.Effects)
	}
	_, p, err := e.svc.Decide(ctx, c.ID, model.DecisionFalsePositive, "")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(p.Changes, pv.Changes) || !reflect.DeepEqual(p.Notes, pv.Notes) {
		t.Fatalf("preview ≠ decide:\npreview %+v %+v\ndecide  %+v %+v", pv.Changes, pv.Notes, p.Changes, p.Notes)
	}
}

// 런타임 악성: 이미지 차단 → 같은 이미지를 쓰는 지금 실행 중 컨테이너 수(다음 시작 때 격리)
func TestPreviewDecisionRunningContainers(t *testing.T) {
	e := newEnv(t)
	ctx := t.Context()
	c := e.runtimeCase(t, "pkg-runtime-1", "demo/reqeusts:1.0.2")

	e.svc.o.Containers = fakeContainers{list: []dockerapi.Container{
		{Name: "pkg-runtime-1", Image: "demo/reqeusts:1.0.2", Running: true},
		{Name: "pkg-runtime-2", Image: "demo/reqeusts:1.0.2", Running: true},
		{Name: "web", Image: "nginx:1.27", Running: true},
	}}
	pv, err := e.svc.PreviewDecision(ctx, c.ID, model.DecisionMalicious)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(pv.Changes, []model.ProposalChange{{Op: "block", List: model.ListImages, Value: "demo/reqeusts:1.0.2"}}) {
		t.Fatalf("changes: %+v", pv.Changes)
	}
	x, ok := effectOf(pv, EffectImage)
	if !ok || x.Count == nil || *x.Count != 2 || !strings.Contains(x.Text, "2개") || !strings.Contains(x.Text, "다음 시작") {
		t.Fatalf("image effect: %+v", pv.Effects)
	}

	// 실행 중 목록을 못 읽으면 수는 비우고(null) 그렇다고 알린다
	e.svc.o.Containers = fakeContainers{err: errors.New("docker down")}
	pv, err = e.svc.PreviewDecision(ctx, c.ID, model.DecisionMalicious)
	if err != nil {
		t.Fatal(err)
	}
	if x, ok := effectOf(pv, EffectImage); !ok || x.Count != nil || !strings.Contains(x.Text, "확인하지 못") {
		t.Fatalf("image effect without docker: %+v", pv.Effects)
	}
	e.svc.o.Containers = nil
	if x, ok := effectOf(mustPreview(t, e, c.ID), EffectImage); !ok || x.Count != nil {
		t.Fatalf("image effect without lister: %+v", x)
	}
}

// 이미 차단 목록에 있는 값은 +N 에서 빼고 따로 알린다(적용이 건너뛰는 것과 같게)
func TestPreviewDecisionAlreadyBlocked(t *testing.T) {
	e := newEnv(t)
	ctx := t.Context()
	_, p := e.maliciousInstallCase(t)
	if _, _, err := e.svc.Apply(ctx, p.ID, ""); err != nil {
		t.Fatal(err)
	}
	s, err := e.svc.StartInstall(ctx, StartInput{Manager: "pip", Packages: []string{"./reqeusts"}, Container: "sg-install-pip-2", Image: "python:3.12-slim"})
	if err != nil {
		t.Fatal(err)
	}
	ev := sandboxEv(s.Container)
	ev.Kind, ev.Path = model.KindOpen, "/etc/shadow"
	v := e.observe(t, ev)
	pv, err := e.svc.PreviewDecision(ctx, *v.CaseID, model.DecisionMalicious)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := effectOf(pv, EffectBlocklist); ok {
		t.Fatalf("nothing new to block: %+v", pv.Effects)
	}
	if x, ok := effectOf(pv, EffectAlreadyBlocked); !ok || x.Count == nil || *x.Count != 1 {
		t.Fatalf("already blocked effect: %+v", pv.Effects)
	}
}

func TestPreviewDecisionInvalid(t *testing.T) {
	e := newEnv(t)
	ctx := t.Context()
	c := e.installCase(t)
	if _, err := e.svc.PreviewDecision(ctx, c.ID, model.DecisionPending); ErrorKind(err) != KindInvalid {
		t.Fatalf("pending decision: %v", err)
	}
	if _, err := e.svc.PreviewDecision(ctx, "case-9999", model.DecisionMalicious); ErrorKind(err) != KindNotFound {
		t.Fatalf("missing case: %v", err)
	}
}

func mustPreview(t *testing.T, e *env, id string) DecisionPreview {
	t.Helper()
	pv, err := e.svc.PreviewDecision(t.Context(), id, model.DecisionMalicious)
	if err != nil {
		t.Fatal(err)
	}
	return pv
}
