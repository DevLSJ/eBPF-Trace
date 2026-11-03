package review

import (
	"testing"

	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/model"
)

// 종합 판정(11/04): 세션 보고 뒤 서버가 시작한 정적 검사 id · 건너뛴 이유를 세션에 남긴다 — 저장소에도(재시작 뒤 그대로)
func TestAttachScanPersists(t *testing.T) {
	e := newEnv(t)
	ctx := t.Context()
	a, err := e.svc.StartInstall(ctx, StartInput{Manager: "pip", Packages: []string{"requests"}, Container: "sg-install-pip-1-1"})
	if err != nil {
		t.Fatal(err)
	}
	b, err := e.svc.StartInstall(ctx, StartInput{Manager: "pip", Packages: []string{"./reqeusts"}, Container: "sg-install-pip-2-2"})
	if err != nil {
		t.Fatal(err)
	}
	if a.ScanID != nil || a.ScanSkip != "" {
		t.Fatalf("new session has no scan yet: %+v %q", a.ScanID, a.ScanSkip)
	}
	if err := e.svc.AttachScan(ctx, a.ID, "scan-0007", ""); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.AttachScan(ctx, b.ID, "", "local"); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.AttachScan(ctx, "ins-9999", "scan-0001", ""); ErrorKind(err) != KindNotFound {
		t.Fatalf("unknown session: %v", err)
	}
	// 붙인 뒤 들어온 이벤트 · 끝 보고는 그대로 쌓인다
	ev := sandboxEv("sg-install-pip-1-1")
	ev.Kind, ev.Args = model.KindExec, "python3 setup.py"
	e.observe(t, ev)
	if _, err := e.svc.FinishInstall(ctx, a.ID, 0); err != nil {
		t.Fatal(err)
	}
	check := func(svc *Service, when string) {
		t.Helper()
		x, err := svc.GetInstall(a.ID)
		if err != nil || x.ScanID == nil || *x.ScanID != "scan-0007" || x.ScanSkip != "" || x.Status != model.InstallPassed {
			t.Fatalf("%s a: %+v %q %s %v", when, x.ScanID, x.ScanSkip, x.Status, err)
		}
		y, err := svc.GetInstall(b.ID)
		if err != nil || y.ScanID != nil || y.ScanSkip != "local" {
			t.Fatalf("%s b: %+v %q %v", when, y.ScanID, y.ScanSkip, err)
		}
	}
	check(e.svc, "cache")
	re := New(Options{Store: e.store, Policies: e.store, Audit: e.store, Engine: e.engine})
	if err := re.Load(ctx); err != nil {
		t.Fatal(err)
	}
	check(re, "reloaded")

	// 저장이 실패해도 캐시에는 남기고 다음 flush 에 다시 쓴다
	e.store.setFail(true)
	if err := e.svc.AttachScan(ctx, b.ID, "scan-0008", ""); err == nil {
		t.Fatal("store failure must be reported")
	}
	if y, _ := e.svc.GetInstall(b.ID); y.ScanID == nil || *y.ScanID != "scan-0008" || y.ScanSkip != "" {
		t.Fatalf("cache after failed commit: %+v %q", y.ScanID, y.ScanSkip)
	}
	e.store.setFail(false)
	e.svc.Flush(ctx)
	re = New(Options{Store: e.store, Policies: e.store, Audit: e.store, Engine: e.engine})
	if err := re.Load(ctx); err != nil {
		t.Fatal(err)
	}
	if y, _ := re.GetInstall(b.ID); y.ScanID == nil || *y.ScanID != "scan-0008" {
		t.Fatalf("flushed: %+v", y.ScanID)
	}
}
