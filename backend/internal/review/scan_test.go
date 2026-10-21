package review

import (
	"strings"
	"testing"

	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/model"
)

func blockValues(p model.Proposal) []string {
	var out []string
	for _, c := range p.Changes {
		if c.Op == "block" && c.List == model.ListPackages {
			out = append(out, c.Value)
		}
	}
	return out
}

// FromScan(W4): 패키지 검사는 그대로 — 선택 없이 대상 패키지 하나, 두 번 올려도 같은 건 · 제안
func TestFromScanPackageTarget(t *testing.T) {
	e := newEnv(t)
	ctx := t.Context()
	sc := model.Scan{ID: "scan-0001", Status: "done", Verdict: "malicious", Threats: 2, Risk: &model.ScanRisk{Score: 7.5},
		Target:   model.ScanTarget{Kind: "package", Manager: "pip", Name: "Reqeusts", Label: "pip Reqeusts"},
		Findings: []model.ScanFinding{{Rule: "threat-network-exfiltration", Category: "threat"}, {Rule: "capability-x", Category: "capability"}}}
	c, p, err := e.svc.FromScan(ctx, sc, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	if c.Source != model.CaseScan || c.Package != "pip:reqeusts" || c.Level != model.LevelKilled || c.Decision != model.DecisionMalicious || c.ScanID == nil || *c.ScanID != "scan-0001" {
		t.Fatalf("case %+v", c)
	}
	if strings.Join(blockValues(p), ",") != "pip:reqeusts" || !strings.Contains(c.Note, "scan-0001") {
		t.Fatalf("proposal %+v note %q", p, c.Note)
	}
	c2, p2, err := e.svc.FromScan(ctx, sc, nil, "")
	if err != nil || c2.ID != c.ID || p2.ID != p.ID {
		t.Fatalf("second call must return the same case · proposal: %v %s %s", err, c2.ID, p2.ID)
	}
}

// FromScan(W4): 저장소 · 파일 검사는 고른 패키지만 — 한 건에 여러 차단, 같은 선택은 같은 제안, 다른 선택은 새 건
func TestFromScanSelectedPackages(t *testing.T) {
	e := newEnv(t)
	ctx := t.Context()
	sc := model.Scan{ID: "scan-0002", Status: "done", Verdict: "vulnerable", VulnCount: 3,
		Target: model.ScanTarget{Kind: "repo", Name: "r", Label: "github.com/o/r@main/pkg", URL: "https://github.com/o/r/tree/main/pkg", Ref: "main", Subpath: "pkg"}}
	sel := []model.ScanPackage{
		{Manager: "pip", Name: "Urllib3", Version: "1.26.4", Source: "requirements.txt", Vulns: 2},
		{Manager: "npm", Name: "lodash", Version: "4.17.20", Source: "package-lock.json"},
		{Manager: "pip", Name: "urllib3", Version: "1.26.4"}, // 중복은 하나로
	}
	c, p, err := e.svc.FromScan(ctx, sc, sel, "")
	if err != nil {
		t.Fatal(err)
	}
	if c.Source != model.CaseScan || c.Level != model.LevelAlert || c.Label != "github.com/o/r@main/pkg" {
		t.Fatalf("case %+v", c)
	}
	if c.Package != "npm:lodash, pip:urllib3" {
		t.Fatalf("case package keys %q", c.Package)
	}
	if got := strings.Join(blockValues(p), ","); got != "npm:lodash,pip:urllib3" {
		t.Fatalf("block changes %q", got)
	}
	if !strings.Contains(c.Note, "urllib3@1.26.4") || !strings.Contains(c.Note, "lodash@4.17.20") {
		t.Fatalf("note should list the chosen packages with versions: %q", c.Note)
	}
	// 같은 선택(순서 다름) → 같은 건 · 제안
	c2, p2, err := e.svc.FromScan(ctx, sc, []model.ScanPackage{{Manager: "npm", Name: "lodash"}, {Manager: "pip", Name: "urllib3"}}, "")
	if err != nil || c2.ID != c.ID || p2.ID != p.ID {
		t.Fatalf("same selection must reuse: %v %s %s", err, c2.ID, p2.ID)
	}
	// 다른 선택 → 새 건 · 새 제안
	c3, p3, err := e.svc.FromScan(ctx, sc, []model.ScanPackage{{Manager: "pip", Name: "urllib3"}}, "")
	if err != nil || c3.ID == c.ID || p3.ID == p.ID || c3.Package != "pip:urllib3" {
		t.Fatalf("different selection must open a new case: %v %+v", err, c3)
	}
	if got := strings.Join(blockValues(p3), ","); got != "pip:urllib3" {
		t.Fatalf("block changes %q", got)
	}
	// 거절: 매니저 없음 · 잘못된 매니저 · 빈 이름
	for _, bad := range [][]model.ScanPackage{
		{{Name: "urllib3"}},
		{{Manager: "apt", Name: "x"}},
		{{Manager: "pip", Name: ""}},
	} {
		if _, _, err := e.svc.FromScan(ctx, sc, bad, ""); ErrorKind(err) != KindInvalid {
			t.Errorf("%+v: want invalid, got %v", bad, err)
		}
	}
	// 저장소 검사에 선택이 없으면 거절(대상이 패키지가 아니다)
	if _, _, err := e.svc.FromScan(ctx, sc, nil, ""); ErrorKind(err) != KindInvalid {
		t.Fatalf("repo scan without selection: %v", err)
	}
}

// FromScan(W18): 확인 대화상자의 사유 → 판정 메모 끝에 「사유: …」(앞뒤 공백 제거, 500자 상한 — 넘으면 건을 열지 않고 거절)
func TestFromScanReason(t *testing.T) {
	e := newEnv(t)
	ctx := t.Context()
	sc := model.Scan{ID: "scan-0003", Status: "done", Verdict: "malicious", Threats: 1, Risk: &model.ScanRisk{Score: 8},
		Target: model.ScanTarget{Kind: "package", Manager: "pip", Name: "evil", Label: "pip evil"}}
	if _, _, err := e.svc.FromScan(ctx, sc, nil, strings.Repeat("가", 501)); ErrorKind(err) != KindInvalid {
		t.Fatalf("501 runes must be invalid: %v", err)
	}
	c, _, err := e.svc.FromScan(ctx, sc, nil, "  타이포스쿼팅 확인  ")
	if err != nil {
		t.Fatal(err)
	}
	if c.ID != "case-0001" {
		t.Fatalf("a rejected reason must not open a case first: %s", c.ID)
	}
	if !strings.HasPrefix(c.Note, "공급망 검사 scan-0003 — 위험 점수 8.0") || !strings.HasSuffix(c.Note, " — 사유: 타이포스쿼팅 확인") {
		t.Fatalf("note %q", c.Note)
	}
	// 사유가 없으면 예전 메모 그대로
	sc2 := sc
	sc2.ID, sc2.Target.Name, sc2.Target.Label = "scan-0004", "evil2", "pip evil2"
	c2, _, err := e.svc.FromScan(ctx, sc2, nil, "   ")
	if err != nil || strings.Contains(c2.Note, "사유") {
		t.Fatalf("blank reason: %v %q", err, c2.Note)
	}
	// 500자는 된다
	sc3 := sc
	sc3.ID, sc3.Target.Name, sc3.Target.Label = "scan-0005", "evil3", "pip evil3"
	if _, _, err := e.svc.FromScan(ctx, sc3, nil, strings.Repeat("가", 500)); err != nil {
		t.Fatalf("500 runes: %v", err)
	}
}
