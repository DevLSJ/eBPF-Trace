package scan

import (
	"bytes"
	"strings"
	"testing"

	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/model"
)

func th(rule string) model.ScanFinding { return model.ScanFinding{Rule: rule, Category: "threat"} }

// 11/02 sg-vm 실측 23건(scan-bench-1102.txt)을 그대로 — 인기 패키지는 악성이 아니어야 하고 데모 악성은 악성이어야 한다
func TestVerdictThreeTier(t *testing.T) {
	cases := []struct {
		name     string
		score    float64
		findings []model.ScanFinding
		vulns    int
		want     string
		wantIT   int
	}{
		{"pyyaml 6.0.3 — 동적 로딩만 8.8", 8.8, []model.ScanFinding{th("threat-runtime-dynamic-loader"), th("threat-runtime-dynamic-loader"), th("threat-runtime-dynamic-loader")}, 0, "caution", 0},
		{"numpy 2.5.4 — 난독화 · 자동 실행 7.3", 7.3, []model.ScanFinding{th("threat-runtime-obfuscation-unicode"), th("threat-filesystem-autostart")}, 0, "caution", 0},
		{"django 6.1.2 — 동적 로딩 · 환경 변수 6.7", 6.7, []model.ScanFinding{th("threat-runtime-dynamic-loader"), th("threat-runtime-environment-read"), th("threat-runtime-obfuscation-steganography")}, 0, "caution", 0},
		{"django 2.2.0 — 5.9 + 취약점 75", 5.9, []model.ScanFinding{th("threat-runtime-environment-read")}, 75, "vulnerable", 0},
		{"requests sdist — setup.py process-hooks 4.5", 4.5, []model.ScanFinding{th("threat-process-hooks")}, 0, "clean", 0},
		{"idna — 유니코드 4.9", 4.9, []model.ScanFinding{th("threat-runtime-obfuscation-unicode")}, 0, "clean", 0},
		{"최신 requests — 의존성 취약점 4", 0, nil, 4, "vulnerable", 0},
		{"데모 reqeusts — setup 네트워크 · 유출 8.6", 8.6, []model.ScanFinding{th("threat-setup-suspicious-imports"), th("threat-network-exfiltration"), th("threat-filesystem-read"), th("threat-setup-network-in-install"), th("threat-process-hooks")}, 0, "malicious", 3},
		{"가상 — 설치 시점 규칙인데 점수 3", 3, []model.ScanFinding{th("threat-network-exfiltration")}, 0, "clean", 1},
		{"가상 — 악성 + 취약점이면 악성 우선", 9, []model.ScanFinding{th("threat-npm-preinstall-script")}, 10, "malicious", 1},
		{"가상 — 테스트 코드의 설치 시점 규칙은 세지 않음", 9, []model.ScanFinding{{Rule: "threat-network-exfiltration", Category: "threat", Test: true}}, 0, "caution", 0},
	}
	for _, c := range cases {
		got, it := verdictOf(&model.ScanRisk{Score: c.score}, c.findings, c.vulns)
		if got != c.want || it != c.wantIT {
			t.Errorf("%s: verdict %s(설치 시점 %d) — want %s(%d)", c.name, got, it, c.want, c.wantIT)
		}
	}
	if v, _ := verdictOf(nil, nil, 0); v != "clean" {
		t.Errorf("risk 없음 → clean, got %s", v)
	}
}

// 검사 끝까지: 점수가 높아도 런타임 휴리스틱 규칙만이면 「주의」, 설치 시점 규칙이 걸리면 「악성」(수정 전 코드는 둘 다 malicious)
func TestRuntimeOnlyHighScoreIsCaution(t *testing.T) {
	gd := func(rules string, score string) func(string, []string) []byte {
		return func(target string, _ []string) []byte {
			return []byte(`{"results":{` + strings.ReplaceAll(rules, "@T", target) + `},"risk_score":{"score":` + score + `,"label":"high_risk"}}`)
		}
	}
	cases := []struct {
		name, rules, score, want string
		wantIT, wantThreats      int
	}{
		{"런타임 휴리스틱만 8.8", `"threat-runtime-dynamic-loader":[{"location":"@T/pkg-1.0/pkg/c.py:5","match":"__import__(name)","message":"dyn"},{"location":"@T/pkg-1.0/pkg/c.py:9","match":"__import__(name)","message":"dyn"}]`, "8.8", "caution", 0, 2},
		{"설치 시점 규칙 8.6", `"threat-setup-suspicious-imports":[{"location":"@T/pkg-1.0/setup.py:1","match":"import socket","message":"imp"}],"threat-network-exfiltration":[{"location":"@T/pkg-1.0/setup.py:3","match":"http://203.0.113.7","message":"exfil"}],"threat-filesystem-read":[{"location":"@T/pkg-1.0/setup.py:4","match":"/etc/shadow","message":"read"}]`, "8.6", "malicious", 2, 3},
	}
	for _, c := range cases {
		r := &recRunner{gd: gd(c.rules, c.score)}
		s := newRecSvc(t, r)
		tgz := fakeTarball(t, "pkg-1.0", map[string]string{"setup.py": "import socket\n", "pkg/c.py": "x=1\n"})
		id, err := s.Start(t.Context(), Input{Kind: "file", FileName: "pkg-1.0.tar.gz", File: bytes.NewReader(tgz)})
		if err != nil {
			t.Fatal(err)
		}
		sc := waitDone(t, s, id)
		if sc.Status != "done" {
			t.Fatalf("%s: status %s %q", c.name, sc.Status, sc.Error)
		}
		if sc.Verdict != c.want || sc.InstallThreats != c.wantIT || sc.Threats != c.wantThreats {
			t.Errorf("%s: verdict %s 설치 시점 %d 위협 %d — want %s/%d/%d", c.name, sc.Verdict, sc.InstallThreats, sc.Threats, c.want, c.wantIT, c.wantThreats)
		}
	}
}
