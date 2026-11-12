package rules

import (
	"encoding/json"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// 연쇄 규칙(kind: sequence, 11/03) — 스키마 · 검증. 규칙은 YAML 로 만든다(정책 파일 · 화면 YAML 편집과 같은 입력).

const seqYAML = `rules:
  - id: chain-download-secrets
    description: 다운로더 → 외부 연결 → 자격 증명
    kind: sequence
    action: kill
    dryRun: true
    containers: ["web-*"]
    windowSeconds: 10
    steps:
      - kind: exec
        denyComms: [curl, wget]
      - kind: connect
        allowCidrs: [10.0.0.0/8, "::1"]
      - kind: open
        denyPaths: [/root/.netrc, /root/.ssh/]
`

func TestSequenceParseYAML(t *testing.T) {
	rs, err := ParseYAML([]byte(seqYAML))
	if err != nil {
		t.Fatalf("sequence rule must parse: %v", err)
	}
	if len(rs) != 1 {
		t.Fatalf("rules = %d", len(rs))
	}
	r := rs[0]
	if r.Kind != "sequence" || r.Action != "kill" || !r.DryRun || len(r.Containers) != 1 {
		t.Fatalf("header: %+v", r)
	}
	if r.WindowSeconds != 10 || len(r.Steps) != 3 || r.Steps[0].Kind != "exec" || len(r.Steps[0].DenyComms) != 2 ||
		r.Steps[1].Kind != "connect" || len(r.Steps[1].AllowCIDRs) != 2 || r.Steps[2].Kind != "open" || len(r.Steps[2].DenyPaths) != 2 {
		t.Fatalf("steps: %+v window=%d", r.Steps, r.WindowSeconds)
	}
	// 다시 내보낼 때(정책 내보내기 · 화면 YAML) 단계는 kind + 조건만 — 빈 id · action 키가 붙지 않는다
	b, err := yaml.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	out := string(b)
	for _, want := range []string{"windowSeconds: 10", "steps:", "- kind: exec", "- kind: connect", "- kind: open", "/root/.netrc"} {
		if !strings.Contains(out, want) {
			t.Fatalf("re-marshal lost %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, `id: ""`) || strings.Contains(out, `action: ""`) {
		t.Fatalf("steps must not carry empty header keys:\n%s", out)
	}
	j, err := json.Marshal(r.Steps[0])
	if err != nil {
		t.Fatal(err)
	}
	if string(j) != `{"kind":"exec","denyComms":["curl","wget"]}` {
		t.Fatalf("step json: %s", j)
	}
}

// V1~V8: 규칙 하나짜리 YAML → Validate. want 가 "" 이면 통과, 아니면 오류 문구에 그 조각이 있어야 한다.
func TestSequenceValidate(t *testing.T) {
	const head = "id: c\nkind: sequence\naction: kill\nwindowSeconds: 10\n"
	const exec = "  - kind: exec\n    denyComms: [curl]\n"
	const open = "  - kind: open\n    denyPaths: [/root/.netrc]\n"
	two := "steps:\n" + exec + open
	cases := []struct {
		name string
		yaml string
		want string
	}{
		{"ok two steps", head + two, ""},
		{"ok five steps all kinds", head + "steps:\n" + exec +
			"  - kind: connect\n    allowCidrs: [10.0.0.0/8]\n" +
			"  - kind: dns\n    denyQtypes: [TXT]\n" +
			"  - kind: connect\n    directIp: alert\n" + open, ""},
		{"ok open step allowPaths", head + "steps:\n" + exec + "  - kind: open\n    denyPaths: [/root/]\n    allowPaths: [/root/.cache/]\n", ""},
		{"ok window 1", "id: c\nkind: sequence\naction: alert\nwindowSeconds: 1\n" + two, ""},
		{"ok window 60", "id: c\nkind: sequence\naction: alert\nwindowSeconds: 60\n" + two, ""},
		// V1
		{"V1 bad kind lists sequence", "id: c\nkind: read\naction: kill\ndenyPaths: [/x]\n", "kind \"read\": exec | open | connect | dns | sequence"},
		// V2
		{"V2 no steps", head, "steps: 단계 2~5개"},
		{"V2 one step", head + "steps:\n" + exec, "steps: 단계 2~5개 (지금 1개)"},
		{"V2 six steps", head + "steps:\n" + exec + exec + exec + exec + exec + exec, "steps: 단계 2~5개 (지금 6개)"},
		// V3
		{"V3 window missing", "id: c\nkind: sequence\naction: kill\n" + two, "windowSeconds 0: 1~60"},
		{"V3 window 61", "id: c\nkind: sequence\naction: kill\nwindowSeconds: 61\n" + two, "windowSeconds 61: 1~60"},
		{"V3 window negative", "id: c\nkind: sequence\naction: kill\nwindowSeconds: -1\n" + two, "windowSeconds -1: 1~60"},
		// V4
		{"V4 top denyPaths", head + "denyPaths: [/x]\n" + two, "sequence 규칙 최상위에는 조건을 쓸 수 없음(조건은 steps 에)"},
		{"V4 top directIp", head + "directIp: kill\n" + two, "sequence 규칙 최상위에는 조건을 쓸 수 없음(조건은 steps 에)"},
		{"V4 top allowHosts", head + "allowHosts: [pypi.org]\n" + two, "sequence 규칙 최상위에는 조건을 쓸 수 없음(조건은 steps 에)"},
		{"V4 top maxLabelLength", head + "maxLabelLength: 40\n" + two, "sequence 규칙 최상위에는 조건을 쓸 수 없음(조건은 steps 에)"},
		{"V4 top allowPorts", head + "allowPorts: [443]\n" + two, "sequence 규칙 최상위에는 조건을 쓸 수 없음(조건은 steps 에)"},
		// V5
		{"V5 exec with steps", "id: c\nkind: exec\naction: kill\ndenyComms: [curl]\n" + two, "steps · windowSeconds 는 sequence 규칙에서만"},
		{"V5 open with window", "id: c\nkind: open\naction: kill\ndenyPaths: [/x]\nwindowSeconds: 10\n", "steps · windowSeconds 는 sequence 규칙에서만"},
		// V6
		{"V6 nested sequence", head + "steps:\n" + exec + "  - kind: sequence\n    denyPaths: [/x]\n", "steps[1]: kind \"sequence\": exec | open | connect | dns"},
		{"V6 unknown step kind", head + "steps:\n  - kind: read\n    denyPaths: [/x]\n" + open, "steps[0]: kind \"read\": exec | open | connect | dns"},
		// V7
		{"V7 step id", head + "steps:\n" + exec + "  - kind: open\n    id: x\n    denyPaths: [/x]\n", "steps[1]: 단계에는 kind 와 조건만 쓸 수 있음(id · description · action"},
		{"V7 step description", head + "steps:\n" + exec + "  - kind: open\n    description: x\n    denyPaths: [/x]\n", "steps[1]: 단계에는 kind 와 조건만 쓸 수 있음(id · description · action"},
		{"V7 step action", head + "steps:\n  - kind: exec\n    action: kill\n    denyComms: [curl]\n" + open, "steps[0]: 단계에는 kind 와 조건만 쓸 수 있음(id · description · action"},
		{"V7 step dryRun", head + "steps:\n  - kind: exec\n    dryRun: true\n    denyComms: [curl]\n" + open, "steps[0]: 단계에는 kind 와 조건만 쓸 수 있음(id · description · action"},
		{"V7 step disabled", head + "steps:\n  - kind: exec\n    disabled: true\n    denyComms: [curl]\n" + open, "steps[0]: 단계에는 kind 와 조건만 쓸 수 있음(id · description · action"},
		{"V7 step containers", head + "steps:\n  - kind: exec\n    containers: [x]\n    denyComms: [curl]\n" + open, "steps[0]: 단계에는 kind 와 조건만 쓸 수 있음(id · description · action"},
		{"V7 step window", head + "steps:\n  - kind: exec\n    windowSeconds: 5\n    denyComms: [curl]\n" + open, "steps[0]: 단계에는 kind 와 조건만 쓸 수 있음(id · description · action"},
		{"V7 step steps", head + "steps:\n  - kind: exec\n    denyComms: [curl]\n    steps:\n" + "    - kind: open\n      denyPaths: [/x]\n" + open, "steps[0]: 단계에는 kind 와 조건만 쓸 수 있음(id · description · action"},
		// V8
		{"V8 empty step", head + "steps:\n" + exec + "  - kind: open\n", "steps[1]: open 규칙에 조건이 없음"},
		{"V8 open step allowPaths only", head + "steps:\n" + exec + "  - kind: open\n    allowPaths: [/x]\n", "steps[1]: open 규칙에 조건이 없음"},
		{"V8 bad cidr", head + "steps:\n  - kind: connect\n    allowCidrs: [nope]\n" + open, "steps[0]: cidr \"nope\""},
		{"V8 bad host", head + "steps:\n  - kind: connect\n    denyHosts: [\"not a host!\"]\n" + open, "steps[0]: host \"not a host!\""},
		{"V8 bad qtype", head + "steps:\n" + exec + "  - kind: dns\n    denyQtypes: [txt]\n", "steps[1]: denyQtypes \"txt\""},
		{"V8 bad directIp", head + "steps:\n  - kind: connect\n    directIp: block\n" + open, "steps[0]: directIp \"block\""},
		{"V8 dns step with port", head + "steps:\n" + exec + "  - kind: dns\n    denyHosts: [x.test]\n    denyPorts: [53]\n", "steps[1]: dns 규칙에는 포트 · 대역 · directIp 조건을 쓸 수 없음"},
		{"V8 exec step with dns field", head + "steps:\n  - kind: exec\n    denyComms: [curl]\n    maxNameLength: 10\n" + open, "steps[0]: denyQtypes · maxNameLength · maxLabelLength 는 dns 규칙에서만"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var r Rule
			if err := yaml.Unmarshal([]byte(c.yaml), &r); err != nil {
				t.Fatalf("yaml: %v", err)
			}
			err := r.Validate()
			switch {
			case c.want == "" && err != nil:
				t.Fatalf("want valid, got %v", err)
			case c.want != "" && err == nil:
				t.Fatalf("want error containing %q, got nil", c.want)
			case c.want != "" && !strings.Contains(err.Error(), c.want):
				t.Fatalf("want error containing %q, got %v", c.want, err)
			}
		})
	}
}
