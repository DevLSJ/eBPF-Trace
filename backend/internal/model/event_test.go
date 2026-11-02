package model

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// W20: connect 이벤트는 dnsTraced 를 false 여도 명시한다 — 화면이 「판단 불가(trace_dns 꺼짐)」와 「기록 없음(옛 기록)」을 구별
func TestEventJSONDNSTracedConnectOnly(t *testing.T) {
	ts := time.Date(2026, 10, 20, 9, 0, 0, 0, time.UTC)
	cases := []struct {
		name string
		ev   Event
		want string // "" = 필드 없음
	}{
		{"connect false", Event{Kind: KindConnect, Timestamp: ts, DstIP: "203.0.113.7", DstPort: 443}, `"dnsTraced":false`},
		{"connect true", Event{Kind: KindConnect, Timestamp: ts, DstIP: "203.0.113.7", DstPort: 443, DNSTraced: true}, `"dnsTraced":true`},
		{"exec", Event{Kind: KindExec, Timestamp: ts, Comm: "sh"}, ""},
		{"open", Event{Kind: KindOpen, Timestamp: ts, Path: "/etc/passwd"}, ""},
		{"dns", Event{Kind: KindDNS, Timestamp: ts, DNSName: "a.test"}, ""},
		{"start", Event{Kind: KindStart, Timestamp: ts}, ""},
		{"exit", Event{Kind: KindExit, Timestamp: ts}, ""},
	}
	for _, c := range cases {
		got := mustJSON(t, c.ev)
		if c.want == "" {
			if strings.Contains(got, "dnsTraced") {
				t.Errorf("%s: dnsTraced must be absent, got %s", c.name, got)
			}
		} else if !strings.Contains(got, c.want) {
			t.Errorf("%s: want %s in %s", c.name, c.want, got)
		}
		// 다른 필드는 그대로(omitempty 유지 · 내부 필드 숨김)
		if strings.Contains(got, "DNSName") || strings.Contains(got, "a.test") {
			t.Errorf("%s: internal DNS fields leaked: %s", c.name, got)
		}
	}
	// Verdict 안에 있어도(WS · recent · audit 응답) 같은 모양
	v := Verdict{Event: Event{Kind: KindConnect, Timestamp: ts, DstIP: "203.0.113.7", DstPort: 443}}
	if got := mustJSON(t, v); !strings.Contains(got, `"dnsTraced":false`) {
		t.Errorf("verdict: want dnsTraced false, got %s", got)
	}
	if got := mustJSON(t, &v); !strings.Contains(got, `"dnsTraced":false`) {
		t.Errorf("*verdict: want dnsTraced false, got %s", got)
	}
}

// 저장(PG jsonb · Redis) 왕복: 명시한 값은 그대로, 필드가 없던 옛 connect 기록은 다시 내보내도 없음
func TestEventJSONRoundTrip(t *testing.T) {
	ts := time.Date(2026, 10, 20, 9, 0, 0, 0, time.UTC)
	for _, traced := range []bool{false, true} {
		in := Verdict{Event: Event{Kind: KindConnect, Timestamp: ts, ContainerName: "c", DstIP: "203.0.113.7", DstPort: 443, DNSTraced: traced}, Matched: true, RuleID: "r"}
		var out Verdict
		if err := json.Unmarshal([]byte(mustJSON(t, in)), &out); err != nil {
			t.Fatal(err)
		}
		if out.Event.DNSTraced != traced || out.Event.DstIP != in.Event.DstIP || out.Event.ContainerName != "c" || out.RuleID != "r" || !out.Event.Timestamp.Equal(ts) {
			t.Fatalf("round trip lost data: %+v", out)
		}
		if a, b := mustJSON(t, in), mustJSON(t, out); a != b {
			t.Fatalf("round trip changed JSON:\n%s\n%s", a, b)
		}
	}
	old := `{"event":{"kind":"connect","timestamp":"2026-10-01T00:00:00Z","containerId":"x","containerName":"c","imageName":"i","comm":"curl","pid":1,"dstIp":"203.0.113.7","dstPort":443},"matched":false,"caseId":null,"install":null}`
	var v Verdict
	if err := json.Unmarshal([]byte(old), &v); err != nil {
		t.Fatal(err)
	}
	if v.Event.DNSTraced {
		t.Fatal("old record must read as not traced (fail-open)")
	}
	if got := mustJSON(t, v); strings.Contains(got, "dnsTraced") {
		t.Fatalf("old record must stay without dnsTraced, got %s", got)
	}
	// exec 기록에 잘못 들어 있던 dnsTraced 는 다시 내보내지 않는다
	var e Event
	if err := json.Unmarshal([]byte(`{"kind":"exec","timestamp":"2026-10-01T00:00:00Z","comm":"sh","dnsTraced":true}`), &e); err != nil {
		t.Fatal(err)
	}
	if got := mustJSON(t, e); strings.Contains(got, "dnsTraced") {
		t.Fatalf("exec must not carry dnsTraced, got %s", got)
	}
}

// DNS 질의 이벤트(10/30): qtype 이 실리고 dnsTraced 는 없다. 상세는 "<name> (<qtype>)". 응답 전용 내부 필드는 숨긴다
func TestEventJSONDNS(t *testing.T) {
	ts := time.Date(2026, 10, 30, 9, 0, 0, 0, time.UTC)
	name := strings.Repeat("deadbeef", 6) + ".exfil.example"
	q := Event{Kind: KindDNS, Timestamp: ts, ContainerName: "sg-install-demo-1", Comm: "python3", Pid: 123, DstHost: name, Qtype: "A", DstIP: "127.0.0.11", DstPort: 53}
	got := mustJSON(t, q)
	for _, want := range []string{`"kind":"dns"`, `"qtype":"A"`, `"dstHost":"` + name + `"`, `"dstIp":"127.0.0.11"`, `"dstPort":53`} {
		if !strings.Contains(got, want) {
			t.Errorf("want %s in %s", want, got)
		}
	}
	for _, no := range []string{"dnsTraced", "DNSName", "DNSAddrs", "addresses"} {
		if strings.Contains(got, no) {
			t.Errorf("%s must be absent: %s", no, got)
		}
	}
	if d := q.Detail(); d != name+" (A)" {
		t.Fatalf("detail: %q", d)
	}
	if !q.IsDNSQuery() || (Event{Kind: KindDNS, DNSName: "a.test", DstHost: "a.test"}).IsDNSQuery() || (Event{Kind: KindConnect, DstHost: "a.test"}).IsDNSQuery() {
		t.Fatal("IsDNSQuery: query = dns kind with a name and no answer")
	}
	var back Event
	if err := json.Unmarshal([]byte(got), &back); err != nil || back.Qtype != "A" || back.DstHost != name || back.Kind != KindDNS {
		t.Fatalf("round trip: %+v %v", back, err)
	}
	if !KindDNS.Valid() || len(Kinds) != 4 || Kinds[3] != KindDNS {
		t.Fatalf("Kinds must end with dns: %v", Kinds)
	}
	if DNSDetail("x.test", "") != "x.test" || DNSDetail("x.test", "TXT") != "x.test (TXT)" {
		t.Fatal("DNSDetail")
	}
}
