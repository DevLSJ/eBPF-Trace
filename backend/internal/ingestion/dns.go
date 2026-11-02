package ingestion

import (
	"strconv"
	"strings"
)

// trace_dns 필드 해석(10/30). IG v0.56.1 의 qr · qtype · pkt_type 은 문자열 열거로 오고, *_raw 는 숫자 문자열이다.
// 문자열 열거가 비어 있으면 raw 값으로 판단한다 (gadget.yaml 의 value.one-of 와 raw 주석 기준).

// dnsIsQuery: qr 이 Q(또는 raw 0)이면 질의. 둘 다 비면 응답으로 본다(옛 동작 — 응답만 학습)
func dnsIsQuery(qr, raw string) bool {
	switch strings.ToUpper(strings.TrimSpace(qr)) {
	case "Q":
		return true
	case "R":
		return false
	}
	return strings.TrimSpace(raw) == "0"
}

// dnsOutgoing: 컨테이너가 보낸 패킷인지(pkt_type OUTGOING = raw 4). 필드가 없으면 보낸 것으로 본다
func dnsOutgoing(pktType, raw string) bool {
	if pt := strings.ToUpper(strings.TrimSpace(pktType)); pt != "" {
		return pt == "OUTGOING"
	}
	if r := strings.TrimSpace(raw); r != "" {
		return r == "4"
	}
	return true
}

// qtypeNames: qtype_raw → 이름 (gadget.yaml 주석과 같다). 모르는 번호는 TYPE<n>
var qtypeNames = map[int]string{1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 13: "HINFO", 14: "MINFO", 15: "MX", 16: "TXT",
	28: "AAAA", 33: "SRV", 41: "OPT", 44: "WKS", 252: "AXFR", 255: "ALL"}

// dnsQtype: 질의 유형 — 문자열 열거를 대문자로, 없으면 raw 번호를 이름으로
func dnsQtype(qtype, raw string) string {
	if q := strings.ToUpper(strings.TrimSpace(qtype)); q != "" {
		return q
	}
	n, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil {
		return ""
	}
	if name, ok := qtypeNames[n]; ok {
		return name
	}
	return "TYPE" + strconv.Itoa(n)
}

// dnsQueryName: 질의 이름을 소문자 · 끝 점 없이 (규칙 · 화면 · 리졸버가 같은 꼴을 쓴다)
func dnsQueryName(name string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
}
