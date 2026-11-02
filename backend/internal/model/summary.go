package model

import "time"

// MinuteCount: 1분 동안 수집한 이벤트 수(종류별) — 대시보드 eBPF 수집 종합(10/16)이 기간별로 더한다
type MinuteCount struct {
	Minute  time.Time `json:"minute"`
	Exec    int64     `json:"exec"`
	Open    int64     `json:"open"`
	Connect int64     `json:"connect"`
	// DNS: DNS 질의(kind: dns, 10/30). 옛 백엔드 호환을 위해 화면은 선택 값으로 읽는다
	DNS int64 `json:"dns"`
}
