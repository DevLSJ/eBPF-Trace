package model

import "time"

// MinuteCount: 1분 동안 수집한 이벤트 수(종류별) — 대시보드 eBPF 수집 종합(10/16)이 기간별로 더한다
type MinuteCount struct {
	Minute  time.Time `json:"minute"`
	Exec    int64     `json:"exec"`
	Open    int64     `json:"open"`
	Connect int64     `json:"connect"`
}
