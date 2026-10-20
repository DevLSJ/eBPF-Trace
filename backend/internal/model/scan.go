package model

import "time"

// 공급망 검사(10/16) — 패키지 이름 · GitHub 저장소 · 올린 파일을 GuardDog(악성 코드 패턴) · OSV-Scanner(알려진 취약점)로 정적 검사

type ScanTarget struct {
	Kind     string `json:"kind"` // package | repo | file
	Manager  string `json:"manager,omitempty"`
	Name     string `json:"name,omitempty"`
	Version  string `json:"version,omitempty"`
	URL      string `json:"url,omitempty"`
	FileName string `json:"fileName,omitempty"`
	Size     int64  `json:"size,omitempty"`
	Label    string `json:"label"`
}

type ScanFinding struct {
	Rule     string `json:"rule"`
	Category string `json:"category"` // threat | capability
	Message  string `json:"message"`
	File     string `json:"file"`
	Line     int    `json:"line"`
	Match    string `json:"match"`
}

type ScanVuln struct {
	Package     string   `json:"package"`
	Version     string   `json:"version"`
	Ecosystem   string   `json:"ecosystem"`
	Direct      bool     `json:"direct"`
	Count       int      `json:"count"`
	MaxSeverity string   `json:"maxSeverity"`
	IDs         []string `json:"ids"`
}

type ScanRisk struct {
	Score float64 `json:"score"`
	Label string  `json:"label"`
}

type ScanEngine struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type Scan struct {
	ID         string        `json:"id"`
	Target     ScanTarget    `json:"target"`
	Status     string        `json:"status"` // running | done | failed
	StartedAt  time.Time     `json:"startedAt"`
	FinishedAt *time.Time    `json:"finishedAt"`
	Error      string        `json:"error,omitempty"`
	Verdict    string        `json:"verdict,omitempty"` // malicious | vulnerable | clean
	Risk       *ScanRisk     `json:"risk"`
	Engines    []ScanEngine  `json:"engines"`
	Findings   []ScanFinding `json:"findings"`
	Vulns      []ScanVuln    `json:"vulns"`
	// Files: 위협이 나온 파일의 코드만(경로 → 내용) — 원본은 검사 뒤 지운다, 결과와 함께 30일
	Files  map[string]string `json:"files"`
	CaseID *string           `json:"caseId"`
	// 목록용 집계
	Threats      int      `json:"threats"`
	Capabilities int      `json:"capabilities"`
	VulnCount    int      `json:"vulnCount"`
	VulnMax      *float64 `json:"vulnMax"`
}
