package model

import "time"

// 공급망 검사(10/16) — 패키지 이름 · GitHub 저장소 · 올린 파일을 GuardDog(악성 코드 패턴) · OSV-Scanner(알려진 취약점)로 정적 검사

type ScanTarget struct {
	Kind    string `json:"kind"` // package | repo | file
	Manager string `json:"manager,omitempty"`
	Name    string `json:"name,omitempty"`
	Version string `json:"version,omitempty"`
	URL     string `json:"url,omitempty"`
	// Ref · Subpath: 저장소 검사(W4) — 브랜치 · 태그 · 커밋과 하위 폴더. 비면 기본 브랜치 · 저장소 전체. 라벨은 github.com/o/r@ref/subpath
	Ref      string `json:"ref,omitempty"`
	Subpath  string `json:"subpath,omitempty"`
	FileName string `json:"fileName,omitempty"`
	Size     int64  `json:"size,omitempty"`
	Label    string `json:"label"`
}

// ScanPackage: 결과에 나온 패키지(OSV-Scanner 가 읽은 잠금 · 의존성 파일의 항목) — 저장소 · 파일 검사에서 「차단 목록에 올리기」 후보(W4).
// Manager 는 OSV ecosystem(PyPI → pip · npm · crates.io → cargo), 없으면 잠금 파일 이름으로 추론. 비면 차단 목록이 다루지 않는 생태계
type ScanPackage struct {
	Manager   string `json:"manager"`
	Name      string `json:"name"`
	Version   string `json:"version"`
	Ecosystem string `json:"ecosystem,omitempty"`
	Source    string `json:"source,omitempty"` // 잠금 파일 경로(검사 대상 기준)
	Direct    bool   `json:"direct"`
	Vulns     int    `json:"vulns"`
}

type ScanFinding struct {
	Rule     string `json:"rule"`
	Category string `json:"category"` // threat | capability
	Message  string `json:"message"`
	File     string `json:"file"`
	Line     int    `json:"line"`
	Match    string `json:"match"`
	// Test: 테스트 코드(tests/ · test_*.py 등)에서 나온 탐지 — 위험 점수 · 판정 · 위협 수에 넣지 않는다(11/02)
	Test bool `json:"test,omitempty"`
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
	Verdict    string        `json:"verdict,omitempty"` // malicious | vulnerable | caution | clean (scan/verdict.go)
	Risk       *ScanRisk     `json:"risk"`
	Engines    []ScanEngine  `json:"engines"`
	Findings   []ScanFinding `json:"findings"`
	Vulns      []ScanVuln    `json:"vulns"`
	// Packages: 결과의 패키지 목록(차단 후보, W4) — 목록 응답에서는 뺀다
	Packages []ScanPackage `json:"packages"`
	// Files: 위협이 나온 파일의 코드만(경로 → 내용) — 원본은 검사 뒤 지운다, 결과와 함께 30일
	Files  map[string]string `json:"files"`
	CaseID *string           `json:"caseId"`
	// 목록용 집계
	Threats        int      `json:"threats"`
	Capabilities   int      `json:"capabilities"`
	TestFindings   int      `json:"testFindings"`   // 테스트 코드 탐지 수(점수 제외, 11/02)
	InstallThreats int      `json:"installThreats"` // 설치 시점 규칙(setup-* · exfil · preinstall …)에 걸린 위협 수 — 악성 판정의 근거(11/03)
	VulnCount      int      `json:"vulnCount"`
	VulnMax        *float64 `json:"vulnMax"`
	// Trigger: 누가 시작했나(11/04 종합 판정) — manual(공급망 검사 화면 · API) | install(설치 세션 보고 때 서버가 자동으로)
	Trigger string `json:"trigger"`
	// InstallID: 이 검사를 시작한 설치 세션(trigger=install). 수동 검사는 null
	InstallID *string `json:"installId"`
}

// 정적 검사 트리거
const (
	ScanManual  = "manual"
	ScanInstall = "install"
)

// InstallScan: 설치 세션 응답의 scan(11/04 종합 판정) — 세션의 scanId · scanSkip 과 검사 기록으로 읽을 때 계산한다.
// 옛 세션(둘 다 없음)이거나 검사 기록이 없으면 응답에 scan 필드가 없다(하위 호환)
type InstallScan struct {
	ID     string `json:"id"`     // 건너뜀이면 ""
	Status string `json:"status"` // running | done | failed | skipped
	// Verdict: done 일 때만 — malicious | vulnerable | caution | clean
	Verdict        string   `json:"verdict,omitempty"`
	Label          string   `json:"label"`   // 검사 대상 라벨(건너뜀이면 「매니저 입력」)
	Version        string   `json:"version"` // 받은 버전(최신으로 검사했으면 그 버전)
	RiskScore      *float64 `json:"riskScore"`
	InstallThreats int      `json:"installThreats"`
	Threats        int      `json:"threats"`
	VulnCount      int      `json:"vulnCount"`
	Error          string   `json:"error"`
	Skip           string   `json:"skip"`   // local | unsupported | busy | off | invalid
	Reused         bool     `json:"reused"` // 다른 세션이 시작한 검사에 합류했거나 24시간 안 결과를 재사용
}
