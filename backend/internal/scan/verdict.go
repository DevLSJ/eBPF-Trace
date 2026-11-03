package scan

import (
	"strings"

	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/model"
)

// 판정(11/03 결정) — GuardDog 위험 점수(0~10) 하나로는 인기 패키지가 「악성」이 된다(11/02 sg-vm 실측: pyyaml 8.8 · numpy 7.3 · django 6.7 — 전부
// 동적 로딩 · 환경 변수 읽기 · 난독화 같은 런타임 휴리스틱 규칙). 데모 악성 패키지(8.6)는 설치 시점 규칙(setup.py 의 네트워크 · 유출)에 걸린다.
//
//	malicious  점수 ≥ riskThreshold 이고 설치 시점 규칙에 걸린 위협이 1개 이상
//	vulnerable 알려진 취약점이 있다(자기 버전 · 의존성)
//	caution    점수 ≥ riskThreshold 인데 런타임 휴리스틱 규칙만 — 코드 보기로 확인하라는 뜻
//	clean      그 외
//
// 우선순위는 malicious > vulnerable > caution > clean. 테스트 코드 탐지(Test)는 어디에도 넣지 않는다.
const riskThreshold = 5

// installTimeRules: 설치 · 적재 시점에 실행되거나 밖으로 보내는 행동 — 정상 라이브러리의 본체 코드에는 나오지 않는다.
// threat-process-hooks(설치 훅의 시스템 도구)는 넣지 않는다 — requests 의 setup.py 「publish」 도우미처럼 정상 패키지에도 흔하다(11/02 실측 4.5).
var installTimeRules = []string{
	"threat-setup-",                   // setup.py 의 의심 import · 네트워크 · import 별칭
	"threat-npm-preinstall-script",    // npm preinstall
	"threat-npm-dependency-confusion", // 자기 참조 의존성 · 스크립트의 DNS 유출
	"threat-npm-http-dependency",      // URL 의존성
	"threat-network-exfil",            // exfiltration · exfil-messenger · exfil-sysinfo
	"threat-network-dns-exfil",
	"threat-network-reverse-shell",
	"threat-process-download-exec",
	"threat-runtime-self-propagation",
}

// IsInstallTimeRule: GuardDog 규칙 이름이 설치 시점 규칙인지(접두어 비교)
func IsInstallTimeRule(rule string) bool {
	for _, p := range installTimeRules {
		if strings.HasPrefix(rule, p) {
			return true
		}
	}
	return false
}

// verdictOf: 판정과 설치 시점 위협 수. findings 는 테스트 코드를 뺀 본체 탐지만 넘긴다
func verdictOf(risk *model.ScanRisk, findings []model.ScanFinding, vulnCount int) (verdict string, installThreats int) {
	for _, f := range findings {
		if f.Category == "threat" && !f.Test && IsInstallTimeRule(f.Rule) {
			installThreats++
		}
	}
	risky := risk != nil && risk.Score >= riskThreshold
	switch {
	case risky && installThreats > 0:
		return "malicious", installThreats
	case vulnCount > 0:
		return "vulnerable", installThreats
	case risky:
		return "caution", installThreats
	default:
		return "clean", installThreats
	}
}
