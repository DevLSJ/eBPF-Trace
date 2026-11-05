package chat

import (
	"regexp"
	"strings"

	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/model"
)

// Plan: 규칙 분류 결과. Tool 이 비면(IntentUnknown) 모델 도구 호출 1회로 고른다. IntentPage · IntentUsage 는 도구 없이 고정 문구
type Plan struct {
	Intent Intent
	Tool   string
	Args   map[string]string
}

var (
	rePage    = regexp.MustCompile(`이\s*화면|이\s*페이지|여기는|여긴|무슨\s*화면|어떤\s*화면|뭘\s*하는\s*곳|뭐\s*하는\s*곳|무엇을\s*하는\s*곳`)
	rePending = regexp.MustCompile(`판정\s*대기|대기\s*중|처리할|할\s*일|판정할`)
	reWhy     = regexp.MustCompile(`왜|이유|격리\s*됐|격리\s*되었|걸렸|경고\s*났|경고가\s*났|막혔|죽었|종료\s*됐`)
	// reUsage: 사용법 · 명령을 묻는 말. 「어떻게 됐어」(기록) · 「실행한 명령」(관찰 데이터)은 걸리지 않게 동사를 좁힌다
	reUsage = regexp.MustCompile(`사용법|명령어|쓰는\s*법|하는\s*법|방법|하는\s*명령|명령.{0,6}(알려|가르쳐)|하려면|` +
		`어떻게\s*(하|해|써|쓰|돌리|돌려|실행|시작|켜|끄|바꾸|바꿔|고치|고쳐|추가|적용|만들|설치|검사|스캔|풀|해제)`)
	reInstall   = regexp.MustCompile(`(?i)sg-install|설치`)
	reScan      = regexp.MustCompile(`(?i)공급망|검사|스캔|scan|guarddog|osv`)
	reBlocklist = regexp.MustCompile(`(?i)차단\s*목록|차단된|blocklist|블록\s*리스트`)
	rePolicy    = regexp.MustCompile(`(?i)정책|규칙|룰|rule`)
	reTop       = regexp.MustCompile(`(?i)가장\s*많이|제일\s*많이|많이\s*걸린|자주|순위|top`)
	reSummary   = regexp.MustCompile(`요약|종합|수집|통계|몇\s*건|얼마나|현황|오늘|이번\s*주|일주일|하루`)
	reRange1h   = regexp.MustCompile(`(?i)1\s*시간|한\s*시간|\b1h\b`)
	reRange7d   = regexp.MustCompile(`(?i)일주일|7\s*일|이번\s*주|주간|\b7d\b`)
	reToken     = regexp.MustCompile(`[A-Za-z0-9][A-Za-z0-9_.:/-]*[A-Za-z0-9]`)
	reScanID    = regexp.MustCompile(`^scan-\d+$`)
)

// stopTokens: 컨테이너 · 정책 이름으로 보지 않는 영문 낱말
var stopTokens = map[string]bool{
	"pip": true, "npm": true, "cargo": true, "ebpf": true, "supplyguard": true, "sg-install": true, "scan": true,
	"osv": true, "guarddog": true, "dns": true, "top": true, "rule": true, "blocklist": true, "api": true,
}

// Classify: 질문 → 의도 · 도구 · 인자(규칙 기반 키워드). cases 는 건 라벨(「pip ./reqeusts」)로 컨테이너를 찾는 데 쓴다
func Classify(q string, cases []model.Case) Plan {
	toks := tokens(q)
	switch {
	case rePage.MatchString(q):
		return Plan{Intent: IntentPage}
	}
	for _, t := range toks {
		if reScanID.MatchString(t) {
			return Plan{Intent: IntentScan, Tool: ToolScan, Args: map[string]string{"id": t}}
		}
	}
	switch {
	case rePending.MatchString(q):
		return Plan{Intent: IntentPending, Tool: ToolPending}
	case reWhy.MatchString(q) && len(toks) > 0:
		return Plan{Intent: IntentWhy, Tool: ToolAudit, Args: map[string]string{"container": resolveContainer(toks, cases)}}
	case reWhy.MatchString(q) && strings.Contains(q, "격리"):
		return Plan{Intent: IntentPending, Tool: ToolPending} // 이름 없는 「왜 격리됐어?」 → 지금 열린 건부터
	case reUsage.MatchString(q):
		return Plan{Intent: IntentUsage, Args: map[string]string{"topic": usageTopic(q)}}
	case reScan.MatchString(q):
		return Plan{Intent: IntentScan, Tool: ToolLatestScan}
	case reBlocklist.MatchString(q):
		return Plan{Intent: IntentBlocklist, Tool: ToolBlocklist}
	case rePolicy.MatchString(q):
		if !reTop.MatchString(q) && len(toks) > 0 {
			return Plan{Intent: IntentPolicy, Tool: ToolPolicy, Args: map[string]string{"id": toks[0]}}
		}
		return Plan{Intent: IntentSummary, Tool: ToolSummary, Args: map[string]string{"range": rangeOf(q)}}
	case reSummary.MatchString(q) || reTop.MatchString(q):
		return Plan{Intent: IntentSummary, Tool: ToolSummary, Args: map[string]string{"range": rangeOf(q)}}
	}
	return Plan{Intent: IntentUnknown}
}

func tokens(q string) []string {
	out := []string{}
	for _, t := range reToken.FindAllString(q, -1) {
		if len(t) < 3 || stopTokens[strings.ToLower(t)] || onlyDigits(t) {
			continue
		}
		out = append(out, t)
	}
	return out
}

func onlyDigits(s string) bool {
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// resolveContainer: 낱말이 건의 컨테이너 · 라벨에 들어 있으면 그 건의 컨테이너 이름(최신 건 우선), 아니면 첫 낱말 그대로
func resolveContainer(toks []string, cases []model.Case) string {
	for _, t := range toks {
		for _, c := range cases {
			if c.Container == t {
				return c.Container
			}
		}
	}
	for _, t := range toks {
		for _, c := range cases {
			if c.Container != "" && (strings.Contains(c.Label, t) || strings.Contains(c.Container, t)) {
				return c.Container
			}
		}
	}
	return toks[0]
}

func rangeOf(q string) string {
	switch {
	case reRange1h.MatchString(q):
		return "1h"
	case reRange7d.MatchString(q):
		return "7d"
	}
	return "24h"
}

// --- 화면 설명(모델 없이 서버 고정 문구, 목업 chat.js PAGES 와 같은 뜻) ---

var pageTexts = map[string]string{
	"/":         "대시보드는 지금 처리할 일(판정 대기)과 eBPF 수집 종합을 보여 줍니다.",
	"/installs": "설치 검사는 sg-install 로 감시 컨테이너에서 패키지를 실제 설치해 보며 eBPF 로 행동을 관찰한 결과입니다.",
	"/scans":    "공급망 검사는 설치 전에 GuardDog · OSV-Scanner 로 코드와 의존성을 정적 검사합니다.",
	"/events":   "이벤트는 지금 걸리고 있는 위반을 실시간으로 보여 줍니다.",
	"/topology": "토폴로지는 런타임 컨테이너가 무엇을 실행 · 열기 · 연결했는지 관계로 보여 줍니다.",
	"/policies": "정책은 무엇을 막을지 정하는 곳입니다. 쉬운 설정으로 고치고 저장 전 확인을 거쳐 적용합니다.",
	"/audit":    "감사 로그는 지난 위반과 판정 · 정책 변경 이력입니다.",
}

const pageSuffix = " 궁금한 컨테이너 · 정책 · 검사 이름을 함께 물어보면 기록을 찾아 답합니다."

// normalizePage: 「#/installs?id=…」 · 「/installs/」 → 「/installs」
func normalizePage(p string) string {
	p = strings.TrimSpace(p)
	p = strings.TrimPrefix(p, "#")
	if i := strings.IndexAny(p, "?#"); i >= 0 {
		p = p[:i]
	}
	if p != "/" {
		p = strings.TrimRight(p, "/")
	}
	if p == "" {
		return "/"
	}
	return p
}

// --- 사용법(모델 없이 서버 고정 문구 — 명령을 모델이 지어내지 않게, 11/05) ---

// usageTopic: 설치(sg-install)가 먼저 — 「설치 전에 검사하는 명령」은 sg-install 이 정적 검사까지 같이 시작한다
func usageTopic(q string) string {
	switch {
	case reInstall.MatchString(q):
		return "install"
	case reScan.MatchString(q) || strings.Contains(q, "저장소"):
		return "scan"
	case rePolicy.MatchString(q):
		return "policy"
	}
	return ""
}

var usageInstall = "설치 검사는 터미널에서 sg-install 로 실행합니다.\n" +
	"```bash\n" +
	"tools/sg-install pip <패키지>     # npm · cargo 도 같음\n" +
	"tools/sg-install pip ./폴더       # 로컬 폴더\n" +
	"```\n" +
	"감시 컨테이너 안에서 설치하며 위반이면 설치가 끝나기 전에 격리하고, 같은 패키지의 공급망 검사도 자동으로 시작합니다. " +
	"백엔드 주소는 SUPPLYGUARD_API, 토큰은 SUPPLYGUARD_SANDBOX_TOKEN 환경 변수로 줍니다. 결과는 「설치 검사」 화면에 나옵니다."

var usageScan = "공급망 검사는 「공급망 검사」 화면에서 「패키지 이름」 · 「저장소 주소」 · 「파일 올리기」 중 하나를 고르고 값을 넣은 뒤 「검사 시작」을 누릅니다(관리자만). " +
	"설치하지 않고 GuardDog · OSV-Scanner 로 코드와 알려진 취약점을 검사해 악성 · 취약 · 주의 · 정상으로 판정합니다."

var usagePolicy = "정책은 「정책」 화면에서 규칙을 고르고 쉬운 설정으로 고친 뒤, 「저장 전 확인」(최근 감사 로그로 결과가 바뀌는 건 확인)을 거쳐 적용합니다(관리자만)."

var usageGeneral = "할 수 있는 일: 설치 검사(터미널에서 「tools/sg-install pip <패키지>」) · 공급망 검사(「공급망 검사」 화면의 「검사 시작」) · 정책 고치기(「정책」 화면). " +
	"「sg-install 사용법」 · 「공급망 검사는 어떻게 해?」처럼 물어보면 자세히 알려 드립니다."

// usageText: 주제별 고정 문구와 관련 화면
func usageText(topic string) (string, []Link) {
	install, scan, policy := Link{"설치 검사", "/installs"}, Link{"공급망 검사", "/scans"}, Link{"정책", "/policies"}
	switch topic {
	case "install":
		return usageInstall, []Link{install, scan}
	case "scan":
		return usageScan, []Link{scan}
	case "policy":
		return usagePolicy, []Link{policy}
	}
	return usageGeneral, []Link{install, scan, policy}
}

func pageText(p string) string {
	t, ok := pageTexts[normalizePage(p)]
	if !ok {
		t = "SupplyGuard 화면입니다."
	}
	return t + pageSuffix
}
