package scan

import (
	"net/url"
	"regexp"
	"strings"
)

// GitHub 저장소 주소(W4) — 공개 저장소만. 받는 형식:
//
//	https://github.com/<o>/<r>            (.git · 끝 / · www. 허용, ?쿼리 · #조각은 버린다)
//	https://github.com/<o>/<r>/tree/<ref>[/<하위경로>]
//	https://github.com/<o>/<r>/commit/<sha>
//	https://github.com/<o>/<r>/releases/tag/<tag>
//
// ref 에 / 가 들어간 브랜치(feature/x)는 지원하지 않는다 — tree/feature/x 는 ref=feature · 하위경로=x 로 읽히고,
// 내려받기 404 · 폴더 없음 안내에서 그 사실을 알린다.

const defaultCodeload = "https://codeload.github.com"

type RepoRef struct {
	Owner, Repo string
	Ref         string // 비면 기본 브랜치(HEAD)
	Subpath     string // 비면 저장소 전체. 슬래시로 이어진 폴더 경로(앞뒤 / 없음)
}

var (
	ghName    = regexp.MustCompile(`^[\w.-]+$`)    // 소유자 · 저장소
	ghRefPat  = regexp.MustCompile(`^[\w.+-]+$`)   // 브랜치 · 태그 · 커밋 — / 없음
	ghPathSeg = regexp.MustCompile(`^[\w.@+~-]+$`) // 하위 경로 한 조각
)

const ghHint = "https://github.com/<소유자>/<저장소> 형식으로 써 주세요(브랜치 · 폴더는 …/tree/<브랜치>/<폴더>, 커밋은 …/commit/<sha>, 릴리스는 …/releases/tag/<태그>)"

func ParseGitHubURL(raw string) (RepoRef, error) {
	s := strings.TrimSpace(raw)
	if i := strings.IndexAny(s, "?#"); i >= 0 {
		s = s[:i]
	}
	var rest string
	switch {
	case strings.HasPrefix(s, "https://github.com/"):
		rest = strings.TrimPrefix(s, "https://github.com/")
	case strings.HasPrefix(s, "https://www.github.com/"):
		rest = strings.TrimPrefix(s, "https://www.github.com/")
	default:
		return RepoRef{}, bad("%s", ghHint)
	}
	parts := strings.Split(strings.TrimSuffix(rest, "/"), "/")
	if len(parts) < 2 || !validName(parts[0]) || !validName(strings.TrimSuffix(parts[1], ".git")) {
		return RepoRef{}, bad("%s", ghHint)
	}
	r := RepoRef{Owner: parts[0], Repo: strings.TrimSuffix(parts[1], ".git")}
	tail := parts[2:]
	if len(tail) == 0 {
		return r, nil
	}
	var sub []string
	switch tail[0] {
	case "tree":
		if len(tail) < 2 {
			return RepoRef{}, bad("%s", ghHint)
		}
		r.Ref, sub = tail[1], tail[2:]
	case "commit":
		if len(tail) != 2 {
			return RepoRef{}, bad("%s", ghHint)
		}
		r.Ref = tail[1]
	case "releases":
		if len(tail) != 3 || tail[1] != "tag" {
			return RepoRef{}, bad("%s", ghHint)
		}
		r.Ref = tail[2]
	case "blob", "raw":
		return RepoRef{}, bad("파일 하나는 「파일 올리기」로 검사하세요. 저장소 주소는 …/tree/<브랜치>/<폴더> 까지입니다")
	default:
		return RepoRef{}, bad("%s", ghHint)
	}
	if !ghRefPat.MatchString(r.Ref) || strings.Trim(r.Ref, ".") == "" {
		return RepoRef{}, bad("브랜치 · 태그 · 커밋 이름을 확인하세요(브랜치 이름에 / 는 지원하지 않습니다)")
	}
	for _, seg := range sub {
		if !ghPathSeg.MatchString(seg) || strings.Trim(seg, ".") == "" {
			return RepoRef{}, bad("하위 경로 %q 을(를) 읽을 수 없습니다. 폴더 이름만 / 로 이어 주세요(. · .. 조각 불가)", strings.Join(sub, "/"))
		}
	}
	r.Subpath = strings.Join(sub, "/")
	return r, nil
}

func validName(s string) bool { return ghName.MatchString(s) && strings.Trim(s, ".") != "" }

// Tarball: codeload 내려받기 주소(base 는 테스트용 가짜 서버로 바꿀 수 있다)
func (r RepoRef) Tarball(base string) string {
	ref := r.Ref
	if ref == "" {
		ref = "HEAD"
	}
	return base + "/" + url.PathEscape(r.Owner) + "/" + url.PathEscape(r.Repo) + "/tar.gz/" + url.PathEscape(ref)
}

// Label: 화면 표기 — github.com/o/r[@ref][/subpath]
func (r RepoRef) Label() string {
	l := "github.com/" + r.Owner + "/" + r.Repo
	if r.Ref != "" {
		l += "@" + r.Ref
	}
	if r.Subpath != "" {
		l += "/" + r.Subpath
	}
	return l
}

// URL: 정규화한 GitHub 주소(다시 읽어도 같은 RepoRef)
func (r RepoRef) URL() string {
	u := "https://github.com/" + r.Owner + "/" + r.Repo
	if r.Ref != "" {
		u += "/tree/" + r.Ref
		if r.Subpath != "" {
			u += "/" + r.Subpath
		}
	}
	return u
}
