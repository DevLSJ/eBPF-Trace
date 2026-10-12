"""Diff 파싱·언어 판별·파일 분류 (docs/03 §2).

입력 diff는 두 형식을 모두 받는다.
- gateway 형식: `diff --- path (status, +a -d)` 헤더 + GitHub patch(@@ hunk)
- git 형식(코퍼스): `diff --git a/x b/x` … `+++ b/x` … @@ hunk
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import PurePosixPath

_GATEWAY_HDR = re.compile(r"^diff --- (?P<path>.+?) \((?P<status>[a-z_]+), \+\d+ -\d+\)$")
_GIT_HDR = re.compile(r"^diff --git a/(?P<a>.+?) b/(?P<path>.+)$")
_MARKERS = ("…[파일 절삭]",)

_JS = {".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".mts", ".cts"}
_SHELL = {".sh", ".bash", ".zsh", ".ksh"}
_CONFIG = {".json", ".yaml", ".yml", ".toml", ".cfg", ".ini"}
_DOC_EXT = {".md", ".rst", ".adoc"}

_TEST_RE = re.compile(r"(^|/)(tests?|__tests__|specs?|fixtures?)/|\.(test|spec)\.[cm]?[jt]sx?$|(^|/)test_[^/]*\.py$|_test\.py$")
_DOC_RE = re.compile(r"(^|/)(docs?|examples?)/|(^|/)(README|CHANGELOG|LICENSE|CONTRIBUTING)[^/]*$", re.I)
_INSTALL_RE = re.compile(
    r"(^|/)(package\.json|setup\.py|setup\.cfg|pyproject\.toml|Makefile|GNUmakefile|"
    r"(pre|post)?install\.(js|sh|py|mjs|cjs))$|^\.github/workflows/|(^|/)Dockerfile[^/]*$"
)
# docs/03 §2 민감 파일 — 변경 자체가 LLM 트리거
_SENSITIVE_RE = re.compile(
    r"(^|/)(package\.json|setup\.py|setup\.cfg|pyproject\.toml|\.npmrc|\.pypirc|Dockerfile[^/]*|"
    r"docker-compose[^/]*\.ya?ml|Makefile|index\.js|main\.js|__init__\.py)$|^\.github/workflows/|"
    r"(^|/)bin/|(^|/)\.env[^/]*$|\.pem$|\.key$|(^|/)credentials[^/]*$",
    re.I,
)


@dataclass
class ParsedFile:
    path: str
    status: str = "modified"
    lang: str = "OTHER"
    added: list[str] = field(default_factory=list)
    removed: list[str] = field(default_factory=list)

    @property
    def is_test(self) -> bool:
        return bool(_TEST_RE.search(self.path))

    @property
    def is_doc(self) -> bool:
        suffix = PurePosixPath(self.path).suffix.lower()
        return suffix in _DOC_EXT or bool(_DOC_RE.search(self.path))

    @property
    def is_install_or_ci(self) -> bool:
        return bool(_INSTALL_RE.search(self.path))

    @property
    def is_sensitive(self) -> bool:
        return bool(_SENSITIVE_RE.search(self.path))

    @property
    def multiplier(self) -> float:
        """docs/03 §3.3 파일 가중치: 설치 훅/CI 1.5, 테스트 0.5, 문서 0.2."""
        if self.is_doc:
            return 0.2
        if self.is_test:
            return 0.5
        if self.is_install_or_ci:
            return 1.5
        return 1.0


def detect_lang(path: str, first_line: str = "") -> str:
    p = PurePosixPath(path)
    name, suffix = p.name, p.suffix.lower()
    if path.startswith(".github/workflows/") and suffix in (".yml", ".yaml"):
        return "WORKFLOW"
    if name.startswith("Dockerfile") or name.endswith(".dockerfile") or suffix == ".dockerfile":
        return "DOCKER"
    if name in ("Makefile", "GNUmakefile") or suffix == ".mk":
        return "MAKE"
    if suffix in _JS:
        return "JS"
    if suffix == ".py":
        return "PY"
    if suffix in _SHELL:
        return "SHELL"
    if first_line.startswith("#!"):
        if re.search(r"\b(ba|z|k|da)?sh\b", first_line):
            return "SHELL"
        if "python" in first_line:
            return "PY"
        if "node" in first_line:
            return "JS"
    if suffix in _CONFIG or re.fullmatch(r"requirements[\w.-]*\.txt", name) or name in (".npmrc", ".pypirc"):
        return "CONFIG"
    return "OTHER"


def parse_diff(diff: str, statuses: dict[str, str] | None = None) -> list[ParsedFile]:
    files: list[ParsedFile] = []
    cur: ParsedFile | None = None
    in_hunk = False
    for line in diff.splitlines():
        m = _GATEWAY_HDR.match(line) or _GIT_HDR.match(line)
        if m:
            cur = ParsedFile(path=m.group("path"), status=m.groupdict().get("status") or "modified")
            files.append(cur)
            in_hunk = False
            continue
        if cur is None:
            continue
        if line.startswith("@@"):
            in_hunk = True
            continue
        if not in_hunk:
            # git 헤더 영역 (index/---/+++/new file mode)
            if line.startswith("new file mode"):
                cur.status = "added"
            elif line.startswith("deleted file mode"):
                cur.status = "removed"
            continue
        if line in _MARKERS:
            continue
        if line.startswith("+"):
            cur.added.append(line[1:])
        elif line.startswith("-"):
            cur.removed.append(line[1:])
    for f in files:
        if statuses and f.path in statuses:
            f.status = statuses[f.path]
        f.lang = detect_lang(f.path, f.added[0] if f.added else "")
    return files
