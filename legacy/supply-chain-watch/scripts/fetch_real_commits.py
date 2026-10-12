"""실제 공개 레포 최근 커밋 내려받기 — LLM 호출 비율(게이트 통과율) 측정용 (Phase 4 완료 기준 ≤ 30%).

유명 JS/TS·파이썬 레포의 기본 브랜치 최근 커밋을 gateway와 같은 단건 커밋 API(files[].patch)로 받아 JSON으로 저장한다.
clone하지 않고 코드를 실행하지 않는다. 토큰은 .env의 GITHUB_TOKEN(없으면 `gh auth token`)을 쓰고 출력하지 않는다.
    python3 -I scripts/fetch_real_commits.py data/real-commits 20
"""
from __future__ import annotations

import json
import os
import ssl
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REPOS = [
    # JS/TS
    "expressjs/express", "axios/axios", "vercel/next.js", "facebook/react", "vitejs/vite",
    "webpack/webpack", "nodejs/node", "prettier/prettier", "eslint/eslint", "microsoft/TypeScript",
    # Python
    "psf/requests", "pallets/flask", "django/django", "fastapi/fastapi", "pandas-dev/pandas",
    "pytest-dev/pytest", "python-poetry/poetry", "huggingface/transformers", "pydantic/pydantic", "encode/httpx",
]

try:  # macOS 공식 설치 파이썬은 시스템 인증서가 없을 수 있어 certifi 묶음을 우선 사용
    import certifi

    CTX = ssl.create_default_context(cafile=certifi.where())
except ImportError:
    CTX = ssl.create_default_context()


def token() -> str:
    for line in (ROOT / ".env").read_text(encoding="utf-8").splitlines():
        if line.startswith("GITHUB_TOKEN=") and line.split("=", 1)[1].strip():
            return line.split("=", 1)[1].strip()
    return subprocess.run(["gh", "auth", "token"], capture_output=True, text=True, check=True).stdout.strip()


def get_json(url: str, tok: str):
    req = urllib.request.Request(url, headers={
        "Authorization": f"Bearer {tok}", "Accept": "application/vnd.github+json",
        "User-Agent": "supply-chain-watch-eval/0.1 (capstone research)",
    })
    with urllib.request.urlopen(req, timeout=30, context=CTX) as r:
        remaining = int(r.headers.get("X-RateLimit-Remaining", "1000"))
        if remaining < 100:  # 쿼터 보호 (CLAUDE.md §5-4)
            raise SystemExit(f"GitHub 남은 쿼터 {remaining} — 중단")
        return json.load(r)


def main() -> int:
    out = Path(sys.argv[1])
    per_repo = int(sys.argv[2]) if len(sys.argv) > 2 else 20
    tok = token()
    total = 0
    for repo in REPOS:
        d = out / repo.replace("/", "__")
        d.mkdir(parents=True, exist_ok=True)
        try:
            listing = get_json(f"https://api.github.com/repos/{repo}/commits?per_page={per_repo}", tok)
        except Exception as e:  # noqa: BLE001 — 레포 단위 실패는 건너뜀
            print(f"  {repo}: 목록 실패 {e}")
            continue
        for item in listing:
            dest = d / f"{item['sha']}.json"
            if not dest.exists():
                c = get_json(f"https://api.github.com/repos/{repo}/commits/{item['sha']}", tok)
                dest.write_text(json.dumps({
                    "repo": repo, "sha": c["sha"], "message": c["commit"]["message"],
                    "author": (c.get("author") or {}).get("login") or c["commit"]["author"]["name"],
                    "parents": len(c.get("parents", [])),
                    "files": [{k: f.get(k) for k in ("filename", "status", "additions", "deletions", "patch")} for f in c.get("files", [])],
                }, ensure_ascii=False), encoding="utf-8")
                time.sleep(0.05)
            total += 1
        print(f"  {repo}: {len(list(d.glob('*.json')))}개")
    print(f"real-commits: {total}개 → {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
