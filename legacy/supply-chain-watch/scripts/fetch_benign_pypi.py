"""정상(대조군) PyPI 패키지 내려받기 — 오탐률 측정용 (scripts/fetch-datasets.sh benign-pypi 가 호출).

다운로드 수 상위 패키지의 최신 wheel(zip)만 받는다. 설치·실행하지 않으며 sdist(setup.py 실행 위험)는 받지 않는다.
    python3 -I scripts/fetch_benign_pypi.py data/benign-pypi 300
"""
from __future__ import annotations

import json
import ssl
import sys
import time
import urllib.request
from pathlib import Path

TOP_URL = "https://hugovk.github.io/top-pypi-packages/top-pypi-packages-30-days.min.json"
MAX_BYTES = 15 * 1024 * 1024  # torch 등 초대형 바이너리 휠 제외
UA = {"User-Agent": "supply-chain-watch-eval/0.1 (capstone research)"}

try:  # macOS 공식 설치 파이썬은 시스템 인증서가 없을 수 있어 certifi 묶음을 우선 사용
    import certifi

    CTX = ssl.create_default_context(cafile=certifi.where())
except ImportError:
    CTX = ssl.create_default_context()


def get_json(url: str) -> dict:
    with urllib.request.urlopen(urllib.request.Request(url, headers=UA), timeout=30, context=CTX) as r:
        return json.load(r)


def pick_wheel(meta: dict) -> dict | None:
    wheels = [u for u in meta.get("urls", []) if u.get("packagetype") == "bdist_wheel" and u.get("size", 0) <= MAX_BYTES]
    if not wheels:
        return None
    # 순수 파이썬 휠 우선, 다음은 작은 것
    return sorted(wheels, key=lambda u: ("none-any" not in u["filename"], u["size"]))[0]


def main() -> int:
    out = Path(sys.argv[1])
    want = int(sys.argv[2]) if len(sys.argv) > 2 else 300
    out.mkdir(parents=True, exist_ok=True)
    names = [row["project"] for row in get_json(TOP_URL)["rows"]]
    have = {p.name.split("-")[0].lower().replace("_", "-") for p in out.glob("*.whl")}
    got = len(list(out.glob("*.whl")))
    skipped = 0
    for name in names:
        if got >= want:
            break
        if name.lower().replace("_", "-") in have:
            continue
        try:
            wheel = pick_wheel(get_json(f"https://pypi.org/pypi/{name}/json"))
        except Exception:  # noqa: BLE001 — 개별 실패는 건너뜀
            skipped += 1
            continue
        if wheel is None:
            skipped += 1
            continue
        dest = out / wheel["filename"]
        if not dest.exists():
            with urllib.request.urlopen(urllib.request.Request(wheel["url"], headers=UA), timeout=120, context=CTX) as r:
                dest.write_bytes(r.read())
            time.sleep(0.1)
        got += 1
    print(f"benign-pypi: {got}개 보유 (휠 없음·초대형 {skipped}개 건너뜀) → {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
