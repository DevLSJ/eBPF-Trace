#!/usr/bin/env python3
"""평가 규칙 v3 — v2 층 도구를 v3 분할 · v3 데이터로 돌리는 진입점(코드는 v2 것 그대로, 규약 폴더 · 데이터 폴더만 바꾼다).

  python3 -B bench/v3/run.py run_static run --parts train calibration --api http://127.0.0.1:8010/api
  bench/.venv/bin/python -B bench/v3/run.py rules_layer run --part train
  bench/.venv/bin/python -B bench/v3/run.py static_ml train
  bench/.venv/bin/python -B bench/v3/run.py llm_input build --part calibration --out … --order-seed 20261118 …
  bench/.venv/bin/python -B bench/v3/run.py llm_layer run --part calibration --budget 45 --reuse … …

SG_BENCH_RULES = bench/v3(split.json · selection.json · unseal-log.json), SG_BENCH_DATA = v3 데이터 폴더(이미 있으면 그 값,
없으면 bench/datasets/v3). v2 데이터 폴더(SG_BENCH_V2_DATA, 없으면 bench/datasets/v2)가 없거나 v3 데이터 폴더와 같은 곳이면
(파일 동일성 — bench/v3/guard.py) 도구를 띄우지 않는다. llm_layer run 에는 늘 --strict-order(앞쪽부터 자르기, 규약 rev 2)를 붙인다.
분할 · 봉인 · 수집은 v2 도구가 아니라 split3.py · collect3.py 로 한다.
"""
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import guard  # noqa: E402

V2 = os.path.join(os.path.dirname(HERE), "v2")
TOOLS = ("run_static", "rules_layer", "static_ml", "llm_input", "llm_layer")
DEFAULT_DATA = os.path.join(os.path.dirname(HERE), "datasets", "v3")
DEFAULT_V2_DATA = os.path.join(os.path.dirname(HERE), "datasets", "v2")
SPLIT = os.path.join(HERE, "split.json")
STRICT = "--strict-order"


def tool_env(environ=None):
    """v2 도구에 넘길 환경: 규약 폴더는 bench/v3, 데이터 폴더는 SG_BENCH_DATA 가 있으면 그것, 없으면 bench/datasets/v3."""
    env = dict(os.environ if environ is None else environ)
    env["SG_BENCH_RULES"] = HERE
    env["SG_BENCH_DATA"] = env.get("SG_BENCH_DATA") or DEFAULT_DATA
    env["SG_BENCH_V3_ENTRY"] = "1"
    return env


def command(tool, args):
    """층 도구만 — 분할 · 수집 도구(split · collect)는 v3 에서 부르지 않는다."""
    if tool not in TOOLS:
        raise ValueError(f"{tool} 은 v3 진입점으로 돌리는 도구가 아니다({' · '.join(TOOLS)}). 분할 · 봉인은 split3.py, 수집은 collect3.py")
    args = list(args)
    if tool == "llm_layer" and args[:1] == ["run"] and STRICT not in args:
        args.append(STRICT)  # v3 의 비용 상한 끝자락은 늘 앞쪽부터 자른다(protocol rev 2 layers.llm.order)
    return [sys.executable, "-B", os.path.join(V2, tool + ".py"), *args]


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if not argv:
        sys.exit(__doc__)
    try:
        cmd = command(argv[0], argv[1:])
    except ValueError as e:
        sys.exit(f"거부: {e}")
    env = tool_env()
    try:
        guard.check(env["SG_BENCH_DATA"], os.environ.get("SG_BENCH_V2_DATA") or DEFAULT_V2_DATA)
    except guard.GuardError as e:
        sys.exit(f"거부: {e}")
    if not os.path.exists(SPLIT):
        sys.exit("거부: bench/v3/split.json 이 없다 — 먼저 split3.py build · seal")
    return subprocess.run(cmd, env=env).returncode


if __name__ == "__main__":
    sys.exit(main())
