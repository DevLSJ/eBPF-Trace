"""평가 규칙 v3 — v2 · v3 데이터 폴더 가르기(표준 라이브러리만). 글자 비교가 아니라 파일 동일성(os.path.samefile)으로 본다:
대소문자를 가리지 않는 파일 시스템 · 심볼릭 링크 · 아직 없는 하위 경로도 같은 곳으로 잡는다."""
import os


class GuardError(Exception):
    """v3 도구가 v2 데이터 폴더를 대상으로 하거나 v2 데이터 폴더를 찾지 못했다."""


def same_or_inside(path, folder):
    """path 가 folder 와 같은 곳이거나 그 안인가. 아직 없는 경로는 있는 조상까지 올라가 본다."""
    if not os.path.exists(folder):
        return False
    p = os.path.abspath(path)
    while True:
        if os.path.exists(p) and os.path.samefile(p, folder):
            return True
        parent = os.path.dirname(p)
        if parent == p:
            return False
        p = parent


def check(data, v2):
    """v3 데이터 폴더(data)를 써도 되는가. v2 데이터 폴더가 없거나(worktree 에서 SG_BENCH_V2_DATA 를 주지 않은 경우 포함),
    data 가 v2 와 같은 곳 · 그 안 · 그 위면 GuardError."""
    if not os.path.isdir(v2):
        raise GuardError(f"v2 데이터 폴더가 없다({v2}) — SG_BENCH_V2_DATA 에 메인 작업 폴더의 bench/datasets/v2 를 준다")
    if same_or_inside(data, v2):
        raise GuardError(f"v3 데이터 폴더({data})가 v2 데이터 폴더와 같은 곳이거나 그 안이다 — SG_BENCH_DATA 를 확인하라")
    if same_or_inside(v2, data):
        raise GuardError(f"v3 데이터 폴더({data})가 v2 데이터 폴더를 품고 있다 — SG_BENCH_DATA 를 확인하라")
