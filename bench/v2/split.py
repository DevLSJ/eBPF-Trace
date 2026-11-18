#!/usr/bin/env python3
"""평가 규칙 v2 — 표본 색인을 캠페인 묶음으로 묶고, 구간으로 나누고, 시험 · 예비 구간을 봉인한다.

규칙은 bench/v2/protocol.json 에 먼저 고정했다. 이 파일은 그 규칙의 기계적 구현이다.
표본 내용이나 검사 결과는 보지 않는다 — 색인의 이름 · 날짜 · 코드 파일 해시 · 줄 수만 쓴다. 표준 라이브러리만 쓴다.

  python3 bench/v2/split.py build --index bench/datasets/v2/index.jsonl --source "<출처 · 커밋>"   # → bench/v2/split.json
  python3 bench/v2/split.py status
  python3 bench/v2/split.py unseal test --reason "최종 측정"      # selection.json 이 있고 작업 폴더가 깨끗할 때, 구간마다 한 번
  python3 -B -m unittest discover -s bench/v2 -p 'test_*.py'

색인 한 줄(다음 단계의 수집 도구가 만든다):
  {"id": 표본 파일 sha256 앞 16자, "ecosystem": "pypi"|"npm", "label": "malicious"|"benign", "name": 패키지 이름,
   "date": "YYYY-MM-DD"(악성 = 발견일 · 정상 = 그 판 출시일), "source": 출처 묶음, "codeLines": 코드 줄 수,
   "codeFiles": [{"sha256": 이름을 가린 글의 해시, "bytes": 크기}, ...]}
"""
import argparse
import collections
import datetime as dt
import hashlib
import json
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
PROTOCOL = os.path.join(HERE, "protocol.json")
SEEN = os.path.join(HERE, "seen-groups.json")
SPLIT = os.path.join(HERE, "split.json")
SELECTION = os.path.join(HERE, "selection.json")
LEDGER = os.path.join(HERE, "unseal-log.json")

SEED = 20261112
PARTS = ("train", "calibration", "test", "reserve")
FRACTIONS = {"train": 0.5, "calibration": 0.2, "test": 0.2, "reserve": 0.1}
SEALED = ("test", "reserve")
HELD_OUT = ("test", "reserve", "calibration")  # 채우는 순서 — 처음 받는 표본만 들어간다
MIN_LINK_BYTES = 256  # 이보다 작은 코드 파일은 캠페인 근거로 쓰지 않는다
GIANT_FRACTION = 0.10  # 한 묶음이 그 층 시험 목표의 이 비율을 넘으면 학습 구간에만
ECOSYSTEMS = ("pypi", "npm")
LABELS = ("malicious", "benign")


class SealedError(Exception):
    """봉인 규칙을 어기는 요청."""


def sha256(b):
    return hashlib.sha256(b).hexdigest()


def norm_name(eco, name):
    """tools/sg-bench-dataset 의 norm_name 과 같은 식(v1 packageGroup 과 맞아야 seen 을 가려낸다)."""
    name = name.lower()
    if eco == "pypi":
        return re.sub(r"[-_.]+", "-", name)
    return name.replace("@", "/").lstrip("/") if name.startswith("@") else name


def name_group(eco, name):
    return sha256((eco + ":" + norm_name(eco, name)).encode())[:8]


def read_jsonl(path):
    with open(path, encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def validate(rows):
    seen_ids = set()
    for i, r in enumerate(rows):
        where = f"색인 {i + 1}번째 줄"
        for k in ("id", "ecosystem", "label", "name", "codeFiles", "codeLines"):
            if k not in r:
                raise ValueError(f"{where}: {k} 가 없다")
        if r["ecosystem"] not in ECOSYSTEMS or r["label"] not in LABELS:
            raise ValueError(f"{where}: ecosystem · label 값이 규칙 밖이다")
        if not isinstance(r["codeLines"], int) or r["codeLines"] < 0:
            raise ValueError(f"{where}: codeLines 는 0 이상의 정수")
        if r["id"] in seen_ids:
            raise ValueError(f"{where}: id {r['id']} 가 두 번 나온다")
        seen_ids.add(r["id"])


def fingerprint(row):
    """코드 파일 해시(0바이트 제외)를 정렬해 이은 글의 해시. 코드 파일이 없으면 None."""
    hashes = sorted(f["sha256"] for f in row["codeFiles"] if f["bytes"] > 0)
    return sha256("\n".join(hashes).encode()) if hashes else None


def dedupe(rows):
    """악성만, 같은 생태계에서 지문이 같으면 날짜가 가장 이른 것(같으면 id 가 작은 것) 하나만 남긴다."""
    kept, dropped, first = [], [], {}
    for r in sorted(rows, key=lambda r: (r.get("date") or "9999-99-99", r["id"])):
        fp = fingerprint(r) if r["label"] == "malicious" else None
        key = (r["ecosystem"], fp)
        if fp and key in first:
            dropped.append({"id": r["id"], "duplicateOf": first[key]})
            continue
        if fp:
            first[key] = r["id"]
        kept.append(r)
    return kept, dropped


def campaign_groups(rows):
    """{id: 묶음 이름}. 같은 생태계에서 이름이 같으면 한 묶음(라벨이 달라도).
    악성끼리는 MIN_LINK_BYTES 이상인 코드 파일 해시가 같아도 한 묶음 — 정상 표본에도 있는 파일은 근거로 쓰지 않는다.
    묶음 이름 = 묶음에서 가장 작은 id."""
    parent = {r["id"]: r["id"] for r in rows}

    def find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(a, b):
        a, b = find(a), find(b)
        if a != b:
            parent[max(a, b)] = min(a, b)

    benign_files = {f["sha256"] for r in rows if r["label"] == "benign" for f in r["codeFiles"]}
    owner = {}
    for r in sorted(rows, key=lambda r: r["id"]):
        keys = [("name", r["ecosystem"], name_group(r["ecosystem"], r["name"]))]
        if r["label"] == "malicious":
            keys += [("file", r["ecosystem"], f["sha256"]) for f in r["codeFiles"]
                     if f["bytes"] >= MIN_LINK_BYTES and f["sha256"] not in benign_files]
        for k in keys:
            if k in owner:
                union(owner[k], r["id"])
            else:
                owner[k] = r["id"]
    return {i: find(i) for i in parent}


def order_key(seed, stratum, group):
    return sha256(f"{seed}:{stratum[0]}:{stratum[1]}:{group}".encode())


def assign(rows, groups, seen, seed=SEED, fractions=None):
    """{id: 구간}. 층 = (생태계, 묶음 라벨). 처음 받는 · 크지 않은 묶음을 정해진 순서로 시험 → 예비 → 보정에 채우고 나머지는 학습."""
    fractions = fractions or FRACTIONS
    members = collections.defaultdict(list)
    for r in rows:
        members[groups[r["id"]]].append(r)
    strata = collections.defaultdict(list)
    for g, ms in members.items():
        label = "malicious" if any(m["label"] == "malicious" for m in ms) else "benign"
        strata[(ms[0]["ecosystem"], label)].append(g)
    out = {}
    for stratum in sorted(strata):
        gs = strata[stratum]
        n = sum(len(members[g]) for g in gs)
        target = {p: round(n * fractions[p]) for p in PARTS}
        giant_over = max(1.0, GIANT_FRACTION * target["test"])
        fresh = [g for g in sorted(gs, key=lambda g: order_key(seed, stratum, g))
                 if len(members[g]) <= giant_over
                 and not any(name_group(m["ecosystem"], m["name"]) in seen for m in members[g])]
        placed, queue = {}, iter(fresh)
        for part in HELD_OUT:
            count = 0
            while count < target[part]:
                g = next(queue, None)
                if g is None:
                    raise ValueError(f"{stratum[0]} · {stratum[1]}: 처음 받는 표본이 모자라 {part} 구간(목표 {target[part]})을 "
                                     f"채울 수 없다(지금 {count})")
                placed[g] = part
                count += len(members[g])
        for g in gs:
            for m in members[g]:
                out[m["id"]] = placed.get(g, "train")
    return out


def list_sha(ids):
    return sha256("\n".join(sorted(ids)).encode())


def build(rows, seen, protocol_bytes, seen_bytes, source=""):
    """색인 → 분할 결과(dict). 같은 입력이면 같은 결과(줄 순서와 무관)."""
    validate(rows)
    kept, dropped = dedupe(rows)
    groups = campaign_groups(kept)
    parts = assign(kept, groups, seen)
    counts = {f"{e}:{lab}": {p: 0 for p in PARTS} for e in ECOSYSTEMS for lab in LABELS}
    sizes = collections.Counter(groups.values())
    for r in kept:
        counts[f"{r['ecosystem']}:{r['label']}"][parts[r["id"]]] += 1
    by_part = {p: [i for i, q in parts.items() if q == p] for p in PARTS}
    return {
        "schema": 2,
        "protocolSha256": sha256(protocol_bytes),
        "seenSha256": sha256(seen_bytes),
        "source": source,
        "seed": SEED,
        "fractions": FRACTIONS,
        "sealed": list(SEALED),
        "rows": len(rows),
        "kept": len(kept),
        "duplicates": sorted(dropped, key=lambda d: d["id"]),
        "groups": len(sizes),
        "largestGroups": sorted(sizes.values(), reverse=True)[:5],
        "counts": counts,
        "indexSha256": list_sha(r["id"] for r in rows),
        "listSha256": {p: list_sha(by_part[p]) for p in PARTS},
        "assignments": {i: parts[i] for i in sorted(parts)},
        "groupOf": {i: groups[i] for i in sorted(groups)},
    }


# ── 봉인 ──

def read_ledger(path=LEDGER):
    if not os.path.exists(path):
        return []
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def opened(ledger):
    return {e["part"] for e in ledger}


def select_ids(split, parts, ledger):
    """구간에 든 표본 id. 봉인 구간은 연 기록이 있을 때만 — 없으면 SealedError."""
    unknown = [p for p in parts if p not in PARTS]
    if unknown:
        raise ValueError(f"없는 구간: {unknown}")
    blocked = [p for p in parts if p in split["sealed"] and p not in opened(ledger)]
    if blocked:
        raise SealedError(f"봉인 구간 {blocked} 은 `split.py unseal` 로 연 뒤에만 쓸 수 있다")
    want = set(parts)
    return sorted(i for i, p in split["assignments"].items() if p in want)


def unseal(part, reason, *, split_bytes, protocol_bytes, selection_path=SELECTION, ledger_path=LEDGER,
           head="", dirty=False, now=None):
    """봉인 구간을 한 번 연다. 기록을 ledger 에 더하고 그 항목을 돌려준다."""
    if part not in SEALED:
        raise ValueError(f"{part} 는 봉인 구간이 아니다")
    if not reason.strip():
        raise ValueError("여는 사유를 적어야 한다")
    ledger = read_ledger(ledger_path)
    if part in opened(ledger):
        raise SealedError(f"{part} 구간은 이미 한 번 열었다 — 다시 재면 「이미 본 구간 재사용」이다")
    if part == "reserve" and "test" not in opened(ledger):
        raise SealedError("예비 구간은 시험 구간을 연 뒤에만 열 수 있다")
    if not os.path.exists(selection_path):
        raise SealedError("운영점 선택 파일(selection.json)이 없다 — 보정 구간에서 고르고 커밋한 뒤에만 열 수 있다")
    if dirty:
        raise SealedError("작업 폴더에 커밋하지 않은 변경이 있다 — 최종 측정은 커밋된 코드로만 한다")
    with open(selection_path, "rb") as f:
        selection_sha = sha256(f.read())
    entry = {
        "part": part,
        "at": (now or dt.datetime.now(dt.timezone.utc)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "reason": reason.strip(),
        "protocolSha256": sha256(protocol_bytes),
        "splitSha256": sha256(split_bytes),
        "selectionSha256": selection_sha,
        "gitHead": head,
    }
    ledger.append(entry)
    with open(ledger_path, "w", encoding="utf-8") as f:
        json.dump(ledger, f, ensure_ascii=False, indent=1)
        f.write("\n")
    return entry


# ── 명령 ──

def _read(path):
    with open(path, "rb") as f:
        return f.read()


def _git(*args):
    return subprocess.run(["git", "-C", ROOT, *args], capture_output=True, text=True).stdout.strip()


def cmd_build(args):
    if os.path.exists(SPLIT) and not args.force:
        sys.exit("bench/v2/split.json 이 이미 있다 — 분할은 한 번만 만든다(규칙 revisions). 정말 다시 만들려면 --force 와 사유 기록")
    seen_bytes = _read(SEEN)
    result = build(read_jsonl(args.index), set(json.loads(seen_bytes)["groups"]), _read(PROTOCOL), seen_bytes, args.source)
    write_split(result, SPLIT)
    print_status(result, read_ledger())


LONG_KEYS = ("duplicates", "assignments", "groupOf")


def write_split(result, path):
    """split.json — 요약은 줄을 나눠 읽기 쉽게, 긴 표(LONG_KEYS)는 한 줄씩."""
    head = {k: v for k, v in result.items() if k not in LONG_KEYS}
    with open(path, "w", encoding="utf-8") as f:
        f.write(json.dumps(head, ensure_ascii=False, indent=1)[:-2])  # 끝의 "\n}" 를 떼고 긴 표를 잇는다
        for k in LONG_KEYS:
            f.write(",\n " + json.dumps(k) + ": " + json.dumps(result[k], ensure_ascii=False, separators=(",", ":")))
        f.write("\n}\n")


def print_status(split, ledger):
    print(f"표본 {split['rows']} → 중복 제거 뒤 {split['kept']} · 묶음 {split['groups']} · 가장 큰 묶음 {split['largestGroups']}")
    for stratum, c in split["counts"].items():
        print(f"  {stratum:16s} " + " · ".join(f"{p} {c[p]}" for p in PARTS))
    done = opened(ledger)
    print("봉인: " + " · ".join(f"{p} {'열림' if p in done else '봉인'}" for p in split["sealed"]))


def cmd_status(_args):
    print_status(json.loads(_read(SPLIT)), read_ledger())


def cmd_unseal(args):
    dirty = bool(_git("status", "--porcelain", "--", "bench", "backend", "tools"))
    try:
        entry = unseal(args.part, args.reason, split_bytes=_read(SPLIT), protocol_bytes=_read(PROTOCOL),
                       head=_git("rev-parse", "HEAD"), dirty=dirty)
    except SealedError as e:
        sys.exit(f"거부: {e}")
    print(f"{entry['part']} 구간을 열었다({entry['at']}). bench/v2/unseal-log.json 을 커밋하라")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    b = sub.add_parser("build", help="색인 → split.json")
    b.add_argument("--index", required=True)
    b.add_argument("--source", default="", help="데이터 출처 · 커밋 · 받은 날(그대로 기록)")
    b.add_argument("--force", action="store_true")
    b.set_defaults(fn=cmd_build)
    sub.add_parser("status", help="구간별 수 · 봉인 상태").set_defaults(fn=cmd_status)
    u = sub.add_parser("unseal", help="봉인 구간을 한 번 연다")
    u.add_argument("part", choices=SEALED)
    u.add_argument("--reason", required=True)
    u.set_defaults(fn=cmd_unseal)
    args = ap.parse_args()
    args.fn(args)


if __name__ == "__main__":
    main()
