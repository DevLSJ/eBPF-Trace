#!/usr/bin/env python3
"""평가 규칙 v3 — v2 분할을 그대로 잇고 새 표본만 나눈다 · 봉인 · v2 결과 옮기기 · 시험 구간 개봉. 규칙은 bench/v3/protocol.json.

색인의 이름 · 라벨 · 코드 파일 해시만 쓴다(표본 파일은 열지 않는다). 표준 라이브러리만 쓴다.

  python3 -B bench/v3/split3.py build --source "$(python3 -B bench/v3/collect3.py source-line)"   # → bench/v3/split.json(한 번만)
  python3 -B bench/v3/split3.py seal              # 새 시험 · 예비 파일을 sealed/ 로, v2 파일은 상대 링크, 합친 index.jsonl
  python3 -B bench/v3/split3.py inherit-results   # v2 학습 · 보정의 정적 · 규칙 결과 줄을 v3 결과 파일로(같은 엔진 · 같은 표본)
  python3 -B bench/v3/split3.py status
  python3 -B bench/v3/split3.py unseal test --reason "최종 측정"   # selection.json 커밋 뒤 · 깨끗한 작업 폴더에서 한 번. 예비는 열지 않는다

데이터 폴더: SG_BENCH_DATA(없으면 bench/datasets/v3) · v2 데이터 폴더: SG_BENCH_V2_DATA(없으면 bench/datasets/v2, 읽기만).
"""
import argparse
import collections
import hashlib
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
V2 = os.path.join(os.path.dirname(HERE), "v2")
sys.path.insert(0, V2)
sys.path.insert(0, HERE)
import collect  # noqa: E402
import guard  # noqa: E402
import rules_layer  # noqa: E402
import run_static  # noqa: E402
import split  # noqa: E402

ROOT = split.ROOT
SEED = 20261118
NEVER = ("reserve",)  # v3 에서는 열지 않는 구간(protocol sealing.reserve)
PROTOCOL3 = os.path.join(HERE, "protocol.json")
SPLIT3 = os.path.join(HERE, "split.json")
SELECTION3 = os.path.join(HERE, "selection.json")
LEDGER3 = os.path.join(HERE, "unseal-log.json")
V2_SPLIT = os.path.join(split.HERE, "split.json")  # split.SPLIT 는 SG_BENCH_RULES 를 따르므로 v2 파일은 경로를 적어 쓴다
V2_SEEN = os.path.join(split.HERE, "seen-groups.json")
DEFAULT_DATA = os.path.join(ROOT, "bench", "datasets", "v3")
DEFAULT_V2_DATA = os.path.join(ROOT, "bench", "datasets", "v2")
LONG_KEYS = ("duplicates", "excluded", "inheritedIds", "assignments", "groupOf")
WHY = {"file": "v2 같은 파일", "print": "v2 지문", "new": "새 표본끼리 지문"}


class Stop(Exception):
    """멈춰야 하는 상황(파일 없음 · 폴더 잘못 · 링크가 다른 곳을 가리킴). 아무것도 바꾸지 않고 멈춘다."""


def v2_data_dir():
    return os.path.abspath(os.environ.get("SG_BENCH_V2_DATA") or DEFAULT_V2_DATA)


def check_folders(data, v2_data):
    """guard.check — v2 데이터 폴더가 있고, v3 데이터 폴더가 그것과 (파일 동일성으로) 겹치지 않을 때만."""
    try:
        guard.check(data, v2_data)
    except guard.GuardError as e:
        raise Stop(str(e)) from None


def data_dir():
    """v3 데이터 폴더. v2 데이터 폴더가 없거나 v2 와 같은 곳 · 그 안이면 거부한다 — v2 표본 · 결과를 덮어쓰지 않게."""
    data = os.path.abspath(os.environ.get("SG_BENCH_DATA") or DEFAULT_DATA)
    check_folders(data, v2_data_dir())
    return data


def sha256_file(path):
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


# ── 분할(순수) ──

def drop_known(new_rows, v2_rows, kept_ids=()):
    """v2 와 겹치는 새 표본을 버린다 → (남은 줄, 버린 기록). 같은 파일(같은 id)이면 「v2 같은 파일」,
    악성인데 같은 생태계 v2 악성과 지문이 같으면 「v2 지문」(v2 표본이 남는다 — 새 표본의 날짜가 더 일러도). 정상은 지문으로 버리지 않는다."""
    ids = {r["id"] for r in v2_rows}
    prints = {}
    for r in sorted(v2_rows, key=lambda r: (r["id"] not in kept_ids, r["id"])):  # 분할에 든 v2 표본을 먼저 가리킨다
        fp = split.fingerprint(r) if r["label"] == "malicious" else None
        if fp:
            prints.setdefault((r["ecosystem"], fp), r["id"])
    kept, dropped = [], []
    for r in sorted(new_rows, key=lambda r: r["id"]):
        fp = split.fingerprint(r) if r["label"] == "malicious" else None
        if r["id"] in ids:
            dropped.append({"id": r["id"], "duplicateOf": r["id"], "why": WHY["file"]})
        elif fp and (r["ecosystem"], fp) in prints:
            dropped.append({"id": r["id"], "duplicateOf": prints[(r["ecosystem"], fp)], "why": WHY["print"]})
        else:
            kept.append(r)
    return kept, dropped


def _benign_files(rows):
    return {f["sha256"] for r in rows if r["label"] == "benign" for f in r["codeFiles"]}


def link(new_rows, v2_kept, v2_split, seen, benign_files):
    """새 묶음 → (그 묶음의 v2 묶음 이름들, 이어진 구간 집합 T). 새 묶음은 새 표본끼리만 이은 것(v2 묶음 규칙)."""
    groups = split.campaign_groups(new_rows, benign_files=benign_files)
    owner = collections.defaultdict(set)
    for r in v2_kept:
        for k in split.link_keys(r, benign_files):
            owner[k].add(v2_split["groupOf"][r["id"]])
    part_of = {v2_split["groupOf"][i]: p for i, p in v2_split["assignments"].items()}
    touched, parts = collections.defaultdict(set), collections.defaultdict(set)
    for r in new_rows:
        g = groups[r["id"]]
        touched[g].update(*(owner.get(k, ()) for k in split.link_keys(r, benign_files)))
        if split.name_group(r["ecosystem"], r["name"]) in seen:
            parts[g].add("train")
    for g, gs in touched.items():
        parts[g].update(part_of[x] for x in gs)
    return groups, touched, parts


def _group_names(v2_split, new_rows, groups, touched, inherited_groups):
    """v3 묶음 이름 {id: 이름}: 이어받은 새 묶음은 이어진 v2 묶음과 한 묶음, 이름은 합친 묶음에서 가장 작은 id."""
    parent = {}

    def find(x):
        parent.setdefault(x, x)
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    for g in inherited_groups:
        for v in touched.get(g, ()):
            a, b = find(g), find(v)
            if a != b:
                parent[max(a, b)] = min(a, b)
    label = {i: find(g) for i, g in v2_split["groupOf"].items() if i in v2_split["assignments"]}
    label.update({r["id"]: find(groups[r["id"]]) for r in new_rows})
    smallest = {}
    for i, lab in label.items():
        smallest[lab] = min(smallest.get(lab, i), i)
    return {i: smallest[lab] for i, lab in label.items()}


def build(new_rows, v2_rows, v2_split, seen, *, protocol_bytes=b"", v2_split_bytes=b"", seen_bytes=b"", source=""):
    """새 색인 + v2 색인 · 분할 → v3 분할(dict). v2 표본의 구간은 그대로, 새 표본은 버림 → 연결 → 이어받기 · 제외 · fresh 분할.
    같은 입력이면 줄 순서와 무관하게 같은 결과."""
    split.validate(new_rows)
    v2_assign = v2_split["assignments"]
    v2_kept = [r for r in v2_rows if r["id"] in v2_assign]
    known, dropped_v2 = drop_known(new_rows, v2_rows, kept_ids=set(v2_assign))
    kept, dropped_new = split.dedupe(known)
    duplicates = dropped_v2 + [dict(d, why=WHY["new"]) for d in dropped_new]

    benign_files = _benign_files(v2_kept) | _benign_files(kept)
    groups, touched, parts = link(kept, v2_kept, v2_split, seen, benign_files)

    members = collections.defaultdict(list)
    for r in kept:
        members[groups[r["id"]]].append(r)
    assignments, excluded, inherited_ids, inherited_groups = dict(v2_assign), [], [], set()
    fresh = []
    for g in sorted(members):
        t = sorted(parts.get(g, ()))
        if len(t) >= 2:
            why = "v2 묶음 · seen 이름이 서로 다른 구간에 이어짐"
            excluded += [{"id": r["id"], "why": why, "parts": t, "group": g} for r in members[g]]
        elif len(t) == 1:
            inherited_groups.add(g)
            for r in members[g]:
                assignments[r["id"]] = t[0]
                inherited_ids.append(r["id"])
        else:
            fresh += members[g]
    if fresh:
        assignments.update(split.assign(fresh, {r["id"]: groups[r["id"]] for r in fresh}, seen, seed=SEED))

    new_assigned = {r["id"] for r in kept if r["id"] in assignments}
    group_of = _group_names(v2_split, [r for r in kept if r["id"] in new_assigned], groups, touched, inherited_groups)
    by_id = {r["id"]: r for r in v2_kept + kept}
    counts = {f"{e}:{lab}": {p: 0 for p in split.PARTS} for e in split.ECOSYSTEMS for lab in split.LABELS}
    new_counts = {f"{e}:{lab}": {p: 0 for p in split.PARTS} for e in split.ECOSYSTEMS for lab in split.LABELS}
    for i, p in assignments.items():
        key = f"{by_id[i]['ecosystem']}:{by_id[i]['label']}"
        counts[key][p] += 1
        if i in new_assigned:
            new_counts[key][p] += 1
    inherited = {p: 0 for p in split.PARTS}
    for i in inherited_ids:
        inherited[assignments[i]] += 1
    sizes = collections.Counter(group_of.values())
    by_part = {p: [i for i, q in assignments.items() if q == p] for p in split.PARTS}
    why_count = collections.Counter(d["why"] for d in duplicates)
    return {
        "schema": 3,
        "protocolSha256": split.sha256(protocol_bytes),
        "v2SplitSha256": split.sha256(v2_split_bytes),
        "seenSha256": split.sha256(seen_bytes),
        "source": source,
        "seed": SEED,
        "fractions": split.FRACTIONS,
        "sealed": list(split.SEALED),
        "neverUnseal": list(NEVER),
        "v2Kept": len(v2_assign),
        "newRows": len(new_rows),
        "newKept": len(new_assigned),
        "kept": len(assignments),
        "duplicatesDropped": {w: why_count.get(w, 0) for w in WHY.values()},
        "inherited": inherited,
        "excludedRows": len(excluded),
        "groups": len(sizes),
        "largestGroups": sorted(sizes.values(), reverse=True)[:5],
        "counts": counts,
        "newCounts": new_counts,
        "indexSha256": split.list_sha(r["id"] for r in new_rows),
        "listSha256": {p: split.list_sha(by_part[p]) for p in split.PARTS},
        "duplicates": sorted(duplicates, key=lambda d: (d["id"], d["why"])),
        "excluded": sorted(excluded, key=lambda e: e["id"]),
        "inheritedIds": sorted(inherited_ids),
        "assignments": {i: assignments[i] for i in sorted(assignments)},
        "groupOf": {i: group_of[i] for i in sorted(assignments)},
    }


def build_file(*, out=SPLIT3, new_index, v2_index, v2_split_path=V2_SPLIT, seen_path=V2_SEEN, protocol_path=PROTOCOL3, source=""):
    """파일에서 읽어 split.json 을 한 번 쓴다. 이미 있으면 FileExistsError(다시 만들지 않는다 — protocol revisions).
    출처(source — collect3.py source-line)는 꼭 준다."""
    if not (source or "").strip():
        raise ValueError("출처(--source)가 비었다 — python3 -B bench/v3/collect3.py source-line 의 한 줄을 준다")
    if os.path.exists(out):
        raise FileExistsError(f"{out} 이 이미 있다 — v3 분할은 한 번만 만든다")
    with open(v2_split_path, "rb") as f:
        v2_bytes = f.read()
    with open(seen_path, "rb") as f:
        seen_bytes = f.read()
    with open(protocol_path, "rb") as f:
        protocol_bytes = f.read()
    result = build(split.read_jsonl(new_index), split.read_jsonl(v2_index), json.loads(v2_bytes), set(json.loads(seen_bytes)["groups"]),
                   protocol_bytes=protocol_bytes, v2_split_bytes=v2_bytes, seen_bytes=seen_bytes, source=source)
    tmp = out + ".part"
    split.write_split(result, tmp, long_keys=LONG_KEYS)
    os.replace(tmp, out)
    return result


# ── 봉인 · 링크 · 합친 색인 ──

def _place(root, part, name, sealed):
    return os.path.join(root, "sealed", part, name) if part in sealed else os.path.join(root, "store", name)


def seal(sp, data, v2_data, new_rows, v2_rows):
    """분할 뒤 한 번(다시 해도 같다): 새 시험 · 예비 표본 파일을 store/ → sealed/<구간>/ 으로 옮기고, v2 표본은 v2 파일을 가리키는
    상대 링크를 둔다(대상 파일은 열지 않고 있는지만 본다). 그다음 분할에 든 표본의 합친 색인 index.jsonl(round = v2 · v3)을 쓴다.
    빠진 파일이 하나라도 있으면 아무것도 바꾸지 않고 Stop.
    새로 받은 파일이 v2 표본과 같은 파일(같은 id — 분할이 「v2 같은 파일」로 버린 줄)이면 store/ 의 그 사본은 지운다: 분할은 v2 표본으로만
    세고 v2 파일은 그대로 있으며, 두면 봉인 구간(v2 시험 · 예비)과 같은 파일이 봉인 밖에 남는다. id 는 파일 내용의 해시이고 색인 단계가
    저장한 파일과 맞춰 보았으므로 사본을 열어 견주지 않는다."""
    check_folders(data, v2_data)
    v2_by_id = {r["id"]: r for r in v2_rows}
    new_by_id = {r["id"]: r for r in new_rows}
    copies = {os.path.join(data, "store", f"{i}.{collect.EXT[new_by_id[i]['form']]}")
              for i in sp["assignments"] if i in v2_by_id and i in new_by_id}
    plan, missing = [], []
    for i, part in sorted(sp["assignments"].items()):
        r = v2_by_id.get(i) or new_by_id.get(i)
        if r is None:
            missing.append(f"{i}(색인 없음)")
            continue
        name = f"{i}.{collect.EXT[r['form']]}"
        place = _place(data, part, name, sp["sealed"])
        if i in v2_by_id:
            target = _place(v2_data, part, name, sp["sealed"])
            if not os.path.exists(target):
                missing.append(i)
            plan.append(("link", target, place, part))
        else:
            src = os.path.join(data, "store", name)
            if not (os.path.exists(place) or os.path.exists(src)):
                missing.append(i)
            plan.append(("move" if part in sp["sealed"] else "keep", src, place, part))
    if missing:
        raise Stop(f"분할에 든 표본 파일 {len(missing)}개가 없다(처음 {missing[0]}) — 아무것도 바꾸지 않았다")
    for kind, src, place, _ in plan:
        if kind != "link":
            continue
        want = os.path.relpath(src, os.path.dirname(place))
        if os.path.lexists(place) and not (os.path.islink(place) and os.readlink(place) == want):
            if place in copies and not os.path.islink(place):
                continue  # 링크 자리에 있는 것은 치울 새 사본이다(v2 학습 · 보정 표본과 같은 파일)
            raise Stop(f"링크 자리에 다른 파일이 있다: {place} — 아무것도 바꾸지 않았다")
    removed = 0
    for copy in sorted(copies):
        if os.path.isfile(copy) and not os.path.islink(copy):
            os.remove(copy)
            removed += 1
    moved = {p: 0 for p in sp["sealed"]}
    linked = {"store": 0, "sealed": 0}
    for kind, src, place, part in plan:
        os.makedirs(os.path.dirname(place), exist_ok=True)
        if kind == "link":
            if not os.path.lexists(place):
                os.symlink(os.path.relpath(src, os.path.dirname(place)), place)
            linked["sealed" if part in sp["sealed"] else "store"] += 1
        elif kind == "move":
            if not os.path.exists(place):
                os.replace(src, place)
            moved[part] += 1
    rows = [dict(v2_by_id[i], round="v2") if i in v2_by_id else dict(new_by_id[i], round="v3") for i in sorted(sp["assignments"])]
    index = os.path.join(data, "index.jsonl")
    with open(index + ".part", "w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, ensure_ascii=False, separators=(",", ":")) + "\n")
    os.replace(index + ".part", index)
    return {"moved": moved, "linked": linked, "index": len(rows), "removed": removed}


# ── v2 결과 옮기기 ──

READERS = (("static", run_static.read_results), ("rules", rules_layer.read_results))
INHERIT_PARTS = ("train", "calibration")  # 옮기는 구간 — 시험 · 예비 결과 파일은 있어도 건드리지 않는다


def inherit_results(sp, v2_assignments, v2_data, data):
    """v2 결과 파일(results/<static|rules>-<구간>.jsonl)의 줄 가운데, v3 에서도 같은 구간인 v2 표본의 마지막 줄을 v3 결과 파일에 덧붙인다
    (이미 있는 id 는 건너뛴다 — 다시 해도 같다). 학습 · 보정 구간만(INHERIT_PARTS). 규칙 엔진 표식(.meta.json)은 v3 쪽에 없으면 옮기고,
    있는데 엔진이 다르면 Stop. → {"<종류>-<구간>": 옮긴 줄 수} (v2 결과 파일이 있는 것만)."""
    out = {}
    for kind, read in READERS:
        for part in INHERIT_PARTS:
            src = os.path.join(v2_data, "results", f"{kind}-{part}.jsonl")
            if not os.path.exists(src):
                continue
            dst = os.path.join(data, "results", f"{kind}-{part}.jsonl")
            if kind == "rules":
                _carry_mark(src, dst)
            want = {i for i, p in sp["assignments"].items() if p == part and v2_assignments.get(i) == part}
            have = read(dst) if os.path.exists(dst) else {}
            rows = read(src)
            add = [rows[i] for i in sorted(want) if i in rows and i not in have]
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            with open(dst, "a", encoding="utf-8") as f:
                for row in add:
                    f.write(json.dumps(row, ensure_ascii=False, separators=(",", ":")) + "\n")
            out[f"{kind}-{part}"] = len(add)
    return out


def _carry_mark(src, dst):
    src_mark, dst_mark = os.path.splitext(src)[0] + ".meta.json", os.path.splitext(dst)[0] + ".meta.json"
    if not os.path.exists(src_mark):
        return
    with open(src_mark, encoding="utf-8") as f:
        mark = json.load(f)
    if os.path.exists(dst_mark):
        with open(dst_mark, encoding="utf-8") as f:
            if json.load(f).get("engineSha256") != mark.get("engineSha256"):
                raise Stop(f"규칙 엔진이 v2 결과와 다르다({os.path.basename(dst_mark)}) — 같은 엔진의 결과만 옮긴다")
        return
    os.makedirs(os.path.dirname(dst_mark), exist_ok=True)
    with open(dst_mark, "w", encoding="utf-8") as f:
        json.dump(mark, f, ensure_ascii=False, indent=1)
        f.write("\n")


# ── 봉인 열기 ──

def unseal(part, reason, *, split_path=SPLIT3, protocol_path=PROTOCOL3, selection_path=SELECTION3, ledger_path=LEDGER3,
           v2_assignments, head="", dirty=False):
    """v3 시험 구간을 한 번 연다(v2 표본의 시험 구간과 새 표본의 시험 구간이 함께). 예비 구간은 열지 않는다.
    나머지 조건(선택 파일 · 깨끗한 작업 폴더 · 한 번)은 v2 split.unseal 그대로. 기록에 출신별 수 · 목록 해시를 더한다."""
    if part in NEVER:
        raise split.SealedError(f"{part} 구간은 v3 에서 열지 않는다(protocol sealing.reserve)")
    with open(split_path, "rb") as f:
        split_bytes = f.read()
    with open(protocol_path, "rb") as f:
        protocol_bytes = f.read()
    ids = [i for i, p in json.loads(split_bytes)["assignments"].items() if p == part]
    old = [i for i in ids if i in v2_assignments]
    new = [i for i in ids if i not in v2_assignments]
    extra = {"rules": "v3", "rows": {"v2": len(old), "new": len(new)},
             "listSha256": {"v2": split.list_sha(old), "new": split.list_sha(new)}}
    return split.unseal(part, reason, split_bytes=split_bytes, protocol_bytes=protocol_bytes, selection_path=selection_path,
                        ledger_path=ledger_path, head=head, dirty=dirty, extra=extra)


# ── 명령 ──

def _read_split():
    if not os.path.exists(SPLIT3):
        raise Stop("bench/v3/split.json 이 없다 — 먼저 split3.py build")
    with open(SPLIT3, encoding="utf-8") as f:
        return json.load(f)


def _v2_split():
    with open(V2_SPLIT, encoding="utf-8") as f:
        return json.load(f)


def cmd_build(args):
    data, v2_data = data_dir(), v2_data_dir()
    result = build_file(new_index=args.new_index or os.path.join(data, "index-new.jsonl"),
                        v2_index=args.v2_index or os.path.join(v2_data, "index.jsonl"), source=args.source)
    print_status(result, [])
    print("다음: split3.py seal → split.json 커밋")


def cmd_seal(_args):
    data, v2_data = data_dir(), v2_data_dir()
    sp = _read_split()
    got = seal(sp, data, v2_data, split.read_jsonl(os.path.join(data, "index-new.jsonl")), split.read_jsonl(os.path.join(v2_data, "index.jsonl")))
    print("봉인(새 표본 파일 옮김): " + " · ".join(f"{p} {n:,}" for p, n in got["moved"].items())
          + f" · v2 링크 store {got['linked']['store']:,} · sealed {got['linked']['sealed']:,} · 합친 색인 {got['index']:,}줄"
          + f" · v2 표본과 같은 새 사본 지움 {got['removed']:,}")


def cmd_inherit(_args):
    got = inherit_results(_read_split(), _v2_split()["assignments"], v2_data_dir(), data_dir())
    print("v2 결과 줄 옮김: " + (" · ".join(f"{k} {n:,}" for k, n in got.items()) or "옮길 v2 결과 파일 없음"))


def print_status(sp, ledger):
    print(f"v2 표본 {sp['v2Kept']:,} + 새 표본 {sp['newKept']:,}(받은 {sp['newRows']:,} · 버림 {sum(sp['duplicatesDropped'].values()):,} "
          f"{json.dumps(sp['duplicatesDropped'], ensure_ascii=False)} · 뺌 {sp['excludedRows']:,}) = {sp['kept']:,} · 묶음 {sp['groups']:,} · "
          f"가장 큰 묶음 {sp['largestGroups']}")
    print("v2 묶음 · seen 이름과 이어져 구간을 이어받은 새 표본: " + " · ".join(f"{p} {n:,}" for p, n in sp["inherited"].items()))
    for stratum, c in sp["counts"].items():
        print(f"  {stratum:16s} " + " · ".join(f"{p} {c[p]:,}(새 {sp['newCounts'][stratum][p]:,})" for p in split.PARTS))
    done = split.opened(ledger)
    print("봉인: " + " · ".join(f"{p} {'열림' if p in done else ('열지 않음' if p in sp['neverUnseal'] else '봉인')}" for p in sp["sealed"]))


def cmd_status(_args):
    print_status(_read_split(), split.read_ledger(LEDGER3))


def cmd_unseal(args):
    dirty = bool(split._git("status", "--porcelain", "--", "bench", "backend", "tools"))
    try:
        entry = unseal(args.part, args.reason, v2_assignments=_v2_split()["assignments"], head=split._git("rev-parse", "HEAD"), dirty=dirty)
    except split.SealedError as e:
        sys.exit(f"거부: {e}")
    print(f"{entry['part']} 구간을 열었다({entry['at']} · v2 출신 {entry['rows']['v2']:,} · 새 표본 {entry['rows']['new']:,}). "
          "bench/v3/unseal-log.json 을 커밋하라")


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    b = sub.add_parser("build", help="새 색인 + v2 분할 → bench/v3/split.json(한 번만)")
    b.add_argument("--source", required=True, help="데이터 출처 한 줄 — collect3.py source-line 의 출력(비면 거부)")
    b.add_argument("--new-index", help="새 표본 색인(기본 <데이터>/index-new.jsonl)")
    b.add_argument("--v2-index", help="v2 색인(기본 <v2 데이터>/index.jsonl)")
    b.set_defaults(fn=cmd_build)
    sub.add_parser("seal", help="새 시험 · 예비 파일 봉인 · v2 파일 링크 · 합친 색인").set_defaults(fn=cmd_seal)
    sub.add_parser("inherit-results", help="v2 학습 · 보정 결과 줄을 v3 결과 파일로(시험 · 예비는 옮기지 않는다)").set_defaults(fn=cmd_inherit)
    sub.add_parser("status", help="구간별 수 · 봉인 상태").set_defaults(fn=cmd_status)
    u = sub.add_parser("unseal", help="시험 구간을 한 번 연다(예비는 열지 않는다)")
    u.add_argument("part", choices=("test",))
    u.add_argument("--reason", required=True)
    u.set_defaults(fn=cmd_unseal)
    args = ap.parse_args(argv)
    try:
        args.fn(args)
    except (Stop, FileExistsError, ValueError) as e:
        sys.exit(f"멈춤: {e}")


if __name__ == "__main__":
    main()
