#!/usr/bin/env python3
"""평가 규칙 v3 — 새 표본 수집(두 걸음: 악성 전부 → 정상 몫 고정 → 정상). 규칙은 bench/v3/protocol.json 의 data.

내려받기 · 색인 · 이어받기(journal)는 v2 수집기(bench/v2/collect.py)의 함수를 그대로 쓰고, 이 파일은 v3 의 대상 · 몫 · 건너뛸 것만 정한다.
악성은 암호 zip 그대로 저장하고 메모리에서 글로만 읽는다. 어떤 파일도 실행하지 않는다. v2 데이터 폴더는 읽기만 한다.
결과는 bench/datasets/v3/(git 추적 제외): store/ · meta/<단계>.jsonl · sources.json · cache/ · index-new.jsonl

  python3 -B bench/v3/collect3.py malicious --eco pypi       # v2 가 받지 않은 zip 전부
  python3 -B bench/v3/collect3.py malicious --eco npm        # v2 가 훑지 않은 이름마다 최신 zip, 상한 없음
  python3 -B bench/v3/collect3.py plan                       # 악성 총수 → 정상 몫을 meta/benign-plan.json 에 한 번 고정
  python3 -B bench/v3/collect3.py benign --eco pypi --kind popular        # 인기 먼저(모자라면 롱테일로 넘김)
  python3 -B bench/v3/collect3.py benign --eco pypi --kind longTail
  python3 -B bench/v3/collect3.py benign --eco npm --kind popular --top-pages 60
  python3 -B bench/v3/collect3.py benign --eco npm --kind longTail
  python3 -B bench/v3/collect3.py index                      # → index-new.jsonl(새 표본만)
  python3 -B bench/v3/collect3.py source-line                # split3.py build --source 에 넘길 한 줄
  python3 -B bench/v3/collect3.py prune                      # 분할 · 봉인 뒤: 분할에 들지 않은 새 표본 파일 · 복제본 · 캐시 삭제(v2 링크는 그대로)
  python3 -B bench/v3/collect3.py status
"""
import argparse
import dataclasses
import hashlib
import json
import os
import shutil
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
V2 = os.path.join(os.path.dirname(HERE), "v2")
sys.path.insert(0, V2)
sys.path.insert(0, HERE)
import collect  # noqa: E402
import split  # noqa: E402
import split3  # noqa: E402

TOTAL = 40000
V2_MALICIOUS = 3876   # bench/v2/split.json counts(악성 · 분할에 든 것)
V2_BENIGN = 3876
SEED = split3.SEED
TOP_PAGES = 60        # npm 인기 순위 쪽 수 기본 상한(v2 와 같다) — --top-pages 로 바꾸고 쓴 값을 남긴다
SLACK = 400           # npm 인기 목록을 몫보다 넉넉히 받는 여유(v2 와 같다)


# ── 순수 함수(시험 대상) ──

@dataclasses.dataclass
class V2Record:
    """v2 가 받은 것: 수집 기록의 경로(생태계별) · npm 에서 훑은 이름 · 악성 지문(생태계별 지문 → id) · 표본 id · 정규화 이름(생태계별)."""
    paths: dict = dataclasses.field(default_factory=dict)
    npm_names: set = dataclasses.field(default_factory=set)
    prints: dict = dataclasses.field(default_factory=dict)
    ids: set = dataclasses.field(default_factory=set)
    names: dict = dataclasses.field(default_factory=dict)


def v2_record(v2_rows, journals):
    """v2 색인 줄 + v2 악성 수집 기록({생태계: [기록 줄]}) → V2Record. npm 이름은 기록 경로에서 읽는다(남김 · 버림 모두)."""
    rec = V2Record(paths={e: set() for e in split.ECOSYSTEMS}, prints={e: {} for e in split.ECOSYSTEMS},
                   names={e: set() for e in split.ECOSYSTEMS})
    for eco, rows in journals.items():
        for j in rows:
            rec.paths[eco].add(j["key"])
            parsed = collect.parse_datadog_path(j["key"])
            if eco == "npm" and parsed:
                rec.npm_names.add(parsed["name"])
    for r in sorted(v2_rows, key=lambda r: r["id"]):
        rec.ids.add(r["id"])
        rec.names[r["ecosystem"]].add(split.norm_name(r["ecosystem"], r["name"]))
        fp = split.fingerprint(r) if r["label"] == "malicious" else None
        if fp:
            rec.prints[r["ecosystem"]].setdefault(fp, r["id"])
    return rec


def malicious_targets(eco, entries, rec):
    """받을 악성 zip(차례대로). PyPI: v2 수집 기록에 경로가 없는 zip 전부(경로 순). npm: v2 가 훑지 않은 이름마다 발견일이 가장 늦은 zip,
    sha256("20261118:npm:<이름>") 순."""
    done = rec.paths.get(eco, set())
    fresh = [e for e in entries if e["path"] not in done]
    if eco == "pypi":
        return sorted(fresh, key=lambda e: e["path"])
    latest = collect.latest_per_name([e for e in fresh if e["name"] not in rec.npm_names])
    return [latest[n] for n in collect.hash_order(SEED, eco, latest)]


def malicious_total(v2_malicious, new_rows, v2_rows):
    """v3 악성 총수 = v2 악성 + 새 악성 가운데 v2 와 겹치는 것(같은 파일 · v2 지문)을 버리고 v2 dedupe 를 한 뒤 남은 수."""
    known, _ = split3.drop_known([r for r in new_rows if r["label"] == "malicious"], v2_rows)
    kept, _ = split.dedupe(known)
    return v2_malicious + len(kept)


def benign_plan(mal_total, v2_benign=V2_BENIGN, total=TOTAL):
    """정상 몫. 정상 총수 = total − 악성 총수, 새 정상 = 정상 총수 − v2 정상(0 아래면 0). 생태계별 절반(PyPI 올림),
    생태계 안에서 인기 절반(올림) · 롱테일 나머지."""
    benign_total = total - mal_total
    new = max(0, benign_total - v2_benign)
    plan = {"total": total, "maliciousTotal": mal_total, "benignTotal": benign_total, "v2Benign": v2_benign, "newBenign": new}
    for eco, n in (("pypi", (new + 1) // 2), ("npm", new // 2)):
        plan[eco] = {"popular": (n + 1) // 2, "longTail": n // 2}
    return plan


def longtail_quota(plan, eco, popular_kept):
    """롱테일 몫 = 계획의 롱테일 몫 + 인기 단계가 모자란 수(목록을 끝까지 훑고도 못 채운 수)."""
    return plan[eco]["longTail"] + max(0, plan[eco]["popular"] - popular_kept)


# ── 폴더 ──

def bind(data):
    """v2 수집기의 폴더 전역을 v3 데이터 폴더로 바꾼다(그 함수들이 부를 때마다 이 값을 읽는다)."""
    collect.DATA = data
    collect.STORE = os.path.join(data, "store")
    collect.SEALED_DIR = os.path.join(data, "sealed")
    collect.META = os.path.join(data, "meta")
    collect.CACHE = os.path.join(data, "cache")
    collect.REPO = os.path.join(data, "datadog-repo")
    collect.SOURCES = os.path.join(data, "sources.json")
    collect.INDEX = os.path.join(data, "index-new.jsonl")


def load_v2_record(v2_data):
    rows = split.read_jsonl(os.path.join(v2_data, "index.jsonl"))
    journals = {}
    for eco in split.ECOSYSTEMS:
        path = os.path.join(v2_data, "meta", f"malicious-{eco}.jsonl")
        journals[eco] = split.read_jsonl(path) if os.path.exists(path) else []
    return v2_record(rows, journals), rows


def _meta(name):
    return os.path.join(collect.META, name)


def _read_json(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def _write_once(path, obj):
    if os.path.exists(path):
        raise collect.Stop(f"{os.path.basename(path)} 이 이미 있다 — 한 번만 정한다")
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path + ".part", "w", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False, indent=1)
        f.write("\n")
    os.replace(path + ".part", path)


def _write(path, obj):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path + ".part", "w", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False, indent=1)
        f.write("\n")
    os.replace(path + ".part", path)


def _file_sha(path):
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


# ── 단계 ──

def cmd_malicious(args):
    rec, _ = load_v2_record(split3.v2_data_dir())
    eco = args.eco
    targets = malicious_targets(eco, collect.datadog_entries(eco), rec)
    j = collect.journal(f"malicious-{eco}")
    print(f"악성 {eco}: 대상 {len(targets):,}(v2 수집 기록 {len(rec.paths[eco]):,}건 · v2 지문 {len(rec.prints[eco]):,}개와 겹치면 버림)", flush=True)
    collect.collect_malicious(eco, targets, j, known_ids=rec.ids, known_prints=rec.prints[eco], dedupe=(eco == "npm"))
    datadog = collect.sources({}).get("datadog") or {}
    _write(_meta(f"malicious-{eco}.done.json"), {"targets": len(targets), "kept": len(j.kept()), "records": len(j.rows),
                                                 "datadogCommit": datadog.get("commit"), "journalSha256": _file_sha(j.path)})


def cmd_plan(_args):
    for eco in split.ECOSYSTEMS:
        if not os.path.exists(_meta(f"malicious-{eco}.done.json")):
            raise collect.Stop(f"악성 {eco} 수집이 끝나지 않았다(meta/malicious-{eco}.done.json 없음)")
    _, v2_rows = load_v2_record(split3.v2_data_dir())
    new = [r for eco in split.ECOSYSTEMS for r in collect.journal(f"malicious-{eco}").kept()]
    plan = benign_plan(malicious_total(V2_MALICIOUS, new, v2_rows))
    plan["malicious"] = {eco: _read_json(_meta(f"malicious-{eco}.done.json")) for eco in split.ECOSYSTEMS}
    _write_once(_meta("benign-plan.json"), plan)
    print(f"악성 총수 {plan['maliciousTotal']:,} → 정상 총수 {plan['benignTotal']:,} · 새 정상 {plan['newBenign']:,} "
          f"(PyPI {plan['pypi']} · npm {plan['npm']})")


def _plan():
    path = _meta("benign-plan.json")
    if not os.path.exists(path):
        raise collect.Stop("정상 몫이 아직 없다 — 악성 수집 뒤 collect3.py plan")
    return _read_json(path)


def _popular_list(eco, n=None, pages=None):
    """인기 목록. PyPI 는 순위표 전체, npm 은 n 개 넘게 · pages 쪽까지(쪽마다 캐시 — 인기 · 롱테일 단계가 같은 목록을 본다)."""
    if eco == "pypi":
        return collect.top_pypi()
    names = collect.top_npm(n, max_pages=pages)
    collect.sources({"npmTop": {**collect.sources({}).get("npmTop", {}), "maxPages": pages, "asked": n}})
    return names


def cmd_benign(args):
    plan, eco, kind = _plan(), args.eco, args.kind
    rec, _ = load_v2_record(split3.v2_data_dir())
    skip = rec.names[eco]
    done_path = _meta(f"benign-{eco}-popular.done.json")
    j = collect.journal(f"benign-{eco}-{kind}")
    if kind == "popular":
        quota = plan[eco]["popular"]
        n = quota + len(skip) + SLACK  # v2 이름을 건너뛰므로 그만큼 더 받는다
        popular = _popular_list(eco, n, args.top_pages)
        got = collect.collect_benign(eco, kind, quota, popular, set(), j, skip=skip, allow_short=True)
        _write(done_path, {"quota": quota, **got, "listNames": len(popular), "asked": n, "maxPages": args.top_pages,
                           "moveToLongTail": max(0, quota - got["kept"])})
        if got["exhausted"]:
            print(f"인기 목록을 다 훑었다: 남김 {got['kept']:,}/{quota:,} — 모자란 {quota - got['kept']:,} 은 롱테일 몫으로 넘긴다")
        return
    if not os.path.exists(done_path):
        raise collect.Stop(f"정상 {eco} 인기 단계가 끝나지 않았다 — 롱테일은 그 뒤에(모자란 몫을 넘겨받는다)")
    done = _read_json(done_path)
    quota = longtail_quota(plan, eco, done["kept"])
    popular = _popular_list(eco, done.get("asked"), done.get("maxPages"))
    popular_set = {split.norm_name(eco, x) for x in popular}
    order = collect.hash_order(SEED, eco, collect.pypi_names() if eco == "pypi" else collect.npm_names())
    collect.collect_benign(eco, kind, quota, order, popular_set, j, skip=skip)


def cmd_index(_args):
    collect.cmd_index(None)  # bind 가 INDEX 를 index-new.jsonl 로 바꿔 두었다


def cmd_source_line(_args):
    collect.cmd_source_line(None)


def cmd_status(_args):
    collect.cmd_status(None)
    if os.path.exists(_meta("benign-plan.json")):
        p = _plan()
        print(f"정상 몫: 새 정상 {p['newBenign']:,} · PyPI {p['pypi']} · npm {p['npm']}")


def cmd_prune(_args):
    """분할 · 봉인 뒤: 분할에 들지 않은 새 표본 파일(중복 · 뺀 것) · 받다 만 파일 · DataDog 복제본 · 목록 캐시를 지운다.
    v2 를 가리키는 링크와 v2 데이터 폴더는 건드리지 않는다. 분할에 든 표본이 모두 제자리에 있는지 먼저 본다."""
    with open(split3.SPLIT3, encoding="utf-8") as f:
        sp = json.load(f)
    forms = {r["id"]: r["form"] for r in split.read_jsonl(os.path.join(collect.DATA, "index.jsonl"))}
    for i, part in sp["assignments"].items():
        name = f"{i}.{collect.EXT[forms[i]]}"
        if not any(os.path.exists(os.path.join(d, name)) for d in (collect.STORE, os.path.join(collect.SEALED_DIR, part))):
            raise collect.Stop(f"분할에 든 표본 파일이 없다({i}) — 아무것도 지우지 않았다")
    files = freed = 0
    for name in sorted(os.listdir(collect.STORE)):
        path = os.path.join(collect.STORE, name)
        if os.path.islink(path):
            continue
        if name.endswith(".part") or name.split(".", 1)[0] not in sp["assignments"]:
            freed += os.path.getsize(path)
            os.remove(path)
            files += 1
    dirs = []
    for d in (collect.REPO, collect.CACHE):
        if os.path.isdir(d):
            freed += sum(os.path.getsize(os.path.join(a, f)) for a, _, fs in os.walk(d) for f in fs)
            shutil.rmtree(d)
            dirs.append(os.path.basename(d))
    print(f"정리: 새 표본 파일 {files}개 · 폴더 {dirs} 삭제 · {freed / (1 << 20):.0f}MB 비움(v2 링크 · v2 폴더는 그대로)")


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    m = sub.add_parser("malicious")
    m.add_argument("--eco", required=True, choices=split.ECOSYSTEMS)
    m.set_defaults(fn=cmd_malicious)
    b = sub.add_parser("benign")
    b.add_argument("--eco", required=True, choices=split.ECOSYSTEMS)
    b.add_argument("--kind", required=True, choices=("popular", "longTail"))
    b.add_argument("--top-pages", type=int, default=TOP_PAGES, help=f"npm 인기 순위 쪽 수 상한(기본 {TOP_PAGES})")
    b.set_defaults(fn=cmd_benign)
    for name, fn in (("plan", cmd_plan), ("index", cmd_index), ("source-line", cmd_source_line), ("prune", cmd_prune),
                     ("status", cmd_status)):
        sub.add_parser(name).set_defaults(fn=fn)
    args = ap.parse_args(argv)
    try:
        bind(split3.data_dir())
        args.fn(args)
    except (collect.Stop, split3.Stop) as e:
        sys.exit(f"멈춤: {e}")


if __name__ == "__main__":
    main()
