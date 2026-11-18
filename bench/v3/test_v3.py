"""평가 규칙 v3 점검(규약 값 · 분할 승계 · 연결 · 제외 · 봉인 · 개봉 · 수집 몫 · 진입점) —
python3 -B -m unittest discover -s bench/v3 -p 'test_*.py'

네트워크 · 실제 표본 · 실제 API 없이 돈다: 가짜 색인 · 임시 폴더만 쓴다. 표준 라이브러리만 쓴다.
"""
import hashlib
import json
import os
import random
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
V2 = os.path.join(os.path.dirname(HERE), "v2")
sys.path.insert(0, V2)
sys.path.insert(0, HERE)
import collect  # noqa: E402
import collect3  # noqa: E402
import run  # noqa: E402
import split  # noqa: E402
import split3  # noqa: E402


def h(text):
    return hashlib.sha256(text.encode()).hexdigest()


def row(i, eco="pypi", label="malicious", name=None, files=None, date="2025-01-01", lines=10, source="t", form=None):
    """표본 한 줄. 기본은 저마다 다른 이름 · 다른 코드 파일(= 저마다 한 묶음)."""
    return {
        "id": f"{i:016x}", "ecosystem": eco, "label": label, "name": name or f"pkg-{eco}-{label}-{i}", "date": date,
        "source": source, "codeLines": lines, "form": form or ("zip" if label == "malicious" else "sdist"),
        "codeFiles": [{"sha256": h(f"file-{i}"), "bytes": 1000}] if files is None else files,
    }


def corpus(start, n):
    """층(생태계 × 라벨)마다 n 줄."""
    rows, i = [], start
    for eco in split.ECOSYSTEMS:
        for label in split.LABELS:
            for _ in range(n):
                rows.append(row(i, eco, label))
                i += 1
    return rows


def v2_world(n=60):
    """v2 표본 · 분할(v2 시드 · v2 규칙 그대로)."""
    rows = corpus(1, n)
    return rows, split.build(rows, set(), b"protocol-v2", b"seen-v2")


def in_part(v2_rows, v2_split, part, eco="pypi", label="malicious"):
    return next(r for r in v2_rows if v2_split["assignments"][r["id"]] == part and r["ecosystem"] == eco and r["label"] == label)


def build3(new_rows, v2_rows, v2_split, seen=()):
    return split3.build(new_rows, v2_rows, v2_split, set(seen))


class Constants(unittest.TestCase):
    """규약(protocol.json)과 도구의 값이 같은지."""

    @classmethod
    def setUpClass(cls):
        with open(os.path.join(HERE, "protocol.json"), encoding="utf-8") as f:
            cls.p = json.load(f)

    def test_seed_total_and_fractions(self):
        self.assertEqual(self.p["data"]["seed"], split3.SEED)
        self.assertEqual(split3.SEED, 20261118)
        self.assertEqual(self.p["split"]["fresh"]["seed"], split3.SEED)
        self.assertEqual(self.p["data"]["total"], collect3.TOTAL)
        self.assertEqual(self.p["split"]["fresh"]["fractions"], split.FRACTIONS)
        self.assertEqual(self.p["sealing"]["sealed"], list(split.SEALED))

    def test_base_hashes_match_the_v2_files(self):
        root = os.path.dirname(os.path.dirname(HERE))
        for rel, sha in self.p["base"]["files"].items():
            with open(os.path.join(root, rel), "rb") as f:
                self.assertEqual(hashlib.sha256(f.read()).hexdigest(), sha, rel)

    def test_disclosure_and_decisions_are_written(self):
        text = json.dumps(self.p, ensure_ascii=False)
        for needle in ("v2 학습 · 보정 구간의 결과", "v2 시험 · 예비 구간은 봉인된 채", "확대 이유", "0.001", "$45", "$55",
                       "20261118:llm:", "out-calibration.jsonl", "excluded", "neverUnseal"):
            self.assertIn(needle, text)


# ── 분할 ──

class Inherit(unittest.TestCase):
    def setUp(self):
        self.v2_rows, self.v2 = v2_world()

    def test_v2_parts_are_kept_exactly(self):
        sp = build3(corpus(10_000, 40), self.v2_rows, self.v2)
        for i, part in self.v2["assignments"].items():
            self.assertEqual(sp["assignments"][i], part)

    def test_new_sample_with_a_v2_name_follows_the_v2_part(self):
        cal = in_part(self.v2_rows, self.v2, "calibration", "npm", "benign")
        twin = row(20_001, "npm", "benign", name=cal["name"].upper())  # 같은 정규화 이름(npm 은 소문자)
        sp = build3(corpus(10_000, 40) + [twin], self.v2_rows, self.v2)
        self.assertEqual(sp["assignments"][twin["id"]], "calibration")
        self.assertEqual(sp["groupOf"][twin["id"]], sp["groupOf"][cal["id"]])
        self.assertGreaterEqual(sp["inherited"]["calibration"], 1)

    def test_new_malicious_sharing_a_code_file_with_a_v2_test_group_goes_to_test(self):
        t = in_part(self.v2_rows, self.v2, "test")
        kin = row(20_002, files=[t["codeFiles"][0], {"sha256": h("own"), "bytes": 900}])
        sp = build3(corpus(10_000, 40) + [kin], self.v2_rows, self.v2)
        self.assertEqual(sp["assignments"][kin["id"]], "test")

    def test_small_shared_files_and_files_also_in_benign_do_not_link(self):
        t = in_part(self.v2_rows, self.v2, "test")
        small = row(20_003, files=[{"sha256": h("tiny"), "bytes": 100}])
        t_small = dict(t, codeFiles=t["codeFiles"] + [{"sha256": h("tiny"), "bytes": 100}])
        common = {"sha256": h("lib"), "bytes": 5000}
        kin = row(20_004, files=[common])
        new_benign = row(20_005, label="benign", files=[common])
        tr = in_part(self.v2_rows, self.v2, "train")
        v2_rows = [t_small if r["id"] == t["id"] else (dict(r, codeFiles=r["codeFiles"] + [common]) if r["id"] == tr["id"] else r)
                   for r in self.v2_rows]
        sp = build3(corpus(10_000, 40) + [small, kin, new_benign], v2_rows, self.v2)
        self.assertNotIn(small["id"], sp["inheritedIds"])
        self.assertNotIn(kin["id"], sp["inheritedIds"])   # 새 정상에도 있는 파일 — 근거가 아니다

    def test_new_group_touching_two_v2_parts_is_left_out(self):
        tr, te = in_part(self.v2_rows, self.v2, "train"), in_part(self.v2_rows, self.v2, "test")
        a = row(20_010, name=tr["name"])                     # 이름으로 학습 묶음에
        b = row(20_011, files=[te["codeFiles"][0], a["codeFiles"][0]])  # 코드 파일로 a 와 · 시험 묶음에
        sp = build3(corpus(10_000, 40) + [a, b], self.v2_rows, self.v2)
        for x in (a, b):
            self.assertNotIn(x["id"], sp["assignments"])
        out = {e["id"]: e for e in sp["excluded"]}
        self.assertEqual(set(out), {a["id"], b["id"]})
        self.assertEqual(out[a["id"]]["parts"], ["test", "train"])
        self.assertTrue(out[a["id"]]["why"])

    def test_seen_name_goes_to_train_and_seen_plus_a_held_out_link_is_left_out(self):
        seen_new = row(20_020, name="old-favourite")
        cal = in_part(self.v2_rows, self.v2, "calibration")
        both = row(20_021, name="also-seen", files=[cal["codeFiles"][0]])
        seen = {split.name_group("pypi", "old-favourite"), split.name_group("pypi", "also-seen")}
        sp = build3(corpus(10_000, 40) + [seen_new, both], self.v2_rows, self.v2, seen)
        self.assertEqual(sp["assignments"][seen_new["id"]], "train")
        self.assertNotIn(both["id"], sp["assignments"])
        self.assertEqual([e["parts"] for e in sp["excluded"] if e["id"] == both["id"]], [["calibration", "train"]])

    def test_same_file_or_same_fingerprint_as_v2_is_dropped(self):
        m = in_part(self.v2_rows, self.v2, "train", "npm")
        copy = dict(m, name="other-name")                      # 같은 파일(같은 id)
        same_fp = row(20_030, "npm", files=list(m["codeFiles"]), name="third-name", date="2020-01-01")  # 더 이른 날짜여도 v2 가 남는다
        benign_same = row(20_031, "npm", "benign", files=list(m["codeFiles"]))  # 정상은 지문으로 버리지 않는다
        sp = build3(corpus(10_000, 40) + [copy, same_fp, benign_same], self.v2_rows, self.v2)
        dups = {d["id"]: d for d in sp["duplicates"]}
        self.assertEqual(dups[same_fp["id"]], {"id": same_fp["id"], "duplicateOf": m["id"], "why": "v2 지문"})
        self.assertEqual(dups[m["id"]]["why"], "v2 같은 파일")
        self.assertEqual(sp["assignments"][m["id"]], self.v2["assignments"][m["id"]])
        self.assertNotIn(same_fp["id"], sp["assignments"])
        self.assertIn(benign_same["id"], sp["assignments"])

    def test_new_duplicates_among_themselves_follow_v2_dedupe(self):
        files = [{"sha256": h("shared-new"), "bytes": 2000}]
        early, late = row(20_040, files=files, date="2024-01-01"), row(20_041, files=files, date="2025-06-01")
        sp = build3(corpus(10_000, 40) + [late, early], self.v2_rows, self.v2)
        self.assertIn(early["id"], sp["assignments"])
        self.assertEqual({d["id"]: d["duplicateOf"] for d in sp["duplicates"]}[late["id"]], early["id"])

    def test_fresh_new_samples_use_the_v2_method_with_the_v3_seed(self):
        new = corpus(10_000, 100)
        sp = build3(new, self.v2_rows, self.v2)
        groups = split.campaign_groups(new)
        want = split.assign(new, groups, set(), seed=20261118)
        self.assertEqual({i: sp["assignments"][i] for i in want}, want)
        self.assertNotEqual(want, split.assign(new, groups, set(), seed=split.SEED))
        for stratum in ("pypi:malicious", "npm:benign"):
            self.assertEqual(sp["newCounts"][stratum], {"train": 50, "calibration": 20, "test": 20, "reserve": 10})

    def test_same_input_any_order_same_split(self):
        new = corpus(10_000, 40) + [row(20_050, name=in_part(self.v2_rows, self.v2, "test")["name"])]
        a = build3(new, self.v2_rows, self.v2)
        shuffled = list(new)
        random.Random(3).shuffle(shuffled)
        b = build3(shuffled, list(reversed(self.v2_rows)), self.v2)
        self.assertEqual(a["assignments"], b["assignments"])
        self.assertEqual(a["groupOf"], b["groupOf"])
        self.assertEqual(a["listSha256"], b["listSha256"])

    def test_output_marks_sealed_and_never_unsealed_parts(self):
        sp = build3(corpus(10_000, 40), self.v2_rows, self.v2)
        self.assertEqual(sp["sealed"], ["test", "reserve"])
        self.assertEqual(sp["neverUnseal"], ["reserve"])
        self.assertEqual(sp["seed"], 20261118)
        self.assertEqual(sum(sum(c.values()) for c in sp["counts"].values()), len(sp["assignments"]))


class BuildFile(unittest.TestCase):
    def test_split_file_is_made_once(self):
        v2_rows, v2 = v2_world(30)
        with tempfile.TemporaryDirectory() as d:
            paths = {k: os.path.join(d, k) for k in ("new.jsonl", "v2.jsonl", "v2split.json", "seen.json", "protocol.json")}
            for key, rows in (("new.jsonl", corpus(10_000, 30)), ("v2.jsonl", v2_rows)):
                with open(paths[key], "w") as f:
                    f.writelines(json.dumps(r) + "\n" for r in rows)
            for key, obj in (("v2split.json", v2), ("seen.json", {"groups": []}), ("protocol.json", {"schema": 3})):
                with open(paths[key], "w") as f:
                    json.dump(obj, f)
            out = os.path.join(d, "split.json")
            kw = dict(new_index=paths["new.jsonl"], v2_index=paths["v2.jsonl"], v2_split_path=paths["v2split.json"],
                      seen_path=paths["seen.json"], protocol_path=paths["protocol.json"], source="t")
            split3.build_file(out=out, **kw)
            with open(out, "rb") as f:
                first = f.read()
            with self.assertRaises(FileExistsError):
                split3.build_file(out=out, **kw)
            with open(out, "rb") as f:
                self.assertEqual(f.read(), first)
            self.assertEqual(json.loads(first)["v2SplitSha256"], hashlib.sha256(open(paths["v2split.json"], "rb").read()).hexdigest())


class Seal(unittest.TestCase):
    """봉인 · 링크 · 합친 색인 — 임시 폴더에서."""

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = tmp.name
        self.v2_rows, self.v2 = v2_world(30)
        self.new = corpus(10_000, 30)
        self.sp = build3(self.new, self.v2_rows, self.v2)
        self.v2_data, self.data = os.path.join(self.root, "v2"), os.path.join(self.root, "v3")
        for r in self.v2_rows:
            part = self.v2["assignments"][r["id"]]
            folder = os.path.join(self.v2_data, "sealed", part) if part in split.SEALED else os.path.join(self.v2_data, "store")
            self.put(folder, r, b"v2-" + r["id"].encode())
        for r in self.new:
            self.put(os.path.join(self.data, "store"), r, b"v3-" + r["id"].encode())

    def put(self, folder, r, data):
        os.makedirs(folder, exist_ok=True)
        with open(os.path.join(folder, f"{r['id']}.{collect.EXT[r['form']]}"), "wb") as f:
            f.write(data)

    def snapshot(self, folder):
        out = {}
        for d, _, files in os.walk(folder):
            for name in files:
                p = os.path.join(d, name)
                with open(p, "rb") as f:
                    out[os.path.relpath(p, folder)] = f.read()
        return out

    def test_seal_moves_new_held_out_files_and_links_v2_files_without_touching_them(self):
        before = self.snapshot(self.v2_data)
        counts = split3.seal(self.sp, self.data, self.v2_data, self.new, self.v2_rows)
        self.assertEqual(self.snapshot(self.v2_data), before)
        for r in self.new + self.v2_rows:
            part = self.sp["assignments"][r["id"]]
            name = f"{r['id']}.{collect.EXT[r['form']]}"
            place = os.path.join(self.data, "sealed", part, name) if part in split.SEALED else os.path.join(self.data, "store", name)
            self.assertTrue(os.path.exists(place), place)
            self.assertEqual(os.path.islink(place), r in self.v2_rows)
            if os.path.islink(place):
                self.assertFalse(os.path.isabs(os.readlink(place)))
        new_test = [r for r in self.new if self.sp["assignments"][r["id"]] == "test"]
        self.assertTrue(new_test)
        self.assertFalse(os.path.exists(os.path.join(self.data, "store", f"{new_test[0]['id']}.{collect.EXT[new_test[0]['form']]}")))
        self.assertEqual(counts["moved"]["test"], len(new_test))
        index = split.read_jsonl(os.path.join(self.data, "index.jsonl"))
        self.assertEqual({r["id"] for r in index}, set(self.sp["assignments"]))
        self.assertEqual({r["round"] for r in index}, {"v2", "v3"})
        self.assertEqual(split3.seal(self.sp, self.data, self.v2_data, self.new, self.v2_rows)["moved"]["test"], len(new_test))  # 다시 해도 같다

    def test_seal_refuses_when_a_v2_target_is_missing(self):
        r = next(r for r in self.v2_rows if self.v2["assignments"][r["id"]] == "train")
        os.remove(os.path.join(self.v2_data, "store", f"{r['id']}.zip"))
        with self.assertRaises(split3.Stop):
            split3.seal(self.sp, self.data, self.v2_data, self.new, self.v2_rows)

    def test_sealed_parts_are_refused_by_the_v2_guard(self):
        with self.assertRaises(split.SealedError):
            split.select_ids(self.sp, ["test"], [])
        with self.assertRaises(split.SealedError):
            split.select_ids(self.sp, ["reserve"], [{"part": "test"}])
        self.assertTrue(split.select_ids(self.sp, ["train", "calibration"], []))


class Unseal(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        d = tmp.name
        v2_rows, self.v2 = v2_world(30)
        sp = build3(corpus(10_000, 30), v2_rows, self.v2)
        self.paths = {k: os.path.join(d, k) for k in ("split.json", "protocol.json", "selection.json", "unseal-log.json")}
        split.write_split(sp, self.paths["split.json"])
        with open(self.paths["protocol.json"], "w") as f:
            f.write("{}")

    def unseal(self, part, **kw):
        kw.setdefault("dirty", False)
        return split3.unseal(part, "최종 측정", split_path=self.paths["split.json"], protocol_path=self.paths["protocol.json"],
                             selection_path=self.paths["selection.json"], ledger_path=self.paths["unseal-log.json"],
                             v2_assignments=self.v2["assignments"], head="abc", **kw)

    def test_reserve_is_never_opened(self):
        with open(self.paths["selection.json"], "w") as f:
            f.write("{}")
        self.unseal("test")
        with self.assertRaises(split.SealedError):
            self.unseal("reserve")

    def test_test_opens_once_with_selection_and_clean_tree_and_records_both_origins(self):
        with self.assertRaises(split.SealedError):
            self.unseal("test")                      # 선택 파일 없음
        with open(self.paths["selection.json"], "w") as f:
            f.write("{}")
        with self.assertRaises(split.SealedError):
            self.unseal("test", dirty=True)
        entry = self.unseal("test")
        sp = json.load(open(self.paths["split.json"]))
        v2_test = [i for i, p in self.v2["assignments"].items() if p == "test"]
        new_test = [i for i, p in sp["assignments"].items() if p == "test" and i not in self.v2["assignments"]]
        self.assertEqual(entry["rows"], {"v2": len(v2_test), "new": len(new_test)})
        self.assertEqual(entry["listSha256"]["v2"], split.list_sha(v2_test))
        self.assertEqual(split.read_ledger(self.paths["unseal-log.json"]), [entry])
        with self.assertRaises(split.SealedError):
            self.unseal("test")
        self.assertTrue(split.select_ids(sp, ["test"], split.read_ledger(self.paths["unseal-log.json"])))

class InheritResults(unittest.TestCase):
    def test_v2_result_lines_are_copied_into_the_same_part_once(self):
        v2_rows, v2 = v2_world(30)
        sp = build3(corpus(10_000, 30), v2_rows, v2)
        with tempfile.TemporaryDirectory() as d:
            v2_data, data = os.path.join(d, "v2"), os.path.join(d, "v3")
            os.makedirs(os.path.join(v2_data, "results"))
            tr = [i for i, p in v2["assignments"].items() if p == "train"]
            with open(os.path.join(v2_data, "results", "static-train.jsonl"), "w") as f:
                f.write(json.dumps({"id": tr[0], "status": "error", "why": "x"}) + "\n")
                f.write(json.dumps({"id": tr[0], "status": "ok", "verdict": "clean"}) + "\n")   # 마지막 줄이 이긴다
                f.write(json.dumps({"id": "ffffffffffffffff", "status": "ok"}) + "\n")         # 분할에 없는 id
            with open(os.path.join(v2_data, "results", "rules-train.jsonl"), "w") as f:
                f.write(json.dumps({"id": tr[1], "status": "ok", "score": 3, "hits": [], "strong": []}) + "\n")
            with open(os.path.join(v2_data, "results", "rules-train.meta.json"), "w") as f:
                json.dump({"engineSha256": "e"}, f)
            got = split3.inherit_results(sp, v2["assignments"], v2_data, data)
            self.assertEqual(got["static-train"], 1)
            self.assertEqual(got["rules-train"], 1)
            static = split.read_jsonl(os.path.join(data, "results", "static-train.jsonl"))
            self.assertEqual(static, [{"id": tr[0], "status": "ok", "verdict": "clean"}])
            with open(os.path.join(data, "results", "rules-train.meta.json")) as f:
                self.assertEqual(json.load(f), {"engineSha256": "e"})
            again = split3.inherit_results(sp, v2["assignments"], v2_data, data)
            self.assertEqual(again["static-train"], 0)
            self.assertEqual(len(split.read_jsonl(os.path.join(data, "results", "static-train.jsonl"))), 1)


# ── 수집 ──

class Plan(unittest.TestCase):
    def test_benign_plan(self):
        p = collect3.benign_plan(3876 + 7000)
        self.assertEqual((p["maliciousTotal"], p["benignTotal"], p["newBenign"]), (10876, 29124, 25248))
        self.assertEqual(p["pypi"], {"popular": 6312, "longTail": 6312})
        self.assertEqual(p["npm"], {"popular": 6312, "longTail": 6312})
        odd = collect3.benign_plan(3876 + 6999)
        self.assertEqual(odd["newBenign"], 25249)
        self.assertEqual(odd["pypi"], {"popular": 6313, "longTail": 6312})
        self.assertEqual(odd["npm"], {"popular": 6312, "longTail": 6312})
        self.assertEqual(sum(sum(odd[e].values()) for e in ("pypi", "npm")), 25249)
        none = collect3.benign_plan(40_000)
        self.assertEqual(none["newBenign"], 0)
        self.assertEqual(none["pypi"], {"popular": 0, "longTail": 0})

    def test_popular_shortfall_moves_to_long_tail(self):
        p = collect3.benign_plan(3876 + 7000)
        self.assertEqual(collect3.longtail_quota(p, "npm", 6312), 6312)
        self.assertEqual(collect3.longtail_quota(p, "npm", 5000), 6312 + 1312)
        self.assertEqual(collect3.longtail_quota(p, "pypi", 7000), 6312)

    def test_malicious_total_counts_v2_and_new_after_drops(self):
        v2_rows = [row(1, "npm"), row(2, "pypi")]
        same_fp = row(3, "npm", files=list(v2_rows[0]["codeFiles"]))
        files = [{"sha256": h("x"), "bytes": 500}]
        new = [same_fp, row(4, "npm", files=files, date="2024-01-01"), row(5, "npm", files=files, date="2025-01-01"), row(6, "pypi"),
               row(7, "pypi", "benign")]
        self.assertEqual(collect3.malicious_total(3876, new, v2_rows), 3876 + 2)


class Targets(unittest.TestCase):
    def entry(self, eco, name, date, kind="malicious_intent"):
        folder = name.replace("/", "@") if name.startswith("@") else name
        return {"ecosystem": eco, "kind": kind, "name": name, "version": "", "date": date,
                "path": f"samples/{eco}/{kind}/{folder}/{date}-{name.replace('/', '-')}.zip", "oid": h(name + date)}

    def test_npm_skips_names_v2_scanned_and_takes_the_latest_zip_in_v3_hash_order(self):
        entries = [self.entry("npm", "old", "2024-01-01"), self.entry("npm", "a", "2024-01-01"), self.entry("npm", "a", "2025-02-02"),
                   self.entry("npm", "@s/b", "2023-03-03"), self.entry("npm", "c", "2022-01-01")]
        rec = collect3.V2Record(paths={"npm": {"samples/npm/malicious_intent/zzz/2020-01-01-zzz.zip"}}, npm_names={"old"})
        got = collect3.malicious_targets("npm", entries, rec)
        self.assertEqual([e["name"] for e in got], collect.hash_order(20261118, "npm", ["a", "@s/b", "c"]))
        self.assertEqual(next(e for e in got if e["name"] == "a")["date"], "2025-02-02")

    def test_pypi_takes_every_zip_v2_did_not_take(self):
        entries = [self.entry("pypi", "x", "2024-01-01"), self.entry("pypi", "x", "2026-11-10"), self.entry("pypi", "y", "2026-11-11")]
        rec = collect3.V2Record(paths={"pypi": {entries[0]["path"]}}, npm_names=set())
        self.assertEqual([e["path"] for e in collect3.malicious_targets("pypi", entries, rec)], sorted(e["path"] for e in entries[1:]))

    def test_v2_record_reads_paths_names_prints_and_ids(self):
        v2_rows = [row(1, "npm", name="m1"), row(2, "npm", "benign", name="B-One"), row(3, "pypi", name="Py_Thing")]
        journals = {"npm": [{"key": "samples/npm/malicious_intent/@s@x/2024-01-01-x.zip", "status": "duplicate"},
                            {"key": "samples/npm/malicious_intent/m1/2024-01-01-m1.zip", "status": "kept"}],
                    "pypi": [{"key": "samples/pypi/malicious_intent/Py_Thing/1.0/2024-01-01-p.zip", "status": "kept"}]}
        rec = collect3.v2_record(v2_rows, journals)
        self.assertEqual(rec.npm_names, {"@s/x", "m1"})
        self.assertEqual(rec.paths["pypi"], {"samples/pypi/malicious_intent/Py_Thing/1.0/2024-01-01-p.zip"})
        self.assertEqual(rec.ids, {r["id"] for r in v2_rows})
        self.assertEqual(set(rec.prints["npm"].values()), {v2_rows[0]["id"]})   # 악성만
        self.assertEqual(rec.names["npm"], {"m1", "b-one"})
        self.assertEqual(rec.names["pypi"], {"py-thing"})


# ── 진입점 ──

class Entry(unittest.TestCase):
    def test_tool_env_points_v2_tools_at_v3_rules_and_data(self):
        env = run.tool_env({"PATH": "/bin"})
        self.assertEqual(env["SG_BENCH_RULES"], HERE)
        self.assertEqual(env["SG_BENCH_DATA"], os.path.join(os.path.dirname(HERE), "datasets", "v3"))
        self.assertEqual(run.tool_env({"SG_BENCH_DATA": "/x"})["SG_BENCH_DATA"], "/x")

    def test_command_runs_only_the_layer_tools(self):
        cmd = run.command("run_static", ["report", "--parts", "train"])
        self.assertEqual(cmd[1:], ["-B", os.path.join(V2, "run_static.py"), "report", "--parts", "train"])
        for tool in ("split", "collect", "../v2/split", "nope"):
            with self.assertRaises(ValueError):
                run.command(tool, [])


if __name__ == "__main__":
    unittest.main()
