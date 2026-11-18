"""평가 규칙 v2 점검 — python3 -B -m unittest discover -s bench/v2 -p 'test_*.py'"""
import datetime as dt
import hashlib
import importlib.machinery
import importlib.util
import json
import os
import random
import re
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import metrics  # noqa: E402
import split  # noqa: E402

NOW = dt.datetime(2026, 11, 12, tzinfo=dt.timezone.utc)


def h(text):
    return hashlib.sha256(text.encode()).hexdigest()


def row(i, eco="pypi", label="malicious", name=None, date="2025-01-01", files=None, lines=10):
    """표본 한 줄. 기본은 저마다 다른 이름 · 다른 코드 파일(= 저마다 한 묶음)."""
    return {
        "id": f"{i:016x}", "ecosystem": eco, "label": label, "name": name or f"pkg-{eco}-{label}-{i}", "date": date,
        "source": "t", "codeLines": lines,
        "codeFiles": [{"sha256": h(f"file-{i}"), "bytes": 1000}] if files is None else files,
    }


def corpus(n=200):
    """층(생태계 × 라벨)마다 n 줄, 모두 처음 받는 표본."""
    rows, i = [], 1
    for eco in split.ECOSYSTEMS:
        for label in split.LABELS:
            for _ in range(n):
                rows.append(row(i, eco, label))
                i += 1
    return rows


def parts_of(rows, seen=frozenset(), **kw):
    kept, _ = split.dedupe(rows)
    groups = split.campaign_groups(kept)
    return split.assign(kept, groups, set(seen), **kw), groups


class Protocol(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with open(split.PROTOCOL, encoding="utf-8") as f:
            cls.p = json.load(f)

    def test_split_constants_match(self):
        s = self.p["split"]
        self.assertEqual(s["seed"], split.SEED)
        self.assertEqual(s["fractions"], split.FRACTIONS)
        self.assertAlmostEqual(sum(split.FRACTIONS.values()), 1.0)
        self.assertEqual(self.p["sealing"]["sealed"], list(split.SEALED))
        self.assertIn(f"{split.MIN_LINK_BYTES}바이트", self.p["unit"]["campaign"])
        self.assertIn(f"{round(split.GIANT_FRACTION * 100)}%", s["giant"])

    def test_metric_constants_match(self):
        t = self.p["target"]
        self.assertEqual(t["detection"], metrics.TARGET_DETECTION)
        self.assertEqual(t["falsePositiveRate"], metrics.MAX_FPR)
        self.assertEqual(self.p["layers"]["order"], list(metrics.LAYER_ORDER))
        listed = re.search(r"오탐률이 (.+?) 이하", self.p["layers"]["budgets"]).group(1)
        found = tuple(float(x) for x in listed.split(" · "))
        self.assertEqual(found, metrics.FPR_BUDGETS)
        self.assertIn(str(metrics.MAX_FPR), self.p["selection"]["rule"])
        self.assertIn(str(metrics.Z95), self.p["metrics"]["interval"])

    def test_seen_list_covers_v1_and_is_hashed_only(self):
        with open(split.SEEN, encoding="utf-8") as f:
            seen = json.load(f)["groups"]
        self.assertEqual(seen, sorted(set(seen)))
        self.assertTrue(all(re.fullmatch(r"[0-9a-f]{8}", g) for g in seen))
        v1 = {r["packageGroup"] for r in split.read_jsonl(os.path.join(split.ROOT, "bench", "reports", "static-items.jsonl"))}
        self.assertTrue(v1 <= set(seen))

    def test_name_group_is_v1_package_group(self):
        path = os.path.join(split.ROOT, "tools", "sg-bench-dataset")
        loader = importlib.machinery.SourceFileLoader("sg_bench_dataset", path)
        v1 = importlib.util.module_from_spec(importlib.util.spec_from_loader("sg_bench_dataset", loader))
        loader.exec_module(v1)
        for eco, name in [("pypi", "My_Pkg.Name"), ("pypi", "requests"), ("npm", "@Scope/Name"), ("npm", "left-pad")]:
            self.assertEqual(split.norm_name(eco, name), v1.norm_name(eco, name))
            self.assertEqual(split.name_group(eco, name), v1.sha256((eco + ":" + v1.norm_name(eco, name)).encode())[:8])


class Dedupe(unittest.TestCase):
    def test_same_fingerprint_keeps_earliest(self):
        same = [{"sha256": h("payload"), "bytes": 900}]
        rows = [row(3, files=same, date="2025-03-01"), row(1, files=same, date="2025-02-01"), row(2, files=same, date="2025-02-01")]
        kept, dropped = split.dedupe(rows)
        self.assertEqual([r["id"] for r in kept], [row(1)["id"]])
        self.assertEqual({d["duplicateOf"] for d in dropped}, {row(1)["id"]})

    def test_not_across_ecosystems_or_for_benign_or_without_code(self):
        same = [{"sha256": h("payload"), "bytes": 900}]
        empty = [{"sha256": h(""), "bytes": 0}]
        rows = [row(1, "pypi", files=same), row(2, "npm", files=same),
                row(3, label="benign", files=same), row(4, label="benign", files=same),
                row(5, files=[]), row(6, files=[]), row(7, files=empty), row(8, files=empty)]
        kept, dropped = split.dedupe(rows)
        self.assertEqual(len(kept), 8)
        self.assertEqual(dropped, [])
        self.assertIsNone(split.fingerprint(row(7, files=empty)))


class Campaign(unittest.TestCase):
    def test_same_normalized_name_is_one_group_within_ecosystem(self):
        rows = [row(1, name="My_Pkg"), row(2, name="my-pkg"), row(3, "npm", name="my-pkg")]
        g = split.campaign_groups(rows)
        self.assertEqual(g[row(1)["id"]], g[row(2)["id"]])
        self.assertNotEqual(g[row(1)["id"]], g[row(3)["id"]])
        self.assertEqual(g[row(2)["id"]], row(1)["id"])  # 묶음 이름 = 가장 작은 id

    def test_shared_code_file_links_malicious_only_when_big_and_not_benign(self):
        big = {"sha256": h("payload"), "bytes": split.MIN_LINK_BYTES}
        small = {"sha256": h("tiny"), "bytes": split.MIN_LINK_BYTES - 1}
        vendored = {"sha256": h("six.py"), "bytes": 5000}
        rows = [row(1, files=[big]), row(2, files=[big]),          # 묶인다
                row(3, files=[small]), row(4, files=[small]),      # 작아서 안 묶인다
                row(5, files=[vendored]), row(6, files=[vendored]),  # 정상에도 있는 파일이라 안 묶인다
                row(7, label="benign", files=[vendored]), row(8, label="benign", files=[vendored])]  # 정상끼리는 안 묶는다
        g = split.campaign_groups(rows)
        gid = lambda i: g[row(i)["id"]]  # noqa: E731
        self.assertEqual(gid(1), gid(2))
        self.assertEqual(len({gid(i) for i in (3, 4, 5, 6, 7, 8)}), 6)

    def test_compromised_package_stays_with_its_clean_release(self):
        rows = corpus(100) + [row(9001, label="malicious", name="shared-lib"), row(9002, label="benign", name="shared-lib")]
        parts, groups = parts_of(rows)
        self.assertEqual(groups[row(9001)["id"]], groups[row(9002)["id"]])
        self.assertEqual(parts[row(9001)["id"]], parts[row(9002)["id"]])


class Assign(unittest.TestCase):
    def test_groups_never_straddle_and_targets_are_met(self):
        rows = corpus(200)
        payload = [{"sha256": h("campaign"), "bytes": 2000}]
        rows += [row(5000 + k, files=payload + [{"sha256": h(f"extra-{k}"), "bytes": 300}]) for k in range(3)]  # 3줄짜리 캠페인
        parts, groups = parts_of(rows)
        by_group = {}
        for i, p in parts.items():
            by_group.setdefault(groups[i], set()).add(p)
        self.assertTrue(all(len(ps) == 1 for ps in by_group.values()))
        for eco in split.ECOSYSTEMS:
            for label in split.LABELS:
                ids = [r["id"] for r in rows if (r["ecosystem"], r["label"]) == (eco, label)]
                for part in split.HELD_OUT:
                    target = round(len(ids) * split.FRACTIONS[part])
                    got = sum(1 for i in ids if parts[i] == part)
                    self.assertGreaterEqual(got, target)
                    self.assertLessEqual(got, target + 4)

    def test_seen_and_everything_linked_to_seen_is_train_only(self):
        rows = corpus(200)
        pypi = [r for r in rows if r["ecosystem"] == "pypi"]
        seen_rows = [r for r in pypi if r["label"] == "malicious"][:60] + [r for r in pypi if r["label"] == "benign"][:60]
        seen = {split.name_group(r["ecosystem"], r["name"]) for r in seen_rows}
        mal = seen_rows[0]
        linked = row(7000, files=mal["codeFiles"] + [{"sha256": h("other"), "bytes": 400}])  # 이름은 새것, 코드 파일이 본 표본과 같다
        parts, _ = parts_of(rows + [linked], seen)
        self.assertTrue(all(parts[r["id"]] == "train" for r in seen_rows))
        self.assertEqual(parts[linked["id"]], "train")

    def test_same_input_in_any_order_gives_same_split(self):
        rows = corpus(150)
        a, _ = parts_of(rows)
        shuffled = rows[:]
        random.Random(7).shuffle(shuffled)
        b, _ = parts_of(shuffled)
        self.assertEqual(a, b)
        c, _ = parts_of(rows, seed=split.SEED + 1)
        self.assertNotEqual(a, c)

    def test_other_ecosystem_does_not_move_assignments(self):
        rows = corpus(150)
        pypi = [r for r in rows if r["ecosystem"] == "pypi"]
        whole, _ = parts_of(rows)
        alone, _ = parts_of(pypi)
        self.assertEqual({i: whole[i] for i in alone}, alone)

    def test_giant_campaign_goes_to_train(self):
        rows = corpus(200)  # 시험 목표 40 → 4줄 넘는 묶음은 큰 묶음
        payload = [{"sha256": h("mass"), "bytes": 3000}]
        giant = [row(8000 + k, files=payload + [{"sha256": h(f"g-{k}"), "bytes": 300}]) for k in range(6)]
        parts, _ = parts_of(rows + giant)
        self.assertEqual({parts[r["id"]] for r in giant}, {"train"})

    def test_refuses_when_fresh_samples_run_out(self):
        rows = corpus(100)
        seen = {split.name_group(r["ecosystem"], r["name"]) for r in rows if r["ecosystem"] == "npm" and r["label"] == "benign"}
        with self.assertRaisesRegex(ValueError, "npm · benign.*모자라"):
            parts_of(rows, seen)


class Build(unittest.TestCase):
    def test_result_is_consistent_and_round_trips(self):
        rows = corpus(120)
        dup = row(9100, files=rows[0]["codeFiles"], date="2026-01-01")
        result = split.build(rows + [dup], set(), b"protocol", b"seen", "test source")
        self.assertEqual((result["rows"], result["kept"]), (481, 480))
        self.assertEqual(result["duplicates"], [{"id": dup["id"], "duplicateOf": rows[0]["id"]}])
        self.assertEqual(sum(sum(c.values()) for c in result["counts"].values()), 480)
        for part in split.PARTS:
            ids = [i for i, p in result["assignments"].items() if p == part]
            self.assertEqual(result["listSha256"][part], split.list_sha(ids))
        self.assertEqual(result["protocolSha256"], hashlib.sha256(b"protocol").hexdigest())
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "split.json")
            split.write_split(result, path)
            with open(path, encoding="utf-8") as f:
                self.assertEqual(json.load(f), result)

    def test_rejects_malformed_index(self):
        bad = row(1)
        del bad["codeLines"]
        with self.assertRaises(ValueError):
            split.build([bad], set(), b"", b"")
        with self.assertRaises(ValueError):
            split.build([row(1), row(1)], set(), b"", b"")


class Seal(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        self.ledger = os.path.join(self.dir.name, "unseal-log.json")
        self.selection = os.path.join(self.dir.name, "selection.json")
        self.split = split.build(corpus(100), set(), b"p", b"s")
        self.kw = dict(split_bytes=b"split", protocol_bytes=b"p", selection_path=self.selection, ledger_path=self.ledger,
                       head="abc123", now=NOW)

    def ids(self, *parts):
        return split.select_ids(self.split, parts, split.read_ledger(self.ledger))

    def test_sealed_parts_are_refused_until_opened(self):
        self.assertEqual(len(self.ids("train", "calibration")), 280)
        for part in split.SEALED:
            with self.assertRaises(split.SealedError):
                self.ids(part)
        with self.assertRaises(ValueError):
            self.ids("holdout")

    def test_unseal_needs_selection_clean_tree_reason_and_order(self):
        with self.assertRaisesRegex(split.SealedError, "selection.json"):
            split.unseal("test", "최종", **self.kw)
        with open(self.selection, "w") as f:
            f.write("{}")
        with self.assertRaisesRegex(split.SealedError, "커밋하지 않은"):
            split.unseal("test", "최종", dirty=True, **self.kw)
        with self.assertRaises(ValueError):
            split.unseal("test", "  ", **self.kw)
        with self.assertRaises(ValueError):
            split.unseal("train", "최종", **self.kw)
        with self.assertRaisesRegex(split.SealedError, "시험 구간을 연 뒤"):
            split.unseal("reserve", "재측정", **self.kw)
        self.assertEqual(split.read_ledger(self.ledger), [])

    def test_each_part_opens_once_and_is_recorded(self):
        with open(self.selection, "w") as f:
            f.write("{}")
        entry = split.unseal("test", "최종 측정", **self.kw)
        self.assertEqual(entry, {
            "part": "test", "at": "2026-11-12T00:00:00Z", "reason": "최종 측정",
            "protocolSha256": hashlib.sha256(b"p").hexdigest(), "splitSha256": hashlib.sha256(b"split").hexdigest(),
            "selectionSha256": hashlib.sha256(b"{}").hexdigest(), "gitHead": "abc123"})
        self.assertEqual(len(self.ids("test")), 80)
        with self.assertRaises(split.SealedError):
            self.ids("reserve")
        with self.assertRaisesRegex(split.SealedError, "이미 한 번"):
            split.unseal("test", "다시", **self.kw)
        split.unseal("reserve", "개선 뒤 재측정", **self.kw)
        self.assertEqual([e["part"] for e in split.read_ledger(self.ledger)], ["test", "reserve"])
        self.assertEqual(len(self.ids("reserve")), 40)


class Metrics(unittest.TestCase):
    def test_wilson_reference_values(self):
        for (k, n), want in {(5, 10): (0.2366, 0.7634), (0, 10): (0.0, 0.2775), (10, 10): (0.7225, 1.0), (98, 100): (0.9300, 0.9945)}.items():
            lo, hi = metrics.wilson(k, n)
            self.assertAlmostEqual(lo, want[0], places=4)
            self.assertAlmostEqual(hi, want[1], places=4)
        self.assertEqual(metrics.wilson(0, 0), (0.0, 1.0))

    def test_goal_uses_unrounded_values(self):
        self.assertTrue(metrics.goal_met(0.98, 0.02))
        self.assertFalse(metrics.goal_met(0.97999, 0.02))
        self.assertFalse(metrics.goal_met(0.98, 0.02001))
        y = [1] * 4999 + [0] * 100
        pred = [True] * 4899 + [False] * 100 + [False] * 100  # 4899/4999 = 0.979996 → 반올림하면 0.98 이지만 미달
        s = metrics.summary(y, pred)
        self.assertEqual((s["detection"], s["met"]), (0.98, False))

    def test_unprocessed_samples_count_as_missed_not_removed(self):
        y = [1, 1, 1, 1, 0, 0]
        static = [True, False, False, False, False, False]
        dynamic = [None, True, None, None, None, None]  # 설치 실패 등
        s = metrics.summary(y, metrics.any_layer([static, dynamic]))
        self.assertEqual((s["tp"], s["fn"], s["fp"], s["tn"]), (2, 2, 0, 2))
        self.assertEqual(metrics.score_flags([0.9, None, 0.1], 0.5), [True, False, False])

    def test_main_rows_drop_only_malicious_without_code(self):
        rows = [row(1), row(2, lines=0), row(3, label="benign", lines=0), row(4, label="benign")]
        kept = metrics.main_rows(rows)
        self.assertEqual([r["id"] for r in kept], [row(i)["id"] for i in (1, 3, 4)])
        self.assertEqual(metrics.labels(kept), [1, 0, 0])

    def test_budget_points_pick_lowest_threshold_within_each_budget(self):
        y = [0] * 400 + [1] * 10
        scores = [i / 1000 for i in range(400)] + [0.9] * 9 + [None]  # 정상 점수 0.000 ~ 0.399
        pts = dict(metrics.budget_points(scores, y))
        self.assertEqual(pts["fpr<=0.0"], 0.9)        # 정상 위로는 0.9 뿐
        self.assertEqual(pts["fpr<=0.0025"], 0.399)   # 정상 1개(0.25%)까지
        self.assertEqual(pts["fpr<=0.02"], 0.392)     # 정상 8개(2%)까지
        flat = metrics.budget_points([0.5] * 10, [0] * 5 + [1] * 5)
        self.assertEqual(flat, [])                    # 어떤 예산으로도 못 가른다

    def test_select_prefers_detection_then_fpr_then_fewer_layers_then_order(self):
        y = [1] * 10 + [0] * 100
        m = lambda hits, fps: [k < hits for k in range(10)] + [k < fps for k in range(100)]  # noqa: E731
        layers = [
            ("static", [("S-malicious", m(6, 0)), ("S-suspicious", m(8, 3))]),  # 뒤쪽은 오탐 3% — 혼자서는 못 쓴다
            ("llm", [("fpr<=0.01", m(9, 1))]),
            ("dynamic", [("D-kill", m(9, 1))]),
        ]
        got = metrics.select(y, layers)
        self.assertEqual(got["points"], {"llm": "fpr<=0.01"})  # 탐지 0.9 · 오탐 0.01 · 층 1개 · 순서가 앞
        self.assertEqual((got["calibration"]["detection"], got["calibration"]["fpr"]), (0.9, 0.01))
        better = layers + [("ml", [("fpr<=0.02", [k >= 1 for k in range(10)] + [k >= 99 for k in range(100)])])]
        self.assertEqual(metrics.select(y, better)["points"], {"static": "S-malicious", "ml": "fpr<=0.02"})  # 합쳐서 10/10 · 오탐 1%
        with self.assertRaises(ValueError):
            metrics.select(y, [("static", [("S-suspicious", m(8, 3))])])

    def test_ablation_adds_layers_in_protocol_order(self):
        y = [1, 1, 1, 1, 0, 0]
        flags = {"dynamic": [False, False, True, False, False, False], "static": [True, False, False, False, False, False],
                 "llm": [False, True, False, False, False, True]}
        a = metrics.ablation(y, flags)
        self.assertEqual([c["through"] for c in a["cumulative"]], ["static", "llm", "dynamic"])
        self.assertEqual([c["tp"] for c in a["cumulative"]], [1, 2, 3])
        self.assertEqual([c["fp"] for c in a["cumulative"]], [0, 1, 1])
        self.assertEqual(a["alone"]["dynamic"]["tp"], 1)

    def test_by_year_counts_malicious_only(self):
        rows = [row(1, date="2024-05-01"), row(2, date="2024-09-01"), row(3, date="2026-01-01"), row(4, label="benign", date="2024-01-01")]
        self.assertEqual(metrics.by_year(rows, [True, False, True, True]),
                         {"2024": {"detected": 1, "rows": 2, "detection": 0.5}, "2026": {"detected": 1, "rows": 1, "detection": 1.0}})


if __name__ == "__main__":
    unittest.main()
