"""M1 실험 모델 점검 — bench/.venv/bin/python -B -m unittest discover -s bench/ml -p 'test_*.py'"""
import copy
import datetime as dt
import inspect
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import train  # noqa: E402

NOW = dt.datetime(2026, 11, 4, tzinfo=dt.timezone.utc)


def read(path):
    with open(path, "rb") as f:
        return f.read()


class Base(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = read(train.DATA)
        cls.proto_bytes = read(train.PROTOCOL)
        cls.proto = json.loads(cls.proto_bytes)
        cls.rows = train.load_rows(cls.data)
        cls.pypi = train.usable(cls.rows, "pypi")
        cls.assign = train.split_groups(cls.pypi, cls.proto["split"]["seed"], cls.proto["split"]["fractions"])
        cls.parts = train.partition(cls.pypi, cls.assign)


class TestSplit(Base):
    def test_no_group_leakage(self):
        seen = {}
        for p, rows in self.parts.items():
            for r in rows:
                self.assertEqual(seen.setdefault(r["packageGroup"], p), p, "한 그룹이 두 구간에 걸쳤다")
        groups = [{r["packageGroup"] for r in rows} for rows in self.parts.values()]
        self.assertFalse(groups[0] & groups[1] or groups[0] & groups[2] or groups[1] & groups[2])

    def test_wheel_and_sdist_together(self):
        where = {}
        for p, rows in self.parts.items():
            for r in rows:
                if r["set"].startswith("benign-"):
                    where.setdefault(r["packageGroup"], set()).add((r["set"], p))
        paired = [v for v in where.values() if len({s for s, _ in v}) == 2]
        self.assertGreater(len(paired), 250, "wheel · sdist 가 같은 packageGroup 이어야 한다")
        for v in paired:
            self.assertEqual(len({p for _, p in v}), 1)

    def test_pypi_only_and_no_errors(self):
        self.assertTrue(all(r["ecosystem"] == "pypi" and r["verdict"] != "error" for r in self.pypi))
        self.assertEqual(sum(len(v) for v in self.parts.values()), len(self.pypi))

    def test_stratified_fractions(self):
        for y in (0, 1):
            groups = {r["packageGroup"] for r in self.pypi if train.label(r) == y}
            n = len(groups)
            got = {p: len({r["packageGroup"] for r in rows if train.label(r) == y}) for p, rows in self.parts.items()}
            self.assertEqual(got["train"], round(n * 0.6))
            self.assertEqual(got["train"] + got["calibration"], round(n * 0.8))

    def test_vocab_from_train_only(self):
        vocab = train.rule_vocab(self.parts["train"])
        for rule in vocab:
            self.assertGreaterEqual(sum(rule in (r["rules"] or []) for r in self.parts["train"]), 2)

    def test_excluded_inputs(self):
        names = train.feature_names(train.rule_vocab(self.parts["train"]), self.proto["features"]["numeric"])
        for bad in ("ecosystem", "id", "seconds", "vulns", "verdict", "set", "packageGroup"):
            self.assertNotIn(bad, names)

    def test_numeric_inputs_have_no_missing(self):
        """빈 값은 채우지 않는다 — 입력으로 쓰는 숫자 칸은 주 실험 모든 행에 값이 있어야 한다."""
        X = train.featurize(self.pypi, [], self.proto["features"]["numeric"])
        self.assertEqual(X.shape[0], len(self.pypi))

    def test_missing_value_fails(self):
        row = dict(self.pypi[0], files=None)
        with self.assertRaises(ValueError):
            train.featurize([row], [], ["log1p(files)"])


class TestScope(Base):
    def test_all_requires_npm_benign(self):
        if any(r["ecosystem"] == "npm" and train.label(r) == 0 for r in self.rows):
            self.skipTest("npm 정상 세트가 이미 있다")
        with self.assertRaises(ValueError):
            train.run(self.rows, self.proto, scope="all")
        self.assertEqual(train.main(["--scope", "all", "--out", os.devnull, "--selection", os.devnull]), 2)

    def test_all_with_npm_benign_has_by_ecosystem(self):
        """가짜 npm 정상(정상 PyPI 행을 npm 으로 바꿔 붙임)으로 all 범위 모양만 확인 — 수치는 의미 없다."""
        fake = [dict(r, ecosystem="npm", set="benign-npm", packageGroup="n" + r["packageGroup"][1:], id="n" + r["id"])
                for r in self.rows if r["set"] == "benign-pypi"]
        m, sel = train.build(self.data + b"".join(json.dumps(r).encode() + b"\n" for r in fake),
                             self.proto_bytes, now=NOW, scope="all")
        self.assertEqual(sel["scope"], "all")
        self.assertEqual(set(m["byEcosystem"]), {"npm", "pypi"})
        self.assertIn("npmBenign", m["dataset"]["used"])
        for e in ("npm", "pypi"):
            self.assertGreater(m["byEcosystem"][e]["test"]["benign"], 0)
        groups = {}
        for r in train.scoped(train.load_rows(self.data) + fake, "all")[0]:
            groups.setdefault(r["packageGroup"], set()).add(r["ecosystem"])
        self.assertTrue(all(len(v) == 1 for v in groups.values()))

    def test_pypi_scope_has_no_by_ecosystem(self):
        m, _ = train.build(self.data, self.proto_bytes, now=NOW)
        self.assertNotIn("byEcosystem", m)


class TestSelection(Base):
    def test_select_signature_has_no_test(self):
        self.assertEqual(list(inspect.signature(train.fit_and_select).parameters),
                         ["train_rows", "cal_rows", "seed", "numeric"])

    def test_selection_ignores_test_partition(self):
        """시험 구간 라벨 · 특징을 마구 바꿔도 선택 · 임계값은 같고, 시험 점수만 달라진다."""
        sel_a, rep_a = train.run(self.rows, self.proto)
        test_groups = {g for g, p in self.assign.items() if p == "test"}
        mutated = copy.deepcopy(self.rows)
        for r in mutated:
            if r["ecosystem"] == "pypi" and r["packageGroup"] in test_groups:
                r["score"] = 0.0 if train.label(r) else 9.9
                r["rules"] = [] if train.label(r) else ["threat-network-exfiltration"]
                r["verdict"] = "clean" if train.label(r) else "malicious"
        sel_b, rep_b = train.run(mutated, self.proto)
        self.assertEqual(sel_a, sel_b)
        self.assertNotEqual(rep_a["candidates"], rep_b["candidates"])

    def test_selection_written_before_test(self):
        order = []
        orig = train.evaluate

        def spy(cid, rows, models, selection):
            order.append("eval")
            return orig(cid, rows, models, selection)

        train.evaluate = spy
        try:
            train.run(self.rows, self.proto, on_selection=lambda s: order.append("selection"))
        finally:
            train.evaluate = orig
        self.assertEqual(order[0], "selection")

    def test_thresholds_respect_fpr(self):
        sel, _ = train.run(self.rows, self.proto)
        for cid in ("logreg", "hgb"):
            self.assertLessEqual(sel["calibration"][cid]["fpr"], train.MAX_FPR)
        self.assertLessEqual(sel["calibration"][sel["preferredId"]]["fpr"], train.MAX_FPR)


class TestReproducible(Base):
    def test_same_output_twice(self):
        a, sa = train.build(self.data, self.proto_bytes, now=NOW)
        b, sb = train.build(self.data, self.proto_bytes, now=NOW)
        self.assertEqual(json.dumps(a, ensure_ascii=False), json.dumps(b, ensure_ascii=False))
        self.assertEqual(sa, sb)

    def test_schema_keys(self):
        m, _ = train.build(self.data, self.proto_bytes, now=NOW)
        for k in ("schema", "generatedAt", "dataset", "protocol", "features", "candidates", "preferredId",
                  "deploymentApproved", "npmReference", "topFeatures", "limits"):
            self.assertIn(k, m)
        self.assertFalse(m["deploymentApproved"])
        self.assertEqual([c["id"] for c in m["candidates"]], ["rule-malicious", "rule-suspicious", "logreg", "hgb"])
        for c in m["candidates"]:
            self.assertEqual(set(c["test"]), {"f1", "precision", "recall", "fpr"})
            self.assertEqual(set(c["confusion"]), {"tp", "fn", "fp", "tn"})
            self.assertTrue({"f1", "fpr"} <= set(c["calibration"]))
        self.assertEqual(len(m["topFeatures"]), 10)
        self.assertEqual(set(m["npmReference"]["recall"]), {c["id"] for c in m["candidates"]})


if __name__ == "__main__":
    unittest.main()
