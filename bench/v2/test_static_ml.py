"""평가 규칙 v2 정적 ML 층 점검(합성 색인 · 합성 결과 줄) — python3 -B -m unittest discover -s bench/v2 -p 'test_*.py'

명세는 bench/v2/addenda/2-ml.json. 특징 · 어휘 · 봉인 · 결과 줄 계산은 표준 라이브러리만으로 돈다.
모델을 맞춰야 하는 시험은 scikit-learn(bench/requirements-ml.txt)이 없으면 건너뛴다.
"""
import contextlib
import io
import json
import os
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import metrics  # noqa: E402
import split  # noqa: E402
import static_ml  # noqa: E402

NEEDS_ML = unittest.skipUnless(static_ml.ml_missing() == "", static_ml.ml_missing())


# ── 합성 데이터 ──

def index_row(i, label, eco="pypi", lines=5):
    return {"id": f"{i:016x}", "ecosystem": eco, "label": label, "name": f"p{i}", "codeLines": lines, "codeFiles": []}


def hit(rule, count=1, test=False, doc=False):
    return {"rule": rule, "severity": "HIGH", "category": "NONE", "file": "f", "count": count, "test": test, "doc": doc}


def rules_res(row, hits=(), score=0, status="ok"):
    return {"id": row["id"], "status": status, "why": "" if status == "ok" else "엔진 오류: X",
            "score": score if status == "ok" else None, "level": "LOW", "hits": list(hits), "strong": [],
            "truncatedFiles": 0, "files": 1, "ms": 1}


def gd_res(row, rules=(), score=0, install=0, status="ok"):
    if status != "ok":
        return {"id": row["id"], "status": status, "why": "내용 없음(메타데이터만)"}
    return {"id": row["id"], "status": "ok", "verdict": "clean", "score": score, "rules": list(rules),
            "installThreats": install, "threats": 0, "capabilities": 0, "testFindings": 0, "vulns": 0, "seconds": 1.0,
            "engines": {"GuardDog": "3.2.0"}}


class Data:
    """임시 데이터 폴더(index.jsonl · results/static-<구간>.jsonl · results/rules-<구간>.jsonl)와 가짜 분할."""

    def __init__(self, case):
        tmp = tempfile.TemporaryDirectory()
        case.addCleanup(tmp.cleanup)
        self.dir = tmp.name
        self.rows, self.gd, self.rules = [], {}, {}
        self.sp = {"sealed": list(split.SEALED), "assignments": {}, "groupOf": {}}

    def add(self, label, *, part="train", eco="pypi", lines=5, gd=None, rules=None, group=None):
        row = index_row(len(self.rows) + 1, label, eco, lines)
        self.rows.append(row)
        self.sp["assignments"][row["id"]] = part
        self.sp["groupOf"][row["id"]] = group or row["id"]
        if gd is not None:
            self.gd.setdefault(part, []).append({**gd, "id": row["id"]})
        if rules is not None:
            self.rules.setdefault(part, []).append({**rules, "id": row["id"]})
        return row

    def write(self):
        with open(os.path.join(self.dir, "index.jsonl"), "w", encoding="utf-8") as f:
            for r in self.rows:
                f.write(json.dumps(r) + "\n")
        os.makedirs(os.path.join(self.dir, "results"), exist_ok=True)
        for kind, table in (("static", self.gd), ("rules", self.rules)):
            for part, lines in table.items():
                with open(os.path.join(self.dir, "results", f"{kind}-{part}.jsonl"), "w", encoding="utf-8") as f:
                    for line in lines:
                        f.write(json.dumps(line) + "\n")
        return self

    def corpus(self, n=30, seed_rule="EVIL"):
        """배울 신호가 있는 학습 구간: 악성은 EVIL 규칙 · 높은 점수, 정상은 대부분 조용함(몇 개는 흔한 규칙)."""
        for i in range(n):
            r = index_row(0, "malicious")
            self.add("malicious", eco="npm" if i % 2 else "pypi",
                     rules=rules_res(r, [hit(seed_rule, 3 + i % 4)], score=60 + i % 30),
                     gd=gd_res(r, ["threat-x"], score=5 + i % 3, install=1), group=f"g{i // 2:04d}")
            self.add("benign", eco="npm" if i % 2 else "pypi",
                     rules=rules_res(r, [hit("COMMON")] if i % 5 == 0 else [], score=5 if i % 5 == 0 else 0),
                     gd=gd_res(r, ["capability-net"] if i % 3 == 0 else [], score=1), group=f"b{i:04d}")
        return self


# ── 특징 ──

class Features(unittest.TestCase):
    """특징 순서 · 어휘 · 결측 — 부록 features 그대로."""

    def setUp(self):
        d = Data(self)
        r = index_row(0, "x")
        self.a = d.add("malicious", rules=rules_res(r, [hit("ZETA", 2), hit("ALPHA", 50), hit("ALPHA", 4),
                                                         hit("TESTONLY", 9, test=True)], score=80),
                       gd=gd_res(r, ["threat-b", "threat-a"], score=7.5, install=2))
        self.b = d.add("benign", eco="npm", rules=rules_res(r, [hit("DOCONLY", 3, doc=True)], score=10),
                       gd=gd_res(r, ["capability-c"], score=1.5))
        self.d = d.write()
        self.rows, self.gd, self.rules = static_ml.load_part(d.dir, d.sp, [], ["train"])
        self.vocab = static_ml.build_vocab(self.rows, self.gd, self.rules)

    def test_vocab_is_sorted_names_from_the_part(self):
        self.assertEqual(self.vocab, {"rules": ["ALPHA", "DOCONLY", "TESTONLY", "ZETA"],
                                      "guarddog": ["capability-c", "threat-a", "threat-b"]})

    def test_feature_order_is_rules_then_guarddog_then_scalars(self):
        names = static_ml.feature_names(self.vocab)
        self.assertEqual(names, ["rules:ALPHA", "rules:DOCONLY", "rules:TESTONLY", "rules:ZETA",
                                 "guarddog:capability-c", "guarddog:threat-a", "guarddog:threat-b",
                                 "rules.score", "guarddog.score", "guarddog.installThreats", "npm"])

    def test_rule_counts_are_capped_and_test_or_doc_hits_left_out(self):
        x = static_ml.features(self.a, self.gd.get(self.a["id"]), self.rules.get(self.a["id"]), self.vocab)
        # ALPHA = min(50,20) + min(4,20) = 24 · TESTONLY 는 시험 파일이라 0 · ZETA = 2
        self.assertEqual(x, [24, 0, 0, 2, 0, 1, 1, 80, 7.5, 2, 0])
        y = static_ml.features(self.b, self.gd.get(self.b["id"]), self.rules.get(self.b["id"]), self.vocab)
        self.assertEqual(y, [0, 0, 0, 0, 1, 0, 0, 10, 1.5, 0, 1])

    def test_names_never_seen_in_training_are_dropped(self):
        r = index_row(99, "malicious")
        x = static_ml.features(r, gd_res(r, ["threat-new", "threat-a"], score=3),
                               rules_res(r, [hit("BRAND_NEW", 7), hit("ZETA", 1)], score=40), self.vocab)
        self.assertEqual(len(x), len(static_ml.feature_names(self.vocab)))
        self.assertEqual(x, [0, 0, 0, 1, 0, 1, 0, 40, 3, 0, 0])

    def test_engine_that_could_not_run_gives_zeros(self):
        r = index_row(98, "malicious", eco="npm")
        zeros_but_npm = [0] * 10 + [1]
        for gd in (None, gd_res(r, status="skip"), gd_res(r, status="error")):
            for ru in (None, rules_res(r, status="error")):
                self.assertEqual(static_ml.features(r, gd, ru, self.vocab), zeros_but_npm)
        # 한 엔진만 처리하지 못하면 그 엔진의 특징만 0
        x = static_ml.features(r, None, rules_res(r, [hit("ALPHA", 1)], score=30), self.vocab)
        self.assertEqual(x, [1, 0, 0, 0, 0, 0, 0, 30, 0, 0, 1])

    def test_vocab_only_uses_results_that_ran(self):
        d = Data(self)
        r = index_row(0, "x")
        d.add("malicious", rules=rules_res(r, status="error"), gd=gd_res(r, status="skip"))
        d.add("benign", rules=rules_res(r, [hit("ONLY")]), gd=gd_res(r, ["g-only"]))
        d.write()
        rows, gd, ru = static_ml.load_part(d.dir, d.sp, [], ["train"])
        self.assertEqual(static_ml.build_vocab(rows, gd, ru), {"rules": ["ONLY"], "guarddog": ["g-only"]})

    def test_training_rows_leave_out_malicious_without_code(self):
        d = Data(self)
        a = d.add("malicious", lines=0)
        b = d.add("malicious", lines=3)
        c = d.add("benign", lines=0)
        self.assertEqual([r["id"] for r in static_ml.training_rows(d.rows)], [b["id"], c["id"]])
        self.assertNotIn(a["id"], [r["id"] for r in static_ml.training_rows(d.rows)])


# ── 봉인 ──

class Sealed(unittest.TestCase):
    """봉인 구간은 split.select_ids 에서 거부되고, 아무것도 쓰지 않는다."""

    def test_the_real_split_refuses_test_and_reserve(self):
        with open(split.SPLIT, encoding="utf-8") as f:
            sp = json.load(f)
        with tempfile.TemporaryDirectory() as d:
            for part in split.SEALED:
                with self.assertRaises(split.SealedError):
                    static_ml.load_part(d, sp, [], [part])
            self.assertEqual(os.listdir(d), [])

    def test_sealed_part_is_refused_until_the_ledger_opens_it(self):
        d = Data(self)
        r = index_row(0, "x")
        d.add("benign", rules=rules_res(r), gd=gd_res(r))
        held = d.add("malicious", part="test", rules=rules_res(r, [hit("X")]), gd=gd_res(r))
        d.write()
        with self.assertRaises(split.SealedError):
            static_ml.load_part(d.dir, d.sp, [], ["train", "test"])
        rows, _, _ = static_ml.load_part(d.dir, d.sp, [{"part": "test"}], ["test"])
        self.assertEqual([x["id"] for x in rows], [held["id"]])

    def test_predict_command_refuses_a_sealed_part_and_writes_nothing(self):
        d = Data(self).write()
        out = os.path.join(d.dir, "out")
        err = io.StringIO()
        with self.assertRaises(SystemExit) as stop, contextlib.redirect_stderr(err):
            static_ml.main(["predict", "--model", os.path.join(d.dir, "none.pkl"), "--parts", "test", "--data", d.dir,
                            "--out-dir", out])
        self.assertIn("거부", str(stop.exception.code))
        self.assertFalse(os.path.exists(out))


# ── 결과 줄 ──

class Predictions(unittest.TestCase):
    """ml-<구간>.jsonl — LLM 관문이 읽는 계약: 표본마다 {"id": str, "p": float(소수 6자리)}."""

    def test_line_format_is_id_and_p_only(self):
        with tempfile.TemporaryDirectory() as d:
            path = static_ml.predictions_path(d, "calibration")
            self.assertEqual(path, os.path.join(d, "ml-calibration.jsonl"))
            static_ml.write_predictions(path, [("00000000000000b2", 0.123456789), ("00000000000000a1", 1)])
            with open(path, encoding="utf-8") as f:
                lines = f.read().splitlines()
            self.assertEqual([json.loads(x) for x in lines], [{"id": "00000000000000b2", "p": 0.123457},
                                                               {"id": "00000000000000a1", "p": 1.0}])
            for x in lines:
                rec = json.loads(x)
                self.assertEqual(list(rec), ["id", "p"])
                self.assertIsInstance(rec["id"], str)
                self.assertIsInstance(rec["p"], float)
            self.assertEqual(static_ml.read_predictions(path), {"00000000000000b2": 0.123457, "00000000000000a1": 1.0})


@NEEDS_ML
class Model(unittest.TestCase):
    """학습 · 예측 · 재현성 · 모델 파일 메타 · 교차 검증."""

    def setUp(self):
        self.d = Data(self).corpus()
        r = index_row(0, "x")
        self.nocode = self.d.add("malicious", lines=0, rules=rules_res(r, [hit("NOCODE_ONLY")], score=99),
                                 gd=gd_res(r, ["threat-nocode"], score=9))
        self.d.write()

    def test_estimator_is_the_fixed_one(self):
        est = static_ml.make_estimator()
        self.assertEqual(type(est).__name__, "HistGradientBoostingClassifier")
        p = est.get_params()
        self.assertEqual((p["max_iter"], p["learning_rate"], p["random_state"]), (300, 0.05, 7))

    def test_training_leaves_out_no_code_malicious_but_its_names_enter_the_vocab(self):
        bundle = static_ml.train(self.d.dir, self.d.sp, [])
        self.assertEqual(bundle["trainRows"], {"total": 60, "malicious": 30, "benign": 30, "noCodeMaliciousLeftOut": 1})
        self.assertIn("NOCODE_ONLY", bundle["vocab"]["rules"])  # 어휘는 학습 구간 결과 전체에서
        self.assertEqual(bundle["featureCount"], len(static_ml.feature_names(bundle["vocab"])))

    def test_same_input_gives_the_same_p(self):
        one = static_ml.train(self.d.dir, self.d.sp, [])
        two = static_ml.train(self.d.dir, self.d.sp, [])
        rows, gd, ru = static_ml.load_part(self.d.dir, self.d.sp, [], ["train"])
        p1, p2 = static_ml.predict(one, rows, gd, ru), static_ml.predict(two, rows, gd, ru)
        self.assertEqual(p1, p2)
        self.assertEqual([i for i, _ in p1], [r["id"] for r in rows])  # 구간의 모든 표본(코드 없는 악성 포함)
        mal = [p for (i, p), r in zip(p1, rows) if r["label"] == "malicious" and r["codeLines"] >= 1]
        ben = [p for (i, p), r in zip(p1, rows) if r["label"] == "benign"]
        self.assertGreater(min(mal), max(ben))

    def test_model_file_round_trip_with_meta(self):
        bundle = static_ml.train(self.d.dir, self.d.sp, [])
        path = os.path.join(self.d.dir, "models", "static-ml.pkl")
        meta = static_ml.save_model(bundle, path)
        with open(static_ml.meta_path(path), encoding="utf-8") as f:
            self.assertEqual(json.load(f), meta)
        self.assertEqual(meta["modelSha256"], static_ml.file_sha(path))
        for k in ("vocab", "features", "featureCount", "trainRows", "sklearn", "estimator"):
            self.assertIn(k, meta)
        loaded = static_ml.load_model(path)
        rows, gd, ru = static_ml.load_part(self.d.dir, self.d.sp, [], ["train"])
        self.assertEqual(static_ml.predict(loaded, rows, gd, ru), static_ml.predict(bundle, rows, gd, ru))
        with open(path, "ab") as f:  # 모델 파일이 메타와 다르면 쓰지 않는다
            f.write(b"x")
        with self.assertRaises(ValueError):
            static_ml.load_model(path)

    def test_predict_command_writes_one_line_per_sample(self):
        model = os.path.join(self.d.dir, "m", "static-ml.pkl")
        out = os.path.join(self.d.dir, "preds")
        with contextlib.redirect_stdout(io.StringIO()):
            static_ml.main(["train", "--data", self.d.dir, "--out", model, "--split-json", self._split_file()])
            static_ml.main(["predict", "--model", model, "--parts", "train", "--data", self.d.dir, "--out-dir", out,
                            "--split-json", self._split_file()])
        preds = static_ml.read_predictions(os.path.join(out, "ml-train.jsonl"))
        self.assertEqual(sorted(preds), sorted(r["id"] for r in self.d.rows))
        with open(os.path.join(out, "ml-train.meta.json"), encoding="utf-8") as f:
            self.assertEqual(json.load(f)["modelSha256"], static_ml.file_sha(model))

    def _split_file(self):
        path = os.path.join(self.d.dir, "split.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump(self.d.sp, f)
        return path

    def test_cross_validation_keeps_groups_whole(self):
        rows, gd, ru = static_ml.load_part(self.d.dir, self.d.sp, [], ["train"])
        main = static_ml.training_rows(rows)
        groups = [self.d.sp["groupOf"][r["id"]] for r in main]
        folds = static_ml.folds(metrics.labels(main), groups)
        self.assertEqual(len(folds), 5)
        self.assertEqual(sorted(i for _, te in folds for i in te), list(range(len(main))))
        for tr, te in folds:
            self.assertFalse({groups[i] for i in tr} & {groups[i] for i in te})
        res = static_ml.cross_validate(rows, gd, ru, self.d.sp["groupOf"])
        self.assertEqual(res["rows"], {"total": 60, "malicious": 30, "benign": 30})
        self.assertEqual([b["budget"] for b in res["atFpr"]], [0.01, 0.02, 0.03, 0.05])
        for b in res["atFpr"]:
            self.assertLessEqual(b["fpr"], b["budget"])
            self.assertEqual(b["detection"], 1.0)
        self.assertEqual(res, static_ml.cross_validate(rows, gd, ru, self.d.sp["groupOf"]))


# ── 보고 ──

class Report(unittest.TestCase):
    """후보 M-static@<예산> — 임계값은 보정 구간 예산(protocol budgets)으로, 분모는 정상 전부 + 코드 있는 악성."""

    def setUp(self):
        mk = index_row
        # 보정 구간: 정상 200 · 악성 10
        self.cal = [mk(i, "benign") for i in range(200)] + [mk(1000 + i, "malicious") for i in range(10)]
        self.cal_p = {r["id"]: (i / 1000 if r["label"] == "benign" else 0.9) for i, r in enumerate(self.cal)}
        # 평가 구간: 정상 4 · 코드 있는 악성 3(하나는 예측 없음) · 코드 없는 악성 1
        self.rows = [mk(2000, "benign"), mk(2001, "benign"), mk(2002, "benign", eco="npm"), mk(2003, "benign"),
                     mk(2010, "malicious"), mk(2011, "malicious", eco="npm"), mk(2012, "malicious"),
                     mk(2020, "malicious", lines=0)]
        self.p = {"00000000000007d0": 0.0, "00000000000007d1": 0.5, "00000000000007d2": 0.199, "00000000000007d3": 0.1,
                  "00000000000007da": 0.95, "00000000000007db": 0.198, "00000000000007e4": 0.99}

    def test_thresholds_come_from_budget_points_of_the_calibration_part(self):
        th = static_ml.thresholds(self.cal, self.cal_p)
        main = metrics.main_rows(self.cal)
        want = metrics.budget_points([self.cal_p[r["id"]] for r in main], metrics.labels(main))
        self.assertEqual(th, [(float(name[5:]), t) for name, t in want])
        # 정상 최대 0.199 → 오탐 0 인 가장 낮은 임계값은 그 위의 첫 점수 0.9. 0.0025 도 같은 0.9 라 한 번만 나온다
        self.assertEqual(th, [(0.0, 0.9), (0.005, 0.199), (0.01, 0.198), (0.015, 0.197), (0.02, 0.196)])

    def test_candidates_and_missing_predictions(self):
        rep = static_ml.report(self.rows, self.p, [(0.0, 0.199), (0.01, 0.1)])
        self.assertEqual([c["name"] for c in rep["candidates"]], ["M-static@0.0", "M-static@0.01"])
        first = rep["candidates"][0]
        # 0.199 이상: 정상 0.5 · 0.199 → 오탐 2 · 악성 0.95 만(0.198 아래, 하나는 예측 없음 → 못 잡음)
        self.assertEqual((first["all"]["tp"], first["all"]["fn"], first["all"]["fp"], first["all"]["tn"]), (1, 2, 2, 2))
        self.assertEqual(first["noCode"], {"rows": 1, "detected": 1})
        self.assertEqual(first["all"], metrics.summary([0, 0, 0, 0, 1, 1, 1], [False, True, True, False, True, False, False]))
        self.assertEqual(first["npm"]["tp"] + first["npm"]["fn"], 1)
        self.assertEqual(rep["main"], {"malicious": 3, "benign": 4})
        self.assertEqual(rep["predictions"], {"rows": 8, "missing": 1})

    def test_report_prints_as_table(self):
        rep = static_ml.report(self.rows, self.p, [(0.0, 0.199)])
        text = static_ml.format_report({**rep, "part": "train", "thresholdsFrom": "calibration"})
        self.assertIn("M-static@0.0", text)
        self.assertIn("코드 없는 악성", text)


if __name__ == "__main__":
    unittest.main()
