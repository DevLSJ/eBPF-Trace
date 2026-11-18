"""평가 규칙 v3 점검(운영점 선택 · 시험 측정 · 정적 기준선 · LLM 비용 상한 · 관문 경계) —
python3 -B -m unittest discover -s bench/v3 -p 'test_*.py'

네트워크 · 실제 데이터 · 실제 API 없이 돈다(가짜 점수 · 임시 폴더).
"""
import json
import os
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
V2 = os.path.join(os.path.dirname(HERE), "v2")
sys.path.insert(0, V2)
sys.path.insert(0, HERE)
import metrics  # noqa: E402
import select3  # noqa: E402
import split  # noqa: E402
import test_llm_layer as TL  # noqa: E402 — v2 시험의 JSONL 쓰기를 그대로 쓴다


def r(i, label, eco="pypi", lines=10, source="popular", date="2025-03-01"):
    return {"id": f"{i:016x}", "ecosystem": eco, "label": label, "codeLines": lines, "source": source, "date": date}


class World:
    """보정 구간 장난감: 정상 1,000 · 코드 있는 악성 200.
    ML: 정상 p = i/1000. 악성 100 개 0.9995 · 50 개 0.985 · 50 개 0.5.
    LLM: p 0.5 인 악성 50 개와 ML 이 낮게 본 정상 5 개만 90, 나머지 10."""

    def __init__(self, llm_helps=True):
        self.rows, self.ml, self.llm = [], {}, {}
        for i in range(1000):
            row = r(i, "benign")
            self.rows.append(row)
            self.ml[row["id"]] = i / 1000
            self.llm[row["id"]] = 90 if i < 5 else 10
        for k in range(200):
            row = r(10_000 + k, "malicious", eco="npm" if k % 2 else "pypi")
            self.rows.append(row)
            self.ml[row["id"]] = 0.9995 if k < 100 else (0.985 if k < 150 else 0.5)
            self.llm[row["id"]] = 90 if (k >= 150 and llm_helps) else 10
        self.rows.append(r(20_000, "malicious", lines=0))   # 코드 없는 악성 — 주 지표 밖
        self.scores = {"ml": self.ml, "llm": self.llm}


class Candidates(unittest.TestCase):
    def test_score_candidates_use_the_v2_budgets_and_a_tenth_of_a_percent_on_the_main_rows(self):
        w = World()
        main = metrics.main_rows(w.rows)
        ml = select3.candidates("ml", "M-static", main, w.ml)
        self.assertEqual([(c["name"], c["threshold"]) for c in ml],
                         [("M-static@0.0", 0.9995), ("M-static@0.001", 0.999), ("M-static@0.0025", 0.998), ("M-static@0.005", 0.995),
                          ("M-static@0.01", 0.99), ("M-static@0.015", 0.985), ("M-static@0.02", 0.98)])
        llm = select3.candidates("llm", "L", main, w.llm)
        self.assertEqual([(c["name"], c["threshold"]) for c in llm], [("L@0.005", 90)])

    def test_missing_scores_count_as_not_flagged(self):
        rows = [r(1, "malicious"), r(2, "benign")]
        cand = {"layer": "llm", "name": "L@0.0", "threshold": 50}
        self.assertEqual(select3.flags(cand, rows, {rows[0]["id"]: None}), [False, False])
        self.assertEqual(select3.flags(cand, rows, {rows[0]["id"]: 50, rows[1]["id"]: 49}), [True, False])


class Selection(unittest.TestCase):
    def test_primary_at_two_percent_and_secondary_at_a_tenth_of_a_percent(self):
        w = World()
        sel = select3.make_selection(w.rows, w.scores)
        self.assertTrue(sel["llmInclusion"]["included"])
        p = sel["primary"]
        self.assertEqual(p["maxFpr"], 0.02)
        self.assertEqual({k: v["name"] for k, v in p["points"].items()}, {"ml": "M-static@0.015", "llm": "L@0.005"})
        self.assertEqual((p["calibration"]["tp"], p["calibration"]["fp"]), (200, 20))
        s = sel["secondary"]
        self.assertEqual(s["maxFpr"], 0.001)
        self.assertEqual({k: v["name"] for k, v in s["points"].items()}, {"ml": "M-static@0.0"})
        self.assertEqual((s["calibration"]["tp"], s["calibration"]["fp"]), (100, 0))

    def test_llm_is_left_out_when_it_adds_less_than_one_point(self):
        sel = select3.make_selection(World(llm_helps=False).rows, World(llm_helps=False).scores)
        self.assertFalse(sel["llmInclusion"]["included"])
        self.assertLess(sel["llmInclusion"]["gain"], 0.01)
        self.assertEqual(set(sel["primary"]["points"]), {"ml"})
        self.assertEqual(set(sel["secondary"]["points"]), {"ml"})

    def test_secondary_is_none_when_no_combination_is_that_strict(self):
        w = World()
        for i in range(1000):
            w.ml[f"{i:016x}"] = 0.9995 if i < 3 else i / 1000   # 정상 3 개가 가장 높은 점수에 — 0.1% 안이 없다
        for k in range(100):
            w.ml[f"{10_000 + k:016x}"] = 0.9995
        sel = select3.make_selection(w.rows, w.scores)
        self.assertIsNone(sel["secondary"])

    def test_selection_file_is_written_until_the_test_part_is_opened(self):
        w = World()
        sel = select3.make_selection(w.rows, w.scores)
        with tempfile.TemporaryDirectory() as d:
            path, ledger = os.path.join(d, "selection.json"), os.path.join(d, "unseal-log.json")
            select3.write_selection(sel, path, ledger_path=ledger)
            select3.write_selection(sel, path, ledger_path=ledger)   # 열기 전에는 고칠 수 있다
            with open(ledger, "w") as f:
                json.dump([{"part": "test"}], f)
            with self.assertRaises(split.SealedError):
                select3.write_selection(sel, path, ledger_path=ledger)
            with open(path, encoding="utf-8") as f:
                self.assertEqual(json.load(f)["primary"]["points"]["ml"]["threshold"], 0.985)


class Measure(unittest.TestCase):
    def test_test_part_uses_the_selected_thresholds_and_reports_both_points(self):
        w = World()
        sel = select3.make_selection(w.rows, w.scores)
        rows, ml, llm = [], {}, {}
        for i in range(100):                                  # 정상 100: 3 개만 ML 0.99(주 운영점 0.985 에 걸림)
            row = r(30_000 + i, "benign", source="longTail" if i % 2 else "popular")
            rows.append(row)
            ml[row["id"]], llm[row["id"]] = (0.99 if i < 3 else 0.1), 10
        for k in range(65):                                   # 악성 65: ML 50 · LLM 10 · 놓침 5
            row = r(40_000 + k, "malicious", eco="npm", date="2024-05-05" if k < 30 else "2026-01-01")
            rows.append(row)
            ml[row["id"]] = 0.9996 if k < 50 else 0.2
            llm[row["id"]] = 95 if 50 <= k < 60 else None
        nocode = r(50_000, "malicious", lines=0)
        rows.append(nocode)
        ml[nocode["id"]] = 0.9999
        v2_ids = {row["id"] for row in rows[:50]} | {row["id"] for row in rows[100:120]}
        rep = select3.measure(rows, {"ml": ml, "llm": llm}, sel, v2_ids=v2_ids)
        main = rep["primary"]["main"]
        self.assertEqual((main["tp"], main["fn"], main["fp"], main["tn"]), (60, 5, 3, 97))
        self.assertFalse(main["met"])
        self.assertEqual(main["detectionCi95"], [round(x, 4) for x in metrics.wilson(60, 65)])
        self.assertEqual(rep["primary"]["noCode"], {"rows": 1, "detected": 1})
        self.assertEqual(rep["primary"]["byOrigin"]["v2"]["fp"], 3)
        self.assertEqual(rep["primary"]["byOrigin"]["new"]["tp"], 40)
        self.assertEqual(set(rep["primary"]["benignBySource"]), {"popular", "longTail"})
        self.assertEqual(rep["primary"]["byYear"]["2024"]["rows"], 30)
        self.assertEqual([c["through"] for c in rep["primary"]["ablation"]["cumulative"]], ["llm", "ml"])
        sec = rep["secondary"]["main"]                        # 0.9995 만: 악성 50 · 정상 0
        self.assertEqual((sec["tp"], sec["fp"]), (50, 0))
        self.assertEqual(rep["goal"], {"point": "primary", "met": False})


class Baselines(unittest.TestCase):
    def test_static_baselines_follow_addendum_1(self):
        rows = [r(1, "malicious"), r(2, "malicious"), r(3, "benign"), r(4, "benign")]
        gd = {rows[0]["id"]: {"status": "ok", "verdict": "malicious"}, rows[2]["id"]: {"status": "ok", "verdict": "suspicious"},
              rows[3]["id"]: {"status": "error"}}
        ru = {rows[1]["id"]: {"status": "ok", "strong": ["SH_CRED_READ"]}, rows[2]["id"]: {"status": "ok", "strong": ["OBF_LONG_LINE"]}}
        got = select3.baselines(rows, gd, ru)
        self.assertEqual(got["S-malicious"], [True, False, False, False])
        self.assertEqual(got["S-suspicious"], [True, False, True, False])
        self.assertEqual(got["R-strong"], [False, True, True, False])
        self.assertEqual(got["R-precise@0"], [False, True, False, False])
        self.assertEqual(set(got), {"S-malicious", "S-suspicious", "R-strong", "R-precise@0", "R-precise@1", "R-precise@3"})


class Budget(unittest.TestCase):
    def test_forty_five_for_calibration_and_the_rest_of_a_hundred_for_test(self):
        self.assertEqual(select3.llm_budget("calibration", 0.0), 45.0)
        self.assertEqual(select3.llm_budget("test", 30.0), 70.0)
        self.assertEqual(select3.llm_budget("test", 45.0), 55.0)
        self.assertEqual(select3.llm_budget("test", 0.0), 100.0)
        with self.assertRaises(ValueError):
            select3.llm_budget("reserve", 0.0)

    def test_calibration_spend_counts_only_v3_calls(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "out.jsonl")
            TL.write_jsonl(path, [{"id": "a", "status": "OK", "costUsd": 1.25}, {"id": "b", "status": "OK", "costUsd": 0.0,
                                                                                 "reusedFrom": {"costUsd": 3.0}}])
            self.assertEqual(select3.calibration_spent(path), 1.25)


class Gate(unittest.TestCase):
    def test_upper_bound_is_the_quarter_percent_point_of_out_of_fold_predictions(self):
        y = [0] * 1000 + [1] * 100
        oof = [i / 1000 for i in range(1000)] + [0.9999] * 60 + [0.5] * 40
        g = select3.gate_bounds(oof, y)
        self.assertEqual(g["high"], 0.998)
        self.assertEqual(g["low"], 0.02)
        self.assertEqual(g["benignInBand"], 978)   # 0.02 <= p < 0.998
        self.assertEqual(g["missedAtTwoPercent"], {"rows": 40, "inBand": 40})


if __name__ == "__main__":
    unittest.main()
