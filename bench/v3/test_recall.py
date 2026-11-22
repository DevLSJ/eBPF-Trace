#!/usr/bin/env python3
"""recall.py(LLM 재호출 변동 측정, 부록 4-recall)의 순수 계산 시험. python3 -B -m unittest bench/v3/test_recall.py"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import recall as R  # noqa: E402


def row(score, status="OK", models=("h",), cost=0.01):
    return {"status": status, "riskScore": score, "costUsd": cost, "stages": [{"model": m} for m in models]}


class Pick(unittest.TestCase):
    def test_order_depends_only_on_the_seed_and_the_id(self):
        ids = [f"s{i:03d}" for i in range(50)]
        a = R.pick_ids(ids, "seed-a", 10)
        self.assertEqual(a, R.pick_ids(list(reversed(ids)), "seed-a", 10))      # 입력 순서와 무관
        self.assertEqual(len(set(a)), 10)
        self.assertNotEqual(a, R.pick_ids(ids, "seed-b", 10))                   # 시드가 다르면 다른 표본
        self.assertEqual(a, sorted(ids, key=lambda s: R.order_key("seed-a", s))[:10])

    def test_asking_for_more_rows_than_there_are_is_refused(self):
        with self.assertRaises(ValueError):
            R.pick_ids(["a", "b"], "seed", 3)


class Rank(unittest.TestCase):
    def test_nearest_rank(self):
        xs = [0, 0, 1, 2, 10]
        self.assertEqual(R.nearest_rank(xs, 0.5), 1)
        self.assertEqual(R.nearest_rank(xs, 0.9), 10)
        self.assertEqual(R.nearest_rank([7], 0.9), 7)


class Summary(unittest.TestCase):
    def setUp(self):
        self.ids = ["a", "b", "c", "d"]
        self.kind = {"a": "codeMalicious", "b": "benign", "c": "benign", "d": "codeMalicious"}
        self.original = {"a": row(80), "b": row(10), "c": row(57), "d": row(95)}
        self.runs = [
            {"a": row(82, models=("h", "o")), "b": row(10), "c": row(58, models=("h", "o")), "d": row(None, status="REFUSED")},
            {"a": row(78, models=("h", "o")), "b": row(12), "c": row(40), "d": row(96, models=("h", "o"))},
            {"a": row(90, models=("h", "o")), "b": row(10), "c": row(57, models=("h", "o")), "d": row(95, models=("h", "o"))},
        ]

    def test_decisions_scores_and_escalation_are_counted_per_sample(self):
        s = R.summarize(self.original, self.runs, self.ids, {"primary": 58, "secondary": 90}, self.kind)
        self.assertEqual((s["rows"], s["runs"]), (4, 3))
        p = s["decision"]["primary"]
        # a: 세 번 모두 양성 · b: 세 번 모두 음성 · c: 58 · 40 · 57 → 갈림 · d: 점수 없음(음성) · 96 · 95 → 갈림
        self.assertEqual((p["allFlagged"], p["noneFlagged"], p["unstable"]), (1, 1, 2))
        self.assertEqual(p["originalFlagged"], 2)                                # a(80) · d(95)
        self.assertEqual(p["differsFromOriginal"], 2)                            # c 는 원래 음성인데 한 번 양성, d 는 원래 양성인데 한 번 음성
        self.assertEqual(p["perRunDiffersFromOriginal"], [2, 0, 0])
        self.assertEqual(p["pairAgreement"], [2, 2, 4])                          # (1,2) · (1,3) · (2,3) 에서 판정이 같은 표본 수
        q = s["decision"]["secondary"]
        self.assertEqual((q["allFlagged"], q["noneFlagged"], q["unstable"]), (0, 2, 2))   # a: 82 · 78 · 90 → 갈림, d: 없음 · 96 · 95 → 갈림
        sc = s["score"]
        self.assertEqual(sc["complete"], 3)                                      # d 는 점수 없는 호출이 있어 점수 통계에서 뺀다
        self.assertEqual(sc["ranges"], {"zero": 0, "median": 12, "p90": 18, "max": 18})   # a 12 · b 2 · c 18
        self.assertEqual(sc["originalInsideRange"], 3)                           # 80 ∈ [78, 90] · 10 ∈ [10, 12] · 57 ∈ [40, 58]
        self.assertAlmostEqual(sc["meanSd"], (4.98888 + 0.94281 + 8.25968) / 3, places=4)
        e = s["escalation"]
        self.assertEqual(e["perRun"], [2, 2, 3])
        self.assertEqual(e["unstable"], 2)                                       # c(올림 · 안 올림 · 올림) · d(안 올림 · 올림 · 올림)
        self.assertEqual(s["status"], [{"OK": 3, "REFUSED": 1}, {"OK": 4}, {"OK": 4}])
        self.assertEqual(s["byKind"]["benign"]["rows"], 2)
        self.assertEqual(s["byKind"]["benign"]["primaryUnstable"], 1)
        self.assertEqual(s["byKind"]["codeMalicious"]["primaryUnstable"], 1)
        self.assertEqual([round(x, 2) for x in s["spentUsd"]], [0.04, 0.04, 0.04])

    def test_a_sample_missing_from_a_run_is_refused(self):
        del self.runs[1]["b"]
        with self.assertRaises(ValueError):
            R.summarize(self.original, self.runs, self.ids, {"primary": 58}, self.kind)

    def test_the_report_carries_no_sample_ids_or_score_lists(self):
        s = R.summarize(self.original, self.runs, self.ids, {"primary": 58, "secondary": 90}, self.kind)
        text = repr(s)
        for sid in self.ids:
            self.assertNotIn(f"'{sid}'", text)


if __name__ == "__main__":
    unittest.main()
