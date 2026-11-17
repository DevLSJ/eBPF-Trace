"""sg-bench-runtime 계산 점검(서버 · Docker 없이) — python3 -B -m unittest discover -s tools -p 'test_*.py'

격리 순서가 정지(pause) → 증거 → 격리(kill)로 바뀐 뒤(11/16), 정지 단계를 보조 값으로 기록 · 집계하는지 본다.
격리 지연의 정의(killedAt − detectedAt)는 그대로이고, 정지 값이 없는 기록은 비우고 따로 센다(추정 · 보간 없음).
"""
import copy
import importlib.machinery
import importlib.util
import json
import os
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
_loader = importlib.machinery.SourceFileLoader("sg_bench_runtime", os.path.join(HERE, "sg-bench-runtime"))
_spec = importlib.util.spec_from_loader("sg_bench_runtime", _loader)
sbr = importlib.util.module_from_spec(_spec)
_loader.exec_module(sbr)

OLD_REPORT = os.path.join(ROOT, "bench", "reports", "runtime.json")


def ts(ms):
    """기준 시각에서 ms 만큼 뒤의 RFC3339(백엔드 형식, 마이크로초 + Z)"""
    sec, rest = divmod(int(round(ms * 1000)), 1_000_000)
    return f"2026-11-17T01:00:{sec:02d}.{rest:06d}Z"


def tl(detected=0.0, matched=0.1, paused=None, ev_start=None, ev_done=None, killed=None, pause_error=None):
    t = {"detectedAt": ts(detected), "matchedAt": ts(matched)}
    for k, v in (("pausedAt", paused), ("evidenceStartedAt", ev_start), ("evidenceDoneAt", ev_done), ("killedAt", killed)):
        if v is not None:
            t[k] = ts(v)
    if pause_error:
        t["pauseError"] = pause_error
    return t


def row(rid, timeline=None, rule="pipe-to-shell", enforced=False, enforce_error=None, container="sg-install-x"):
    r = {"id": rid, "ruleId": rule, "enforced": enforced, "event": {"containerName": container}}
    if timeline is not None:
        r["timeline"] = timeline
    if enforce_error:
        r["enforceError"] = enforce_error
    return r


class SummarizePause(unittest.TestCase):
    def test_new_order_records_pause_and_keeps_isolation(self):
        # 정지 → 증거 → 격리: 탐지 0 · 판정 0.1 · 정지 20.1 · 증거 20.2~150.2 · 격리 330.2
        rows = [row(1, tl(paused=20.1, ev_start=20.2, ev_done=150.2, killed=330.2), enforced=True),
                row(2, None, rule="sandbox-egress", enforced=True)]
        s = sbr.Bench.summarize(rows, None)
        self.assertTrue(s["killed"])
        self.assertEqual(s["isolationMs"], 330.2)  # 정의 그대로: killedAt − detectedAt
        self.assertEqual(s["pauseMs"], 20.1)       # pausedAt − detectedAt
        self.assertEqual(s["pauseApiMs"], 20.0)    # matchedAt → pausedAt
        self.assertEqual(s["killMatchMs"], 0.1)
        self.assertEqual(s["evidenceMs"], 130.0)
        self.assertEqual(s["killApiMs"], 180.0)
        self.assertFalse(s["pauseError"])
        self.assertFalse(s["pausedNotKilled"])
        self.assertFalse(s["evidenceWithoutKill"])

    def test_kill_without_paused_at_leaves_pause_empty(self):
        # 옛 판 · pause 실패: pausedAt 없음 → 정지 값은 비우고(추정하지 않음) pauseError 는 표시
        rows = [row(1, tl(ev_start=0.3, ev_done=130.3, killed=300.3, pause_error="docker pause: 409 Conflict: already paused"),
                    enforced=True)]
        s = sbr.Bench.summarize(rows, None)
        self.assertEqual(s["isolationMs"], 300.3)
        self.assertIsNone(s["pauseMs"])
        self.assertIsNone(s["pauseApiMs"])
        self.assertTrue(s["pauseError"])

    def test_exited_container_is_not_isolated_but_counted(self):
        # 이미 끝난 컨테이너: 증거 시각만 있고 pausedAt · killedAt 없음, 격리 아님 + 사유
        rows = [row(1, tl(ev_start=10.0, ev_done=200.0), enforce_error="container is not running")]
        s = sbr.Bench.summarize(rows, None)
        self.assertFalse(s["killed"])
        self.assertIsNone(s["isolationMs"])
        self.assertIsNone(s["pauseMs"])
        self.assertTrue(s["notRunning"])
        self.assertTrue(s["evidenceWithoutKill"])
        self.assertFalse(s["pausedNotKilled"])

    def test_paused_but_kill_failed(self):
        rows = [row(1, tl(paused=15.0, ev_start=15.1, ev_done=140.0), enforce_error="docker kill: 500 Internal Server Error: x")]
        s = sbr.Bench.summarize(rows, None)
        self.assertFalse(s["killed"])
        self.assertIsNone(s["isolationMs"])
        self.assertEqual(s["pauseMs"], 15.0)
        self.assertTrue(s["pausedNotKilled"])
        self.assertTrue(s["evidenceWithoutKill"])


def run(isolation=None, match=0.1, pause=None, pause_api=None, evidence=None, kill_api=None, killed=None, detected=True,
        pause_error=False, paused_not_killed=False, evidence_without_kill=False, not_running=False):
    killed = isolation is not None if killed is None else killed
    return {"detected": detected, "rule": "sandbox-dns", "killed": killed, "killRule": "sandbox-dns" if killed else None,
            "dryRun": False, "matchMs": match, "isolationMs": isolation, "killMatchMs": match if killed else None,
            "evidenceMs": evidence, "killApiMs": kill_api, "notRunning": not_running, "verdicts": 1,
            "pauseMs": pause, "pauseApiMs": pause_api, "pauseError": pause_error,
            "pausedNotKilled": paused_not_killed, "evidenceWithoutKill": evidence_without_kill}


class ScenarioPause(unittest.TestCase):
    def setUp(self):
        self.runs = [
            run(300.0, pause=20.0, pause_api=19.9, evidence=130.0, kill_api=150.0),
            run(320.0, pause=25.0, pause_api=24.9, evidence=140.0, kill_api=155.0),
            run(310.0, pause=None, pause_api=None, evidence=135.0, kill_api=175.0, pause_error=True),  # pause 실패
            run(None, killed=False, evidence=180.0, evidence_without_kill=True, not_running=True),     # 이미 끝난 컨테이너
        ]
        self.out = sbr.scenario_out("sandbox-dns-exfil", self.runs)

    def test_isolation_definition_unchanged(self):
        self.assertEqual(self.out["latencyMs"], sbr.dist([300.0, 320.0, 310.0]))
        self.assertEqual(self.out["killed"], 3)
        self.assertEqual(self.out["detectedNotKilled"], 1)
        self.assertEqual(self.out["killNotRunning"], 1)

    def test_pause_distribution_and_counts(self):
        self.assertEqual(self.out["pauseLatencyMs"], sbr.dist([20.0, 25.0]))
        self.assertEqual(self.out["pauseApiMs"], sbr.dist([19.9, 24.9]))
        self.assertEqual(self.out["pauseMissing"], 1)  # 격리됐지만 pausedAt 없는 회차
        self.assertEqual(self.out["pauseErrors"], 1)
        self.assertEqual(self.out["pausedNotKilled"], 0)
        self.assertEqual(self.out["evidenceWithoutKill"], 1)

    def test_samples_keep_pause_values(self):
        samples = self.out["samples"]
        self.assertEqual(len(samples), 3)  # 격리된 회차만(지금과 같음)
        self.assertEqual([x["pauseMs"] for x in samples], [20.0, 25.0, None])
        self.assertEqual([x["pauseApiMs"] for x in samples], [19.9, 24.9, None])
        for x in samples:
            self.assertEqual(set(x), {"latencyMs", "matchMs", "evidenceMs", "killApiMs", "pauseMs", "pauseApiMs"})


class Totals(unittest.TestCase):
    def test_pause_totals_over_attack_scenarios(self):
        report = {"scenarios": [
            {"id": "sandbox-typosquat", "kind": "attack", "samples": [
                sbr.sample(300.0, 0.1, 130.0, 150.0, pause=20.0, pause_api=19.9),
                sbr.sample(310.0, 0.1, 135.0, 155.0)]},  # 정지 값 없음
            {"id": "sandbox-dns-exfil", "kind": "attack", "samples": [sbr.sample(330.0, 0.1, 140.0, 170.0, pause=30.0, pause_api=29.9)]},
            {"id": "chain-gap-control", "kind": "control", "samples": [sbr.sample(1.0, 0.1, 1.0, 1.0, pause=1.0, pause_api=1.0)]},
        ]}
        sbr.add_kill_totals(report)
        self.assertEqual(report["killLatencyMs"]["n"], 3)
        p = report["pauseLatencyMs"]
        self.assertEqual({k: p[k] for k in ("p50", "p95", "max", "n")}, sbr.dist([20.0, 30.0]))
        self.assertEqual(p["missing"], 1)
        self.assertEqual(p["scenarios"], ["sandbox-dns-exfil", "sandbox-typosquat"])
        self.assertEqual(report["killStagesMs"]["pauseApi"], sbr.dist([19.9, 29.9]))
        self.assertEqual(set(report["killStagesMs"]), {"match", "pauseApi", "evidence", "killApi"})


class OldReportCompat(unittest.TestCase):
    """11/04 보고서(pausedAt 이전): 다시 합산해도 기존 키 값은 그대로, 정지는 빈 값 + 없는 수"""

    @classmethod
    def setUpClass(cls):
        with open(OLD_REPORT) as f:
            cls.old = json.load(f)

    def test_totals_unchanged_and_pause_empty(self):
        report = copy.deepcopy(self.old)
        sbr.add_kill_totals(report)
        self.assertEqual(report["killLatencyMs"], self.old["killLatencyMs"])
        for k in ("match", "evidence", "killApi"):
            self.assertEqual(report["killStagesMs"][k], self.old["killStagesMs"][k])
        n = self.old["killLatencyMs"]["n"]
        self.assertEqual(report["pauseLatencyMs"], {"p50": None, "p95": None, "max": None, "n": 0, "missing": n,
                                                    "scenarios": self.old["killLatencyMs"]["scenarios"]})
        self.assertIsNone(report["killStagesMs"]["pauseApi"])
        for k in self.old:
            self.assertIn(k, report)  # 키는 더하기만

    def test_rebuild_from_old_timelines(self):
        """--rebuild 의 계산부: 감사 로그 타임라인(pausedAt 없음)에서 samples 를 되살려도 오류 없이 정지는 빈 값"""
        report = copy.deepcopy(self.old)
        api = FakeAPI(self.old, paused=False)
        sbr.rebuild_report(report, api)
        for s in report["scenarios"]:
            want = [x["latencyMs"] for x in self.old_samples(s["id"])]
            self.assertEqual([x["latencyMs"] for x in s["samples"]], want)
            self.assertTrue(all(x["pauseMs"] is None for x in s["samples"]))
        self.assertEqual(report["killLatencyMs"], self.old["killLatencyMs"])
        self.assertEqual(report["pauseLatencyMs"]["missing"], self.old["killLatencyMs"]["n"])

    def test_rebuild_with_paused_at(self):
        report = copy.deepcopy(self.old)
        sbr.rebuild_report(report, FakeAPI(self.old, paused=True))
        pauses = [x["pauseMs"] for s in report["scenarios"] for x in s["samples"]]
        want = [round(x["matchMs"] + 20.0, 1) for s in self.old["scenarios"] for x in s.get("samples") or []]
        self.assertEqual(len(pauses), self.old["killLatencyMs"]["n"])
        self.assertEqual(pauses, want)  # FakeAPI: 판정 20ms 뒤 정지 → pausedAt − detectedAt
        self.assertEqual([x["pauseApiMs"] for s in report["scenarios"] for x in s["samples"]], [20.0] * len(want))
        self.assertEqual(report["pauseLatencyMs"]["missing"], 0)

    def old_samples(self, sid):
        return next(s for s in self.old["scenarios"] if s["id"] == sid).get("samples") or []


class FakeAPI:
    """옛 보고서의 samples 로 감사 로그 kill 판정과 설치 세션을 흉내 낸다"""

    def __init__(self, report, paused):
        self.rows, self.sessions = [], {}
        rid = 0
        for s in report["scenarios"]:
            for x in s.get("samples") or []:
                rid += 1
                m = x["matchMs"]
                p = m + 20.0 if paused else None
                ev_done = x["latencyMs"] - x["killApiMs"]
                t = tl(0.0, m, paused=p, ev_start=ev_done - x["evidenceMs"], ev_done=ev_done, killed=x["latencyMs"])
                ref = f"ins-{rid}"
                pkg = "/work/dns-exfil/reqeusts" if s["id"] == "sandbox-dns-exfil" else "/src/deploy/demo/reqeusts"
                self.sessions[ref] = {"packages": [pkg]}
                self.rows.append({"id": rid, "timeline": t, "install": {"id": ref}})

    def get(self, path):
        if path.startswith("/api/audit"):
            return self.rows
        if path.startswith("/api/installs/"):
            return self.sessions[path.rsplit("/", 1)[1]]
        raise AssertionError(path)


class NotifyGuard(unittest.TestCase):
    def test_blocks_when_notify_enabled(self):
        self.assertTrue(sbr.notify_block_reason({"notify": {"enabled": True, "channels": [{"name": "slack"}]}}, False))

    def test_allows_when_disabled_absent_or_overridden(self):
        self.assertIsNone(sbr.notify_block_reason({"notify": {"enabled": False}}, False))
        self.assertIsNone(sbr.notify_block_reason({}, False))
        self.assertIsNone(sbr.notify_block_reason({"notify": {"enabled": True}}, True))


if __name__ == "__main__":
    unittest.main()
