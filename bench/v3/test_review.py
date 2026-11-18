"""평가 규칙 v3 검토 반영 점검(1~13) — python3 -B -m unittest discover -s bench/v3 -p 'test_*.py'

검토자의 재현(r1 · r1b · r2 · r3 · r4 · r7)을 시험으로 옮겼다. 네트워크 · 실제 데이터 · 실제 API 없이 임시 폴더 · 가짜 트리 · 가짜 클라이언트만 쓴다.
"""
import contextlib
import fcntl
import io
import json
import os
import subprocess
import sys
import tempfile
import textwrap
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
V2 = os.path.join(os.path.dirname(HERE), "v2")
sys.path.insert(0, V2)
sys.path.insert(0, HERE)
import collect  # noqa: E402
import collect3  # noqa: E402
import llm_layer as L  # noqa: E402
import metrics  # noqa: E402
import run  # noqa: E402
import select3  # noqa: E402
import split  # noqa: E402
import split3  # noqa: E402
import test_llm_layer as TL  # noqa: E402 — v2 시험의 가짜 클라이언트 · 합성 표본


def tmpdir(case):
    tmp = tempfile.TemporaryDirectory()
    case.addCleanup(tmp.cleanup)
    return os.path.realpath(tmp.name)


def no_network():
    """수집기가 밖으로 나가는 길(git 복제 · 트리 · HTTP)을 모두 막는다 — 고치기 전 코드로 돌려도 네트워크에 닿지 않게."""
    def refuse(*_a, **_k):
        raise AssertionError("시험에서 네트워크에 닿으려 했다")
    stack = contextlib.ExitStack()
    for name in ("datadog_tree", "datadog_entries", "git", "http", "fetch_blobs"):
        stack.enter_context(mock.patch.object(collect, name, refuse))
    return stack


# 하위 프로세스(v2 collect.py)용: git 은 file 프로토콜만, HTTP 는 닿지 않는 프록시로
OFFLINE_ENV = {"GIT_ALLOW_PROTOCOL": "file", "HTTPS_PROXY": "http://127.0.0.1:9", "HTTP_PROXY": "http://127.0.0.1:9",
               "https_proxy": "http://127.0.0.1:9", "http_proxy": "http://127.0.0.1:9"}


def listing(folder):
    return sorted(os.path.relpath(os.path.join(d, f), folder) for d, _, fs in os.walk(folder) for f in fs)


# ── 1. v2 / v3 폴더 구분 ──

class FolderGuard(unittest.TestCase):
    def setUp(self):
        self.root = tmpdir(self)
        self.v2 = os.path.join(self.root, "datasets", "v2")
        os.makedirs(os.path.join(self.v2, "meta"))
        with open(os.path.join(self.v2, "index.jsonl"), "w") as f:
            f.write("")

    def env(self, data, v2=None):
        env = {k: v for k, v in os.environ.items() if not k.startswith("SG_BENCH")}
        env["SG_BENCH_DATA"] = data
        if v2 is not None:
            env["SG_BENCH_V2_DATA"] = v2
        return mock.patch.dict(os.environ, env, clear=True)

    def variants(self):
        out = [self.v2, os.path.join(self.v2, "sub")]
        link = os.path.join(self.root, "link-to-v2")
        os.symlink(self.v2, link)
        out.append(link)
        upper = self.v2[:-2] + "V2"
        if os.path.exists(upper):  # 대소문자를 가리지 않는 파일 시스템에서만 같은 폴더다
            out.append(upper)
        return out

    def test_data_folder_equal_to_or_inside_v2_is_refused_by_file_identity(self):
        for data in self.variants():
            with self.env(data, self.v2), self.assertRaises(split3.Stop, msg=data):
                split3.data_dir()
        with self.env(os.path.join(self.root, "datasets", "v3"), self.v2):
            self.assertEqual(split3.data_dir(), os.path.join(self.root, "datasets", "v3"))

    def test_missing_v2_folder_stops(self):
        with self.env(os.path.join(self.root, "v3"), os.path.join(self.root, "nowhere")), self.assertRaises(split3.Stop):
            split3.data_dir()
        with self.env(os.path.join(self.root, "v3")), mock.patch.object(split3, "DEFAULT_V2_DATA", os.path.join(self.root, "nowhere")), \
                self.assertRaises(split3.Stop):
            split3.data_dir()   # worktree 에서 SG_BENCH_V2_DATA 를 주지 않은 경우(r1 case 1)

    def test_run_entry_refuses_before_starting_a_tool(self):
        calls = []
        made = os.path.join(self.root, "split.json")   # 분할 파일이 있어도(그 검사에 걸려 멈추는 것이 아니게) 폴더 검사에서 멈춘다
        with open(made, "w") as f:
            f.write("{}")
        cases = [(self.v2[:-2] + "V2" if os.path.exists(self.v2[:-2] + "V2") else self.v2, self.v2),
                 (os.path.join(self.root, "v3"), os.path.join(self.root, "nowhere"))]
        for data, v2 in cases:
            with self.env(data, v2), mock.patch.object(run, "SPLIT", made), \
                    mock.patch.object(run.subprocess, "run", lambda *a, **k: calls.append(a)), \
                    contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                run.main(["static_ml", "train"])
        self.assertEqual(calls, [])

    def test_every_collect3_step_stops_before_touching_anything_when_data_is_v2(self):
        before = listing(self.v2)
        argvs = [["malicious", "--eco", "npm"], ["malicious", "--eco", "pypi"], ["plan"], ["benign", "--eco", "pypi", "--kind", "popular"],
                 ["benign", "--eco", "npm", "--kind", "longTail"], ["index"], ["source-line"], ["prune"], ["status"],
                 ["precheck", "--eco", "npm"], ["summary"]]
        for data in self.variants():
            for argv in argvs:
                with self.env(data, self.v2), no_network(), contextlib.redirect_stdout(io.StringIO()), \
                        contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit, msg=argv):
                    collect3.main(argv)
        self.assertEqual(listing(self.v2), before)

    def test_seal_refuses_the_v2_folder_by_file_identity(self):
        link = os.path.join(self.root, "link")
        os.symlink(self.v2, link)
        with self.assertRaises(split3.Stop):
            split3.seal({"assignments": {}, "sealed": ["test", "reserve"]}, link, self.v2, [], [])


# ── 2. v2 collect.py 가 v3 폴더를 대상으로 돌지 않게 ──

class V2CollectorGuard(unittest.TestCase):
    def test_guard_function(self):
        root = tmpdir(self)
        default = os.path.join(split.ROOT, "bench", "datasets", "v2")
        self.assertIsNone(collect.v3_guard(default, {}))
        v3 = os.path.join(root, "v3")
        os.makedirs(os.path.join(v3, "meta"))
        self.assertIn("v2 기본", collect.v3_guard(v3, {}))                           # v2 기본 폴더가 아니고 v3 진입점도 아님
        with open(os.path.join(v3, "index-new.jsonl"), "w"):
            pass
        self.assertIn("index-new.jsonl", collect.v3_guard(v3, {"SG_BENCH_V3_ENTRY": "1"}))
        plan_only = os.path.join(root, "p")
        os.makedirs(os.path.join(plan_only, "meta"))
        with open(os.path.join(plan_only, "meta", "benign-plan.json"), "w"):
            pass
        self.assertIn("benign-plan.json", collect.v3_guard(plan_only, {"SG_BENCH_V3_ENTRY": "1"}))
        self.assertIn("규약 폴더", collect.v3_guard(default, {"SG_BENCH_RULES": HERE}))

    def test_v2_prune_run_against_a_v3_folder_is_refused_and_deletes_nothing(self):
        """r2: run.py 를 쓰려고 SG_BENCH_DATA 를 v3 폴더로 내보낸 채 v2 collect.py prune 을 돌린 경우."""
        root = tmpdir(self)
        v2, v3 = os.path.join(root, "v2"), os.path.join(root, "v3")
        for d in ("store", "sealed/test"):
            os.makedirs(os.path.join(v2, d))
            os.makedirs(os.path.join(v3, d))
        with open(os.path.join(v2, "store", "aaaa000000000001.zip"), "w") as f:
            f.write("v2a")
        os.symlink("../../v2/store/aaaa000000000001.zip", os.path.join(v3, "store", "aaaa000000000001.zip"))
        for name in ("bbbb000000000001.tgz", "bbbb000000000002.tar.gz"):
            with open(os.path.join(v3, "store", name), "w") as f:
                f.write("new")
        with open(os.path.join(v3, "index-new.jsonl"), "w") as f:
            f.write("")
        before = (listing(v2), sorted(os.listdir(os.path.join(v3, "store"))))
        for argv in (["prune"], ["seal"], ["index"], ["benign", "--eco", "pypi", "--kind", "popular"]):   # 네트워크에 닿는 단계는 넣지 않는다
            env = {k: v for k, v in os.environ.items() if not k.startswith("SG_BENCH")}
            r = subprocess.run([sys.executable, "-B", os.path.join(V2, "collect.py"), *argv], env={**env, **OFFLINE_ENV, "SG_BENCH_DATA": v3},
                               capture_output=True, text=True)
            self.assertNotEqual(r.returncode, 0, argv)
            self.assertIn("거부", r.stderr)
        self.assertEqual((listing(v2), sorted(os.listdir(os.path.join(v3, "store")))), before)


# ── 3. 보조 운영점 후보(예산 격자 ∪ {0.001}) ──

class SecondaryGrid(unittest.TestCase):
    def test_grid_has_a_tenth_of_a_percent(self):
        self.assertEqual(select3.BUDGETS, (0.0, 0.001, 0.0025, 0.005, 0.01, 0.015, 0.02))
        self.assertEqual(metrics.FPR_BUDGETS, (0.0, 0.0025, 0.005, 0.01, 0.015, 0.02))   # v2 기본값은 그대로

    def test_secondary_point_can_use_the_tenth_of_a_percent_candidate(self):
        """r3: 정상 2,000 가운데 높은 점수 5개, 악성 100개 0.995 · 900개 0.97."""
        rows, ml = [], {}
        hi = [0.99, 0.98, 0.96, 0.96, 0.96]
        for k in range(2000):
            rows.append({"id": f"b{k:05d}", "label": "benign", "codeLines": 10, "ecosystem": "npm", "source": "popular"})
            ml[f"b{k:05d}"] = hi[k] if k < len(hi) else 0.1
        for k in range(1000):
            rows.append({"id": f"m{k:05d}", "label": "malicious", "codeLines": 10, "ecosystem": "npm"})
            ml[f"m{k:05d}"] = 0.995 if k < 100 else 0.97
        sel = select3.make_selection(rows, {"ml": ml})
        self.assertIn(("M-static@0.001", 0.97), [(c["name"], c["threshold"]) for c in sel["candidates"]["ml"]])
        s = sel["secondary"]
        self.assertEqual(s["points"]["ml"]["name"], "M-static@0.001")
        self.assertEqual((s["calibration"]["tp"], s["calibration"]["fp"]), (1000, 2))


# ── 4. 시험 구간 LLM 예산 ──

class TestBudget(unittest.TestCase):
    def test_calibration_plus_test_never_exceeds_a_hundred(self):
        self.assertEqual(select3.llm_budget("calibration", 0.0), 45.0)
        for spent in (0.0, 10.0, 44.99, 45.0, 47.5, 99.0, 100.0, 130.0):
            got = select3.llm_budget("test", spent)
            self.assertGreaterEqual(got, 0.0)
            self.assertLessEqual(spent + got, max(100.0, spent) + 1e-9, spent)
            if spent <= 100:
                self.assertLessEqual(min(spent, 45.0) + got, 100.0 + 1e-9)
        self.assertEqual(select3.llm_budget("test", 47.5), 52.5)
        self.assertEqual(select3.llm_budget("test", 130.0), 0.0)

    def test_missing_or_unreadable_calibration_results_stop(self):
        d = tmpdir(self)
        with self.assertRaises(ValueError):
            select3.calibration_spent(os.path.join(d, "none.jsonl"))
        torn = os.path.join(d, "torn.jsonl")
        with open(torn, "w") as f:
            f.write('{"id": "a", "status": "OK", "costUsd": 1.0}\n{"id": "b", "sta')
        with self.assertRaises(ValueError):
            select3.calibration_spent(torn)
        with mock.patch.dict(os.environ, {"SG_BENCH_DATA": os.path.join(d, "v3"), "SG_BENCH_V2_DATA": d}), \
                contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            select3.main(["llm-budget", "--part", "test", "--calibration-results", os.path.join(d, "none.jsonl")])

    def test_lost_batches_and_unwritten_work_count_and_pending_batches_stop(self):
        d = tmpdir(self)
        out = os.path.join(d, "out.jsonl")
        TL.write_jsonl(out, [{"id": "a", "status": "OK", "costUsd": 1.0}, {"id": "b", "status": "OK", "costUsd": 0.0, "reusedFrom": {}}])
        state = out + ".batches.json"
        with open(state, "w") as f:
            json.dump({"lostUsd": 2.5, "work": {"k": {"ids": ["c"], "stages": [{"costUsd": 0.5}], "analyses": {}}},
                       "batches": [{"id": "b1", "collected": True, "heldUsd": 9.0}]}, f)
        self.assertAlmostEqual(select3.calibration_spent(out), 4.0)
        with open(state, "w") as f:
            json.dump({"work": {}, "batches": [{"id": "b2", "collected": False, "heldUsd": 1.0}]}, f)
        with self.assertRaises(ValueError):
            select3.calibration_spent(out)


# ── 5. measure 입력 대조 ──

def selection_with(points, **inputs):
    return {"primary": {"maxFpr": 0.02, "points": points}, "secondary": None,
            "inputs": {"splitSha256": "S", "mlModelSha256": "M", "llmGate": {"low": 0.02, "high": 0.99}, **inputs}}


class MeasureInputs(unittest.TestCase):
    ML = {"name": "M-static@0.0", "threshold": 0.5}
    LLM = {"name": "L@0.0", "threshold": 50}

    def test_selection_with_the_llm_layer_needs_llm_scores(self):
        """r7: LLM 이 든 선택을 --llm 없이 재면 조용히 LLM 을 끈 값이 나왔다."""
        rows = [{"id": f"m{k}", "label": "malicious", "codeLines": 5, "ecosystem": "npm", "date": "2025-01-01"} for k in range(4)]
        sel = selection_with({"llm": self.LLM, "ml": self.ML})
        with self.assertRaises(ValueError):
            select3.measure(rows, {"ml": {r["id"]: 0.9 for r in rows}}, sel)
        select3.measure(rows, {"ml": {r["id"]: 0.9 for r in rows}, "llm": {}}, sel)

    def test_inputs_must_match_the_selection(self):
        sel = selection_with({"llm": self.LLM, "ml": self.ML})
        gate = {"mode": "ml", "low": 0.02, "high": 0.99, "mlSha256": "F"}
        ok = dict(split_sha="S", ml_model_sha="M", ml_file_sha="F", llm_gates=[gate])
        select3.check_inputs(sel, **ok)
        for change in ({"split_sha": "X"}, {"ml_model_sha": "X"}, {"llm_gates": None}, {"llm_gates": [dict(gate, high=0.98)]},
                       {"llm_gates": [dict(gate, low=0.01)]}, {"llm_gates": [dict(gate, mlSha256="X")]}, {"llm_gates": [gate, dict(gate, high=0.5)]}):
            with self.assertRaises(ValueError, msg=change):
                select3.check_inputs(sel, **{**ok, **change})
        select3.check_inputs(selection_with({"ml": self.ML}), **{**ok, "llm_gates": None})   # LLM 을 쓰지 않는 선택

    def test_gates_of_results(self):
        rows = {"a": {"gate": {"mode": "ml", "low": 0.02, "high": 0.9}}, "b": {"gate": {"high": 0.9, "low": 0.02, "mode": "ml"}},
                "c": {"gate": {"mode": "ml", "low": 0.02, "high": 0.8}}}
        self.assertEqual(len(select3.gates_of(rows)), 2)


# ── 6. sources.json 경쟁 · 악성 단계 동시 실행 ──

RACE = textwrap.dedent("""
    import os, sys
    sys.path.insert(0, sys.argv[1])
    import collect
    collect.DATA, collect.SOURCES = sys.argv[2], os.path.join(sys.argv[2], "sources.json")
    for k in range(150):
        collect.sources({sys.argv[3]: {"n": k}})
""")


class SourcesRace(unittest.TestCase):
    def test_two_writers_never_lose_a_key(self):
        """r4: 두 단계가 sources.json 을 동시에 고쳐도 마지막에 두 키가 모두 마지막 값이다."""
        d = tmpdir(self)
        for _ in range(3):
            path = os.path.join(d, "sources.json")
            if os.path.exists(path):
                os.remove(path)
            procs = [subprocess.Popen([sys.executable, "-B", "-c", RACE, V2, d, key]) for key in ("pypiNames", "npmNames")]
            for p in procs:
                self.assertEqual(p.wait(), 0)
            with open(path) as f:
                cur = json.load(f)
            self.assertEqual((cur["pypiNames"]["n"], cur["npmNames"]["n"]), (149, 149))

    def test_malicious_steps_run_one_at_a_time(self):
        d = tmpdir(self)
        with collect3.malicious_lock(d):
            with self.assertRaises(collect.Stop):
                with collect3.malicious_lock(d):
                    pass
        with collect3.malicious_lock(d):
            pass
        holder = open(os.path.join(d, "malicious.lock"), "a")
        self.addCleanup(holder.close)
        fcntl.flock(holder, fcntl.LOCK_EX)
        with self.assertRaises(collect.Stop):
            with collect3.malicious_lock(d):
                pass


# ── 7. inherit-results 는 학습 · 보정만 ──

class InheritOnlyOpenParts(unittest.TestCase):
    def test_test_and_reserve_results_are_never_copied(self):
        d = tmpdir(self)
        v2_data, data = os.path.join(d, "v2"), os.path.join(d, "v3")
        os.makedirs(os.path.join(v2_data, "results"))
        os.makedirs(os.path.join(data, "results"))
        sp = {"assignments": {"t1": "test", "r1": "reserve", "a1": "train"}}
        v2_assign = dict(sp["assignments"])
        for part, i in (("test", "t1"), ("reserve", "r1"), ("train", "a1")):
            with open(os.path.join(v2_data, "results", f"static-{part}.jsonl"), "w") as f:
                f.write(json.dumps({"id": i, "status": "ok"}) + "\n")
        with open(os.path.join(data, "results", "static-test.jsonl"), "w") as f:
            f.write("keep\n")
        got = split3.inherit_results(sp, v2_assign, v2_data, data)
        self.assertEqual(got, {"static-train": 1})
        with open(os.path.join(data, "results", "static-test.jsonl")) as f:
            self.assertEqual(f.read(), "keep\n")
        self.assertFalse(os.path.exists(os.path.join(data, "results", "static-reserve.jsonl")))


# ── 8. 정적 검사기 판 대조 ──

class Engines(unittest.TestCase):
    def test_one_engine_set_across_inherited_and_new_lines(self):
        old = {"GuardDog": "3.2.0", "OSV-Scanner": "2.7.0"}
        rows = [{"id": i} for i in ("a", "b", "c", "d")]
        gd = {"a": {"status": "ok", "engines": old}, "b": {"status": "skip", "engines": None}, "c": {"status": "ok", "engines": dict(old)}}
        self.assertIsNone(select3.engine_check(rows, gd, v2_ids={"a"}))
        gd["d"] = {"status": "ok", "engines": {"GuardDog": "3.3.0", "OSV-Scanner": "2.7.0"}}
        got = select3.engine_check(rows, gd, v2_ids={"a"})
        self.assertEqual(got["v2"], {json.dumps(old, sort_keys=True): 1})
        self.assertEqual(sorted(got["new"].values()), [1, 1])


# ── 9. 예산 끝자락: 엄격한 앞쪽부터 자르기 ──

def pair_worst(sample, batch):
    prompt = L.load_prompt()
    _, user_text = L.prepare(sample["id"], sample["text"], sample["static"], prompt)
    return sum(L.worst_case_usd(m, L.bound_input_tokens(L.build_request(m, prompt, user_text)), batch=batch)
               for m in (L.STAGE1_MODEL, L.STAGE2_MODEL))


class StrictOrder(unittest.TestCase):
    """s0 · s2 는 작고 s1 은 크다. 상한 = s0 · s2 의 (1단계 + 2단계) 최악 몫 합 — s1 은 잡을 수 없다."""

    def setUp(self):
        self.samples = TL.samples(3)
        self.samples[1] = dict(self.samples[1], text=self.samples[1]["text"] + "x = 1\n" * 30000)
        self.dir = tmpdir(self)

    def limit(self, batch):
        a, b, c = (pair_worst(s, batch) for s in self.samples)
        self.assertGreater(b, c + 0.001)
        return a + c + 0.0005

    def called(self, client):
        return sorted(s["id"] for s in self.samples if any(f"# {s['id']}\n" in r["messages"][0]["content"] for r in client.calls))

    def test_batches_stop_at_the_first_sample_that_cannot_be_held(self):
        for strict, want in ((True, ["s0"]), (False, ["s0", "s1", "s2"])):
            client = TL.FakeClient({TL.HAIKU: lambda request: TL.message(TL.analysis(5))})
            results = L.Results(os.path.join(self.dir, f"b-{strict}.jsonl"))
            kw = {"strict_order": True} if strict else {}   # 인자를 주지 않으면 v2 동작
            TL.batches(self.samples, client, results, limit_usd=self.limit(True), **kw)
            self.assertEqual(self.called(client), want, strict)
            if strict:
                self.assertEqual({i: results.rows[i]["status"] for i in ("s0", "s1", "s2")},
                                 {"s0": "OK", "s1": "SKIPPED_BUDGET", "s2": "SKIPPED_BUDGET"})

    def test_realtime_does_the_same(self):
        client = TL.FakeClient({TL.HAIKU: lambda request: TL.message(TL.analysis(5))})
        results = L.Results(os.path.join(self.dir, "rt.jsonl"))
        TL.batch(self.samples, client, results, limit_usd=self.limit(False), strict_order=True)
        self.assertEqual(self.called(client), ["s0"])
        self.assertEqual(results.rows["s2"]["status"], "SKIPPED_BUDGET")

    def test_v3_entry_always_passes_the_flag_to_llm_layer_run(self):
        self.assertEqual(run.command("llm_layer", ["run", "--part", "calibration"])[-1], "--strict-order")
        self.assertEqual(run.command("llm_layer", ["run", "--strict-order"]).count("--strict-order"), 1)
        self.assertNotIn("--strict-order", run.command("llm_layer", ["estimate", "--input", "x"]))
        self.assertNotIn("--strict-order", run.command("static_ml", ["train"]))


# ── 10. 출처 칸 ──

SOURCES = {"datadog": {"commit": "72c723be547033c558244520524b117c8d71663b", "committedAt": "2026-11-05T09:52:48+01:00"},
           "fetchedOn": "2026-11-19",
           "pypiTop": {"sha256": "3e958a64ebe1de0b6a4ab4c6b465d481f350fd1dfa926c639add36eb34dabc1e", "rows": 15000, "lastUpdate": "2026-11-01 06:41:05"},
           "pypiNames": {"sha256": "21ff2a07ad9ec39ca701f286025b752cc1d3adb9f44895d4b8f0e62a02dc290c", "count": 937876},
           "npmTop": {"pages": 60, "names": 5900, "maxPages": 60},
           "npmNames": {"package": "all-the-package-names@2.0.2622", "sha256": "162501805f0bdfa124b70f926b56a9497947b81fb4267e20d81c1d87354e4ff9"}}


class Source(unittest.TestCase):
    def test_source_line_keeps_full_hashes_and_the_commit_time_to_the_second(self):
        line = collect3.source_line(SOURCES)
        for needle in ("72c723be547033c558244520524b117c8d71663b", "2026-11-05T09:52:48+01:00", SOURCES["pypiTop"]["sha256"],
                       SOURCES["pypiNames"]["sha256"], SOURCES["npmNames"]["sha256"], "2026-11-19"):
            self.assertIn(needle, line)

    def test_build_needs_a_source(self):
        d = tmpdir(self)
        with self.assertRaises(ValueError):
            split3.build_file(out=os.path.join(d, "split.json"), new_index=os.path.join(d, "x"), v2_index=os.path.join(d, "y"), source="  ")
        self.assertFalse(os.path.exists(os.path.join(d, "split.json")))
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            split3.main(["build"])


# ── 11. 경로 형식 사전 점검 ──

def entry(eco, name, date="2026-01-01", version=""):
    folder = "@" + name[1:].replace("/", "@") if name.startswith("@") else name
    path = f"samples/{eco}/malicious_intent/{folder}/" + (f"{version}/" if version else "") + f"{date}-{folder}.zip"
    return {"ecosystem": eco, "kind": "malicious_intent", "name": name, "version": version, "date": date, "path": path, "oid": path}


class Precheck(unittest.TestCase):
    def setUp(self):
        self.rec = collect3.V2Record(paths={"pypi": {entry("pypi", f"p{k}", version="1.0")["path"] for k in range(10)}, "npm": set()},
                                     npm_names={f"n{k}" for k in range(10)} | {"@s/x"})

    def test_coverage_of_v2_paths_and_names_in_the_new_tree(self):
        tree = [entry("npm", f"n{k}") for k in range(10)] + [entry("npm", "@s/x"), entry("npm", "brand-new")]
        self.assertEqual(collect3.coverage("npm", tree, self.rec), (11, 11))
        collect3.precheck("npm", tree, self.rec)
        moved = [entry("npm", f"n{k}") for k in range(9)]   # 9/11 < 90%
        with self.assertRaises(collect.Stop):
            collect3.precheck("npm", moved, self.rec)
        pypi = [entry("pypi", f"p{k}", version="1.0") for k in range(9)] + [entry("pypi", "p9", version="2.0")]
        self.assertEqual(collect3.coverage("pypi", pypi, self.rec), (9, 10))
        collect3.precheck("pypi", pypi, self.rec)
        renamed = [dict(e, path=e["path"].replace("malicious_intent", "malicious")) for e in pypi]
        with self.assertRaises(collect.Stop):
            collect3.precheck("pypi", renamed, self.rec)
        with self.assertRaises(collect.Stop):
            collect3.precheck("pypi", pypi, collect3.V2Record(paths={"pypi": set()}))   # 견줄 v2 기록이 없다

    def test_malicious_step_writes_nothing_when_the_tree_layout_changed(self):
        root = tmpdir(self)
        v2, v3 = os.path.join(root, "v2"), os.path.join(root, "v3")
        os.makedirs(os.path.join(v2, "meta"))
        with open(os.path.join(v2, "index.jsonl"), "w"):
            pass
        with open(os.path.join(v2, "meta", "malicious-npm.jsonl"), "w") as f:
            for k in range(10):
                f.write(json.dumps({"key": entry("npm", f"n{k}")["path"], "status": "kept"}) + "\n")
        moved = [dict(entry("npm", f"n{k}"), name=f"renamed-{k}") for k in range(10)]
        env = {"SG_BENCH_DATA": v3, "SG_BENCH_V2_DATA": v2}
        for argv in (["malicious", "--eco", "npm"], ["precheck", "--eco", "npm"]):
            with mock.patch.dict(os.environ, env), no_network(), mock.patch.object(collect, "datadog_entries", lambda eco: moved), \
                    mock.patch.object(collect, "collect_malicious", side_effect=AssertionError("받기 시작함")), \
                    contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                collect3.main(argv)
        self.assertFalse(os.path.exists(os.path.join(v3, "meta", "malicious-npm.jsonl")))
        ok = [entry("npm", f"n{k}") for k in range(10)]
        out = io.StringIO()
        with mock.patch.dict(os.environ, env), no_network(), mock.patch.object(collect, "datadog_entries", lambda eco: ok), \
                contextlib.redirect_stdout(out):
            collect3.main(["precheck", "--eco", "npm"])
        self.assertIn("100.0%", out.getvalue())
        self.assertFalse(os.path.exists(os.path.join(v3, "meta", "malicious-npm.jsonl")))


# ── 12. 수집 요약 ──

class Summary(unittest.TestCase):
    def test_collection_summary_has_counts_and_hashes_only(self):
        kept = {"id": "abc", "name": "secretname", "bytes": 3 << 20, "codeLines": 0, "form": "zip", "codeFiles": []}
        journals = {"malicious-npm": {"samples/npm/x/secretname/1.zip": {"status": "kept", "row": kept},
                                      "samples/npm/x/other/1.zip": {"status": "duplicate", "why": "같은 지문"}},
                    "benign-pypi-popular": {"secretbenign": {"status": "skip", "why": "50MB 초과"}}}
        sp = {"kept": 10, "v2Kept": 7, "newKept": 3, "duplicatesDropped": {"v2 지문": 1}, "excludedRows": 0, "inherited": {"train": 1},
              "groups": 9, "largestGroups": [2], "counts": {}, "newCounts": {}}
        got = collect3.collection_summary(SOURCES, journals, {"newBenign": 5, "pypi": {}, "npm": {}}, {"rows": 3, "sha256": "I"}, sp, "SPLITSHA")
        self.assertEqual(got["sources"]["datadog"]["commit"], SOURCES["datadog"]["commit"])
        npm = got["steps"]["malicious-npm"]
        self.assertEqual((npm["tried"], npm["kept"], npm["noCode"], npm["megabytes"], npm["skipped"]), (2, 1, 1, 3, {"같은 지문": 1}))
        self.assertEqual(got["split"]["sha256"], "SPLITSHA")
        self.assertEqual(got["index"], {"rows": 3, "sha256": "I"})
        text = json.dumps(got, ensure_ascii=False)
        self.assertNotIn("secretname", text)
        self.assertNotIn("secretbenign", text)


# ── 13 · 3 · 9. 규약 revision 2 ──

class ProtocolRevision2(unittest.TestCase):
    def test_revision_two_records_the_changes(self):
        with open(os.path.join(HERE, "protocol.json"), encoding="utf-8") as f:
            p = json.load(f)
        self.assertEqual(p["revision"], 2)
        self.assertIn("새 표본을 받기 전", p["revisedAt"])
        self.assertIn("split.json", p["revisedAt"])
        self.assertEqual(p["layers"]["budgets"], list(select3.BUDGETS))
        self.assertIn("앞쪽부터", p["layers"]["llm"]["order"])
        self.assertIn("앞쪽부터", p["layers"]["llm"]["budget"])
        self.assertTrue(any("40,000 보다 적을 수" in x for x in p["limits"]))
        self.assertIn("90%", json.dumps(p["data"]["malicious"], ensure_ascii=False))


if __name__ == "__main__":
    unittest.main()
