"""v3 가 쓰려고 v2 도구에 더한 것 점검 — 더한 인자 · 함수만 보고, 기본 동작이 그대로인지는 v2 시험이 본다.
python3 -B -m unittest discover -s bench/v3 -p 'test_*.py'

네트워크 · 실제 데이터 · 실제 API 없이 돈다(가짜 색인 · 가짜 git · 가짜 클라이언트 · 임시 폴더). ML 시험은 scikit-learn 이 있을 때만.
"""
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
V2 = os.path.join(os.path.dirname(HERE), "v2")
sys.path.insert(0, V2)
import collect  # noqa: E402
import llm_input  # noqa: E402
import llm_layer as L  # noqa: E402
import metrics  # noqa: E402
import split  # noqa: E402
import static_ml  # noqa: E402
import test_llm_input as TI  # noqa: E402 — v2 시험의 합성 표본 · 임시 데이터 폴더를 그대로 쓴다
import test_llm_layer as TL  # noqa: E402 — v2 시험의 가짜 클라이언트 · CLI 틀을 그대로 쓴다


def h(text):
    return hashlib.sha256(text.encode()).hexdigest()


def row(i, eco="pypi", label="malicious", name=None, files=None, date="2025-01-01", lines=10, source="t"):
    return {
        "id": f"{i:016x}", "ecosystem": eco, "label": label, "name": name or f"pkg-{eco}-{label}-{i}", "date": date,
        "source": source, "codeLines": lines, "form": "zip" if label == "malicious" else "sdist",
        "codeFiles": [{"sha256": h(f"file-{i}"), "bytes": 1000}] if files is None else files,
    }


def r(i, label, eco="pypi", lines=10):
    return {"id": f"{i:016x}", "ecosystem": eco, "label": label, "codeLines": lines, "source": "popular", "date": "2025-03-01"}


# ── split.py ──

class SplitHooks(unittest.TestCase):
    def test_campaign_groups_takes_an_outside_benign_file_set(self):
        common = {"sha256": h("lib"), "bytes": 5000}
        a, b = row(1, files=[common]), row(2, files=[common])
        self.assertEqual(len(set(split.campaign_groups([a, b]).values())), 1)
        self.assertEqual(len(set(split.campaign_groups([a, b], benign_files={common["sha256"]}).values())), 2)

    def test_link_keys(self):
        r = row(5, "npm", files=[{"sha256": "big", "bytes": 256}, {"sha256": "small", "bytes": 255}, {"sha256": "lib", "bytes": 999}])
        keys = split.link_keys(r, {"lib"})
        self.assertEqual(keys, [("name", "npm", split.name_group("npm", r["name"])), ("file", "npm", "big")])
        self.assertEqual(split.link_keys(dict(r, label="benign"), set()), [("name", "npm", split.name_group("npm", r["name"]))])

    def test_rules_folder_follows_the_environment_and_defaults_to_v2(self):
        code = "import split, json; print(json.dumps([split.PROTOCOL, split.SPLIT, split.SELECTION, split.LEDGER, split.SEEN]))"
        env = {k: v for k, v in os.environ.items() if k != "SG_BENCH_RULES"}
        plain = json.loads(subprocess.run([sys.executable, "-B", "-c", code], cwd=V2, env=env, capture_output=True, text=True,
                                          check=True).stdout)
        self.assertEqual(plain, [os.path.join(V2, n) for n in ("protocol.json", "split.json", "selection.json", "unseal-log.json",
                                                              "seen-groups.json")])
        moved = json.loads(subprocess.run([sys.executable, "-B", "-c", code], cwd=V2, env={**env, "SG_BENCH_RULES": HERE},
                                          capture_output=True, text=True, check=True).stdout)
        self.assertEqual(moved[:4], [os.path.join(HERE, n) for n in ("protocol.json", "split.json", "selection.json", "unseal-log.json")])
        self.assertEqual(moved[4], os.path.join(V2, "seen-groups.json"))

    def test_v2_build_and_unseal_commands_refuse_the_v3_rules_folder(self):
        env = {**os.environ, "SG_BENCH_RULES": HERE}
        for argv in (["build", "--index", "/nonexistent/index.jsonl"], ["unseal", "test", "--reason", "x"]):
            r = subprocess.run([sys.executable, "-B", os.path.join(V2, "split.py"), *argv], env=env, capture_output=True, text=True)
            self.assertNotEqual(r.returncode, 0)
            self.assertIn("split3.py", r.stderr)
        self.assertFalse(os.path.exists(os.path.join(HERE, "unseal-log.json")))


class SplitUnseal(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        d = tmp.name
        self.paths = {k: os.path.join(d, k) for k in ("split.json", "selection.json", "unseal-log.json")}
        with open(self.paths["split.json"], "w") as f:
            json.dump({"assignments": {"a": "test", "b": "reserve"}, "sealed": ["test", "reserve"], "neverUnseal": ["reserve"]}, f)

    def test_v2_unseal_function_refuses_never_unseal_parts(self):
        with open(self.paths["selection.json"], "w") as f:
            f.write("{}")
        with open(self.paths["split.json"], "rb") as f:
            split_bytes = f.read()
        split.unseal("test", "x", split_bytes=split_bytes, protocol_bytes=b"{}", selection_path=self.paths["selection.json"],
                     ledger_path=self.paths["unseal-log.json"])
        with self.assertRaises(split.SealedError):
            split.unseal("reserve", "x", split_bytes=split_bytes, protocol_bytes=b"{}", selection_path=self.paths["selection.json"],
                         ledger_path=self.paths["unseal-log.json"])

    def test_unseal_records_extra_fields(self):
        with open(self.paths["selection.json"], "w") as f:
            f.write("{}")
        entry = split.unseal("test", "x", split_bytes=b'{"sealed": ["test"]}', protocol_bytes=b"{}",
                             selection_path=self.paths["selection.json"], ledger_path=self.paths["unseal-log.json"],
                             extra={"rows": {"v2": 1, "new": 2}})
        self.assertEqual(entry["rows"], {"v2": 1, "new": 2})
        self.assertEqual(split.read_ledger(self.paths["unseal-log.json"]), [entry])


# ── collect.py ──

class CollectLoops(unittest.TestCase):
    """collect_malicious · collect_benign · top_npm — git · 저장 · 내려받기를 메모리 가짜로(네트워크 없음)."""

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = tmp.name

    def run_loop(self, eco, rows, **kw):
        """rows = {oid: 색인 줄}. 표본 바이트는 oid 글자, 색인 줄은 rows 의 것(이름 · 생태계 · 라벨만 수집기가 채운다)."""
        stored = []
        by_data = {oid.encode(): r for oid, r in rows.items()}
        targets = [{"path": f"p{oid}", "oid": oid, "name": oid, "version": "", "date": "2025-01-01", "kind": "malicious_intent"}
                   for oid in rows]

        def fake_row(data, **f):
            return dict(by_data[data], **{k: f[k] for k in ("ecosystem", "label", "name")})

        j = collect.Journal(os.path.join(self.dir, f"{eco}.jsonl"))
        with mock.patch.object(collect, "check_disk", lambda: None), \
                mock.patch.object(collect, "fetch_blobs", lambda oids: set()), \
                mock.patch.object(collect, "drop_packs", lambda names: None), \
                mock.patch.object(collect, "git", lambda *a, **k: a[2].encode()), \
                mock.patch.object(collect, "store", lambda data, form: stored.append(data)), \
                mock.patch.object(collect.sample, "build_row", fake_row):
            collect.collect_malicious(eco, targets, j, **kw)
        return j, stored

    def test_v3_drops_v2_files_and_fingerprints_and_dedupes_new_npm_only(self):
        v2 = row(1, "npm")
        rows = {"o1": dict(row(10, "npm"), id=v2["id"]),                      # v2 와 같은 파일
                "o2": row(11, "npm", files=list(v2["codeFiles"])),             # v2 와 같은 지문
                "o3": row(12, "npm", files=[{"sha256": h("n"), "bytes": 400}]),
                "o4": row(13, "npm", files=[{"sha256": h("n"), "bytes": 400}]),  # 이번에 남긴 것과 같은 지문
                "o5": row(14, "npm")}
        j, stored = self.run_loop("npm", rows, known_ids={v2["id"]}, known_prints={split.fingerprint(v2): v2["id"]}, dedupe=True)
        self.assertEqual({k: r["status"] for k, r in j.rows.items()},
                         {"po1": "duplicate", "po2": "duplicate", "po3": "kept", "po4": "duplicate", "po5": "kept"})
        self.assertEqual(len(stored), 2)

    def test_pypi_keeps_same_fingerprint_new_samples_for_the_split_to_dedupe(self):
        rows = {"o1": row(21, files=[{"sha256": h("p"), "bytes": 400}]), "o2": row(22, files=[{"sha256": h("p"), "bytes": 400}])}
        j, _ = self.run_loop("pypi", rows, known_ids=set(), known_prints={})
        self.assertEqual([r["status"] for r in j.rows.values()], ["kept", "kept"])

    def test_benign_loop_skips_given_names_without_asking_and_can_stop_short(self):
        asked = []

        def candidate(name, *, long_tail, popular_set):
            asked.append(name)
            return None, "없음"

        j = collect.Journal(os.path.join(self.dir, "b.jsonl"))
        with mock.patch.object(collect, "check_disk", lambda: None), mock.patch.object(collect.time, "sleep", lambda s: None):
            got = collect.collect_benign("npm", "popular", 2, ["a", "b", "c"], set(), j, candidate=candidate, skip={"b"},
                                         allow_short=True)
            self.assertEqual(asked, ["a", "c"])
            self.assertEqual(got, {"kept": 0, "exhausted": True})
            with self.assertRaises(collect.Stop):
                collect.collect_benign("npm", "popular", 2, ["d"], set(), collect.Journal(os.path.join(self.dir, "c.jsonl")),
                                       candidate=candidate)

    def test_top_npm_page_cap_is_an_argument(self):
        cache = os.path.join(self.dir, "cache")
        os.makedirs(cache)
        for page in (1, 2, 3, 4):
            with open(os.path.join(cache, f"top-npm-{page:02d}.json"), "w") as f:
                json.dump([{"name": f"p{page}-{i}"} for i in range(3)] if page < 4 else [], f)   # 4쪽은 빈 쪽(목록 끝)
        with mock.patch.object(collect, "CACHE", cache), mock.patch.object(collect, "sources", lambda update=None: {}):
            self.assertEqual(len(collect.top_npm(100, max_pages=2)), 6)
            self.assertEqual(len(collect.top_npm(100)), 9)


# ── llm_input.py · llm_layer.py · static_ml.py ──

class Order(unittest.TestCase):
    def test_call_order_is_a_seeded_hash_of_the_sample_id(self):
        ids = [f"{i:016x}" for i in range(50)]
        want = sorted(ids, key=lambda i: hashlib.sha256(f"20261118:llm:{i}".encode()).hexdigest())
        self.assertEqual(sorted(ids, key=lambda i: llm_input.call_order_key(20261118, i)), want)
        self.assertNotEqual(want, sorted(ids))

    def test_input_builder_writes_rows_in_that_order_only_when_asked(self):
        c = TI.Corpus(self)
        for k in range(6):
            c.add(TI.tar_bytes({f"p{k}-1.0/setup.py": TI.SETUP + f"#{k}\n".encode()}), form="sdist", label="benign" if k % 2 else "malicious")
        plain = c.out("plain.jsonl")
        llm_input.build(c.dir, out=plain, part="train", split_path=c.split_path, ledger_path=c.ledger_path)
        ordered = c.out("ordered.jsonl")
        meta = llm_input.build(c.dir, out=ordered, part="train", split_path=c.split_path, ledger_path=c.ledger_path, order_seed=20261118)
        ids = [x["id"] for x in TI.read_rows(plain)]
        self.assertEqual(ids, sorted(ids))
        self.assertEqual([x["id"] for x in TI.read_rows(ordered)], sorted(ids, key=lambda i: llm_input.call_order_key(20261118, i)))
        self.assertEqual(meta["orderSeed"], 20261118)


def v2_row(sample_id, text, status="OK", score=80, cost=0.3):
    row, _ = L.prepare(sample_id, text, TL.STATIC, L.load_prompt())
    return {**row, "status": status, "riskScore": score if status == "OK" else None, "costUsd": cost,
            "stages": [{"model": TL.HAIKU, "status": status, "costUsd": cost}], "gate": {"mode": "ml", "low": 0.02, "high": 0.9994}}


class Reuse(unittest.TestCase):
    def test_only_answered_rows_with_the_same_input_inside_the_gate_are_reused_at_zero_cost(self):
        samples = TL.samples(5)
        prev = {"s0": v2_row("s0", samples[0]["text"]), "s1": v2_row("s1", samples[1]["text"], status="REFUSED"),
                "s2": v2_row("s2", "different input text"), "s3": v2_row("s3", samples[3]["text"]),
                "s4": v2_row("s4", samples[4]["text"], status="ERROR")}
        gate = L.Gate("ml", 0.02, 0.9, {"s0": 0.5, "s1": 0.5, "s2": 0.5, "s3": 0.95, "s4": 0.5}, "mlsha")
        with tempfile.TemporaryDirectory() as d:
            results = L.Results(os.path.join(d, "out.jsonl"))
            n = L.apply_reuse(samples, results=results, reuse=prev, gate=gate, prompt=L.load_prompt(), source="v2:out-calibration")
            self.assertEqual(n, 2)
            self.assertEqual(set(results.rows), {"s0", "s1"})
            s0 = results.rows["s0"]
            self.assertEqual((s0["status"], s0["riskScore"], s0["costUsd"], s0["stages"]), ("OK", 80, 0.0, []))
            self.assertEqual(s0["gate"], gate.config())
            self.assertEqual(s0["reusedFrom"]["costUsd"], 0.3)
            self.assertEqual(s0["reusedFrom"]["source"], "v2:out-calibration")
            self.assertEqual(results.rows["s1"]["status"], "REFUSED")
            self.assertEqual(results.spent, 0.0)
            self.assertEqual(L.Results(results.path).spent, 0.0)
            self.assertTrue(results.done("s0") and results.done("s1"))
            self.assertEqual(L.apply_reuse(samples, results=results, reuse=prev, gate=gate, prompt=L.load_prompt(), source="x"), 0)

    def test_read_reuse_keeps_the_last_answered_line_per_id(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "v2.jsonl")
            TL.write_jsonl(path, [{"id": "a", "status": "ERROR"}, {"id": "a", "status": "OK", "riskScore": 3},
                                  {"id": "b", "status": "OK"}, {"id": "b", "status": "SKIPPED_BUDGET"}, {"id": "c", "status": "CACHED"}])
            got, sha = L.read_reuse([path])
            self.assertEqual(set(got), {"a", "c"})
            self.assertEqual(len(sha), 64)


class ReuseCli(TL.CliBase):
    EXTRA = ["--part", "train", "--mode", "realtime", "--gate", "all"]

    def test_run_does_not_call_samples_answered_in_the_reuse_file(self):
        prev = os.path.join(self.dir.name, "v2-out.jsonl")
        TL.write_jsonl(prev, [v2_row("s0", TL.samples(3)[0]["text"])])
        client = TL.FakeClient({TL.HAIKU: lambda request: TL.message(TL.analysis(5))})
        code, _, err, _ = self.run_cli(["run", "--input", self.inp, "--out", self.out, "--reuse", prev], client=client)
        self.assertEqual((code, len(client.calls)), (0, 2), err)
        rows = L.Results(self.out).rows
        self.assertEqual(rows["s0"]["riskScore"], 80)
        self.assertIn("reusedFrom", rows["s0"])
        self.assertNotIn("reusedFrom", rows["s1"])


@unittest.skipIf(static_ml.ml_missing(), "scikit-learn 없음 — bench/.venv 로 돌리면 돈다")
class OutOfFold(unittest.TestCase):
    def test_cross_validation_and_oof_predictions_agree(self):
        rows, gd, ru, groups = [], {}, {}, {}
        for i in range(120):
            label = "malicious" if i % 2 else "benign"
            row = r(i, label, eco="npm" if i % 3 else "pypi")
            rows.append(row)
            groups[row["id"]] = row["id"]
            gd[row["id"]] = {"status": "ok", "score": (8 if label == "malicious" else 1) + i % 3, "installThreats": i % 2,
                             "rules": ["x"] if label == "malicious" and i % 5 else []}
            ru[row["id"]] = {"status": "ok", "score": i % 7, "hits": []}
        main, y, oof = static_ml.oof_predictions(rows, gd, ru, groups)
        self.assertEqual(len(oof), len(main))
        self.assertTrue(all(p is not None for p in oof))
        cv = static_ml.cross_validate(rows, gd, ru, groups, budgets=(0.02,))
        t = metrics.budget_points(oof, y, budgets=(0.02,))[0][1]
        self.assertEqual(cv["atFpr"][0]["threshold"], t)


if __name__ == "__main__":
    unittest.main()
