"""평가 규칙 v3 — 기록이 0건인 수집 단계 점검(실측 결함: 새 PyPI zip 이 없을 때 악성 PyPI 단계가 끝에서 죽었다).
python3 -B -m unittest discover -s bench/v3 -p 'test_*.py'

실제 상황 그대로: 악성 PyPI 0건 + 악성 npm 만 있음, 정상 단계 0건, 죽은 실행이 남긴 malicious.lock · sources.json.
가짜 폴더 · 가짜 트리만 쓰고 네트워크는 막는다(test_review.no_network).
"""
import contextlib
import hashlib
import io
import json
import os
import sys
import tempfile
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
V2 = os.path.join(os.path.dirname(HERE), "v2")
sys.path.insert(0, V2)
sys.path.insert(0, HERE)
import collect  # noqa: E402
import collect3  # noqa: E402
import split  # noqa: E402
import split3  # noqa: E402
from test_review import SOURCES, entry, no_network  # noqa: E402
from test_v3 import corpus, v2_world  # noqa: E402

EMPTY_SHA = hashlib.sha256(b"").hexdigest()


class ZeroSteps(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = os.path.realpath(tmp.name)
        self.v2, self.v3 = os.path.join(root, "v2"), os.path.join(root, "v3")
        self.root = root
        # v2: 분할 · 색인 + 악성 수집 기록(PyPI 10 경로 · npm 10 이름). 새 트리는 그 경로 · 이름 그대로(새 PyPI zip 없음) + 새 npm 이름 3개
        self.v2_rows, self.v2_split = v2_world(30)
        self.pypi_tree = [entry("pypi", f"p{k}", version="1.0") for k in range(10)]
        self.npm_tree = [entry("npm", f"n{k}") for k in range(10)] + [entry("npm", f"fresh{k}") for k in range(3)]
        os.makedirs(os.path.join(self.v2, "meta"))
        with open(os.path.join(self.v2, "index.jsonl"), "w") as f:
            f.writelines(json.dumps(r) + "\n" for r in self.v2_rows)
        for eco, tree in (("pypi", self.pypi_tree), ("npm", self.npm_tree[:10])):
            with open(os.path.join(self.v2, "meta", f"malicious-{eco}.jsonl"), "w") as f:
                f.writelines(json.dumps({"key": e["path"], "status": "kept"}) + "\n" for e in tree)
        # 죽은 실행이 남긴 것: 잠금 파일 · sources.json(잠금은 프로세스가 끝나면 풀린다)
        os.makedirs(os.path.join(self.v3, "datadog-repo"))
        os.makedirs(os.path.join(self.v3, "logs"))
        for name in ("malicious.lock", "sources.json.lock"):
            open(os.path.join(self.v3, name), "w").close()
        with open(os.path.join(self.v3, "sources.json"), "w") as f:
            json.dump(SOURCES, f)
        self.env = {"SG_BENCH_DATA": self.v3, "SG_BENCH_V2_DATA": self.v2}

    def cli(self, argv, **patches):
        out = io.StringIO()
        with mock.patch.dict(os.environ, self.env), no_network(), \
                mock.patch.object(collect, "datadog_entries", lambda eco: self.pypi_tree if eco == "pypi" else self.npm_tree), \
                contextlib.ExitStack() as stack, contextlib.redirect_stdout(out):
            for name, value in patches.items():
                stack.enter_context(mock.patch.object(collect, name, value))
            collect3.main(argv)
        return out.getvalue()

    def fake_npm(self, eco, targets, j, **_kw):
        """npm 수집 흉내: 대상마다 색인 줄 하나(표본은 받지 않는다)."""
        for k, e in enumerate(targets):
            data = f"fake-npm-{k}".encode()          # 무해한 가짜 바이트 — 색인 id 는 이 바이트의 해시
            r = dict(corpus(50_000 + 10 * k, 1)[2], id=collect.sample.sample_id(data), name=e["name"])   # npm 악성 줄 하나
            collect.store(data, "zip")
            j.add(e["path"], status="kept", row=r)

    def done(self, eco):
        with open(os.path.join(self.v3, "meta", f"malicious-{eco}.done.json")) as f:
            return json.load(f)

    def test_malicious_pypi_with_no_target_finishes_and_records_completion(self):
        out = self.cli(["malicious", "--eco", "pypi"])
        self.assertIn("대상 0", out)
        d = self.done("pypi")
        self.assertEqual((d["targets"], d["kept"], d["records"], d["journalSha256"]), (0, 0, 0, EMPTY_SHA))
        self.cli(["malicious", "--eco", "pypi"])   # 다시 돌려도 같은 자리에서 끝난다
        self.assertEqual(self.done("pypi")["journalSha256"], EMPTY_SHA)

    def test_zero_steps_pass_through_every_later_step(self):
        self.cli(["malicious", "--eco", "pypi"])
        self.cli(["malicious", "--eco", "npm"], collect_malicious=self.fake_npm)
        self.assertEqual(self.done("npm")["kept"], 3)
        plan_out = self.cli(["plan"])
        self.assertIn("악성 총수 3,879", plan_out)
        # 정상 단계가 0건인 경우: 몫이 0 인 계획으로 인기 · 롱테일을 지나간다(목록은 비어 있다)
        plan_path = os.path.join(self.v3, "meta", "benign-plan.json")
        with open(plan_path) as f:
            plan = json.load(f)
        plan.update(newBenign=0, pypi={"popular": 0, "longTail": 0}, npm={"popular": 0, "longTail": 0})
        with open(plan_path, "w") as f:
            json.dump(plan, f)
        lists = dict(top_pypi=lambda: [], top_npm=lambda n, max_pages=60: [], pypi_names=lambda: [], npm_names=lambda: [])
        for eco in ("pypi", "npm"):
            self.cli(["benign", "--eco", eco, "--kind", "popular"], **lists)
            self.cli(["benign", "--eco", eco, "--kind", "longTail"], **lists)
        self.cli(["index"])
        index = split.read_jsonl(os.path.join(self.v3, "index-new.jsonl"))
        self.assertEqual(sorted(r["ecosystem"] for r in index), ["npm"] * 3)
        self.assertIn("malicious-pypi", self.cli(["status"]))
        self.assertIn(SOURCES["datadog"]["commit"], self.cli(["source-line"]))
        # 분할 · 요약
        v2_split_path, seen = os.path.join(self.root, "v2split.json"), os.path.join(self.root, "seen.json")
        with open(v2_split_path, "w") as f:
            json.dump(self.v2_split, f)
        with open(seen, "w") as f:
            json.dump({"groups": []}, f)
        out_split = os.path.join(self.root, "split.json")
        sp = split3.build_file(out=out_split, new_index=os.path.join(self.v3, "index-new.jsonl"),
                               v2_index=os.path.join(self.v2, "index.jsonl"), v2_split_path=v2_split_path, seen_path=seen,
                               protocol_path=os.path.join(HERE, "protocol.json"), source="t")
        self.assertEqual(sp["newKept"], 3)
        summary = os.path.join(self.root, "collection.json")
        with mock.patch.object(split3, "SPLIT3", out_split), mock.patch.object(collect3, "COLLECTION", summary):
            self.cli(["summary"])
        with open(summary) as f:
            steps = json.load(f)["steps"]
        self.assertEqual((steps["malicious-pypi"]["tried"], steps["benign-npm-longTail"]["kept"]), (0, 0))


if __name__ == "__main__":
    unittest.main()
