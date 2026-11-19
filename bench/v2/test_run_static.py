"""평가 규칙 v2 정적 층 측정 도구 점검(네트워크 없이 · 임시 폴더에서) — python3 -B -m unittest discover -s bench/v2 -p 'test_*.py'"""
import collections
import contextlib
import io
import json
import os
import re
import sys
import tarfile
import tempfile
import unittest
import zipfile
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import collect  # noqa: E402
import run_static  # noqa: E402
import sample  # noqa: E402
import split  # noqa: E402

TOKEN = "tok-3f9c1e7a5b2d4c6e8f0a1b3c5d7e9f1a"
ENGINES = [{"name": "GuardDog", "version": "2.6.0"}, {"name": "OSV-Scanner", "version": "2.2.2"}]


def zipped(files):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, data in files.items():
            zf.writestr(zipfile.ZipInfo(name, date_time=(2025, 1, 1, 0, 0, 0)), data)   # 시각을 고정해 id(파일 해시)가 늘 같게
    return buf.getvalue()


def tarred(files):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for name, data in files.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def slurp(path):
    with open(path, "rb") as f:
        return f.read()


def scan_record(verdict):
    """백엔드 검사 기록(GET /api/scans/{id}) 모양. 테스트 코드 탐지 한 건은 규칙 목록에서 빠져야 한다."""
    return {"status": "done", "verdict": verdict, "risk": {"score": 8.2, "label": "high"}, "engines": ENGINES,
            "findings": [{"rule": "threat-setup-network-in-install", "category": "threat"},
                         {"rule": "capability-process-spawn", "category": "capability"},
                         {"rule": "threat-only-in-tests", "category": "threat", "test": True}],
            "threats": 1, "capabilities": 1, "installThreats": 1, "testFindings": 1, "vulnCount": 2,
            "startedAt": "2026-11-12T00:00:00.000000000Z", "finishedAt": "2026-11-12T00:00:01.500000000Z"}


class Clock:
    """가짜 시계 — sleep 은 기다리지 않고 시각만 민다."""

    def __init__(self):
        self.now, self.slept = 1_000_000.0, []

    def time(self):
        return self.now

    def sleep(self, seconds):
        self.slept.append(seconds)
        self.now += seconds


class FakeApi:
    """v1 도구 API 자리의 가짜 — 네트워크에 닿지 않는다. 표본 id(올린 파일 이름 sgb-<id>.<확장자>)마다 정해 둔 답을 준다.
    답: 판정 글(clean · caution · malicious · vulnerable) · "failed" · "running"(끝나지 않음) · (응답 코드, 본문) = 시작 단계에서 끝남 ·
    함수(몇 번째 시도) → 위의 것."""

    def __init__(self, answers=None):
        self.answers = answers or {}
        self.calls = collections.Counter()   # 표본 id → 올린 횟수
        self.uploads = {}                    # 표본 id → (파일 이름, 바이트)
        self.scans = {}

    def upload(self, filename, data):
        sid = re.fullmatch(r"sgb-([0-9a-f]{16})\.(tar\.gz|tgz|whl|zip)", filename).group(1)
        self.calls[sid] += 1
        self.uploads[sid] = (filename, data)
        answer = self.answers.get(sid, "clean")
        if callable(answer):
            answer = answer(self.calls[sid])
        if isinstance(answer, tuple):
            return answer
        scan_id = f"scan-{len(self.scans) + 1:04d}"
        self.scans[scan_id] = answer
        return 202, {"id": scan_id}

    def get(self, scan_id):
        answer = self.scans[scan_id]
        if answer == "running":
            return 200, {"id": scan_id, "status": "running"}
        if answer == "failed":
            return 200, {"status": "failed", "error": "검사기 메모리 부족(GuardDog, 종료 코드 137)",
                         "startedAt": "2026-11-12T00:00:00Z", "finishedAt": "2026-11-12T00:00:09Z"}
        return 200, scan_record(answer)


class Base(unittest.TestCase):
    """임시 데이터 폴더(store/ · index.jsonl) + 임시 split.json. 표본 내용은 무해한 한 줄짜리 글이다."""

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.tmp = tmp.name
        self.data = os.path.join(self.tmp, "data")
        os.makedirs(os.path.join(self.data, "store"))
        self.rows, self.assign, self.answers = [], {}, {}
        self.clock, self.api, self.tokens = Clock(), None, []
        env = mock.patch.dict(os.environ, {"SG_BENCH_DATA": self.data})
        env.start()
        self.addCleanup(env.stop)
        os.environ.pop("ADMIN_TOKEN", None)
        for target, name, value in ((split, "SPLIT", os.path.join(self.tmp, "split.json")),
                                    (split, "LEDGER", os.path.join(self.tmp, "unseal-log.json")),
                                    (run_static, "time", self.clock), (run_static.v1(), "time", self.clock),
                                    (run_static, "make_api", self.make_api)):
            p = mock.patch.object(target, name, value)
            p.start()
            self.addCleanup(p.stop)

    def make_api(self, base, token):
        self.tokens.append(token)
        self.api = self.api or FakeApi(self.answers)
        return self.api

    def add(self, part, eco, label, answer="clean", form=None, source="popular", lines=5, raw=None):
        """표본 하나를 store/ 와 색인에 더한다 → id."""
        n = len(self.rows)
        form = form or ("zip" if label == "malicious" else {"pypi": "sdist", "npm": "tarball"}[eco])
        if raw is None and form == "zip":   # DataDog 표본 모양: 깊은 경로 + 메타 파일
            raw = zipped({f"tmp/x/pkg-{n}/setup.py": f"print({n})\n", f"tmp/x/pkg-{n}/src/a.py": "x = 1\n",
                          f"tmp/x/package_info-pkg-{n}.json": "{}"})
        elif raw is None:
            raw = (zipped if form == "wheel" else tarred)({f"pkg-{n}/setup.py": f"print({n})\n".encode()})
        sid = sample.sample_id(raw)
        with open(os.path.join(self.data, "store", f"{sid}.{collect.EXT[form]}"), "wb") as f:
            f.write(raw)
        self.rows.append({"id": sid, "ecosystem": eco, "label": label, "name": f"pkg-{n}", "version": "1.0", "date": "2025-01-01",
                          "source": "datadog:malicious_intent" if label == "malicious" else source, "form": form, "bytes": len(raw),
                          "codeFiles": [], "codeLines": lines, "files": 1})
        self.assign[sid] = part
        self.answers[sid] = answer
        return sid

    def save(self):
        with open(os.path.join(self.data, "index.jsonl"), "w", encoding="utf-8") as f:
            for r in self.rows:
                f.write(json.dumps(r) + "\n")
        with open(split.SPLIT, "w", encoding="utf-8") as f:
            json.dump({"assignments": self.assign, "sealed": list(split.SEALED)}, f)

    def cli(self, *argv):
        """명령 한 번 → (종료 코드 · 화면에 나온 글 전부). sys.exit("글") 은 코드 1 + 그 글."""
        out = io.StringIO()
        code = 0
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
            try:
                run_static.main(list(argv))
            except SystemExit as e:
                code = e.code if isinstance(e.code, int) else 1
                if isinstance(e.code, str):
                    out.write(e.code + "\n")
        return code, out.getvalue()

    def run_ok(self, *argv):
        with open(os.path.join(self.tmp, "tokens"), "w") as f:
            f.write(f"AUTH_SECRET_KEY=other\nADMIN_TOKEN={TOKEN}\n")
        code, text = self.cli("run", "--token-file", os.path.join(self.tmp, "tokens"), *argv)
        self.assertEqual(code, 0, text)
        return text

    def results(self, part="train"):
        return run_static.read_results(run_static.results_path(self.data, part))

    def report(self, part="train"):
        path = os.path.join(self.tmp, "report.json")
        code, text = self.cli("report", "--parts", part, "--json", path)
        self.assertEqual(code, 0, text)
        with open(path, encoding="utf-8") as f:
            return json.load(f)["parts"][part], text


class Corpus(Base):
    """구간 넷에 걸친 작은 표본 묶음. 학습 구간 14개의 답은 아래 이름대로."""

    def setUp(self):
        super().setUp()
        a = self.add
        self.m1 = a("train", "pypi", "malicious", "malicious")
        self.m2 = a("train", "pypi", "malicious", "caution")
        self.m3 = a("train", "pypi", "malicious", "clean")
        self.m4 = a("train", "pypi", "malicious", "malicious", lines=0)            # 코드 없는 악성
        self.n1 = a("train", "npm", "malicious", "malicious")
        self.n2 = a("train", "npm", "malicious", raw=b"PK\x03\x04 not really a zip")  # 묶기 실패
        self.n3 = a("train", "npm", "malicious", "failed")                         # 검사 오류
        self.n4 = a("train", "npm", "malicious", "running")                        # 시간 초과
        self.b1 = a("train", "pypi", "benign", "clean")
        self.b2 = a("train", "pypi", "benign", "caution", form="wheel")
        self.b3 = a("train", "pypi", "benign", "malicious", source="longTail", raw=zipped({"pkg/setup.py": "print('zip sdist')\n"}))
        self.b4 = a("train", "pypi", "benign", "vulnerable", source="longTail")
        self.c1 = a("train", "npm", "benign", "clean")
        self.c2 = a("train", "npm", "benign", (400, {"error": "압축을 풀 수 없습니다: unexpected EOF"}), source="longTail")
        self.k1 = a("calibration", "pypi", "malicious", "malicious")
        self.k2 = a("calibration", "npm", "benign", "clean")
        self.t1 = a("test", "pypi", "malicious", "malicious")
        self.t2 = a("test", "pypi", "benign", "clean")
        self.r1 = a("reserve", "npm", "malicious", "malicious")
        self.save()
        self.train = sorted(i for i, p in self.assign.items() if p == "train")


class Protocol(unittest.TestCase):
    def test_candidates_are_the_ones_the_protocol_names(self):
        with open(split.PROTOCOL, encoding="utf-8") as f:
            text = json.load(f)["layers"]["static"]
        self.assertEqual([name for name, _ in run_static.CANDIDATES], ["S-malicious", "S-suspicious"])
        for name, _ in run_static.CANDIDATES:
            self.assertIn(name, text)
        self.assertEqual(dict(run_static.CANDIDATES), {"S-malicious": ("malicious",), "S-suspicious": ("malicious", "suspicious")})
        self.assertEqual(run_static.v1().VERDICT["caution"], "suspicious")   # 백엔드 「주의」는 v1 표가 suspicious 로 옮긴다

    def test_data_folder_comes_from_the_environment(self):
        with mock.patch.dict(os.environ, {"SG_BENCH_DATA": "/somewhere/else"}):
            self.assertEqual(run_static.data_dir(), "/somewhere/else")
            self.assertEqual(run_static.results_path(run_static.data_dir(), "train"), "/somewhere/else/results/static-train.jsonl")
        with mock.patch.dict(os.environ):
            os.environ.pop("SG_BENCH_DATA", None)
            self.assertEqual(run_static.data_dir(), collect.DATA)


class Sealing(Corpus):
    def test_sealed_parts_are_refused_before_anything_else_happens(self):
        for parts in (["test"], ["reserve"], ["train", "test"]):
            with self.assertRaises(split.SealedError):
                run_static.select(parts, self.data)
        for argv in (("run", "--parts", "test"), ("run", "--parts", "test", "--dry-run"), ("run", "--parts", "train", "reserve"),
                     ("report", "--parts", "test")):
            code, text = self.cli(*argv)
            self.assertEqual(code, 1)
            self.assertIn("거부", text)
            self.assertIn("봉인", text)
        self.assertEqual(self.tokens, [])                                  # 백엔드 쪽은 만들지도 않았다
        self.assertFalse(os.path.exists(os.path.join(self.data, "results")))

    def test_open_parts_come_in_the_order_asked_then_by_id_and_unknown_parts_stop(self):
        got = run_static.select(["train", "calibration", "train"], self.data)
        self.assertEqual([r["id"] for _, r in got], self.train + sorted([self.k1, self.k2]))
        self.assertEqual([p for p, _ in got], ["train"] * 14 + ["calibration"] * 2)
        code, text = self.cli("run", "--parts", "holdout", "--dry-run")
        self.assertEqual(code, 1)
        self.assertIn("없는 구간", text)


class DryRun(Corpus):
    def test_shows_counts_and_upload_forms_without_touching_the_backend_or_disk(self):
        before = sorted(os.listdir(self.data))
        code, text = self.cli("run", "--dry-run")                         # 토큰 없이도 된다 · 기본 구간 = train
        self.assertEqual(code, 0, text)
        self.assertIn("구간 train: 표본 14", text)
        self.assertIn("pypi 악성 4 · pypi 정상 4 · npm 악성 4 · npm 정상 2", text)
        self.assertIn("다시 묶음 8", text)                                # 암호 zip → 메모리에서 tar.gz
        self.assertIn("sdist(.tar.gz) 그대로 3", text)
        self.assertIn("wheel(.whl) 그대로 1", text)
        self.assertIn("npm tarball(.tgz) 그대로 2", text)
        self.assertIn("백엔드에 닿지 않았", text)
        self.assertEqual(self.tokens, [])
        self.assertEqual(sorted(os.listdir(self.data)), before)

    def test_limit_and_recorded_samples_show_in_the_plan(self):
        self.run_ok("--limit", "3")
        _, text = self.cli("run", "--dry-run", "--limit", "4", "--parts", "train", "calibration")
        self.assertIn("구간 train: 표본 14 · 이미 기록 3 · 이번 대상 4", text)
        self.assertIn("구간 calibration: 표본 2 · 이미 기록 0 · 이번 대상 0", text)


class Run(Corpus):
    def test_resume_skips_recorded_ids(self):
        self.run_ok("--limit", "5")
        first = self.results()
        self.assertEqual(sorted(first), self.train[:5])                   # id 순서대로 다섯
        calls = dict(self.api.calls)
        self.run_ok()
        self.assertEqual(sorted(self.results()), self.train)
        for sid, n in calls.items():
            self.assertEqual(self.api.calls[sid], n, sid)                 # 기록한 표본은 다시 올리지 않았다
        for sid, rec in first.items():
            self.assertEqual(self.results()[sid], rec)
        total = sum(self.api.calls.values())
        text = self.run_ok()
        self.assertEqual(sum(self.api.calls.values()), total)             # 세 번째 실행은 할 일이 없다
        self.assertIn("이번 대상 0", text)
        with open(run_static.results_path(self.data, "train"), encoding="utf-8") as f:
            self.assertEqual(len(f.read().splitlines()), 14)              # 표본마다 한 줄

    def test_result_lines_have_the_agreed_fields(self):
        self.run_ok()
        res = self.results()
        self.assertEqual(res[self.m1], {
            "id": self.m1, "status": "ok", "verdict": "malicious", "score": 8.2,
            "rules": ["capability-process-spawn", "threat-setup-network-in-install"], "installThreats": 1, "threats": 1,
            "capabilities": 1, "testFindings": 1, "vulns": 2, "seconds": 1.5,
            "engines": {"GuardDog": "2.6.0", "OSV-Scanner": "2.2.2"}})
        self.assertEqual(res[self.m2]["verdict"], "suspicious")           # 백엔드 caution
        self.assertEqual(res[self.b4]["verdict"], "vulnerable")
        self.assertEqual({r["status"] for r in res.values()}, {"ok", "skip", "error"})

    def test_unprocessed_samples_are_kept_with_a_status_and_a_reason(self):
        text = self.run_ok()
        res = self.results()
        self.assertIn(f"{self.n3} error 검사기 메모리 부족 ·", text)      # 화면에는 오류의 종류만
        self.assertNotIn("종료 코드 137", text)
        self.assertEqual(res[self.n2], {"id": self.n2, "status": "skip", "why": "zip 손상"})            # 묶기 실패 — 올리지 않았다
        self.assertNotIn(self.n2, self.api.calls)
        self.assertEqual((res[self.c2]["status"], res[self.c2]["why"]), ("skip", "백엔드: 압축 해제 실패"))  # 백엔드가 받지 않음
        self.assertEqual((res[self.n3]["status"], res[self.n3]["seconds"]), ("error", 9.0))             # 검사 오류
        self.assertIn("메모리 부족", res[self.n3]["why"])
        self.assertEqual(res[self.n4], {"id": self.n4, "status": "error", "why": "결과 대기 시간 초과"})
        for sid in (self.n2, self.c2, self.n3, self.n4):
            self.assertNotIn("verdict", res[sid])

    def test_malicious_is_repacked_in_memory_and_benign_goes_up_as_stored(self):
        store = os.path.join(self.data, "store")
        before = {n: slurp(os.path.join(store, n)) for n in os.listdir(store)}
        self.run_ok()
        name, data = self.api.uploads[self.m1]
        self.assertEqual(name, f"sgb-{self.m1}.tar.gz")                   # 패키지 이름 없는 파일 이름
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tf:
            self.assertEqual(sorted(tf.getnames()), ["pkg/setup.py", "pkg/src/a.py"])   # 공통 접두 · 메타 파일을 걷어낸 v1 묶음
        stored = lambda sid, ext: before[f"{sid}.{ext}"]  # noqa: E731
        self.assertEqual(self.api.uploads[self.b1], (f"sgb-{self.b1}.tar.gz", stored(self.b1, "tar.gz")))
        self.assertEqual(self.api.uploads[self.b2], (f"sgb-{self.b2}.whl", stored(self.b2, "whl")))
        self.assertEqual(self.api.uploads[self.c1], (f"sgb-{self.c1}.tgz", stored(self.c1, "tgz")))
        self.assertEqual(self.api.uploads[self.b3], (f"sgb-{self.b3}.zip", stored(self.b3, "tar.gz")))  # zip 인 sdist 는 내용에 맞는 확장자
        self.assertEqual({n: slurp(os.path.join(store, n)) for n in os.listdir(store)}, before)   # 표본 파일은 그대로, 풀린 것도 없다
        found = sorted(os.path.relpath(os.path.join(d, f), self.data) for d, _, fs in os.walk(self.data) for f in fs
                       if os.path.basename(d) != "store")
        self.assertEqual(found, ["index.jsonl", os.path.join("results", "static-train.jsonl")])

    def test_each_part_gets_its_own_file(self):
        self.run_ok("--parts", "train", "calibration")
        self.assertEqual(sorted(self.results("calibration")), sorted([self.k1, self.k2]))
        self.assertEqual(sorted(self.results("train")), self.train)

    def test_too_big_to_upload_is_skipped_without_uploading(self):
        with mock.patch.object(run_static.v1(), "MAX_UPLOAD", 10):
            self.run_ok()
        self.assertEqual(sum(self.api.calls.values()), 0)
        skipped = {sid: r["why"] for sid, r in self.results().items() if sid != self.n2}
        self.assertEqual(set(skipped.values()), {"업로드 50MB 초과"})
        self.assertEqual(len(skipped), 13)

    def test_busy_backend_is_waited_for_and_retried(self):
        self.answers[self.m1] = lambda attempt: (503, {"error": "검사기 컨테이너를 띄울 수 없습니다"}) if attempt < 3 else "malicious"
        self.answers[self.b1] = lambda attempt: (0, {"error": "connection refused"}) if attempt < 2 else "clean"
        self.run_ok()
        self.assertEqual((self.api.calls[self.m1], self.api.calls[self.b1]), (3, 2))
        self.assertEqual(self.results()[self.m1]["verdict"], "malicious")
        self.assertEqual(self.results()[self.b1]["verdict"], "clean")
        self.assertEqual(sorted(s for s in self.clock.slept if s >= 10), [10, 10, 20])   # 10초 · 20초 … 로 늘려 가며

    def test_unreachable_backend_stops_the_run_without_recording_the_sample(self):
        stuck = self.b1
        before = self.train[:self.train.index(stuck)]
        self.answers[stuck] = (0, {"error": "connection refused"})
        with open(os.path.join(self.tmp, "tokens"), "w") as f:
            f.write(f"ADMIN_TOKEN={TOKEN}\n")
        code, text = self.cli("run", "--token-file", os.path.join(self.tmp, "tokens"))
        self.assertEqual(code, 1)
        self.assertIn("멈춤", text)
        self.assertEqual(sorted(self.results()), before)                 # 앞의 것만 기록, 걸린 표본 · 뒤 표본은 없다
        self.assertEqual(self.api.calls[stuck], run_static.TRIES)
        self.answers[stuck] = "clean"                                    # 백엔드가 돌아온 뒤 다시 돌리면 이어서
        self.run_ok()
        self.assertEqual(sorted(self.results()), self.train)

    def test_answer_sent_before_the_upload_finished_is_read_and_recorded_as_a_skip(self):
        """2026-11-19 v3 측정: 47MB sdist 가 풀면 200MB 를 넘어 백엔드가 400 으로 먼저 답하고 연결을 끊었는데, 올리던 쪽은 끊김(응답 0)만
        보고 「백엔드가 받지 않는다」로 멈춰 같은 표본을 되풀이했다. 먼저 온 답을 읽어 표본 탓(400)이면 건너뜀으로 남기고 다음으로 간다."""
        stuck = self.b1
        self.answers[stuck] = (0, {"error": "<urlopen error [Errno 32] Broken pipe>"})
        asked = []

        def early(api, filename, body):
            asked.append(filename)
            return 400, {"error": "풀었을 때 200MB 를 넘습니다"}

        with mock.patch.object(run_static, "early_answer", early):
            self.run_ok()
        res = self.results()
        self.assertEqual(sorted(res), self.train)                        # 멈추지 않고 끝까지 간다
        self.assertEqual(res[stuck], {"id": stuck, "status": "skip", "why": "풀면 200MB 초과"})
        self.assertEqual(self.api.calls[stuck], 1)                       # 같은 표본을 되풀이해 올리지 않는다
        self.assertEqual(asked, [f"sgb-{stuck}.tar.gz"])                 # 끊긴 표본에만 묻는다

    def test_no_early_answer_keeps_the_old_wait_and_stop(self):
        stuck = self.b1
        self.answers[stuck] = (0, {"error": "connection refused"})
        with mock.patch.object(run_static, "early_answer", lambda api, filename, body: (0, None)):
            with open(os.path.join(self.tmp, "tokens"), "w") as f:
                f.write(f"ADMIN_TOKEN={TOKEN}\n")
            code, text = self.cli("run", "--token-file", os.path.join(self.tmp, "tokens"))
        self.assertEqual(code, 1)
        self.assertIn("멈춤", text)
        self.assertNotIn(stuck, self.results())
        self.assertEqual(self.api.calls[stuck], run_static.TRIES)

    def test_wrong_address_or_server_error_stops_instead_of_filling_the_file_with_errors(self):
        for code in (404, 500):
            for sid in self.train:
                self.answers[sid] = (code, {"error": "x"})
            with mock.patch.dict(os.environ, {"ADMIN_TOKEN": TOKEN}):
                status, text = self.cli("run", "--api", "http://127.0.0.1:8000")
            self.assertEqual(status, 1)
            self.assertIn(f"응답 {code}", text)
            self.assertLessEqual(set(self.results()), {self.n2})          # 올린 표본은 하나도 기록하지 않았다
        self.assertEqual(sum(self.api.calls.values()), 2)                 # 실행마다 첫 표본에서 멈췄다

    def test_retry_errors_reruns_only_errors_and_the_last_line_wins(self):
        self.run_ok()
        calls = dict(self.api.calls)
        self.answers[self.n3] = "malicious"
        self.run_ok()                                                     # 기본은 오류도 건너뛴다
        self.assertEqual(dict(self.api.calls), calls)
        self.run_ok("--retry-errors")
        again = {sid for sid in self.api.calls if self.api.calls[sid] > calls.get(sid, 0)}
        self.assertEqual(again, {self.n3, self.n4})
        self.assertEqual(self.results()[self.n3]["verdict"], "malicious")
        self.assertEqual(self.results()[self.n2]["status"], "skip")

    def test_missing_or_altered_sample_file_stops_before_any_upload(self):
        path = os.path.join(self.data, "store", f"{self.b1}.tar.gz")
        keep = slurp(path)
        os.remove(path)
        with mock.patch.dict(os.environ, {"ADMIN_TOKEN": TOKEN}):
            code, text = self.cli("run")
            self.assertEqual(code, 1)
            self.assertIn("표본 파일", text)
            self.assertEqual(self.results(), {})
            with open(path, "wb") as f:
                f.write(keep + b"\0")                                     # id(파일 해시)와 다른 내용
            code, text = self.cli("run")
            self.assertEqual(code, 1)
            self.assertIn("색인과 다르다", text)
            self.assertNotIn(self.b1, self.results())
            self.assertNotIn(self.b1, self.api.calls)

    def test_half_written_line_is_ignored_and_does_not_glue_onto_the_next(self):
        self.run_ok("--limit", "2")
        path = run_static.results_path(self.data, "train")
        with open(path, "a", encoding="utf-8") as f:
            f.write('{"id": "' + self.train[2] + '", "status": "o')       # 쓰다 끊긴 줄
        self.assertEqual(sorted(self.results()), self.train[:2])
        self.run_ok()
        self.assertEqual(sorted(self.results()), self.train)


class EarlyAnswer(unittest.TestCase):
    """early_answer(): 올리는 중에 서버가 먼저 답하고 끊었을 때 그 답을 읽는다 — 가짜 연결로(네트워크 없음)."""

    class Api:
        base = "http://127.0.0.1:8010/api"
        h = {"Authorization": "Bearer " + TOKEN}

    def conn(self, *, send_error=None, answer=None, read_error=None):
        made = []

        class Response:
            status = answer[0] if answer else None

            def read(self):
                return answer[1]

        class Conn:
            def __init__(self, netloc, timeout=None):
                self.netloc, self.closed, self.sent = netloc, False, None
                made.append(self)

            def request(self, method, path, body=None, headers=None):
                self.sent = (method, path, body, headers)
                if send_error:
                    raise send_error

            def getresponse(self):
                if read_error:
                    raise read_error
                return Response()

            def close(self):
                self.closed = True

        return Conn, made

    def ask(self, **kw):
        Conn, made = self.conn(**kw)
        with mock.patch.object(run_static.http.client, "HTTPConnection", Conn):
            got = run_static.early_answer(self.Api(), "sgb-0123456789abcdef.tar.gz", b"BODY" * 1000)
        return got, made

    def test_reads_the_answer_after_the_send_broke(self):
        body = json.dumps({"error": "풀었을 때 200MB 를 넘습니다"}, ensure_ascii=False).encode()
        got, made = self.ask(send_error=BrokenPipeError(32, "Broken pipe"), answer=(400, body))
        self.assertEqual(got, (400, {"error": "풀었을 때 200MB 를 넘습니다"}))
        method, path, sent, headers = made[0].sent
        self.assertEqual((made[0].netloc, method, path), ("127.0.0.1:8010", "POST", "/api/scans"))
        self.assertEqual(headers["Authorization"], "Bearer " + TOKEN)
        self.assertTrue(headers["Content-Type"].startswith("multipart/form-data; boundary="))
        self.assertIn(b'filename="sgb-0123456789abcdef.tar.gz"', sent)
        self.assertIn(b"BODY" * 1000, sent)
        self.assertTrue(made[0].closed)

    def test_answer_after_a_whole_send_is_returned_as_it_is(self):
        got, _ = self.ask(answer=(202, b'{"id": "scan-0001"}'))
        self.assertEqual(got, (202, {"id": "scan-0001"}))
        got, _ = self.ask(answer=(413, b"not json"))
        self.assertEqual(got, (413, None))

    def test_no_answer_is_zero(self):
        for kw in ({"send_error": ConnectionRefusedError(61, "refused"), "read_error": ConnectionResetError(54, "reset")},
                   {"send_error": BrokenPipeError(32, "Broken pipe"), "read_error": run_static.http.client.RemoteDisconnected("closed")}):
            got, made = self.ask(**kw)
            self.assertEqual(got, (0, None))
            self.assertTrue(made[0].closed)

    def test_an_api_without_an_address_is_not_asked(self):
        self.assertEqual(run_static.early_answer(object(), "sgb-0123456789abcdef.tar.gz", b"x"), (0, None))


class Token(Corpus):
    def test_token_never_reaches_the_screen_or_the_result_file(self):
        text = self.run_ok()
        self.assertEqual(self.tokens, [TOKEN])                            # 파일의 ADMIN_TOKEN= 줄을 읽어 백엔드 쪽에만 넘겼다
        self.assertNotIn(TOKEN, text)
        with open(run_static.results_path(self.data, "train"), encoding="utf-8") as f:
            self.assertNotIn(TOKEN, f.read())
        _, text = self.report()
        self.assertNotIn(TOKEN, text)

    def test_environment_wins_over_the_file_and_a_refused_token_stops_quietly(self):
        for sid in self.train:
            self.answers[sid] = (401, {"error": "로그인이 필요합니다"})
        with open(os.path.join(self.tmp, "tokens"), "w") as f:
            f.write("ADMIN_TOKEN=from-file\n")
        with mock.patch.dict(os.environ, {"ADMIN_TOKEN": TOKEN}):
            code, text = self.cli("run", "--token-file", os.path.join(self.tmp, "tokens"))
        self.assertEqual(self.tokens, [TOKEN])
        self.assertEqual(code, 1)
        self.assertIn("토큰", text)
        self.assertNotIn(TOKEN, text)
        self.assertNotIn("from-file", text)
        self.assertEqual(sum(self.api.calls.values()), 1)                 # 첫 거부에서 멈췄다
        self.assertLessEqual(set(self.results()), {self.n2})              # 토큰 문제는 표본 탓이 아니다 — 올린 표본은 기록하지 않는다

    def test_no_token_stops_before_any_upload(self):
        code, text = self.cli("run", "--token-file", os.path.join(self.tmp, "no-such-file"))
        self.assertEqual(code, 1)
        self.assertIn("ADMIN_TOKEN", text)
        self.assertEqual(self.tokens, [])
        self.assertEqual(self.results(), {})


class Report(Corpus):
    def test_two_candidates_over_all_benign_and_malicious_with_code(self):
        self.run_ok()
        rep, text = self.report()
        self.assertEqual(rep["rows"], {"benign": 6, "maliciousWithCode": 7, "maliciousWithoutCode": 1})
        strict, loose = rep["candidates"]["S-malicious"]["all"]["main"], rep["candidates"]["S-suspicious"]["all"]["main"]
        # 묶기 실패(n2) · 검사 오류(n3) · 시간 초과(n4) · 백엔드가 받지 않음(c2)은 분모에 남고 「못 잡음」이다
        self.assertEqual((strict["tp"], strict["fn"], strict["fp"], strict["tn"]), (2, 5, 1, 5))
        self.assertEqual((loose["tp"], loose["fn"], loose["fp"], loose["tn"]), (3, 4, 2, 4))      # 주의(m2 · b2)까지, 취약(b4)은 아니다
        self.assertEqual((strict["detection"], strict["fpr"]), (round(2 / 7, 4), round(1 / 6, 4)))
        self.assertEqual(len(strict["detectionCi95"]), 2)
        self.assertEqual(rep["samples"], {"total": 14, "ok": 10, "skip": 2, "error": 2, "missing": 0, "outsidePart": 0})
        self.assertEqual({k: rep["unprocessed"][k] for k in ("total", "malicious", "benign")}, {"total": 4, "malicious": 3, "benign": 1})
        self.assertEqual(rep["unprocessed"]["why"]["skip: zip 손상"], 1)
        self.assertEqual(rep["unprocessed"]["why"]["error: 결과 대기 시간 초과"], 1)
        self.assertEqual(rep["unprocessed"]["why"]["error: 검사기 메모리 부족"], 1)   # 백엔드 오류 글은 종류만 — 나머지는 결과 파일에만
        self.assertNotIn("종료 코드 137", text + json.dumps(rep, ensure_ascii=False))
        self.assertIn("종료 코드 137", self.results()[self.n3]["why"])
        self.assertEqual(rep["engines"], {"GuardDog": ["2.6.0"], "OSV-Scanner": ["2.2.2"]})
        for word in ("S-malicious", "S-suspicious", "못 잡음", "pypi", "npm", "인기", "롱테일", "코드 없는 악성"):
            self.assertIn(word, text)

    def test_by_ecosystem_and_by_benign_source(self):
        self.run_ok()
        rep, _ = self.report()
        eco = rep["candidates"]["S-malicious"]["byEcosystem"]
        cells = lambda s: (s["main"]["tp"], s["main"]["fn"], s["main"]["fp"], s["main"]["tn"])  # noqa: E731
        self.assertEqual(cells(eco["pypi"]), (1, 2, 1, 3))
        self.assertEqual(cells(eco["npm"]), (1, 3, 0, 2))
        src = rep["candidates"]["S-suspicious"]["all"]["benignBySource"]
        self.assertEqual((src["popular"]["flagged"], src["popular"]["rows"], src["popular"]["rate"]), (1, 3, round(1 / 3, 4)))   # b2
        self.assertEqual((src["longTail"]["flagged"], src["longTail"]["rows"]), (1, 3))                                         # b3
        self.assertEqual(rep["candidates"]["S-malicious"]["all"]["benignBySource"]["popular"]["flagged"], 0)
        self.assertEqual(eco["npm"]["benignBySource"]["longTail"], {"flagged": 0, "rows": 1, "rate": 0.0, "ci95": [0.0, 0.7935]})
        self.assertEqual(rep["verdicts"]["pypi:malicious"], {"malicious": 2, "suspicious": 1, "vulnerable": 0, "clean": 1, "unprocessed": 0})
        self.assertEqual(rep["verdicts"]["npm:malicious"], {"malicious": 1, "suspicious": 0, "vulnerable": 0, "clean": 0, "unprocessed": 3})

    def test_malicious_without_code_is_reported_apart(self):
        self.run_ok()
        rep, _ = self.report()
        for name in ("S-malicious", "S-suspicious"):
            c = rep["candidates"][name]
            self.assertEqual(c["all"]["maliciousWithoutCode"], {"flagged": 1, "rows": 1, "rate": 1.0, "ci95": [0.2065, 1.0]})   # m4 — 잡았어도 주 지표 밖
            self.assertEqual(c["all"]["main"]["tp"] + c["all"]["main"]["fn"], 7)
            self.assertEqual(c["byEcosystem"]["npm"]["maliciousWithoutCode"]["rows"], 0)

    def test_samples_without_a_result_count_as_missed_and_are_shown(self):
        self.run_ok("--limit", "5")
        rep, text = self.report()
        done = self.results()
        self.assertEqual(rep["samples"]["missing"], 9)
        self.assertEqual(rep["samples"]["total"], 14)
        strict = rep["candidates"]["S-malicious"]["all"]["main"]
        self.assertEqual(strict["tp"] + strict["fn"], 7)                  # 분모는 그대로
        self.assertEqual(strict["fp"] + strict["tn"], 6)
        hits = sum(1 for sid in (self.m1, self.n1) if done.get(sid, {}).get("status") == "ok")
        self.assertEqual(strict["tp"], hits)
        self.assertEqual(rep["unprocessed"]["why"]["결과 없음"], 9)
        self.assertRegex(text, r"처리: 검사함 \d+ · 건너뜀 \d+ · 오류 \d+ · 결과 없음 9 → 「못 잡음」으로 센 표본 \d+")

    def test_report_before_any_run_and_results_from_outside_the_part(self):
        rep, _ = self.report("calibration")
        self.assertEqual(rep["samples"], {"total": 2, "ok": 0, "skip": 0, "error": 0, "missing": 2, "outsidePart": 0})
        self.assertEqual(rep["candidates"]["S-malicious"]["all"]["main"]["fn"], 1)
        run_static.append_result(run_static.results_path(self.data, "calibration"), {"id": self.m1, "status": "ok", "verdict": "malicious"})
        rep, _ = self.report("calibration")
        self.assertEqual(rep["samples"]["outsidePart"], 1)                # 다른 구간 표본의 줄은 세지 않는다
        self.assertEqual(rep["candidates"]["S-malicious"]["all"]["main"]["tp"], 0)

    def test_report_file_records_what_it_was_made_from(self):
        self.run_ok()
        path = os.path.join(self.tmp, "report.json")
        self.cli("report", "--parts", "train", "calibration", "--json", path)
        with open(path, encoding="utf-8") as f:
            doc = json.load(f)
        self.assertEqual(doc["layer"], "static")
        self.assertEqual(sorted(doc["parts"]), ["calibration", "train"])
        self.assertEqual(doc["candidates"], {"S-malicious": ["malicious"], "S-suspicious": ["malicious", "suspicious"]})
        with open(split.SPLIT, "rb") as f:
            self.assertEqual(doc["splitSha256"], sample.sha256(f.read()))
        with open(run_static.results_path(self.data, "train"), "rb") as f:
            self.assertEqual(doc["parts"]["train"]["resultsSha256"], sample.sha256(f.read()))
        self.assertIsNone(doc["parts"]["calibration"]["resultsSha256"])


def plain_tar(files):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        for name, data in files.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    return buf.getvalue()


class Integration(Base):
    """합치며 더한 것(11/12): bz2 · xz tar 는 gzip 으로 다시 압축해 올림 · 시험 코드 탐지 수 기록 · 봉인을 연 뒤의 파일 자리."""

    def test_bz2_and_xz_sdists_go_up_recompressed_as_gzip_with_the_same_tar_inside(self):
        import bz2
        import gzip
        import lzma
        tar = plain_tar({"pkg-9/setup.py": b"print(9)\n", "pkg-9/pkg/__init__.py": b"x = 1\n"})
        bz = self.add("train", "pypi", "benign", raw=bz2.compress(tar))
        xz = self.add("train", "pypi", "benign", raw=lzma.compress(tar + b"\0" * 512))
        self.save()
        self.run_ok()
        for sid, inner in ((bz, tar), (xz, tar + b"\0" * 512)):
            name, data = self.api.uploads[sid]
            self.assertEqual(name, f"sgb-{sid}.tar.gz")           # 백엔드는 gzip tar 와 zip 만 푼다
            self.assertEqual(gzip.decompress(data), inner)        # 안의 tar 는 한 바이트도 바뀌지 않는다
            self.assertEqual(self.results()[sid]["status"], "ok")

    def test_recompression_refuses_a_bomb_and_a_broken_stream(self):
        import bz2
        bomb = self.add("train", "pypi", "benign", raw=bz2.compress(b"\0" * 4096))
        self.save()
        with mock.patch.object(sample, "MAX_EXTRACT", 1024):   # 풀면 4096 바이트 — 낮춘 상한을 넘는다
            self.run_ok()
        broken = self.add("train", "pypi", "benign", raw=bz2.compress(plain_tar({"a/setup.py": b"x\n"}))[:-8])
        self.save()
        self.run_ok()                                          # 평소 상한 — 끝이 잘린 압축
        res = self.results()
        self.assertEqual(res[bomb], {"id": bomb, "status": "skip", "why": "풀면 크기 상한 초과"})
        self.assertEqual(res[broken], {"id": broken, "status": "skip", "why": "압축을 읽지 못함"})
        self.assertNotIn(bomb, self.api.calls)
        self.assertNotIn(broken, self.api.calls)

    def test_test_code_findings_are_recorded(self):
        sid = self.add("train", "pypi", "malicious", answer="malicious")
        self.save()
        self.run_ok()
        self.assertEqual(self.results()[sid]["testFindings"], 1)

    def test_reverse_run_goes_from_the_end_and_skips_what_another_run_recorded_meanwhile(self):
        ids = sorted(self.add("train", "npm", "benign") for _ in range(4))
        self.save()
        path = run_static.results_path(self.data, "train")

        def other_run_records(_attempt):   # 이 표본을 올리는 순간, 앞에서부터 도는 다른 실행이 ids[1] 을 기록했다고 친다
            run_static.append_result(path, {"id": ids[1], "status": "ok", "verdict": "clean"})
            return "clean"

        self.answers[ids[3]] = other_run_records
        text = self.run_ok("--reverse")
        self.assertEqual(list(self.api.uploads), [ids[3], ids[2], ids[0]])   # 뒤에서부터, 그사이 기록된 ids[1] 은 올리지 않는다
        self.assertIn("다른 실행이 기록함 1", text)
        self.assertEqual(sorted(self.results()), ids)

    def test_an_unsealed_part_is_read_from_the_sealed_folder(self):
        sid = self.add("test", "npm", "benign")
        os.makedirs(os.path.join(self.data, "sealed", "test"))
        os.replace(os.path.join(self.data, "store", f"{sid}.tgz"), os.path.join(self.data, "sealed", "test", f"{sid}.tgz"))
        self.save()
        code, text = self.cli("run", "--parts", "test", "--dry-run")
        self.assertEqual(code, 1)                                 # 봉인 중에는 거부
        with open(split.LEDGER, "w", encoding="utf-8") as f:
            json.dump([{"part": "test"}], f)                      # 연 기록이 있으면
        self.run_ok("--parts", "test")
        self.assertEqual(self.results("test")[sid]["status"], "ok")
        self.assertEqual(self.api.uploads[sid][0], f"sgb-{sid}.tgz")


if __name__ == "__main__":
    unittest.main()
