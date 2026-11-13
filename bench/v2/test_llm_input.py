"""평가 규칙 v2 LLM 입력 만들기 점검(합성 압축 · 네트워크 없이) — python3 -B -m unittest discover -s bench/v2 -p 'test_*.py'

합성 표본은 무해한 흉내다(TEST-NET 주소 · 예약 도메인만, 어떤 파일도 실행하지 않는다). 표준 라이브러리만 쓴다.
"""
import contextlib
import io
import json
import os
import shutil
import struct
import subprocess
import sys
import tarfile
import tempfile
import unittest
import zipfile
import zlib
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import collect  # noqa: E402
import llm_input  # noqa: E402
import llm_layer  # noqa: E402
import rules_layer  # noqa: E402
import sample  # noqa: E402
import split  # noqa: E402


# ── 합성 압축 ──

def tar_bytes(files, mode="w:gz"):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode=mode) as tf:
        for name, data in files.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            info.mtime = 0
            tf.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def _crc_table():
    table = []
    for n in range(256):
        c = n
        for _ in range(8):
            c = (c >> 1) ^ 0xEDB88320 if c & 1 else c >> 1
        table.append(c)
    return table


_CRC = _crc_table()


def _zipcrypto(plain, password):
    """전통 PKWARE(ZipCrypto) 암호화 — DataDog 표본과 같은 방식. zipfile 은 읽기만 하므로 시험에서 직접 만든다."""
    keys = [0x12345678, 0x23456789, 0x34567890]

    def update(b):
        keys[0] = _CRC[(keys[0] ^ b) & 0xFF] ^ (keys[0] >> 8)
        keys[1] = ((keys[1] + (keys[0] & 0xFF)) * 134775813 + 1) & 0xFFFFFFFF
        keys[2] = _CRC[(keys[2] ^ (keys[1] >> 24)) & 0xFF] ^ (keys[2] >> 8)

    for b in password:
        update(b)
    out = bytearray()
    for b in plain:
        t = (keys[2] | 2) & 0xFFFF
        out.append(b ^ (((t * (t ^ 1)) >> 8) & 0xFF))
        update(b)
    return bytes(out)


def encrypted_zip(files, password=sample.ZIP_PASSWORD):
    """{이름: 바이트} → 암호 zip(저장 방식 · ZipCrypto). 머리 12바이트의 마지막은 CRC 의 윗바이트."""
    body, central = io.BytesIO(), io.BytesIO()
    for name, data in files.items():
        raw_name = name.encode()
        crc = zlib.crc32(data) & 0xFFFFFFFF
        enc = _zipcrypto(bytes(range(11)) + bytes([crc >> 24]) + data, password)
        offset = body.tell()
        body.write(struct.pack("<IHHHHHIIIHH", 0x04034B50, 20, 1, 0, 0, 0x21, crc, len(enc), len(data), len(raw_name), 0) + raw_name + enc)
        central.write(struct.pack("<IHHHHHHIIIHHHHHII", 0x02014B50, 20, 20, 1, 0, 0, 0x21, crc, len(enc), len(data), len(raw_name),
                                  0, 0, 0, 0, 0, offset) + raw_name)
    cd = central.getvalue()
    end = struct.pack("<IHHHHIIH", 0x06054B50, 0, 0, len(files), len(files), len(cd), body.tell(), 0)
    return body.getvalue() + cd + end


# ── 합성 표본(무해한 흉내) ──

SETUP = b'from setuptools import setup\nimport urllib.request\nurllib.request.urlopen("http://203.0.113.7/x")\nsetup(name="demo")\n'
BIG = (b"x = 1\n" * 5000)  # 30,000자 — 20KB 에서 잘린다
LONG_LINE = b"y = '" + b"A" * 3000 + b"'\n"  # 2,000자 넘는 줄 — 규칙 엔진처럼 앞 500자 + 표시로 바뀐다
BINARY = b"\x00\x01\x02 not text"

PACKAGE = {
    "demo-1.0/zzz.txt": b"last\n",
    "demo-1.0/demo/util.py": b"def f():\n    return 1\n",
    "demo-1.0/demo/big.py": BIG,
    "demo-1.0/demo/long.py": LONG_LINE,
    "demo-1.0/demo/blob.py": BINARY,
    "demo-1.0/demo/__init__.py": b"from .util import f\n",
    "demo-1.0/demo.pth": b"import demo\n",
    "demo-1.0/setup.cfg": b"[metadata]\nname = demo\n",
    "demo-1.0/pyproject.toml": b"[build-system]\nrequires = []\n",
    "demo-1.0/setup.py": SETUP,
    "demo-1.0/node_modules/x/index.js": b"module.exports = 1\n",  # 규칙 엔진이 빼는 경로
    "demo-1.0/README.md": b"# readme\n",                           # 규칙 엔진이 읽지 않는 확장자
    "demo-1.0/logo.png": b"\x89PNG\x00\x00",
    "package_info.json": b'{"name": "demo"}',                       # DataDog 메타 파일
}
NPM = {
    "package/package.json": b'{"name": "demo-js", "scripts": {"postinstall": "node install.js"}}',
    "package/install.js": b'require("https").get("https://example.invalid/x")\n',
    "package/lib/a.js": b"module.exports = 2\n",
}

GD_OK = {"status": "ok", "verdict": "malicious", "score": 9, "rules": ["code-execution", "exfiltrate-sensitive-data"],
         "installThreats": 2, "threats": 3, "capabilities": 1, "testFindings": 0, "vulns": 0, "seconds": 1.5,
         "engines": {"guarddog": "x"}}
RULES_OK = {"status": "ok", "why": "", "score": 80, "level": "HIGH", "strong": ["SC-NET-001"],
            "hits": [{"rule": "SC-NET-001", "severity": "HIGH", "category": "network", "file": "setup.py", "count": 2,
                      "test": False, "doc": False},
                     {"rule": "SC-ENV-002", "severity": "MEDIUM", "category": "env", "file": "tests/test_a.py", "count": 1,
                      "test": True, "doc": False},
                     {"rule": "SC-ENV-002", "severity": "MEDIUM", "category": "env", "file": "demo/util.py", "count": 3,
                      "test": False, "doc": False}],
            "truncatedFiles": 1, "files": 9, "ms": 10}


class Corpus:
    """임시 데이터 폴더(index.jsonl · store/ · sealed/ · results/) + 분할 파일 + 봉인 기록 경로."""

    def __init__(self, case):
        tmp = tempfile.TemporaryDirectory()
        case.addCleanup(tmp.cleanup)
        self.root = tmp.name
        self.dir = os.path.join(tmp.name, "data")
        os.makedirs(os.path.join(self.dir, "results"))
        self.rows, self.parts = [], {}
        self.split_path = os.path.join(tmp.name, "split.json")
        self.ledger_path = os.path.join(tmp.name, "unseal-log.json")
        self.gd, self.ru = {}, {}

    def add(self, data, *, part="train", form="zip", label="malicious", name="secretname", gd=None, ru=None):
        row = sample.build_row(data, ecosystem="pypi", label=label, name=name, version="9.8.7", date="2024-12-31",
                               source="sourcetag", form=form)
        folder = os.path.join(self.dir, "sealed", part) if part in split.SEALED else os.path.join(self.dir, "store")
        os.makedirs(folder, exist_ok=True)
        with open(os.path.join(folder, f"{row['id']}.{collect.EXT[form]}"), "wb") as f:
            f.write(data)
        self.rows.append(row)
        self.parts[row["id"]] = part
        if gd is not None:
            self.gd.setdefault(part, []).append({"id": row["id"], **gd})
        if ru is not None:
            self.ru.setdefault(part, []).append({"id": row["id"], **ru})
        self.flush()
        return row

    def flush(self):
        with open(os.path.join(self.dir, "index.jsonl"), "w", encoding="utf-8") as f:
            for r in sorted(self.rows, key=lambda r: r["id"]):
                f.write(json.dumps(r, ensure_ascii=False) + "\n")
        with open(self.split_path, "w", encoding="utf-8") as f:
            json.dump({"assignments": dict(self.parts), "sealed": list(split.SEALED)}, f)
        for prefix, store in (("static", self.gd), ("rules", self.ru)):
            for part, rows in store.items():
                with open(os.path.join(self.dir, "results", f"{prefix}-{part}.jsonl"), "w", encoding="utf-8") as f:
                    for r in rows:
                        f.write(json.dumps(r, ensure_ascii=False) + "\n")

    def out(self, name="in.jsonl"):
        return os.path.join(self.root, "out", name)

    def build(self, out=None, **kw):
        kw.setdefault("part", "train")
        return llm_input.build(self.dir, out=out or self.out(), split_path=self.split_path, ledger_path=self.ledger_path,
                               root=os.path.join(self.root, "fake-repo"), **kw)


def read_rows(path):
    with open(path, encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def engine_view(data):
    """규칙 엔진이 실제로 받는 글: {경로: 본문(긴 줄 표시 · 20KB 절삭 뒤)} — rules_layer 의 함수 그대로."""
    files, why = rules_layer.engine_files(data)
    assert why is None, why
    out = {}
    for path, text in files.items():
        if rules_layer.EXCLUDE_RE.search(path):
            continue
        body = rules_layer._clamp(text)
        out[path] = body[:rules_layer.FILE_CAP]
    return out


class Encrypted(unittest.TestCase):
    def test_synthetic_zip_is_really_encrypted_and_sample_reads_it(self):
        data = encrypted_zip({"a/setup.py": SETUP})
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            with self.assertRaises(RuntimeError):
                zf.read("a/setup.py")  # 암호 없이는 못 읽는다
        files, why = sample.members(data, wanted=rules_layer.wanted)
        self.assertIsNone(why)
        self.assertEqual(files, [("a/setup.py", SETUP)])


class PackageFiles(unittest.TestCase):
    def check_same_as_engine(self, data):
        entries, why = llm_input.package_files(data)
        self.assertIsNone(why)
        texts = {e["path"]: e["body"] for e in entries if e["kind"] == "text"}
        self.assertEqual(texts, engine_view(data))
        return entries

    def test_text_files_and_bodies_are_exactly_what_the_rules_engine_reads(self):
        for data in (encrypted_zip(PACKAGE), tar_bytes(PACKAGE), tar_bytes(NPM, "w:bz2"), encrypted_zip(NPM)):
            self.check_same_as_engine(data)

    def test_cut_flags_match_the_rules_engine(self):
        data = tar_bytes(PACKAGE)
        entries = self.check_same_as_engine(data)
        files, _ = rules_layer.engine_files(data)
        engine_cuts = sum(1 for cut, _ in rules_layer._blocks(files) if cut)
        self.assertEqual(sum(1 for e in entries if e["cut"]), engine_cuts)
        self.assertEqual(engine_cuts, 1)

    def test_order_puts_install_scripts_and_manifests_first(self):
        entries, _ = llm_input.package_files(encrypted_zip(PACKAGE))
        paths = [e["path"] for e in entries]
        self.assertEqual(paths[:4], ["setup.py", "pyproject.toml", "setup.cfg", "demo.pth"])
        self.assertEqual(paths[4:], sorted(paths[4:]))
        npm, _ = llm_input.package_files(tar_bytes(NPM))
        self.assertEqual([e["path"] for e in npm], ["package.json", "install.js", "lib/a.js"])

    def test_package_json_comes_before_pth(self):
        entries, _ = llm_input.package_files(tar_bytes({"p-1.0/z.pth": b"x\n", "p-1.0/package.json": b"{}",
                                                        "p-1.0/a.py": b"a\n", "p-1.0/sub/setup.py": b"s\n", "p-1.0/setup.py": b"t\n"}))
        self.assertEqual([e["path"] for e in entries], ["setup.py", "sub/setup.py", "package.json", "z.pth", "a.py"])

    def test_excluded_unwanted_and_meta_files_are_left_out(self):
        entries, _ = llm_input.package_files(tar_bytes(PACKAGE))
        paths = {e["path"] for e in entries}
        for gone in ("node_modules/x/index.js", "README.md", "logo.png", "package_info.json"):
            self.assertNotIn(gone, paths)

    def test_binary_file_is_listed_without_content(self):
        entries, _ = llm_input.package_files(tar_bytes(PACKAGE))
        blob = [e for e in entries if e["path"] == "demo/blob.py"]
        self.assertEqual(len(blob), 1)
        self.assertEqual(blob[0]["kind"], "binary")
        self.assertEqual(blob[0]["bytes"], len(BINARY))
        text, _ = llm_input.render(entries)
        header = [ln for ln in text.split("\n") if "demo/blob.py" in ln]
        self.assertEqual(len(header), 1)
        self.assertIn("글 아님", header[0])
        self.assertNotIn("not text", text)

    def test_unreadable_archive_gives_a_reason(self):
        entries, why = llm_input.package_files(b"not an archive")
        self.assertIsNone(entries)
        self.assertTrue(why)


class Render(unittest.TestCase):
    def test_header_carries_path_original_bytes_and_cut(self):
        entries, _ = llm_input.package_files(tar_bytes(PACKAGE))
        text, over = llm_input.render(entries)
        self.assertFalse(over)
        lines = text.split("\n")
        self.assertEqual(lines[0], f"===== setup.py ({len(SETUP):,} 바이트) =====")
        big = [ln for ln in lines if ln.startswith("===== demo/big.py")]
        self.assertEqual(big, [f"===== demo/big.py ({len(BIG):,} 바이트, 앞 {rules_layer.FILE_CAP:,}자만 실음) ====="])
        start = text.index(big[0]) + len(big[0]) + 1
        self.assertEqual(text[start:start + rules_layer.FILE_CAP], engine_view(tar_bytes(PACKAGE))["demo/big.py"])
        self.assertIn("OBFUSCATION_SUSPECT", text)  # 긴 줄은 규칙 엔진과 같은 표시로

    def test_text_is_cut_a_little_above_the_llm_limit(self):
        files = {f"p-1.0/m{i:02d}.py": b"z = 0\n" * 4000 for i in range(15)}  # 파일당 20KB × 15 > 210,000자
        entries, _ = llm_input.package_files(tar_bytes(files))
        text, over = llm_input.render(entries)
        self.assertTrue(over)
        self.assertEqual(len(text), llm_input.TEXT_LIMIT)
        self.assertGreater(llm_input.TEXT_LIMIT, llm_layer.MAX_TEXT_CHARS)

    def test_package_without_text_files_says_so(self):
        text, over = llm_input.render([])
        self.assertTrue(text)
        self.assertFalse(over)


class Static(unittest.TestCase):
    def test_summary_has_both_engines_and_nothing_that_leaks_the_answer(self):
        s = llm_input.static_summary(GD_OK, RULES_OK)
        self.assertEqual(s["guarddog"], {"status": "ok", "verdict": "malicious", "score": 9, "installThreats": 2,
                                         "rules": ["code-execution", "exfiltrate-sensitive-data"]})
        r = s["rules"]
        self.assertEqual((r["status"], r["score"], r["level"], r["strong"]), ("ok", 80, "HIGH", ["SC-NET-001"]))
        self.assertEqual([h["rule"] for h in r["topHits"]], ["SC-NET-001", "SC-ENV-002"])
        env = r["topHits"][1]
        self.assertEqual(env["count"], 4)
        self.assertEqual(env["fileCount"], 2)
        self.assertEqual(env["files"], ["demo/util.py ×3", "tests/test_a.py ×1 (시험)"])
        blob = json.dumps(s, ensure_ascii=False)
        for word in ('"p"', "label", "source", "version", "date", "name"):
            self.assertNotIn(word, blob)

    def test_engine_that_did_not_finish_is_only_marked(self):
        s = llm_input.static_summary({"status": "error", "why": "시간 초과"}, None)
        self.assertEqual(s, {"guarddog": {"status": llm_input.NOT_DONE}, "rules": {"status": llm_input.NOT_DONE}})
        s = llm_input.static_summary({"status": "skip", "why": "x"}, {"status": "error", "why": "엔진 오류: X", "hits": []})
        self.assertEqual(s["rules"], {"status": llm_input.NOT_DONE})

    def test_summary_fits_the_llm_static_limit_most_important_first(self):
        hits = [{"rule": f"SC-R-{i:03d}", "severity": sev, "category": "c", "file": f"pkg/very/long/path/name_{j}.py",
                 "count": i + j, "test": False, "doc": j == 2}
                for i in range(70) for j in range(4) for sev in (("LOW", "MEDIUM", "HIGH", "CRITICAL")[i % 4],)]
        big = {**RULES_OK, "hits": hits, "strong": sorted({h["rule"] for h in hits})}
        s = llm_input.static_summary(GD_OK, big)
        block = llm_layer.static_block(s)
        self.assertLessEqual(len(block), llm_layer.MAX_STATIC_CHARS)
        self.assertNotIn("[절삭]", block)
        top = s["rules"]["topHits"]
        self.assertGreater(s["rules"]["topHitsOmitted"], 0)
        self.assertEqual(len(top) + s["rules"]["topHitsOmitted"], 70)
        self.assertEqual(top[0]["severity"], "CRITICAL")
        self.assertTrue(all(h["severity"] == "CRITICAL" for h in top[:min(len(top), 17)]))
        self.assertIn("pkg/very/long/path/name_2.py ×", " ".join(top[0]["files"]))
        self.assertTrue(any(f.endswith("(문서)") for f in top[0]["files"]))
        self.assertLessEqual(len(top[0]["files"]), llm_input.MAX_HIT_FILES)
        self.assertIn("installThreats", s["guarddog"])  # GuardDog 칸은 자르지 않는다


class Build(unittest.TestCase):
    def setUp(self):
        self.c = Corpus(self)

    def test_rows_read_back_by_llm_layer(self):
        a = self.c.add(encrypted_zip(PACKAGE), gd=GD_OK, ru=RULES_OK)
        b = self.c.add(tar_bytes(NPM), form="tarball", label="benign")
        meta = self.c.build()
        rows = list(llm_layer.read_input(self.c.out()))
        self.assertEqual([r["id"] for r in rows], sorted([a["id"], b["id"]]))
        by = {r["id"]: r for r in rows}
        self.assertTrue(by[a["id"]]["text"].startswith("===== setup.py"))
        self.assertEqual(by[a["id"]]["static"]["guarddog"]["verdict"], "malicious")
        self.assertEqual(by[b["id"]]["static"], {"guarddog": {"status": llm_input.NOT_DONE}, "rules": {"status": llm_input.NOT_DONE}})
        self.assertEqual(meta["rows"], 2)
        self.assertEqual(meta["truncatedFiles"], 1)
        self.assertEqual(meta["binaryFiles"], 1)
        self.assertEqual(meta["gate"], {"mode": "all"})
        with open(os.path.splitext(self.c.out())[0] + ".meta.json", encoding="utf-8") as f:
            self.assertEqual(json.load(f), meta)
        with open(os.path.abspath(llm_input.__file__), "rb") as f:
            self.assertEqual(meta["toolSha256"], llm_input.sha256_bytes(f.read()))

    def test_rows_carry_no_label_name_source_version_date_or_ml_probability(self):
        a = self.c.add(encrypted_zip(PACKAGE), gd=GD_OK, ru=RULES_OK)
        ml = os.path.join(self.c.root, "ml.jsonl")
        with open(ml, "w", encoding="utf-8") as f:
            f.write(json.dumps({"id": a["id"], "p": 0.123456}) + "\n")
        self.c.build(ml=ml, band_low=0.02, band_high=0.9994)
        (row,) = read_rows(self.c.out())
        self.assertEqual(set(row), {"id", "text", "static"})
        blob = json.dumps({"text": row["text"], "static": row["static"]}, ensure_ascii=False)
        for leak in (a["id"], "secretname", "sourcetag", "9.8.7", "2024-12-31", "0.123456", '"label"', '"p"'):
            self.assertNotIn(leak, blob)

    def test_ml_gate_includes_low_and_excludes_high_and_unknown(self):
        ids = []
        for i in range(4):
            ids.append(self.c.add(tar_bytes({f"p{i}-1.0/setup.py": SETUP + bytes([65 + i])}))["id"])
        ml = os.path.join(self.c.root, "ml.jsonl")
        with open(ml, "w", encoding="utf-8") as f:
            for i, p in zip(ids[:3], (0.02, 0.9994, 0.5)):
                f.write(json.dumps({"id": i, "p": p}) + "\n")
        meta = self.c.build(ml=ml, band_low=0.02, band_high=0.9994)
        got = [r["id"] for r in read_rows(self.c.out())]
        self.assertEqual(got, sorted([ids[0], ids[2]]))
        self.assertEqual(meta["gate"]["mode"], "ml")
        self.assertEqual((meta["gate"]["low"], meta["gate"]["high"]), (0.02, 0.9994))
        self.assertEqual(meta["gate"]["mlSha256"], llm_layer.read_ml(ml)[1])
        self.assertEqual(meta["selected"], 2)

    def test_gate_needs_both_bands(self):
        self.c.add(tar_bytes({"p-1.0/setup.py": SETUP}))
        ml = os.path.join(self.c.root, "ml.jsonl")
        with open(ml, "w", encoding="utf-8") as f:
            f.write("")
        with self.assertRaises(ValueError):
            self.c.build(ml=ml, band_low=0.02)
        with self.assertRaises(ValueError):
            self.c.build(band_low=0.02, band_high=0.5)
        with self.assertRaises(ValueError):
            self.c.build(ml=ml, band_low=0.5, band_high=0.5)

    def test_limit_takes_the_first_rows_after_the_gate(self):
        for i in range(3):
            self.c.add(tar_bytes({f"p{i}-1.0/setup.py": SETUP + bytes([65 + i])}))
        self.c.build(limit=2)
        self.assertEqual([r["id"] for r in read_rows(self.c.out())], sorted(r["id"] for r in self.c.rows)[:2])

    def test_sealed_parts_are_refused_before_anything_is_written(self):
        self.c.add(tar_bytes({"p-1.0/setup.py": SETUP}), part="test")
        self.c.add(tar_bytes({"q-1.0/setup.py": SETUP}), part="reserve")
        for part in ("test", "reserve"):
            with self.assertRaises(split.SealedError):
                self.c.build(part=part)
        self.assertFalse(os.path.exists(os.path.dirname(self.c.out())))

    def test_unreadable_or_mismatched_samples_are_skipped_and_counted(self):
        good = self.c.add(tar_bytes({"p-1.0/setup.py": SETUP}))
        bad = self.c.add(b"not an archive at all")
        swapped = self.c.add(tar_bytes({"s-1.0/setup.py": SETUP + b"#"}))
        with open(os.path.join(self.c.dir, "store", f"{swapped['id']}.zip"), "wb") as f:
            f.write(b"something else")
        meta = self.c.build()
        self.assertEqual([r["id"] for r in read_rows(self.c.out())], [good["id"]])
        self.assertEqual(sum(meta["skipped"].values()), 2)
        self.assertNotIn(bad["id"], json.dumps(meta))

    def test_same_input_gives_the_same_bytes(self):
        self.c.add(encrypted_zip(PACKAGE), gd=GD_OK, ru=RULES_OK)
        self.c.add(tar_bytes(NPM), form="tarball", label="benign")
        self.c.build(out=self.c.out("a.jsonl"))
        self.c.build(out=self.c.out("b.jsonl"))
        for suffix in (".jsonl", ".meta.json"):
            with open(self.c.out("a" + suffix), "rb") as f1, open(self.c.out("b" + suffix), "rb") as f2:
                self.assertEqual(f1.read(), f2.read())

    def test_output_file_is_private_and_data_folder_is_untouched(self):
        self.c.add(encrypted_zip(PACKAGE), gd=GD_OK, ru=RULES_OK)

        def listing():
            return sorted((p, sorted(f)) for p, _, f in os.walk(self.c.dir))

        before = listing()
        self.c.build()
        self.assertEqual(listing(), before)  # 표본을 풀거나 데이터 폴더에 쓰지 않는다
        self.assertEqual(os.stat(self.c.out()).st_mode & 0o777, 0o600)


class OutPath(unittest.TestCase):
    def test_inside_repo_outside_datasets_or_raw_is_refused(self):
        root = split.ROOT
        for bad in (os.path.join(root, "bench", "v2", "in.jsonl"), os.path.join(root, "in.jsonl"),
                    os.path.join(root, "frontend", "x", "in.jsonl")):
            with self.assertRaises(ValueError):
                llm_input.check_out_path(bad)

    def test_ignored_data_folders_and_outside_paths_are_allowed(self):
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp)
        llm_input.check_out_path(os.path.join(tmp, "x", "in.jsonl"))
        if shutil.which("git"):
            llm_input.check_out_path(os.path.join(split.ROOT, "bench", "datasets", "v2", "llm", "in.jsonl"))
            llm_input.check_out_path(os.path.join(split.ROOT, "bench", "raw", "in.jsonl"))

    @unittest.skipUnless(shutil.which("git"), "git 없음")
    def test_other_git_work_tree_needs_the_path_ignored(self):
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp)
        subprocess.run(["git", "init", "-q", tmp], check=True)
        with open(os.path.join(tmp, ".gitignore"), "w", encoding="utf-8") as f:
            f.write("private/\n")
        with self.assertRaises(ValueError):
            llm_input.check_out_path(os.path.join(tmp, "in.jsonl"), root=os.path.join(tmp, "elsewhere"))
        llm_input.check_out_path(os.path.join(tmp, "private", "in.jsonl"), root=os.path.join(tmp, "elsewhere"))

    def test_build_refuses_a_tracked_output_before_reading(self):
        c = Corpus(self)
        c.add(tar_bytes({"p-1.0/setup.py": SETUP}))
        fake = os.path.join(c.root, "fake-repo")
        with self.assertRaises(ValueError):
            llm_input.build(c.dir, out=os.path.join(fake, "bench", "v2", "in.jsonl"), part="train", split_path=c.split_path,
                            ledger_path=c.ledger_path, root=fake)
        self.assertFalse(os.path.exists(os.path.join(fake, "bench", "v2")))


class Cli(unittest.TestCase):
    def test_build_command_writes_rows_and_refuses_sealed(self):
        c = Corpus(self)
        c.add(tar_bytes({"p-1.0/setup.py": SETUP}))
        c.add(tar_bytes({"q-1.0/setup.py": SETUP + b"#"}), part="test")
        with mock.patch.object(split, "SPLIT", c.split_path), mock.patch.object(split, "LEDGER", c.ledger_path), \
                contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(llm_input.main(["build", "--part", "train", "--data", c.dir, "--out", c.out()]), 0)
            self.assertEqual(llm_input.main(["build", "--part", "test", "--data", c.dir, "--out", c.out("t.jsonl")]), 2)
            self.assertEqual(llm_input.main(["build", "--part", "train", "--data", c.dir,
                                              "--out", os.path.join(split.ROOT, "bench", "v2", "in.jsonl")]), 2)
        self.assertEqual(len(read_rows(c.out())), 1)
        self.assertFalse(os.path.exists(c.out("t.jsonl")))
        self.assertFalse(os.path.exists(os.path.join(split.ROOT, "bench", "v2", "in.jsonl")))


if __name__ == "__main__":
    unittest.main()
