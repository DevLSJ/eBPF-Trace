"""평가 규칙 v2 정적 규칙 층 점검(합성 압축 · 네트워크 없이) — python3 -B -m unittest discover -s bench/v2 -p 'test_*.py'

합성 표본의 「악성 모양」은 무해한 흉내다(TEST-NET 주소 · 예약 도메인만, 어떤 파일도 실행하지 않는다).
"""
import io
import json
import os
import sys
import tarfile
import unittest
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import sample  # noqa: E402


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


if __name__ == "__main__":
    unittest.main()
