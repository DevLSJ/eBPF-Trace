#!/usr/bin/env python3
"""평가 규칙 v2 — 표본 파일 하나를 색인 한 줄로 바꾼다(이름을 가린 코드 파일 해시 · 코드 줄 수).

표본은 디스크에 풀지 않고 메모리에서 글로만 읽는다. 어떤 파일도 실행하지 않는다. 규칙은 protocol.json 의 unit.
표준 라이브러리만 쓴다. 압축은 한 단계만 읽는다(안쪽 압축은 열지 않는다 — 악성 · 정상 같은 깊이).
"""
import hashlib
import io
import json
import posixpath
import re
import tarfile
import zipfile

ZIP_PASSWORD = b"infected"  # DataDog 데이터셋 공개 암호(README) — tools/sg-bench-dataset 과 같다
CODE_EXT = (".py", ".pyw", ".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".sh", ".bash", ".ps1", ".bat", ".cmd")
MAX_CODE_BYTES = 5 << 20   # 이보다 큰 파일은 코드 파일로 세지 않는다
MAX_EXTRACT = 200 << 20    # 풀었을 때 합계 상한(백엔드 maxExtract 와 같다)
MAX_FILES = 20000          # 파일 수 상한(백엔드 maxFiles 와 같다)
MIN_MASK_NAME = 3          # 이보다 짧은 이름 · 판 번호는 가리지 않는다(글 전체가 가려지는 것을 막는다)
INSTALL_SCRIPTS = ("preinstall", "install", "postinstall", "prepare")
META_PREFIX = "package_info"  # DataDog 가 표본에 붙인 레지스트리 메타 파일


def sha256(b):
    return hashlib.sha256(b).hexdigest()


def sample_id(data):
    return sha256(data)[:16]


def safe_path(name):
    parts = [x for x in posixpath.normpath("/" + name.replace("\\", "/")).split("/") if x not in ("", ".", "..")]
    return "/".join(parts)


def _zip_members(data):
    out = []
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        infos = [i for i in zf.infolist() if not i.is_dir() and (i.external_attr >> 16) & 0o170000 != 0o120000]
        if len(infos) > MAX_FILES:
            raise ValueError("파일 수 상한 초과")
        if sum(i.file_size for i in infos) > MAX_EXTRACT:
            raise ValueError("풀면 크기 상한 초과")
        for i in infos:
            read = wanted(safe_path(i.filename)) and i.file_size <= MAX_CODE_BYTES
            out.append((i.filename, zf.read(i, pwd=ZIP_PASSWORD) if read else None))
    return out


def _tar_members(data):
    out, total = [], 0
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as tf:
        for m in tf:
            if not m.isreg():
                continue
            total += m.size
            if len(out) >= MAX_FILES:
                raise ValueError("파일 수 상한 초과")
            if total > MAX_EXTRACT:
                raise ValueError("풀면 크기 상한 초과")
            read = wanted(safe_path(m.name)) and m.size <= MAX_CODE_BYTES
            f = tf.extractfile(m) if read else None
            out.append((m.name, f.read() if f else None))
    return out


def wanted(path):
    """내용까지 읽는 파일: 코드 파일과 package.json. 나머지는 이름만 센다(암호 zip 을 통째로 풀면 느리고, 쓸 일도 없다)."""
    return is_code(path) or path.rsplit("/", 1)[-1] == "package.json"


def members(data):
    """표본 바이트 → ([(경로, 바이트 또는 None)], None) 또는 (None, 사유). zip(암호 zip · wheel 포함) 또는 tar(gz · bz2 · xz).
    바이트는 wanted() 인 5MB 이하 파일만 채우고 나머지는 None."""
    try:
        files = _zip_members(data) if data[:2] == b"PK" else _tar_members(data)
    except (zipfile.BadZipFile, tarfile.TarError, RuntimeError, NotImplementedError, OSError, EOFError, ValueError) as e:
        return None, (str(e) if isinstance(e, ValueError) and "상한" in str(e) else "압축을 읽지 못함")
    files = [(safe_path(n), d) for n, d in files]
    return sorted(((n, d) for n, d in files if n), key=lambda x: x[0]), None


def normalize(text):
    """줄 끝을 LF 로, 줄 끝 공백을 지운다."""
    return "\n".join(line.rstrip() for line in text.replace("\r\n", "\n").replace("\r", "\n").split("\n"))


def mask(text, name, version):
    """자기 패키지 이름(-_. 변형 · 대소문자 무시)을 <NAME>, 자기 판 번호를 <VERSION> 으로. npm 은 @범위/이름 전체와 이름 부분 둘 다."""
    targets = [name] + ([name.split("/", 1)[1]] if name.startswith("@") and "/" in name else [])
    for target in targets:
        tokens = [t for t in re.split(r"[-_.]+", target) if t]
        if tokens and len("".join(tokens)) >= MIN_MASK_NAME:
            text = re.sub(r"[-_.]?".join(re.escape(t) for t in tokens), "<NAME>", text, flags=re.IGNORECASE)
    if version and len(version) >= MIN_MASK_NAME:
        text = text.replace(version, "<VERSION>")
    return text


def is_code(path):
    base = path.rsplit("/", 1)[-1]
    return path.lower().endswith(CODE_EXT) and not base.startswith(META_PREFIX)


def count_lines(text):
    """빈 줄 · 한 줄 주석(# 또는 // 로 시작)뿐인 줄을 뺀 줄 수."""
    n = 0
    for line in text.split("\n"):
        s = line.strip()
        if s and not s.startswith("#") and not s.startswith("//"):
            n += 1
    return n


def install_scripts(files):
    """가장 얕은 package.json 의 scripts 가운데 preinstall · install · postinstall · prepare 중 값이 있는 항목 수."""
    cands = sorted((p.count("/"), p) for p, _ in files if p.rsplit("/", 1)[-1] == "package.json")
    if not cands:
        return 0
    data = dict(files)[cands[0][1]]
    if data is None:
        return 0
    try:
        scripts = json.loads(data.decode("utf-8-sig")).get("scripts") or {}
    except (ValueError, AttributeError):
        return 0
    if not isinstance(scripts, dict):
        return 0
    return sum(1 for k in INSTALL_SCRIPTS if isinstance(scripts.get(k), str) and scripts[k].strip())


def describe(files, name, version):
    """[(경로, 바이트)] → codeFiles · codeLines · files. codeFiles 의 bytes = 해시한 글(줄 끝을 맞추고 이름을 가린 것)의 바이트 수."""
    code, lines = [], 0
    for path, data in files:
        if data is None or not is_code(path):
            continue
        try:
            text = normalize(data.decode("utf-8-sig"))
        except UnicodeDecodeError:
            continue
        masked = mask(text, name, version).encode()
        code.append({"sha256": sha256(masked), "bytes": len(masked)})
        lines += count_lines(text)
    code.sort(key=lambda f: (f["sha256"], f["bytes"]))
    return {"codeFiles": code, "codeLines": lines + install_scripts(files), "files": len(files)}


def build_row(data, *, ecosystem, label, name, version, date, source, form):
    """표본 바이트 → 색인 한 줄. 읽지 못하면 코드 없음(codeFiles []) + indexError 로 남긴다 — 표본을 버리지 않는다."""
    row = {"id": sample_id(data), "ecosystem": ecosystem, "label": label, "name": name, "version": version or "",
           "date": date or "", "source": source, "form": form, "bytes": len(data)}
    files, err = members(data)
    if files is None:
        return {**row, "codeFiles": [], "codeLines": 0, "files": 0, "indexError": err}
    return {**row, **describe(files, name, version)}
