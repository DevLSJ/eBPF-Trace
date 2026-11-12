#!/usr/bin/env python3
"""평가 규칙 v2 — 표본 수집(내려받기 → 색인 → 봉인). 규칙은 protocol.json 의 data · unit · sealing.

실제 악성 표본을 받는다. 악성은 암호 zip 그대로 저장하고, 메모리에서 글로만 읽으며, 어떤 파일도 실행하지 않는다.
결과는 bench/datasets/v2/ (git 추적 제외): store/<id>.<확장자> · meta/<단계>.jsonl(시도 기록 — 다시 돌리면 이어서) · sources.json · index.jsonl

  python3 bench/v2/collect.py malicious --eco pypi          # 저장소 트리의 모든 zip
  python3 bench/v2/collect.py malicious --eco npm           # 이름을 해시 순서로, 지문이 새것 2,000 개까지
  python3 bench/v2/collect.py benign --eco pypi --kind popular     # longTail · npm 도 같은 식(악성 수집 뒤에)
  python3 bench/v2/collect.py index                         # → index.jsonl
  python3 bench/v2/split.py build --index bench/datasets/v2/index.jsonl --source "$(python3 bench/v2/collect.py source-line)"
  python3 bench/v2/collect.py seal                          # 시험 · 예비 표본 파일을 sealed/ 로
  python3 bench/v2/collect.py prune                         # 쓰지 않는 표본(지문 중복) · 복제본 · 캐시 삭제
  python3 bench/v2/collect.py status
"""
import argparse
import datetime as dt
import email.utils
import hashlib
import io
import json
import os
import re
import shutil
import ssl
import subprocess
import sys
import tarfile
import time
import urllib.error
import urllib.parse
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import sample  # noqa: E402
import split  # noqa: E402

DATA = os.environ.get("SG_BENCH_DATA") or os.path.join(split.ROOT, "bench", "datasets", "v2")
STORE = os.path.join(DATA, "store")
SEALED_DIR = os.path.join(DATA, "sealed")
META = os.path.join(DATA, "meta")
CACHE = os.path.join(DATA, "cache")
REPO = os.path.join(DATA, "datadog-repo")
SOURCES = os.path.join(DATA, "sources.json")
INDEX = os.path.join(DATA, "index.jsonl")

DATADOG_URL = "https://github.com/DataDog/malicious-software-packages-dataset"
TOP_PYPI_URL = "https://hugovk.github.io/top-pypi-packages/top-pypi-packages-30-days.min.json"
TOP_NPM_URL = "https://packages.ecosyste.ms/api/v1/registries/npmjs.org/packages?sort=downloads&order=desc&per_page=100&page={page}"
PYPI_NAMES_URL = "https://pypi.org/simple/"
NPM_NAMES_PKG = "https://registry.npmjs.org/all-the-package-names/latest"
UA = "sg-bench/2"

NPM_KEEP = 2000            # npm 악성: 지문이 새것인 표본 수 상한
NPM_SCAN_MAX = 8000        # npm 악성: 훑는 이름 수 상한
BATCH = 400                # 한 번에 받는 blob 수
MAX_BENIGN_BYTES = 50 << 20  # 정상 표본 파일 크기 상한(백엔드 검사 상한과 같다) — 넘으면 다음 후보
LONGTAIL_MIN_AGE_DAYS = 365
MIN_FREE_BYTES = 6 << 30   # 디스크 여유가 이보다 적으면 멈춘다
EXT = {"zip": "zip", "sdist": "tar.gz", "wheel": "whl", "tarball": "tgz"}


class Stop(Exception):
    """단계를 멈춰야 하는 상황(일시적 네트워크 오류 · 디스크 부족). 다시 돌리면 이어서 한다."""


# ── 순수 함수(시험 대상) ──

def hash_order(seed, ecosystem, names):
    """이름을 sha256("<seed>:<생태계>:<이름>") 오름차순으로."""
    return sorted(names, key=lambda n: hashlib.sha256(f"{seed}:{ecosystem}:{n}".encode()).hexdigest())


def parse_datadog_path(path):
    """samples/<생태계>/<종류>/<이름 폴더>/[<판>/]<날짜>-….zip → dict, 모양이 다르면 None.
    npm 범위 이름 폴더는 @scope@name 꼴이다."""
    p = path.split("/")
    if len(p) not in (5, 6) or p[0] != "samples" or not p[-1].endswith(".zip"):
        return None
    m = re.match(r"(\d{4}-\d{2}-\d{2})-", p[-1])
    name = p[3]
    if name.startswith("@") and "@" in name[1:]:
        name = "@" + name[1:].replace("@", "/", 1)
    return {"ecosystem": p[1], "kind": p[2], "name": name, "version": p[4] if len(p) == 6 else "",
            "date": m.group(1) if m else "", "path": path}


def latest_per_name(entries):
    """이름마다 발견일이 가장 늦은 것 하나(같으면 경로가 뒤인 것). {이름: 항목}"""
    out = {}
    for e in entries:
        cur = out.get(e["name"])
        if cur is None or (e["date"], e["path"]) > (cur["date"], cur["path"]):
            out[e["name"]] = e
    return out


def pick_pypi_file(urls, max_bytes=MAX_BENIGN_BYTES):
    """PyPI JSON 의 urls → (파일 dict, None) 또는 (None, 사유). sdist 가 있으면 sdist, 없으면 wheel(파일 이름이 앞인 것)."""
    live = [u for u in urls if not u.get("yanked")]
    sdists = sorted((u for u in live if u.get("packagetype") == "sdist"), key=lambda u: u["filename"])
    wheels = sorted((u for u in live if u.get("packagetype") == "bdist_wheel"), key=lambda u: u["filename"])
    pool = sdists or wheels
    if not pool:
        return None, "받을 파일 없음"
    f = pool[0]
    if f.get("size", 0) > max_bytes:
        return None, "50MB 초과"
    return {"url": f["url"], "filename": f["filename"], "form": "sdist" if sdists else "wheel",
            "date": (f.get("upload_time_iso_8601") or "")[:10]}, None


def longtail_reject(first_release, today, *, popular, has_malware_advisory, placeholder=False):
    """롱테일 후보를 버리는 사유(받아들이면 None). 조건은 protocol.json data.benign.longTail."""
    if popular:
        return "인기 묶음"
    if placeholder:
        return "보안 자리표시 패키지"
    if not first_release:
        return "출시 기록 없음"
    if (today - dt.date.fromisoformat(first_release[:10])).days < LONGTAIL_MIN_AGE_DAYS:
        return "첫 출시 1년 미만"
    if has_malware_advisory:
        return "MAL- 권고 있음"
    return None


def benign_quota(n_malicious):
    """정상 표본 수: 악성(중복 제거 뒤) 수와 같게 — 인기 절반(올림) · 롱테일 나머지."""
    return {"popular": (n_malicious + 1) // 2, "longTail": n_malicious // 2}


class Journal:
    """단계별 시도 기록(JSONL). 키 하나에 한 줄 — 다시 돌리면 한 것은 건너뛴다."""

    def __init__(self, path):
        self.path, self.rows = path, {}
        if os.path.exists(path):
            for r in split.read_jsonl(path):
                self.rows[r["key"]] = r

    def __contains__(self, key):
        return key in self.rows

    def add(self, key, **rec):
        rec = {"key": key, **rec}
        self.rows[key] = rec
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        with open(self.path, "a", encoding="utf-8") as f:
            f.write(json.dumps(rec, ensure_ascii=False, separators=(",", ":")) + "\n")
        return rec

    def kept(self):
        return [r["row"] for r in self.rows.values() if r["status"] == "kept"]


# ── 네트워크 · 저장 ──

def check_disk():
    os.makedirs(DATA, exist_ok=True)
    if shutil.disk_usage(DATA).free < MIN_FREE_BYTES:
        raise Stop("디스크 여유가 6GB 아래다")


def _tls():
    """인증서 검증용 컨텍스트. python.org 판 macOS 파이썬은 CA 묶음이 비어 있어(검증이 모두 실패) 시스템 묶음을 더한다.
    검증을 끄지는 않는다."""
    ctx = ssl.create_default_context()
    for path in (os.environ.get("SSL_CERT_FILE"), "/etc/ssl/cert.pem", "/etc/ssl/certs/ca-certificates.crt"):
        if path and os.path.exists(path):
            ctx.load_verify_locations(cafile=path)
            break
    return ctx


TLS = _tls()


def http(url, *, data=None, headers=None, max_bytes=None, timeout=120, tries=4):
    """(본문, 응답 헤더) 또는 (None, None)(404 · 410 · 본문이 max_bytes 초과). 일시적 오류는 다시 하고, 그래도 안 되면 Stop."""
    req_headers = {"User-Agent": UA, **(headers or {})}
    last = None
    for attempt in range(tries):
        try:
            req = urllib.request.Request(url, data=data, headers=req_headers)
            with urllib.request.urlopen(req, timeout=timeout, context=TLS) as r:
                length = r.headers.get("Content-Length")
                if max_bytes is not None and length and int(length) > max_bytes:
                    return None, None
                body = r.read(max_bytes + 1) if max_bytes is not None else r.read()
                if max_bytes is not None and len(body) > max_bytes:
                    return None, None
                return body, r.headers
        except urllib.error.HTTPError as e:
            if e.code in (404, 410):
                return None, None
            last = f"HTTP {e.code}"
        except (urllib.error.URLError, TimeoutError, ConnectionError, OSError) as e:
            last = type(e).__name__
        time.sleep(2 ** attempt)
    raise Stop(f"네트워크 오류({last}) — 다시 돌리면 이어서 한다: {url[:80]}")


def http_json(url, **kw):
    body, _ = http(url, **kw)
    return json.loads(body) if body is not None else None


def has_malware_advisory(ecosystem, name, version=None):
    """OSV 에 MAL- 권고가 있는가(판을 주면 그 판에 해당하는 것만)."""
    q = {"package": {"name": name, "ecosystem": "PyPI" if ecosystem == "pypi" else "npm"}}
    if version:
        q["version"] = version
    while True:
        d = http_json("https://api.osv.dev/v1/query", data=json.dumps(q).encode(), headers={"Content-Type": "application/json"})
        if any(v.get("id", "").startswith("MAL-") for v in (d or {}).get("vulns", [])):
            return True
        if not (d or {}).get("next_page_token"):
            return False
        q["page_token"] = d["next_page_token"]


def store(data, form):
    """표본 바이트를 store/<id>.<확장자> 로(이미 있으면 그대로)."""
    os.makedirs(STORE, exist_ok=True)
    path = os.path.join(STORE, f"{sample.sample_id(data)}.{EXT[form]}")
    if not os.path.exists(path):
        tmp = path + ".part"
        with open(tmp, "wb") as f:
            f.write(data)
        os.replace(tmp, path)
    return path


def sources(update=None):
    cur = {}
    if os.path.exists(SOURCES):
        with open(SOURCES, encoding="utf-8") as f:
            cur = json.load(f)
    if update:
        cur.update(update)
        cur.setdefault("fetchedOn", dt.date.today().isoformat())
        os.makedirs(DATA, exist_ok=True)
        tmp = f"{SOURCES}.{os.getpid()}.part"  # 여러 단계를 함께 돌려도 반쯤 쓴 파일을 읽지 않게
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(cur, f, ensure_ascii=False, indent=1)
            f.write("\n")
        os.replace(tmp, SOURCES)
    return cur


def today():
    """365일 조건의 기준일 — 처음 받은 날로 고정(며칠에 걸쳐 이어 받아도 같다)."""
    return dt.date.fromisoformat(sources({}).get("fetchedOn") or sources({"fetchedOn": dt.date.today().isoformat()})["fetchedOn"])


def cached(name, fetch):
    """cache/<name> 이 있으면 읽고, 없으면 fetch() 결과(바이트)를 저장한다."""
    os.makedirs(CACHE, exist_ok=True)
    path = os.path.join(CACHE, name)
    if not os.path.exists(path):
        data = fetch()
        if data is None:
            raise Stop(f"{name} 을 받지 못했다")
        with open(path + ".part", "wb") as f:
            f.write(data)
        os.replace(path + ".part", path)
    with open(path, "rb") as f:
        return f.read()


def git(*args, stdin=None, binary=False):
    r = subprocess.run(["git", "-C", REPO, *args], input=stdin, capture_output=True)
    if r.returncode != 0:
        raise Stop("git " + " ".join(args[:3]) + " 실패: " + r.stderr.decode(errors="replace")[-200:])
    return r.stdout if binary else r.stdout.decode()


def datadog_tree():
    """고정한 커밋의 표본 zip 목록 [(blob 해시, 경로)]. 저장소가 없으면 blob 없이 얕게 받는다."""
    if not os.path.isdir(os.path.join(REPO, ".git")):
        os.makedirs(DATA, exist_ok=True)
        r = subprocess.run(["git", "clone", "--quiet", "--depth", "1", "--filter=blob:none", "--no-checkout", DATADOG_URL, REPO],
                           capture_output=True)
        if r.returncode != 0:
            raise Stop("DataDog 저장소를 받지 못했다: " + r.stderr.decode(errors="replace")[-200:])
    commit = (sources({}).get("datadog") or {}).get("commit")
    if commit is None:
        commit = git("rev-parse", "HEAD").strip()
        sources({"datadog": {"url": DATADOG_URL, "commit": commit, "committedAt": git("log", "-1", "--format=%cI").strip()}})
    elif subprocess.run(["git", "-C", REPO, "cat-file", "-e", commit + "^{commit}"], capture_output=True).returncode != 0:
        git("fetch", "--quiet", "--depth", "1", "--filter=blob:none", "origin", commit)  # 복제본을 다시 받았고 원격이 그새 앞서 갔다
    out = []
    for line in git("ls-tree", "-r", commit, "--", "samples/pypi", "samples/npm").splitlines():
        meta, path = line.split("\t", 1)
        if path.endswith(".zip"):
            out.append((meta.split()[2], path))
    return out


def _packs():
    d = os.path.join(REPO, ".git", "objects", "pack")
    return {f[:-5] for f in os.listdir(d) if f.endswith(".pack")} if os.path.isdir(d) else set()


def fetch_blobs(oids):
    """빠진 blob 을 한 번에 받는다(부분 복제의 지연 받기와 같은 방식). 새로 생긴 pack 이름들을 돌려준다.
    unpackLimit=1 · gc.auto=0: 받은 것을 늘 pack 하나로 두어, 처리한 뒤 그 pack 만 지울 수 있게 한다."""
    if not oids:
        return set()
    before = _packs()
    git("-c", "fetch.negotiationAlgorithm=noop", "-c", "fetch.unpackLimit=1", "-c", "gc.auto=0", "fetch", "origin", "--no-tags",
        "--no-write-fetch-head", "--recurse-submodules=no", "--filter=blob:none", "--stdin", stdin=("\n".join(oids) + "\n").encode())
    return _packs() - before


def drop_packs(names):
    """처리가 끝난 blob pack 을 지운다. 표본은 store/ 에 이미 있고, 복제본에는 트리만 남긴다."""
    d = os.path.join(REPO, ".git", "objects", "pack")
    for name in names:
        for ext in (".pack", ".idx", ".promisor", ".rev", ".bitmap", ".mtimes"):
            path = os.path.join(d, name + ext)
            if os.path.exists(path):
                os.remove(path)


# ── 단계 ──

def journal(step):
    return Journal(os.path.join(META, step + ".jsonl"))


def cmd_malicious(args):
    eco = args.eco
    entries = [dict(e, oid=oid) for oid, path in datadog_tree() for e in [parse_datadog_path(path)] if e and e["ecosystem"] == eco]
    j = journal(f"malicious-{eco}")
    if eco == "pypi":
        targets, keep_max, scan_max = sorted(entries, key=lambda e: e["path"]), None, None
    else:
        latest = latest_per_name(entries)
        targets, keep_max, scan_max = [latest[n] for n in hash_order(split.SEED, eco, latest)], NPM_KEEP, NPM_SCAN_MAX
    prints = {split.fingerprint(r): r["id"] for r in j.kept() if split.fingerprint(r)}
    ids = {r["id"] for r in j.kept()}
    scanned = 0  # 순서대로 훑은 이름 수 — 이미 기록한 것도 센다(이어 받아도 같은 자리에서 멈춘다)
    for start in range(0, len(targets), BATCH):
        if keep_max is not None and (len(ids) >= keep_max or scanned >= scan_max):
            break
        batch = targets[start:start + BATCH]
        if keep_max is not None:
            batch = batch[:scan_max - scanned]
        check_disk()
        packs = fetch_blobs([e["oid"] for e in batch if e["path"] not in j])
        for e in batch:
            if keep_max is not None and len(ids) >= keep_max:
                break
            scanned += 1
            if e["path"] in j:
                continue
            data = git("cat-file", "blob", e["oid"], binary=True)
            row = sample.build_row(data, ecosystem=eco, label="malicious", name=e["name"], version=e["version"], date=e["date"],
                                   source="datadog:" + e["kind"], form="zip")
            fp = split.fingerprint(row)
            if row["id"] in ids:
                j.add(e["path"], status="duplicate", duplicateOf=row["id"], why="같은 파일")
            elif keep_max is not None and fp and fp in prints:
                j.add(e["path"], status="duplicate", duplicateOf=prints[fp], why="같은 지문")
            else:
                store(data, "zip")
                ids.add(row["id"])
                if fp:
                    prints.setdefault(fp, row["id"])
                j.add(e["path"], status="kept", row=row)
        drop_packs(packs)
        print(f"악성 {eco}: 훑음 {min(start + BATCH, len(targets))}/{len(targets)} · 남김 {len(ids)}", flush=True)
    print(f"악성 {eco} 끝: 남김 {len(ids)} · 기록 {len(j.rows)}")


def n_malicious(eco):
    kept, _ = split.dedupe(journal(f"malicious-{eco}").kept())
    if not kept:
        raise Stop(f"악성 {eco} 수집이 먼저다")
    return len(kept)


def top_pypi():
    raw = cached("top-pypi.json", lambda: http(TOP_PYPI_URL)[0])
    d = json.loads(raw)
    sources({"pypiTop": {"url": TOP_PYPI_URL, "sha256": sample.sha256(raw), "rows": len(d["rows"]), "lastUpdate": d.get("last_update")}})
    return [r["project"] for r in d["rows"]]


def top_npm(n):
    """월간 다운로드 순서 이름(@types/* 제외)을 n 개 넘게 — 쪽마다 캐시한다(서버가 느리다)."""
    names, page = [], 1
    while len(names) < n and page <= 60:
        raw = cached(f"top-npm-{page:02d}.json", lambda: http(TOP_NPM_URL.format(page=page), timeout=600)[0])
        rows = json.loads(raw)
        if not rows:
            break
        names += [r["name"] for r in rows if not r["name"].startswith("@types/")]
        page += 1
    sources({"npmTop": {"url": TOP_NPM_URL, "pages": page - 1, "names": len(names)}})
    return names


def pypi_names():
    raw = cached("pypi-names.json", lambda: http(PYPI_NAMES_URL, headers={"Accept": "application/vnd.pypi.simple.v1+json"}, timeout=600)[0])
    names = [p["name"] for p in json.loads(raw)["projects"]]
    sources({"pypiNames": {"url": PYPI_NAMES_URL, "sha256": sample.sha256(raw), "count": len(names)}})
    return names


def npm_names():
    meta = json.loads(cached("npm-names-meta.json", lambda: http(NPM_NAMES_PKG)[0]))
    raw = cached("npm-names.tgz", lambda: http(meta["dist"]["tarball"], timeout=900)[0])
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz") as tf:
        member = next(m for m in tf if m.name.endswith("names.json"))
        names = json.load(tf.extractfile(member))
    sources({"npmNames": {"package": "all-the-package-names@" + meta["version"], "sha256": sample.sha256(raw), "count": len(names)}})
    return names


def candidate_pypi(name, *, long_tail, popular_set):
    """PyPI 후보 하나 → (표본 바이트, 필드 dict) 또는 (None, 사유)."""
    d = http_json("https://pypi.org/pypi/" + urllib.parse.quote(name) + "/json")
    if d is None:
        return None, "없음"
    version = d["info"]["version"]
    f, why = pick_pypi_file(d.get("urls") or [])
    if f is None:
        return None, why
    if long_tail:
        uploads = [u["upload_time_iso_8601"] for files in d.get("releases", {}).values() for u in files if u.get("upload_time_iso_8601")]
        why = longtail_reject(min(uploads) if uploads else "", today(), popular=split.norm_name("pypi", name) in popular_set,
                              has_malware_advisory=False)
        why = why or ("MAL- 권고 있음" if has_malware_advisory("pypi", name) else None)
    else:
        why = "MAL- 권고 있음" if has_malware_advisory("pypi", name, version) else None
    if why:
        return None, why
    data, _ = http(f["url"], max_bytes=MAX_BENIGN_BYTES, timeout=300)
    if data is None:
        return None, "50MB 초과"
    return data, {"version": version, "date": f["date"], "form": f["form"]}


def candidate_npm(name, *, long_tail, popular_set):
    """npm 후보 하나 → (표본 바이트, 필드 dict) 또는 (None, 사유)."""
    quoted = name.replace("/", "%2F")
    first = ""
    if long_tail:
        doc = http_json("https://registry.npmjs.org/" + quoted, max_bytes=20 << 20)
        if doc is None:
            return None, "없음"
        times = doc.get("time") or {}
        version = (doc.get("dist-tags") or {}).get("latest")
        latest = (doc.get("versions") or {}).get(version or "")
        if "unpublished" in times or not latest:
            return None, "게시 중이 아님"
        first = times.get("created", "")
    else:
        latest = http_json("https://registry.npmjs.org/" + quoted + "/latest")
        if latest is None:
            return None, "없음"
        version = latest["version"]
    if long_tail:
        why = longtail_reject(first, today(), popular=split.norm_name("npm", name) in popular_set, has_malware_advisory=False,
                              placeholder=version.endswith("-security"))
        why = why or ("MAL- 권고 있음" if has_malware_advisory("npm", name) else None)
    else:
        why = "MAL- 권고 있음" if has_malware_advisory("npm", name, version) else None
    if why:
        return None, why
    data, headers = http(latest["dist"]["tarball"], max_bytes=MAX_BENIGN_BYTES, timeout=300)
    if data is None:
        return None, "50MB 초과"
    stamp = email.utils.parsedate_to_datetime(headers["Last-Modified"]).date().isoformat() if headers.get("Last-Modified") else ""
    return data, {"version": version, "date": stamp, "form": "tarball"}


def cmd_benign(args):
    eco, kind = args.eco, args.kind
    quota = benign_quota(n_malicious(eco))[kind]
    j = journal(f"benign-{eco}-{kind}")
    candidate = candidate_pypi if eco == "pypi" else candidate_npm
    # 인기 목록은 두 단계가 같은 것을 쓴다: PyPI 는 순위표 전체, npm 은 인기 몫 + 여유 400(버려지는 후보 몫)
    popular = top_pypi() if eco == "pypi" else top_npm(benign_quota(n_malicious(eco))["popular"] + 400)
    if kind == "popular":
        order, popular_set = popular, set()
    else:
        popular_set = {split.norm_name(eco, n) for n in popular}
        order = hash_order(split.SEED, eco, pypi_names() if eco == "pypi" else npm_names())
    kept_ids = {r["id"] for r in j.kept()}
    for i, name in enumerate(order):
        if len(kept_ids) >= quota:
            break
        if name in j:
            continue
        check_disk()
        data, info = candidate(name, long_tail=(kind == "longTail"), popular_set=popular_set)
        if data is None:
            j.add(name, status="skip", why=info)
        else:
            row = sample.build_row(data, ecosystem=eco, label="benign", name=name, source=kind, **info)
            if row["id"] in kept_ids:
                j.add(name, status="skip", why="같은 파일")
            else:
                store(data, info["form"])
                kept_ids.add(row["id"])
                j.add(name, status="kept", row=row)
        if len(j.rows) % 100 == 0:
            print(f"정상 {eco} {kind}: 후보 {i + 1} · 남김 {len(kept_ids)}/{quota}", flush=True)
        time.sleep(0.03)
    if len(kept_ids) < quota:
        raise Stop(f"정상 {eco} {kind}: 후보가 모자란다(남김 {len(kept_ids)}/{quota})")
    print(f"정상 {eco} {kind} 끝: 남김 {len(kept_ids)}/{quota} · 기록 {len(j.rows)}")


STEPS = [f"malicious-{e}" for e in split.ECOSYSTEMS] + [f"benign-{e}-{k}" for e in split.ECOSYSTEMS for k in ("popular", "longTail")]


def cmd_index(_args):
    rows = {}
    for step in STEPS:
        for r in journal(step).kept():
            rows.setdefault(r["id"], r)
    for r in rows.values():  # 저장한 파일이 색인과 같은지
        path = os.path.join(STORE, f"{r['id']}.{EXT[r['form']]}")
        with open(path, "rb") as f:
            if sample.sample_id(f.read()) != r["id"]:
                raise Stop(f"저장한 파일이 색인과 다르다: {r['id']}")
    with open(INDEX, "w", encoding="utf-8") as f:
        for i in sorted(rows):
            f.write(json.dumps(rows[i], ensure_ascii=False, separators=(",", ":")) + "\n")
    print(f"index.jsonl {len(rows)}줄")
    cmd_status(None)


def cmd_source_line(_args):
    s = sources({})
    print(f"DataDog {s['datadog']['commit'][:12]}({s['datadog']['committedAt'][:10]}) · top-pypi {s['pypiTop']['sha256'][:12]} · "
          f"pypi 이름 {s['pypiNames']['sha256'][:12]} · npm 이름 {s['npmNames']['package']} · 받은 날 {s['fetchedOn']}")


def cmd_seal(_args):
    with open(split.SPLIT, encoding="utf-8") as f:
        sp = json.load(f)
    forms = {r["id"]: r["form"] for r in split.read_jsonl(INDEX)}
    moved = {p: 0 for p in sp["sealed"]}
    for i, part in sp["assignments"].items():
        if part not in sp["sealed"]:
            continue
        name = f"{i}.{EXT[forms[i]]}"
        src, dst = os.path.join(STORE, name), os.path.join(SEALED_DIR, part, name)
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        if os.path.exists(src):
            os.replace(src, dst)
        if not os.path.exists(dst):
            raise Stop(f"봉인할 파일이 없다: {i}")
        moved[part] += 1
    print("봉인: " + " · ".join(f"{p} {n}" for p, n in moved.items()))


def _size(path):
    if os.path.isfile(path):
        return os.path.getsize(path)
    return sum(os.path.getsize(os.path.join(d, f)) for d, _, fs in os.walk(path) for f in fs)


def cmd_prune(_args):
    """쓰지 않는 것을 지운다(분할 · 봉인 뒤): 분할에 들지 않은 표본 파일(지문 중복) · 받다 만 파일 · DataDog 복제본 · 목록 캐시.
    지우기 전에, 분할에 든 표본 파일이 모두 제자리에 있는지 먼저 확인한다. 기록(meta · index · sources)은 남긴다."""
    with open(split.SPLIT, encoding="utf-8") as f:
        sp = json.load(f)
    forms = {r["id"]: r["form"] for r in split.read_jsonl(INDEX)}
    for i, part in sp["assignments"].items():
        name = f"{i}.{EXT[forms[i]]}"
        if not any(os.path.exists(os.path.join(d, name)) for d in (STORE, os.path.join(SEALED_DIR, part))):
            raise Stop(f"분할에 든 표본 파일이 없다({i}) — 아무것도 지우지 않았다")
    files = freed = 0
    for name in sorted(os.listdir(STORE)):
        if name.endswith(".part") or name.split(".", 1)[0] not in sp["assignments"]:
            path = os.path.join(STORE, name)
            freed += os.path.getsize(path)
            os.remove(path)
            files += 1
    dirs = []
    for d in (REPO, CACHE):
        if os.path.isdir(d):
            freed += _size(d)
            shutil.rmtree(d)
            dirs.append(os.path.basename(d))
    print(f"정리: 표본 파일 {files}개 · 폴더 {dirs} 삭제 · {freed / (1 << 20):.0f}MB 비움")


def cmd_status(_args):
    for step in STEPS:
        j = journal(step)
        why = {}
        for r in j.rows.values():
            if r["status"] != "kept":
                why[r.get("why", r["status"])] = why.get(r.get("why", r["status"]), 0) + 1
        kept = j.kept()
        size = sum(r["bytes"] for r in kept) / (1 << 20)
        print(f"{step:22s} 남김 {len(kept):5d} · {size:7.0f}MB · 코드 없음 {sum(1 for r in kept if r['codeLines'] == 0):4d} · "
              f"읽기 실패 {sum(1 for r in kept if r.get('indexError')):3d} · 버림 {json.dumps(why, ensure_ascii=False)}")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    m = sub.add_parser("malicious")
    m.add_argument("--eco", required=True, choices=split.ECOSYSTEMS)
    m.set_defaults(fn=cmd_malicious)
    b = sub.add_parser("benign")
    b.add_argument("--eco", required=True, choices=split.ECOSYSTEMS)
    b.add_argument("--kind", required=True, choices=("popular", "longTail"))
    b.set_defaults(fn=cmd_benign)
    for name, fn in (("index", cmd_index), ("source-line", cmd_source_line), ("seal", cmd_seal), ("prune", cmd_prune), ("status", cmd_status)):
        sub.add_parser(name).set_defaults(fn=fn)
    args = ap.parse_args()
    try:
        args.fn(args)
    except Stop as e:
        sys.exit(f"멈춤: {e}")


if __name__ == "__main__":
    main()
