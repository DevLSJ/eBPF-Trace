"""Resumable, hash-verified full-week PCAP preparation. Never sends packets.

Sealing records the derived artifacts' digests so later label/alignment work resumes
from them after the captures are removed. Feature replay still needs the capture.
"""

import argparse
import gzip
import json
import shutil
from concurrent.futures import ProcessPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path

from collector.feature_schema import CONTEXT_FEATURES, FEATURE_SCHEMA_VERSION
from ml.alignment import align
from ml.artifacts import sha256
from ml.cic_profile import CAPTURE_DAYS
from ml.labels import join_labels
from ml.replay import analyze

ROOT = Path(__file__).resolve().parents[1]
PIPELINE_FILES = [
    "collector/features.py", "collector/feature_schema.py", "ml/replay.py", "ml/pcap.py",
    "ml/labels.py", "ml/alignment.py", "ml/cic_profile.py", "ml/rule_engine.py", "ml/pipeline.py",
]
FEATURE_FILES = ["collector/features.py", "collector/feature_schema.py", "ml/replay.py",
                 "ml/pcap.py", "ml/rule_engine.py"]
ARTIFACTS = ("features", "intervals", "aligned")
SEAL_NOTES = [
    "Digests bind the derived artifacts only; a removed capture can no longer be re-verified.",
    "The recorded capture digest is carried from the run that produced these artifacts.",
    "Changing feature replay code, or relabelling against changed CSVs, still needs the capture.",
]


def write_json(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(json.dumps(value, indent=2) + "\n")
    temporary.replace(path)


def day_paths(directory, day):
    directory, stem = Path(directory), day.lower()
    return (directory / f"{stem}-features.csv.gz", directory / f"{stem}-intervals.jsonl.gz",
            directory / f"{stem}-aligned.csv.gz", directory / f"{stem}-ready.json")


def label_digests(labels, day):
    stem = day.lower()
    digests = {p.name: sha256(p) for p in Path(labels).rglob("*.csv")
               if p.name.lower().startswith(stem + "-")}
    if not digests:
        raise ValueError(f"No label CSV for {day}")
    return digests


def interval_manifest(path):
    with gzip.open(path, "rt") as stream:
        return json.loads(next(stream))["manifest"]


def bound(manifest, capture_hash, label_hashes, features_hash):
    return (manifest.get("capture_sha256") == capture_hash
            and manifest.get("source_sha256") == label_hashes
            and manifest.get("duration_tolerance_us") == 2
            and (features_hash is None or manifest.get("features_sha256") == features_hash))


def rebind_intervals(source, destination, features_hash):
    # Packet intervals depend on capture/labels, not the feature columns.
    # Explicitly bind a new copy to the new feature hash; retain its origin.
    temporary = destination.with_name(destination.name + ".tmp")
    with gzip.open(source, "rt") as stream:
        manifest = json.loads(next(stream))["manifest"]
        manifest.update(features_sha256=features_hash, reused_from_intervals_sha256=sha256(source))
        with gzip.open(temporary, "wt") as output:
            output.write(json.dumps({"manifest": manifest}) + "\n")
            shutil.copyfileobj(stream, output)
    temporary.replace(destination)


def seal_block(record, digests):
    summary = record["summary"]
    return {"sealed_at": datetime.now(timezone.utc).isoformat(),
            "capture_sha256": record["identity"]["capture_sha256"],
            "capture_name": summary["source"], "capture_bytes": summary["source_bytes"],
            "sha256": digests, "notes": SEAL_NOTES}


def seal_day(day, directory, labels):
    features, intervals, joined, record_path = day_paths(directory, day)
    if not record_path.exists():
        raise ValueError("No ready.json; prepare this day from its capture first")
    missing = [path.name for path in (features, intervals, joined) if not path.exists()]
    if missing:
        raise ValueError(f"Missing derived artifacts: {', '.join(missing)}")
    record = json.loads(record_path.read_text())
    identity, summary = record.get("identity", {}), record["summary"]
    digests = {"features": sha256(features), "intervals": sha256(intervals),
               "aligned": sha256(joined)}
    if digests["features"] != record.get("label_report", {}).get("features_sha256"):
        raise ValueError("Features changed after preparation")
    if digests["aligned"] != record.get("output_sha256"):
        raise ValueError("Aligned output changed after preparation")
    if not bound(interval_manifest(intervals), identity.get("capture_sha256"),
                 identity.get("label_sha256"), digests["features"]):
        raise ValueError("Packet intervals are not bound to the recorded capture, labels and features")
    if label_digests(labels, day) != identity.get("label_sha256"):
        raise ValueError("Label CSVs changed after preparation")
    record["sealed"] = seal_block(record, digests)
    write_json(record_path, record)
    rows = summary["feature_rows"]
    return {"day": day, "capture": {"name": summary["source"], "bytes": summary["source_bytes"],
                                    "sha256": identity["capture_sha256"]},
            "feature_rows": rows, "matched_rows": summary["matched_rows"],
            "coverage": round(summary["matched_rows"] / rows, 6) if rows else 0,
            "feature_schema_version": summary["feature_schema_version"],
            "artifacts": {name: {"bytes": path.stat().st_size, "sha256": digests[name]}
                          for name, path in zip(ARTIFACTS, (features, intervals, joined))}}


def seal(directory, labels, reports, days=CAPTURE_DAYS):
    rows, failures = [], []
    for day in days:
        try:
            rows.append(seal_day(day, directory, labels))
            print(f"{day}: derived artifacts verified and sealed", flush=True)
        except Exception as error:
            failures.append({"day": day, "error": str(error)})
            print(f"{day}: SEAL FAILED: {error}", flush=True)
    status = {"schema_version": 1, "status": "failed" if failures else "complete",
              "generated_at": datetime.now(timezone.utc).isoformat(), "directory": str(directory),
              "feature_schema_version": FEATURE_SCHEMA_VERSION, "features": CONTEXT_FEATURES,
              "days": rows, "failures": failures,
              "totals": {"feature_rows": sum(row["feature_rows"] for row in rows),
                         "matched_rows": sum(row["matched_rows"] for row in rows),
                         "capture_bytes": sum(row["capture"]["bytes"] for row in rows),
                         "artifact_bytes": sum(item["bytes"] for row in rows
                                               for item in row["artifacts"].values())},
              "limitations": SEAL_NOTES}
    write_json(Path(reports) / "evaluation" / "sealed.json", status)
    return status


def prepare_day(day, capture, labels, directory, reports, fingerprint):
    directory, reports = Path(directory), Path(reports)
    directory.mkdir(parents=True, exist_ok=True)
    capture, stem = Path(capture) if capture else None, day.lower()
    features, intervals, joined, record = day_paths(directory, day)
    label_hashes = label_digests(labels, day)
    saved = json.loads(record.read_text()) if record.exists() else {}
    sealed = saved.get("sealed") or {}
    cached = {}

    def digest(name, path):
        if name not in cached:
            cached[name] = sha256(path)
        return cached[name]

    if capture is not None:
        capture_hash = sha256(capture)
        source_name, source_bytes = capture.name, capture.stat().st_size
    else:
        if not sealed:
            raise ValueError("No capture and no sealed derived record; "
                             "run --seal while the capture is present")
        if any(not path.exists() for path in (features, intervals, joined)):
            raise ValueError("Sealed record present but derived artifacts are missing")
        cached = {name: sha256(path) for name, path
                  in zip(ARTIFACTS, (features, intervals, joined))}
        if cached != sealed.get("sha256"):
            raise ValueError("Derived artifacts changed after sealing")
        capture_hash = sealed["capture_sha256"]
        source_name, source_bytes = sealed["capture_name"], sealed["capture_bytes"]
    identity = {"capture_sha256": capture_hash, "label_sha256": label_hashes,
                "pipeline_sha256": fingerprint}
    if (saved.get("identity") == identity and joined.exists()
            and saved.get("output_sha256") == digest("aligned", joined)):
        # Re-publish reports if the report directory was cleaned separately.
        write_json(reports / f"{stem}.json", saved["capture_report"])
        write_json(reports / "labels" / f"{stem}.json", saved["label_report"])
        return {**saved["summary"], "resumed": True, "capture_verified": capture is not None}
    old_identity = saved.get("identity", {})
    reusable_features = (features.exists() and old_identity.get("capture_sha256") == capture_hash
                        and all(old_identity.get("pipeline_sha256", {}).get(name) == fingerprint[name]
                                for name in FEATURE_FILES)
                        and saved.get("label_report", {}).get("features_sha256")
                            == digest("features", features))
    if reusable_features:
        print(f"{day}: reusing verified features; refreshing label evidence", flush=True)
        feature_report = saved["capture_report"]
    elif capture is None:
        raise ValueError("Feature replay inputs changed and the capture is unavailable; "
                         "restore the capture or revert the feature code")
    else:
        print(f"{day}: replaying complete capture", flush=True)
        feature_report = analyze(capture, features, directory / f"{stem}-capture.json")
        cached.pop("features", None)
    if not feature_report["complete"] or feature_report["sha256"] != capture_hash:
        raise ValueError("Capture changed during replay")
    manifest = interval_manifest(intervals) if intervals.exists() else None
    reused = manifest is not None and bound(manifest, capture_hash, label_hashes, None)
    if reused and manifest.get("features_sha256") != digest("features", features):
        rebind_intervals(intervals, intervals, digest("features", features))
        cached.pop("intervals", None)
    if not reused:
        legacy = ROOT / "ml/data" / f"{stem}-intervals.jsonl.gz"
        if (legacy.exists() and day != "Monday"
                and bound(interval_manifest(legacy), capture_hash, label_hashes, None)):
            rebind_intervals(legacy, intervals, digest("features", features))
            cached.pop("intervals", None)
            reused = True
    if not reused:
        if capture is None:
            raise ValueError("Packet intervals must be rebuilt and the capture is unavailable")
        align(capture, labels, features, day, intervals, directory / f"{stem}-alignment.json")
        cached.pop("intervals", None)
    evidence = join_labels(features, labels, joined, "America/Halifax", None,
                           profile="cicids2017", day=day, alignment=intervals)
    cached.pop("aligned", None)
    if not evidence["counts"].get("matched"):
        raise ValueError("No matched rows; capture/label preparation is not complete")
    summary = {"day": day, "source": source_name, "source_bytes": source_bytes,
               "sha256": capture_hash, "feature_rows": feature_report["counts"]["feature_rows"],
               "matched_rows": evidence["counts"].get("matched", 0),
               "distribution": evidence["distribution"],
               "replay_seconds": feature_report["elapsed_seconds"],
               "feature_schema_version": FEATURE_SCHEMA_VERSION}
    write_json(reports / f"{stem}.json", feature_report)
    write_json(reports / "labels" / f"{stem}.json", evidence)
    result = {"identity": identity, "output_sha256": digest("aligned", joined),
              "summary": summary, "capture_report": feature_report, "label_report": evidence}
    if sealed:
        result["sealed"] = seal_block(result, {name: digest(name, path) for name, path
                                               in zip(ARTIFACTS, (features, intervals, joined))})
    write_json(record, result)
    return {**summary, "resumed": False, "capture_verified": capture is not None}


def prepare(captures, labels, directory, reports, days=CAPTURE_DAYS, workers=2):
    if workers not in (1, 2):
        raise ValueError("Use 1 or 2 workers to bound packet-index memory")
    captures, directory = Path(captures), Path(directory)
    sources, provenance = {}, {}
    for day in days:
        matches = [p for p in captures.glob("*.pcap")
                   if p.name.lower().startswith(day.lower() + "-")] if captures.is_dir() else []
        if len(matches) > 1:
            raise ValueError(f"Expected at most one capture for {day}")
        if matches:
            sources[day], provenance[day] = str(matches[0]), "capture"
            continue
        record = directory / f"{day.lower()}-ready.json"
        if not (record.exists() and json.loads(record.read_text()).get("sealed")):
            raise ValueError(f"No capture for {day} and no sealed derived record under {directory}; "
                             "run --seal while the captures are present")
        sources[day], provenance[day] = None, "sealed"
    fingerprint = {name: sha256(ROOT / name) for name in PIPELINE_FILES}
    status_path = Path(reports) / "evaluation" / "preparation.json"
    status = {"schema_version": 2, "status": "running", "started_at": datetime.now(timezone.utc).isoformat(),
              "feature_schema_version": FEATURE_SCHEMA_VERSION, "features": CONTEXT_FEATURES,
              "days": list(days), "capture_provenance": provenance, "completed": [], "failures": [],
              "code_sha256": fingerprint}
    write_json(status_path, status)
    with ProcessPoolExecutor(max_workers=workers) as pool:
        pending = {pool.submit(prepare_day, day, path, str(labels), str(directory),
                               str(reports), fingerprint): day for day, path in sources.items()}
        for future in as_completed(pending):
            day = pending[future]
            try:
                status["completed"].append(future.result())
                print(f"{day}: preparation complete", flush=True)
            except Exception as error:
                status["failures"].append({"day": day, "error": str(error)})
                print(f"{day}: FAILED: {error}", flush=True)
            status["completed"].sort(key=lambda item: CAPTURE_DAYS.index(item["day"]))
            write_json(status_path, status)
    status.update(status="failed" if status["failures"] else "complete",
                  finished_at=datetime.now(timezone.utc).isoformat())
    write_json(status_path, status)
    return status


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--captures", default="pcap")
    parser.add_argument("--labels", default="label/TrafficLabelling ")
    parser.add_argument("--directory", default="ml/data/context-v2")
    parser.add_argument("--reports", default="ml/reports")
    parser.add_argument("--days", nargs="+", choices=CAPTURE_DAYS, default=list(CAPTURE_DAYS))
    parser.add_argument("--workers", type=int, choices=[1, 2], default=2)
    parser.add_argument("--seal", action="store_true",
                        help="Verify the derived artifacts and record their digests so later runs "
                             "resume without the captures")
    args = parser.parse_args()
    if args.seal:
        result = seal(args.directory, args.labels, args.reports, args.days)
    else:
        result = prepare(args.captures, args.labels, args.directory, args.reports,
                         args.days, args.workers)
    raise SystemExit(0 if result["status"] == "complete" else 1)
