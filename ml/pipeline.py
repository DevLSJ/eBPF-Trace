"""Resumable, hash-verified full-week PCAP preparation. Never sends packets."""

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


def write_json(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(json.dumps(value, indent=2) + "\n")
    temporary.replace(path)


def prepare_day(day, capture, labels, directory, reports, fingerprint):
    capture, directory, reports = Path(capture), Path(directory), Path(reports)
    directory.mkdir(parents=True, exist_ok=True)
    stem = day.lower()
    features = directory / f"{stem}-features.csv.gz"
    intervals = directory / f"{stem}-intervals.jsonl.gz"
    joined = directory / f"{stem}-aligned.csv.gz"
    record = directory / f"{stem}-ready.json"
    label_hashes = {p.name: sha256(p) for p in Path(labels).rglob("*.csv")
                    if p.name.lower().startswith(stem + "-")}
    if not label_hashes:
        raise ValueError(f"No label CSV for {day}")
    capture_hash = sha256(capture)
    identity = {"capture_sha256": capture_hash, "label_sha256": label_hashes,
                "pipeline_sha256": fingerprint}
    saved = {}
    if record.exists():
        saved = json.loads(record.read_text())
        if (saved.get("identity") == identity and joined.exists()
                and saved.get("output_sha256") == sha256(joined)):
            # Re-publish reports if the report directory was cleaned separately.
            write_json(reports / f"{stem}.json", saved["capture_report"])
            write_json(reports / "labels" / f"{stem}.json", saved["label_report"])
            return {**saved["summary"], "resumed": True}
    feature_files = ["collector/features.py", "collector/feature_schema.py", "ml/replay.py",
                     "ml/pcap.py", "ml/rule_engine.py"]
    old_identity = saved.get("identity", {})
    reusable_features = (features.exists() and old_identity.get("capture_sha256") == capture_hash
                        and all(old_identity.get("pipeline_sha256", {}).get(name) == fingerprint[name]
                                for name in feature_files)
                        and saved.get("label_report", {}).get("features_sha256") == sha256(features))
    if reusable_features:
        print(f"{day}: reusing verified features; refreshing label evidence", flush=True)
        feature_report = saved["capture_report"]
    else:
        print(f"{day}: replaying complete capture", flush=True)
        feature_report = analyze(capture, features, directory / f"{stem}-capture.json")
    if not feature_report["complete"] or feature_report["sha256"] != capture_hash:
        raise ValueError("Capture changed during replay")
    legacy_intervals = ROOT / "ml/data" / f"{stem}-intervals.jsonl.gz"
    if not legacy_intervals.exists() and intervals.exists() and day != "Monday":
        legacy_intervals = intervals
    reused = False
    if legacy_intervals.exists() and day != "Monday":
        with gzip.open(legacy_intervals, "rt") as source:
            manifest = json.loads(next(source))["manifest"]
            if (manifest.get("capture_sha256") == capture_hash
                    and manifest.get("source_sha256") == label_hashes
                    and manifest.get("duration_tolerance_us") == 2):
                # Packet intervals depend on capture/labels, not the feature columns.
                # Explicitly bind a new copy to the new feature hash; retain its origin.
                manifest.update(features_sha256=sha256(features),
                                reused_from_intervals_sha256=sha256(legacy_intervals))
                interval_temporary = intervals.with_name(intervals.name + ".tmp")
                with gzip.open(interval_temporary, "wt") as output:
                    output.write(json.dumps({"manifest": manifest}) + "\n")
                    shutil.copyfileobj(source, output)
                reused = True
        if reused:
            interval_temporary.replace(intervals)
    if not reused:
        align(capture, labels, features, day, intervals, directory / f"{stem}-alignment.json")
    evidence = join_labels(features, labels, joined, "America/Halifax", None,
                           profile="cicids2017", day=day, alignment=intervals)
    if not evidence["counts"].get("matched"):
        raise ValueError("No matched rows; capture/label preparation is not complete")
    summary = {"day": day, "source": capture.name, "source_bytes": capture.stat().st_size,
               "sha256": capture_hash, "feature_rows": feature_report["counts"]["feature_rows"],
               "matched_rows": evidence["counts"].get("matched", 0),
               "distribution": evidence["distribution"],
               "replay_seconds": feature_report["elapsed_seconds"],
               "feature_schema_version": FEATURE_SCHEMA_VERSION}
    write_json(reports / f"{stem}.json", feature_report)
    write_json(reports / "labels" / f"{stem}.json", evidence)
    write_json(record, {"identity": identity, "output_sha256": sha256(joined),
                        "summary": summary, "capture_report": feature_report,
                        "label_report": evidence})
    return {**summary, "resumed": False}


def prepare(captures, labels, directory, reports, days=CAPTURE_DAYS, workers=2):
    if workers not in (1, 2):
        raise ValueError("Use 1 or 2 workers to bound packet-index memory")
    sources = {}
    for day in days:
        matches = [p for p in Path(captures).glob("*.pcap")
                   if p.name.lower().startswith(day.lower() + "-")]
        if len(matches) != 1:
            raise ValueError(f"Expected exactly one capture for {day}")
        sources[day] = matches[0]
    fingerprint = {name: sha256(ROOT / name) for name in PIPELINE_FILES}
    status_path = Path(reports) / "evaluation" / "preparation.json"
    status = {"schema_version": 2, "status": "running", "started_at": datetime.now(timezone.utc).isoformat(),
              "feature_schema_version": FEATURE_SCHEMA_VERSION, "features": CONTEXT_FEATURES,
              "days": list(days), "completed": [], "failures": [], "code_sha256": fingerprint}
    write_json(status_path, status)
    with ProcessPoolExecutor(max_workers=workers) as pool:
        pending = {pool.submit(prepare_day, day, str(path), str(labels), str(directory),
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
    args = parser.parse_args()
    result = prepare(args.captures, args.labels, args.directory, args.reports, args.days, args.workers)
    raise SystemExit(0 if result["status"] == "complete" else 1)
