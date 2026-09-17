"""Join flow labels conservatively by bidirectional 5-tuple and time coverage."""

import argparse
import csv
import gzip
import io
import json
import math
import sqlite3
import tempfile
import zipfile
from collections import Counter
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path
from zoneinfo import ZoneInfo

from ml.artifacts import sha256
from ml.cic_profile import belongs_to_capture
from ml.cic_profile import timestamp as cic_timestamp
from ml.replay import FLOW_FIELDS

REQUIRED = ["Source IP", "Destination IP", "Source Port", "Destination Port",
            "Protocol", "Timestamp", "Flow Duration", "Label"]
UNKNOWN = {"", "UNLABELED", "UNKNOWN", "AMBIGUOUS", "NAN"}


def csv_sources(path, encoding="utf-8-sig", day=None):
    path = Path(path)
    paths = sorted(path.rglob("*")) if path.is_dir() else [path]
    for source in paths:
        if source.suffix.lower() == ".csv" and (not day or belongs_to_capture(source.name, day)):
            with source.open(encoding=encoding, newline="") as stream:
                yield source.name, stream
        elif source.suffix.lower() == ".zip":
            with zipfile.ZipFile(source) as archive:
                for name in sorted(archive.namelist()):
                    if name.lower().endswith(".csv") and (not day or belongs_to_capture(name, day)):
                        with archive.open(name) as raw:
                            with io.TextIOWrapper(raw, encoding=encoding, newline="") as stream:
                                yield name, stream


def canonical(src, dst, sport, dport, protocol):
    ends = sorted([(str(src).strip(), int(sport)), (str(dst).strip(), int(dport))])
    return json.dumps([*ends, int(protocol)], separators=(",", ":"))


def join_labels(features, labels, output, timezone_name, timestamp_format, *, profile=None, day=None,
                alignment=None):
    if Path(output).resolve() in (Path(features).resolve(), Path(labels).resolve()):
        raise ValueError("Label output must be a new file")
    if profile and (profile != "cicids2017" or day not in ("Thursday", "Friday")):
        raise ValueError("CICIDS2017 profile requires --day Thursday or Friday")
    zone = ZoneInfo(timezone_name)
    counts, sources, distribution, raw_distribution = Counter(), [], Counter(), Counter()
    uncertainty = 60 if profile else 0
    label_path = Path(labels)
    source_paths = label_path.rglob("*") if label_path.is_dir() else [label_path]
    source_hashes = {
        path.name: sha256(path) for path in source_paths
        if path.suffix.lower() == ".zip" or (
            path.suffix.lower() == ".csv" and (not day or belongs_to_capture(path.name, day))
        )
    }
    evidence = None
    with tempfile.TemporaryDirectory(prefix="ebpf-labels-") as temporary:
        db = sqlite3.connect(str(Path(temporary) / "labels.sqlite"))
        try:
            db.execute("CREATE TABLE labels (flow TEXT, start REAL, end REAL, label TEXT, uncertainty REAL, method TEXT)")
            for name, stream in csv_sources(labels, "cp1252" if profile else "utf-8-sig", day):
                reader = csv.DictReader(stream)
                if reader.fieldnames is None:
                    raise ValueError(f"Empty label file: {name}")
                reader.fieldnames = [key.strip() for key in reader.fieldnames]
                if missing := set(REQUIRED) - set(reader.fieldnames):
                    raise ValueError(f"{name}: missing GeneratedLabelledFlows fields {sorted(missing)}")
                sources.append(name)
                for row in reader:
                    counts["label_rows"] += 1
                    if profile and all(not (row.get(k) or "").strip() for k in REQUIRED):
                        counts["empty_label_rows"] += 1
                        continue
                    try:
                        if profile:
                            start = cic_timestamp(row["Timestamp"])
                        else:
                            parsed = datetime.strptime(row["Timestamp"].strip(), timestamp_format)
                            start = (parsed if parsed.tzinfo else parsed.replace(tzinfo=zone)).timestamp()
                        duration = float(row["Flow Duration"]) / 1e6
                        label = row["Label"].strip()
                        if not math.isfinite(duration) or duration < 0 or label.upper() in UNKNOWN:
                            raise ValueError("invalid duration or ground-truth label")
                        key = canonical(*(row[field] for field in REQUIRED[:5]))
                    except (ValueError, TypeError, AttributeError) as error:
                        if not profile:
                            raise ValueError(f"{name}: {error}") from error
                        counts["invalid_label_rows"] += 1
                        continue
                    if not alignment:
                        db.execute("INSERT INTO labels VALUES (?, ?, ?, ?, ?, ?)",
                                   (key, start, start + duration, label, uncertainty, "time_5tuple"))
                    raw_distribution[label] += 1
            if not sources:
                raise ValueError("No label CSVs found")
            if alignment:
                aligned_distribution = Counter()
                with gzip.open(alignment, "rt") as stream:
                    evidence = json.loads(next(stream))["manifest"]
                    if (evidence["features_sha256"] != sha256(features)
                            or evidence["source_sha256"] != source_hashes):
                        raise ValueError("Alignment provenance does not match features / labels")
                    for line in stream:
                        item = json.loads(line)
                        db.execute("INSERT INTO labels VALUES (?, ?, ?, ?, ?, ?)", tuple(
                            item[k] for k in ("flow", "start", "end", "label", "uncertainty", "method")))
                        aligned_distribution[item["label"]] += 1
                if aligned_distribution != raw_distribution:
                    raise ValueError("Alignment must retain every valid label, including unresolved rows")
            db.execute("CREATE INDEX labels_flow_time ON labels(flow, start, end)")
            db.commit()

            @lru_cache(maxsize=32768)
            def intervals(key):
                return db.execute("SELECT start, end, label, uncertainty, method FROM labels WHERE flow=?", (key,)).fetchall()

            Path(output).parent.mkdir(parents=True, exist_ok=True)
            read = gzip.open if str(features).endswith(".gz") else open
            write = gzip.open if str(output).endswith(".gz") else open
            with read(features, "rt", newline="") as source, write(output, "wt", newline="") as dest:
                reader = csv.DictReader(source)
                needed = {*FLOW_FIELDS, "timestamp", "window_start", "window_end", "Label"}
                if not needed.issubset(reader.fieldnames or []):
                    raise ValueError("Expected replay feature CSV with tuple and window timestamps")
                fields = list(dict.fromkeys([*reader.fieldnames, "label_status"]))
                writer = csv.DictWriter(dest, fieldnames=fields)
                writer.writeheader()
                for row in reader:
                    key = canonical(*(row[field] for field in FLOW_FIELDS))
                    start, end = float(row["window_start"]), float(row["window_end"])
                    # Float seconds → integer nanoseconds → float seconds can
                    # invert a zero-width window by one ULP (~0.24 µs in 2017).
                    if 0 < start - end <= 1e-6:
                        start = end
                        row["window_start"] = end
                        counts["rounded_window_rows"] += 1
                    if not math.isfinite(start) or not math.isfinite(end) or start > end:
                        raise ValueError("Invalid feature window timestamps")
                    # Union of possible intervals detects conflicts. Intersection
                    # guarantees coverage for every possible sub-minute start.
                    matches = [(a, b, label, u, method) for a, b, label, u, method in intervals(key)
                               if a <= end + 1e-6 and b + u >= start - 1e-6]
                    labels_found = {match[2] for match in matches}
                    coverage = [method for a, b, _, u, method in matches
                                if a + u <= start + 1e-6 and b >= end - 1e-6]
                    covered = bool(coverage)
                    if len(labels_found) == 1 and covered:
                        row["Label"] = labels_found.pop()
                        row["label_status"] = ("matched_packet_evidence" if "unique_packet_signature" in coverage
                                               else "matched_time_5tuple")
                        counts[row["label_status"]] += 1
                        counts["matched"] += 1
                        distribution[row["Label"]] += 1
                    else:
                        row["Label"] = "AMBIGUOUS" if len(labels_found) > 1 else "UNLABELED"
                        row["label_status"] = row["Label"].lower()
                        counts[row["label_status"]] += 1
                        if matches and len(labels_found) == 1:
                            counts["uncertain_time_rows"] += 1
                    writer.writerow(row)
                    if sum(counts[k] for k in ("matched", "unlabeled", "ambiguous")) % 500000 == 0:
                        print(f"Labelled {sum(counts[k] for k in ('matched', 'unlabeled', 'ambiguous')):,} feature rows", flush=True)
        finally:
            db.close()
    summary = {
        "schema_version": 1, "generated_at": datetime.now(timezone.utc).isoformat(),
        "counts": dict(counts), "sources": sources,
        "timezone": "America/Halifax" if profile else timezone_name,
        "timestamp_format": "%d/%m/%Y %H:%M; working-hours 12h clock" if profile else timestamp_format,
        "timestamp_uncertainty_seconds": uncertainty,
        "profile": profile, "policy": "full window guaranteed coverage; bidirectional tuple",
        "distribution": dict(distribution), "source_distribution": dict(raw_distribution),
        "features_sha256": sha256(features), "output_sha256": sha256(output),
    }
    summary["source_sha256"] = source_hashes
    if evidence:
        summary["alignment"] = {**evidence, "intervals_sha256": sha256(alignment)}
        summary["policy"] = "unique packet signature; full window coverage; unresolved intervals retain uncertainty"
    Path(str(output) + ".labels.json").write_text(json.dumps(summary, indent=2) + "\n")
    return summary


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("features")
    parser.add_argument("labels")
    parser.add_argument("--output", required=True)
    parser.add_argument("--timezone")
    parser.add_argument("--timestamp-format")
    parser.add_argument("--profile", choices=["cicids2017"])
    parser.add_argument("--day", choices=["Thursday", "Friday"])
    parser.add_argument("--report", help="Also publish the small join report at this path")
    parser.add_argument("--alignment", help="Packet-aligned intervals with verified provenance")
    args = parser.parse_args()
    if not args.profile and (not args.timestamp_format or not args.timezone):
        parser.error("--timestamp-format and --timezone required without an explicit dataset profile")
    summary = join_labels(args.features, args.labels, args.output,
                          args.timezone or "America/Halifax", args.timestamp_format,
                          profile=args.profile, day=args.day, alignment=args.alignment)
    if args.report:
        Path(args.report).parent.mkdir(parents=True, exist_ok=True)
        Path(args.report).write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps(summary, indent=2))
