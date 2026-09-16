"""Join GeneratedLabelledFlows CSV/ZIP records by bidirectional 5-tuple and time.

The timestamp format and timezone are mandatory: day/month and AM/PM ambiguity
must be resolved from the supplied dataset, not from guessed attack schedules.
"""

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
from datetime import datetime
from pathlib import Path
from zoneinfo import ZoneInfo

from ml.replay import FLOW_FIELDS

REQUIRED = ["Source IP", "Destination IP", "Source Port", "Destination Port",
            "Protocol", "Timestamp", "Flow Duration", "Label"]
UNKNOWN = {"", "UNLABELED", "UNKNOWN", "AMBIGUOUS", "NAN"}


def csv_sources(path):
    path = Path(path)
    paths = sorted(path.rglob("*")) if path.is_dir() else [path]
    for source in paths:
        if source.suffix.lower() == ".csv":
            with source.open(encoding="utf-8-sig", newline="") as stream:
                yield source.name, stream
        elif source.suffix.lower() == ".zip":
            with zipfile.ZipFile(source) as archive:
                for name in sorted(archive.namelist()):
                    if name.lower().endswith(".csv"):
                        with archive.open(name) as raw:
                            with io.TextIOWrapper(raw, encoding="utf-8-sig", newline="") as stream:
                                yield name, stream


def canonical(src, dst, sport, dport, protocol):
    ends = sorted([(str(src).strip(), int(sport)), (str(dst).strip(), int(dport))])
    return json.dumps([*ends, int(protocol)], separators=(",", ":"))


def join_labels(features, labels, output, timezone_name, timestamp_format):
    if Path(output).resolve() in (Path(features).resolve(), Path(labels).resolve()):
        raise ValueError("Label output must be a new file")
    zone = ZoneInfo(timezone_name)
    counts, sources = Counter(), []
    with tempfile.TemporaryDirectory(prefix="ebpf-labels-") as temporary:
        db = sqlite3.connect(str(Path(temporary) / "labels.sqlite"))
        try:
            db.execute("CREATE TABLE labels (flow TEXT, start REAL, end REAL, label TEXT)")
            for name, stream in csv_sources(labels):
                reader = csv.DictReader(stream)
                if reader.fieldnames is None:
                    raise ValueError(f"Empty label file: {name}")
                reader.fieldnames = [key.strip() for key in reader.fieldnames]
                if missing := set(REQUIRED) - set(reader.fieldnames):
                    raise ValueError(f"{name}: missing GeneratedLabelledFlows fields {sorted(missing)}")
                sources.append(name)
                for row in reader:
                    start = datetime.strptime(row["Timestamp"].strip(), timestamp_format)
                    if start.tzinfo is None:
                        start = start.replace(tzinfo=zone)
                    start = start.timestamp()
                    duration = float(row["Flow Duration"]) / 1e6
                    label = row["Label"].strip()
                    if not math.isfinite(duration) or duration < 0 or label.upper() in UNKNOWN:
                        raise ValueError(f"{name}: invalid duration or ground-truth label")
                    key = canonical(*(row[field] for field in REQUIRED[:5]))
                    db.execute("INSERT INTO labels VALUES (?, ?, ?, ?)",
                               (key, start, start + duration, label))
                    counts["label_rows"] += 1
            if not sources:
                raise ValueError("No label CSVs found")
            db.execute("CREATE INDEX labels_flow_time ON labels(flow, start, end)")
            db.commit()
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
                    if not math.isfinite(start) or not math.isfinite(end) or start > end:
                        raise ValueError("Invalid feature window timestamps")
                    matches = db.execute(
                        "SELECT start, end, label FROM labels WHERE flow=? AND start<=? AND end>=?",
                        (key, end, start),
                    ).fetchall()
                    labels_found = {match[2] for match in matches}
                    covered = any(a <= start and b >= end for a, b, _ in matches)
                    if len(labels_found) == 1 and covered:
                        row["Label"], row["label_status"] = labels_found.pop(), "matched_time_5tuple"
                        counts["matched"] += 1
                    else:
                        row["Label"] = "AMBIGUOUS" if len(labels_found) > 1 else "UNLABELED"
                        row["label_status"] = row["Label"].lower()
                        counts[row["label_status"]] += 1
                    writer.writerow(row)
        finally:
            db.close()
    summary = {"counts": dict(counts), "sources": sources, "timezone": timezone_name,
               "timestamp_format": timestamp_format, "policy": "full window coverage; bidirectional tuple"}
    Path(str(output) + ".labels.json").write_text(json.dumps(summary, indent=2) + "\n")
    return summary


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("features")
    parser.add_argument("labels")
    parser.add_argument("--output", required=True)
    parser.add_argument("--timezone", required=True)
    parser.add_argument("--timestamp-format", required=True)
    args = parser.parse_args()
    print(json.dumps(join_labels(args.features, args.labels, args.output,
                                 args.timezone, args.timestamp_format), indent=2))
