"""Serve versioned offline evidence without mixing it with live detector state."""

import json
from copy import deepcopy
from functools import lru_cache
from pathlib import Path

REPORT_DIRECTORY = Path(__file__).resolve().parents[2] / "ml" / "reports"


@lru_cache(maxsize=32)
def _read_version(path, modified_ns, size):
    return json.loads(Path(path).read_text())


def read_report(path):
    if not path.exists():
        return None
    stat = path.stat()
    # Callers attach presentation fields; never mutate a cached report.
    return deepcopy(_read_version(str(path.resolve()), stat.st_mtime_ns, stat.st_size))


def capture_reports():
    reports = []
    for path in sorted(REPORT_DIRECTORY.glob("*.json")):
        report = read_report(path)
        if "traffic_minutes" not in report or "source" not in report:
            continue
        label_path = REPORT_DIRECTORY / "labels" / path.name
        report["labels"] = None
        if label_path.exists():
            labels = read_report(label_path)
            counts = labels["counts"]
            total = sum(counts.get(key, 0) for key in ("matched", "unlabeled", "ambiguous"))
            if total != report["counts"]["feature_rows"]:
                raise ValueError(f"Label/capture row count mismatch: {path.name}")
            if labels.get("alignment", {}).get("capture_sha256", report.get("sha256")) != report.get("sha256"):
                raise ValueError(f"Alignment/capture hash mismatch: {path.name}")
            labels["coverage"] = counts.get("matched", 0) / total if total else 0
            report["labels"] = labels
            report["label_status"] = "joined_conservative"
            report["limitations"] = [
                item for item in report.get("limitations", [])
                if not item.startswith("No label CSV supplied")
            ] + ["Labels cover only conservative matches; model metrics are reported separately."]
        reports.append(report)
    return reports


def model_evaluation(name="combined"):
    if name not in ("combined", "context-v2", "preparation"):
        raise ValueError("Unknown evaluation report")
    return read_report(REPORT_DIRECTORY / "evaluation" / f"{name}.json")
