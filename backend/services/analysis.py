"""Serve versioned offline evidence without mixing it with live detector state."""

import json
from pathlib import Path

REPORT_DIRECTORY = Path(__file__).resolve().parents[2] / "ml" / "reports"


def capture_reports():
    reports = []
    for path in sorted(REPORT_DIRECTORY.glob("*.json")):
        report = json.loads(path.read_text())
        if "traffic_minutes" not in report or "source" not in report:
            continue
        label_path = REPORT_DIRECTORY / "labels" / path.name
        report["labels"] = None
        if label_path.exists():
            labels = json.loads(label_path.read_text())
            counts = labels["counts"]
            total = sum(counts.get(key, 0) for key in ("matched", "unlabeled", "ambiguous"))
            if total != report["counts"]["feature_rows"]:
                raise ValueError(f"Label/capture row count mismatch: {path.name}")
            labels["coverage"] = counts.get("matched", 0) / total if total else 0
            report["labels"] = labels
            report["label_status"] = "joined_conservative"
            report["limitations"] = [
                item for item in report.get("limitations", [])
                if not item.startswith("No label CSV supplied")
            ] + ["Labels cover only conservative matches; model metrics are reported separately."]
        reports.append(report)
    return reports


def model_evaluation():
    path = REPORT_DIRECTORY / "evaluation" / "combined.json"
    return json.loads(path.read_text()) if path.exists() else None
