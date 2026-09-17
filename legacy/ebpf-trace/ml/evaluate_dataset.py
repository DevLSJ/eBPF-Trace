"""Reproducible evaluation of supplied, conservatively joined CIC label exports.

Only matched rows enter the temporal split. Minute-resolution label selection
biases the sample toward long flows, so this experiment cannot approve deployment.
"""

import argparse
import csv
import gzip
import json
from datetime import datetime, timezone
from pathlib import Path

from ml.artifacts import sha256
from ml.preprocess import preprocess
from ml.train_model import train_model
from ml.validate import validate


def evaluate(sources, directory, report_path):
    directory, report_path = Path(directory), Path(report_path)
    directory.mkdir(parents=True, exist_ok=True)
    merged = directory / "matched.csv.gz"
    provenance = []
    with gzip.open(merged, "wt", newline="") as output:
        writer = None
        for source in sources:
            source = Path(source)
            evidence = json.loads(Path(str(source) + ".labels.json").read_text())
            if evidence["output_sha256"] != sha256(source):
                raise ValueError("Labelled source does not match its join evidence")
            provenance.append({"file": source.name, "sha256": evidence["output_sha256"],
                               "timestamp_uncertainty_seconds": evidence["timestamp_uncertainty_seconds"]})
            with gzip.open(source, "rt", newline="") as stream:
                reader = csv.DictReader(stream)
                if writer is None:
                    writer = csv.DictWriter(output, fieldnames=reader.fieldnames)
                    writer.writeheader()
                for row in reader:
                    if row["label_status"] == "matched_time_5tuple":
                        writer.writerow(row)
    preparation = preprocess(merged, directory)
    version = train_model(directory)
    biased_sample = any(item["timestamp_uncertainty_seconds"] for item in provenance)
    version["deployment_eligible"] &= not biased_sample
    version["evaluation_scope"] = "conservatively matched feature windows only"
    version["sources"] = provenance
    (directory / "model_version.json").write_text(json.dumps(version, indent=2) + "\n")
    performance = validate(directory)
    report = {
        "schema_version": 1,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "dataset": "CIC-IDS-2017 · Thursday + Friday",
        "status": "passed" if performance["passed"] else "below_target",
        "deployment_approved": performance["passed"] and performance["deployment_eligible"],
        "scope": "conservatively matched feature windows only",
        "sources": provenance,
        "model": "Isolation Forest", "n_estimators": version["n_estimators"],
        "contamination": version["contamination"], "threshold": version["validation_threshold"],
        "features": version["features"], "performance": performance,
        "split": {key: value for key, value in preparation.items() if key not in ("source", "features", "deployment_eligible")},
        "targets": {"f1_min": 0.8, "fpr_max": 0.05},
        "limitations": [
            "Minute-resolution timestamps exclude short or uncertain flows; this subset is biased toward long flows.",
            "Scores describe matched held-out feature windows, not all attacks or the full CICIDS2017 benchmark.",
            "This evaluation does not approve deployment; live detection remains independent.",
        ],
    }
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(report, indent=2) + "\n")
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("sources", nargs="+")
    parser.add_argument("--directory", default="ml/models/cic2017-experiment")
    parser.add_argument("--report", default="ml/reports/evaluation/combined.json")
    args = parser.parse_args()
    print(json.dumps(evaluate(args.sources, args.directory, args.report), indent=2))
