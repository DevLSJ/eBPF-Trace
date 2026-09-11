import argparse
import json
from pathlib import Path

import joblib
import numpy as np
from sklearn.metrics import confusion_matrix, precision_recall_fscore_support


def validate(directory):
    directory = Path(directory)
    data = np.load(directory / "split.npz")
    predicted = joblib.load(directory / "isolation_forest.pkl").decision_function(data["test"]) < 0
    precision, recall, f1, _ = precision_recall_fscore_support(
        data["labels"], predicted, average="binary", zero_division=0
    )
    tn, fp, fn, tp = confusion_matrix(data["labels"], predicted, labels=[False, True]).ravel()
    fpr = fp / (fp + tn) if fp + tn else 1.0
    result = {
        "precision": float(precision),
        "recall": float(recall),
        "f1": float(f1),
        "fpr": float(fpr),
        "tn": int(tn),
        "fp": int(fp),
        "fn": int(fn),
        "tp": int(tp),
        "passed": bool(f1 >= 0.8 and fpr <= 0.05),
    }
    version_path = directory / "model_version.json"
    version = json.loads(version_path.read_text())
    version.update(performance=result, validated=result["passed"])
    version_path.write_text(json.dumps(version, indent=2))
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--directory", default="ml/models")
    args = parser.parse_args()
    result = validate(args.directory)
    print(json.dumps(result, indent=2))
    raise SystemExit(0 if result["passed"] else 1)
