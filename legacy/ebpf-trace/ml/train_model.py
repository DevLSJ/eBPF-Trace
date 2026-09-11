import argparse
import json
import os
from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy as np
import sklearn
from sklearn.ensemble import IsolationForest

from ml.engine import FEATURE_NAMES


def train_model(directory, contamination=0.05):
    directory = Path(directory)
    data = np.load(directory / "split.npz")
    model = IsolationForest(n_estimators=100, contamination=contamination, random_state=42)
    model.fit(data["train"])
    joblib.dump(model, directory / "isolation_forest.pkl")
    version = {
        "trained_at": datetime.now(timezone.utc).isoformat(),
        "sklearn_version": sklearn.__version__,
        "features": FEATURE_NAMES,
        "n_estimators": 100,
        "contamination": contamination,
        "training_rows": len(data["train"]),
        "score_definition": "clip(decision_function - 0.1, -1, 0)",
        "performance": None,
        "validated": False,
    }
    (directory / "model_version.json").write_text(json.dumps(version, indent=2))
    return version


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--directory", default="ml/models")
    parser.add_argument(
        "--contamination", type=float, default=float(os.getenv("IF_CONTAMINATION", ".05"))
    )
    args = parser.parse_args()
    print(json.dumps(train_model(args.directory, args.contamination), indent=2))
