"""Preprocess six-feature exports without silently inventing unavailable CIC columns."""

import argparse
import json
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler

from ml.engine import FEATURE_NAMES


def load_features(path):
    frame = pd.read_csv(path)
    frame.columns = frame.columns.str.strip()
    missing = set(FEATURE_NAMES) - set(frame.columns)
    if missing:
        raise ValueError(
            "Missing live-compatible features: "
            + ", ".join(sorted(missing))
            + ". CIC flow-level CSVs do not directly provide one-second packet/SYN "
            "windows or ten-second source-port entropy. Replay PCAPs through the "
            "same feature extractor and join labels before training."
        )
    if "Label" not in frame:
        raise ValueError("A Label column is required (BENIGN or an attack label)")
    numeric = frame[FEATURE_NAMES].apply(pd.to_numeric, errors="coerce")
    numeric = numeric.replace([np.inf, -np.inf], np.nan)
    valid = numeric.notna().all(axis=1) & (numeric >= 0).all(axis=1)
    valid &= numeric["syn_ratio"].between(0, 1) & numeric["port_entropy"].between(0, 16)
    labels = frame.loc[valid, "Label"].astype(str).str.strip()
    return numeric.loc[valid].to_numpy(), (labels.str.upper() != "BENIGN").to_numpy()


def preprocess(source, output):
    values, labels = load_features(source)
    # Hold out both benign and attack examples before fitting the scaler/model.
    train_x, test_x, train_y, test_y = train_test_split(
        values, labels, test_size=0.3, random_state=42, stratify=labels
    )
    benign = train_x[~train_y]
    if len(benign) < 100:
        raise ValueError("At least 100 benign training rows are required")
    scaler = StandardScaler().fit(benign)
    output = Path(output)
    output.mkdir(parents=True, exist_ok=True)
    joblib.dump(scaler, output / "scaler.pkl")
    np.savez_compressed(
        output / "split.npz",
        train=scaler.transform(benign),
        test=scaler.transform(test_x),
        labels=test_y,
    )
    summary = {
        "source": str(source),
        "rows": len(labels),
        "benign": int((~labels).sum()),
        "attacks": int(labels.sum()),
        "training_rows": len(benign),
        "held_out_rows": len(test_y),
        "features": FEATURE_NAMES,
    }
    (output / "preprocessing.json").write_text(json.dumps(summary, indent=2))
    return summary


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("source")
    parser.add_argument("--output", default="ml/models")
    args = parser.parse_args()
    print(json.dumps(preprocess(args.source, args.output), indent=2))
