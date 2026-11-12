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


def feature_frame(path, feature_names=FEATURE_NAMES):
    frame = pd.read_csv(path)
    frame.columns = frame.columns.str.strip()
    missing = set(feature_names) - set(frame.columns)
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
    numeric = frame[feature_names].apply(pd.to_numeric, errors="coerce")
    numeric = numeric.replace([np.inf, -np.inf], np.nan)
    valid = numeric.notna().all(axis=1) & (numeric >= 0).all(axis=1)
    valid &= numeric["syn_ratio"].between(0, 1) & numeric["port_entropy"].between(0, 16)
    labels = frame["Label"].astype("string").str.strip().str.upper()
    valid &= labels.notna() & ~labels.isin(["", "UNLABELED", "UNKNOWN", "AMBIGUOUS", "NAN"])
    frame[feature_names] = numeric
    frame["Label"] = labels
    return frame.loc[valid].copy()


def load_features(path):
    frame = feature_frame(path)
    return frame[FEATURE_NAMES].to_numpy(), (frame["Label"] != "BENIGN").to_numpy(dtype=bool)


def preprocess(source, output, allow_random_split=False, feature_names=FEATURE_NAMES):
    frame = feature_frame(source, feature_names)
    values = frame[feature_names].to_numpy()
    labels = (frame["Label"] != "BENIGN").to_numpy(dtype=bool)
    if len(frame) < 2:
        raise ValueError("No sufficient labeled features; UNLABELED/AMBIGUOUS rows are excluded")
    cut = None
    rounded_timestamps = 0
    if "timestamp" in frame and "flow_started_at" in frame:
        times = pd.to_numeric(frame["timestamp"], errors="raise").to_numpy()
        starts = pd.to_numeric(frame["flow_started_at"], errors="raise").to_numpy()
        # Nanosecond conversion can round epoch seconds by one ULP.
        rounded = (starts > times) & (starts - times <= 1e-6)
        rounded_timestamps = int(rounded.sum())
        starts = np.where(rounded, times, starts)
        if (not np.isfinite(times).all() or not np.isfinite(starts).all()
                or (starts > times).any()):
            raise ValueError("Invalid timestamps")
        cut = float(np.quantile(times, 0.7))
        train_mask = times < cut - 10
        # Purge source-window overlap and flows whose lifetime spans the boundary.
        test_mask = (times >= cut + 10) & (starts >= cut + 10)
        train_x, train_y = values[train_mask], labels[train_mask]
        test_x, test_y = values[test_mask], labels[test_mask]
        test_labels = frame.loc[test_mask, "Label"].to_numpy(dtype=str)
        policy = "purged_time_10s_new_flows"
    elif allow_random_split:
        train_x, test_x, train_y, test_y = train_test_split(
            values, labels, test_size=0.3, random_state=42, stratify=labels
        )
        test_labels = np.where(test_y, "ATTACK", "BENIGN")
        policy = "random_experiment_only"
    else:
        raise ValueError("Replay timestamps required; --allow-random-split is for experiments only")
    if len(np.unique(test_y)) != 2:
        raise ValueError("Held-out period must contain both benign and attack labels")
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
        label_names=test_labels,
    )
    summary = {
        "source": str(source),
        "rows": len(labels),
        "benign": int((~labels).sum()),
        "attacks": int(labels.sum()),
        "training_rows": len(benign),
        "held_out_rows": len(test_y),
        "features": feature_names,
        "held_out_distribution": {str(k): int(v) for k, v in zip(*np.unique(test_labels, return_counts=True))},
        "split_policy": policy,
        "cut_timestamp": cut,
        "purged_rows": len(values) - len(train_y) - len(test_y),
        "rounded_timestamp_rows": rounded_timestamps,
        "deployment_eligible": bool(policy == "purged_time_10s_new_flows"
                                    and "label_status" in frame
                                    and frame["label_status"].isin(["matched_time_5tuple", "matched_packet_evidence"]).all()),
    }
    (output / "preprocessing.json").write_text(json.dumps(summary, indent=2))
    return summary


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("source")
    parser.add_argument("--output", default="ml/models")
    parser.add_argument("--allow-random-split", action="store_true")
    args = parser.parse_args()
    print(json.dumps(preprocess(args.source, args.output, args.allow_random_split), indent=2))
