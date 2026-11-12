"""Memory-bounded context benchmark with isolated tuple/time partitions.

This measures within-capture generalization, not a new attack campaign.
Only calibration labels choose thresholds and the preferred candidate.
"""

import argparse
import hashlib
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import sklearn
from sklearn.ensemble import HistGradientBoostingClassifier, IsolationForest
from sklearn.metrics import precision_recall_curve
from threadpoolctl import threadpool_limits

from collector.feature_schema import CONTEXT_FEATURES, LEGACY_FEATURES, SOURCE_FEATURES
from ml.artifacts import sha256
from ml.pipeline import write_json
from ml.validate import classification_metrics

PROTOCOL = {
    "version": 1, "seed": 42, "block_seconds": 300, "purge_seconds": 30,
    "split_policy": "time_block_and_bidirectional_tuple_intersection",
    "partition_slots": {"train": [0, 1, 2, 3, 4, 5], "calibration": [6, 7], "test": [8, 9]},
    "training_cap_per_label": 30000, "training_cap_benign": 200000,
    "selection": "maximum calibration F1 at FPR <= 0.05; test never selects",
    "candidates": [
        {"id": "if_6", "model": "Isolation Forest", "features": LEGACY_FEATURES, "trees": 100, "max_samples": 256},
        {"id": "if_9", "model": "Isolation Forest", "features": SOURCE_FEATURES, "trees": 100, "max_samples": 256},
        {"id": "if_25", "model": "Isolation Forest", "features": CONTEXT_FEATURES, "trees": 100, "max_samples": 256},
        {"id": "if_25_large", "model": "Isolation Forest", "features": CONTEXT_FEATURES, "trees": 128, "max_samples": 1024},
        {"id": "hgb_25", "model": "HistGradientBoosting", "features": CONTEXT_FEATURES, "iterations": 120},
    ],
    "limitations": [
        "Partitions are interleaved time blocks, not prospective chronological deployment tests.",
        "Repeated attack campaigns may span partitions; independent capture/day validation is still required.",
        "Only conservative label matches, new flows and matching tuple/time partitions are evaluated.",
        "Flow labels describe windows, not proof that each individual packet is malicious.",
        "Thursday/Friday were inspected in earlier development; this is not an untouched final benchmark.",
    ],
}


def partitions(frame, protocol=PROTOCOL):
    """Stable directional normalization; tuple identity is NEVER a model feature."""
    left = (frame.src_ip < frame.dst_ip) | ((frame.src_ip == frame.dst_ip) & (frame.src_port <= frame.dst_port))
    tuples = pd.DataFrame({
        "a": np.where(left, frame.src_ip, frame.dst_ip),
        "b": np.where(left, frame.dst_ip, frame.src_ip),
        "ap": np.where(left, frame.src_port, frame.dst_port),
        "bp": np.where(left, frame.dst_port, frame.src_port),
        "protocol": frame.protocol.to_numpy(),
    })
    tuple_slots = pd.util.hash_pandas_object(tuples, index=False).to_numpy() % 10
    times = frame.timestamp.to_numpy(dtype=float)
    blocks = np.floor(times / protocol["block_seconds"]).astype(np.int64)
    block_slots = {int(block): int.from_bytes(hashlib.blake2b(
        f"{protocol['seed']}:{block}".encode(), digest_size=8).digest(), "little") % 10
        for block in np.unique(blocks)}
    slots = np.fromiter((block_slots[int(block)] for block in blocks), dtype=np.int8)
    def translate(values):
        return np.where(values < 6, 0, np.where(values < 8, 1, 2))
    split = translate(slots)
    starts = frame.flow_started_at.to_numpy(dtype=float)
    boundary = blocks * protocol["block_seconds"] + protocol["purge_seconds"]
    context_safe = (times >= boundary) & (starts >= boundary - 1e-6) & (starts <= times + 1e-6)
    agreement = split == translate(tuple_slots)
    return np.where(context_safe & agreement, split, -1), context_safe, agreement


class Reservoir:
    """Uniform per-class reservoir via vectorized random priorities."""

    def __init__(self, capacity, seed):
        self.capacity = capacity
        self.rng = np.random.default_rng(seed)
        self.x = np.empty((0, len(CONTEXT_FEATURES)), dtype=np.float32)
        self.keys = np.empty(0)
        self.seen = 0

    def add(self, values):
        self.seen += len(values)
        keys = self.rng.random(len(values))
        if len(self.keys) == self.capacity:
            keep = keys < self.keys.max()
            keys, values = keys[keep], values[keep]
        if not len(keys):
            return
        keys = np.concatenate((self.keys, keys))
        values = np.concatenate((self.x, values))
        indices = np.argpartition(keys, self.capacity - 1)[:self.capacity] if len(keys) > self.capacity else np.arange(len(keys))
        self.keys, self.x = keys[indices], values[indices]


def prepare_splits(sources, directory, protocol):
    reservoirs, counts, provenance, parts = {}, Counter(), [], {1: [], 2: []}
    matched_distribution = Counter()
    distributions = {"train": Counter(), "calibration": Counter(), "test": Counter()}
    for day_index, source in enumerate(sources):
        source = Path(source)
        evidence = json.loads(Path(str(source) + ".labels.json").read_text())
        if "counts" in evidence and not evidence["counts"].get("matched"):
            raise ValueError("A capture has no matched labels; repair preparation first")
        digest = sha256(source)
        if digest != evidence["output_sha256"]:
            raise ValueError("Labelled file does not match join evidence")
        provenance.append({"file": source.name, "sha256": digest, "day_index": day_index,
                           "capture_sha256": evidence.get("alignment", {}).get("capture_sha256")})
        print(f"Splitting {source.name}", flush=True)
        for chunk_index, frame in enumerate(pd.read_csv(source, chunksize=200000)):
            counts["input_rows"] += len(frame)
            frame = frame[frame.label_status.isin(["matched_packet_evidence", "matched_time_5tuple"])].copy()
            counts["matched_rows"] += len(frame)
            if frame.empty:
                continue
            if not frame.feature_schema_version.eq(2).all():
                raise ValueError("Context benchmark requires feature schema 2")
            values = frame[CONTEXT_FEATURES].to_numpy(dtype=np.float32)
            if not np.isfinite(values).all() or (values < 0).any():
                raise ValueError("Invalid context feature values")
            labels = frame.Label.str.strip().str.upper().to_numpy(dtype="U64")
            matched_distribution.update(labels)
            assignment, context_safe, agreement = partitions(frame, protocol)
            counts["context_or_lifetime_purged"] += int((~context_safe).sum())
            counts["tuple_partition_excluded"] += int((context_safe & ~agreement).sum())
            for split, name in enumerate(("train", "calibration", "test")):
                selected = assignment == split
                selected_labels, selected_values = labels[selected], values[selected]
                distributions[name].update(selected_labels)
                if split == 0:
                    for label in np.unique(selected_labels):
                        if label not in reservoirs:
                            cap = protocol["training_cap_benign"] if label == "BENIGN" else protocol["training_cap_per_label"]
                            reservoirs[label] = Reservoir(cap, protocol["seed"] + len(reservoirs))
                        reservoirs[label].add(selected_values[selected_labels == label])
                elif len(selected_values):
                    path = directory / f"{name}-{day_index}-{chunk_index}.npz"
                    np.savez(path, x=selected_values, labels=selected_labels,
                             reverse=frame.reverse_pkt_rate.to_numpy()[selected] > 0,
                             day=np.full(len(selected_values), day_index, dtype=np.int8))
                    parts[split].append(path)
    if "BENIGN" not in reservoirs or len(reservoirs) < 2:
        raise ValueError("Training partition needs benign and attack examples")
    for name in ("calibration", "test"):
        if not distributions[name]["BENIGN"] or len(distributions[name]) < 2:
            raise ValueError(f"{name} needs benign and attack examples; do not tune on test")
    x = np.concatenate([item.x for item in reservoirs.values()])
    labels = np.concatenate([np.full(len(item.x), label, dtype="U64") for label, item in reservoirs.items()])
    summary = {"counts": dict(counts), "distribution": {key: dict(value) for key, value in distributions.items()},
               "matched_distribution": dict(matched_distribution),
               "sampled_training": {key: len(value.x) for key, value in reservoirs.items()},
               "sources": provenance}
    write_json(directory / "split-manifest.json", summary)
    return x, labels, parts, summary


def calibrate(labels, scores, fpr_max=0.05):
    precision, recall, thresholds = precision_recall_curve(labels, scores)
    tp = recall[:-1] * labels.sum()
    fp = tp / np.maximum(precision[:-1], np.finfo(float).tiny) - tp
    fpr = np.maximum(0, fp) / (~labels).sum()
    f1 = 2 * precision[:-1] * recall[:-1] / np.maximum(precision[:-1] + recall[:-1], np.finfo(float).tiny)
    valid = np.flatnonzero(fpr <= fpr_max + 1e-12)
    if len(valid):
        # Thresholds are ascending; highest threshold breaks exact F1 ties.
        best_f1 = f1[valid].max()
        best = valid[np.flatnonzero(f1[valid] == best_f1)[-1]]
        threshold = float(thresholds[best])
    else:
        threshold = float(np.nextafter(scores.max(), np.inf))
    result = classification_metrics(labels, scores >= threshold)
    indices = np.unique(np.linspace(0, len(thresholds) - 1, min(40, len(thresholds))).astype(int))
    curve = [{"threshold": float(thresholds[i]), "precision": float(precision[i]),
              "recall": float(recall[i]), "f1": float(f1[i]), "fpr": float(fpr[i])} for i in indices]
    return threshold, result, curve


def score(model, values, indices):
    selected = values[:, indices]
    if isinstance(model, IsolationForest):
        return -model.decision_function(selected)
    return model.predict_proba(selected)[:, 1]


def evaluate_candidate(model, indices, parts, threshold):
    totals, groups, days, direction = Counter(), {}, {}, {}
    for path in parts:
        with np.load(path) as data:
            labels = data["labels"]
            actual = labels != "BENIGN"
            predicted = score(model, data["x"], indices) >= threshold
            totals.update({"tp": int((actual & predicted).sum()), "fn": int((actual & ~predicted).sum()),
                           "fp": int((~actual & predicted).sum()), "tn": int((~actual & ~predicted).sum())})
            for label in np.unique(labels):
                mask = labels == label
                entry = groups.setdefault(str(label), Counter())
                entry.update(rows=int(mask.sum()), detected=int(predicted[mask].sum()))
            for bucket, values in ((days, data["day"]), (direction, data["reverse"])):
                for value in np.unique(values):
                    mask = values == value
                    entry = bucket.setdefault(str(value), Counter())
                    entry.update(tp=int((actual & predicted & mask).sum()), fn=int((actual & ~predicted & mask).sum()),
                                 fp=int((~actual & predicted & mask).sum()), tn=int((~actual & ~predicted & mask).sum()))
    def metrics(count):
        tp, fp, fn, tn = (count[key] for key in ("tp", "fp", "fn", "tn"))
        precision = tp / (tp + fp) if tp + fp else 0
        recall = tp / (tp + fn) if tp + fn else 0
        f1 = 2 * tp / (2 * tp + fp + fn) if 2 * tp + fp + fn else 0
        fpr = fp / (fp + tn) if fp + tn else None
        return {**dict(count), "precision": precision, "recall": recall, "f1": f1, "fpr": fpr,
                "passed": f1 >= 0.8 and fpr is not None and fpr <= 0.05}
    return {**metrics(totals), "per_label": {label: {**dict(count), "detection_rate": count["detected"] / count["rows"]}
                                             for label, count in groups.items()},
            "per_day": {key: metrics(count) for key, count in days.items()},
            "reverse_observed": {key: metrics(count) for key, count in direction.items()}}


def benchmark(sources, directory, report_path, protocol=PROTOCOL):
    directory, report_path = Path(directory), Path(report_path)
    directory.mkdir(parents=True, exist_ok=True)
    protocol_path = directory / "protocol.json"
    if protocol_path.exists() and json.loads(protocol_path.read_text()) != protocol:
        raise ValueError("Protocol changed; use a new experiment directory")
    # Persist decisions BEFORE inspecting feature/label rows or fitting a model.
    write_json(protocol_path, protocol)
    x, labels, parts, summary = prepare_splits(sources, directory, protocol)
    candidates, fitted = [], []
    with threadpool_limits(limits=2):
        for specification in protocol["candidates"]:
            indices = [CONTEXT_FEATURES.index(key) for key in specification["features"]]
            print(f"Training {specification['id']} ({len(indices)} features)", flush=True)
            if specification["model"] == "Isolation Forest":
                model = IsolationForest(n_estimators=specification["trees"], max_samples=specification["max_samples"],
                                        contamination=0.05, random_state=protocol["seed"], n_jobs=2)
                model.fit(x[labels == "BENIGN"][:, indices])
            else:
                model = HistGradientBoostingClassifier(max_iter=specification["iterations"], max_leaf_nodes=31,
                    min_samples_leaf=30, l2_regularization=1, class_weight="balanced", early_stopping=False,
                    random_state=protocol["seed"])
                model.fit(x[:, indices], labels != "BENIGN")
            scores, truth = [], []
            for path in parts[1]:
                with np.load(path) as data:
                    scores.append(score(model, data["x"], indices))
                    truth.append(data["labels"] != "BENIGN")
            threshold, calibration, curve = calibrate(np.concatenate(truth), np.concatenate(scores))
            candidates.append({**specification, "threshold": threshold, "calibration": calibration,
                               "calibration_curve": curve, "score_direction": "higher_is_more_anomalous"})
            fitted.append((model, indices))
            joblib.dump({"model": model, "features": specification["features"], "threshold": threshold,
                         "deployment_approved": False}, directory / f"{specification['id']}.pkl")
        # Freeze model choice before reading any test labels or scores for evaluation.
        preferred = max(range(len(candidates)), key=lambda i: candidates[i]["calibration"]["f1"])
        write_json(directory / "selection.json", {"preferred_id": candidates[preferred]["id"],
                                                  "candidates": candidates, "protocol": protocol})
        for candidate, (model, indices) in zip(candidates, fitted):
            print(f"Testing frozen candidate {candidate['id']}", flush=True)
            candidate["performance"] = evaluate_candidate(model, indices, parts[2], candidate["threshold"])
    attacks = set(summary["matched_distribution"]) - {"BENIGN"}
    tested = set(summary["distribution"]["test"]) - {"BENIGN"}
    coverage = {"matched_attack_types": sorted(attacks), "tested_attack_types": sorted(tested),
                "missing_test_attack_types": sorted(attacks - tested)}
    report = {"schema_version": 2, "dataset": "CIC-IDS-2017 · Monday–Friday",
              "generated_at": datetime.now(timezone.utc).isoformat(), "status": "complete",
              "deployment_approved": False, "preferred_id": candidates[preferred]["id"],
              "selection_partition": "calibration", "feature_schema_version": 2,
              "features": CONTEXT_FEATURES, "protocol": protocol, "split": summary,
              "attack_coverage": coverage,
              "candidates": candidates, "targets": {"f1_min": 0.8, "fpr_max": 0.05},
              "limitations": protocol["limitations"], "protocol_sha256": sha256(protocol_path),
              "software": {"sklearn": sklearn.__version__, "numpy": np.__version__, "pandas": pd.__version__},
              "model_sha256": {candidate["id"]: sha256(directory / f"{candidate['id']}.pkl") for candidate in candidates}}
    write_json(report_path, report)
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("sources", nargs="+")
    parser.add_argument("--directory", default="ml/models/context-v2")
    parser.add_argument("--report", default="ml/reports/evaluation/context-v2.json")
    args = parser.parse_args()
    benchmark(args.sources, args.directory, args.report)
