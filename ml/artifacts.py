"""Metadata and integrity checks before deserializing deployment-owned artifacts."""

import hashlib
import json
from pathlib import Path

import sklearn


def sha256(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def verify_artifacts(model_path, scaler_path, features):
    model_path, scaler_path = Path(model_path), Path(scaler_path)
    version = json.loads((model_path.parent / "model_version.json").read_text())
    performance = version.get("performance") or {}
    if (version.get("validated") is not True or performance.get("passed") is not True
            or not 0.8 <= performance.get("f1", 0) <= 1
            or not 0 <= performance.get("fpr", 1) <= 0.05):
        raise ValueError("Model has not passed held-out validation")
    if not version.get("deployment_eligible") or version.get("features") != features:
        raise ValueError("Incompatible features or evaluation provenance")
    if len(features) > 6 and version.get("feature_schema_version") != 2:
        raise ValueError("Context models require explicit feature schema 2")
    if version.get("sklearn_version") != sklearn.__version__:
        raise ValueError("Training/runtime sklearn versions differ")
    if version.get("validation_threshold") != -0.1:
        raise ValueError("Incompatible score threshold")
    hashes = version.get("sha256", {})
    if hashes.get("model") != sha256(model_path) or hashes.get("scaler") != sha256(scaler_path):
        raise ValueError("Model/scaler artifact integrity mismatch")
    return version
