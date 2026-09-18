import hashlib
import json

import joblib
import numpy as np
import sklearn
from sklearn.ensemble import HistGradientBoostingClassifier

from collector.feature_schema import CONTEXT_FEATURES
from ml.shadow import ShadowModel, promotion_gates


def make_bundle(tmp_path):
    x = np.random.default_rng(42).random((100, 25))
    model = HistGradientBoostingClassifier(max_iter=3, min_samples_leaf=5).fit(x, x[:, 0] > 0.5)
    artifact = tmp_path / "model.pkl"
    joblib.dump(model, artifact)
    manifest = {
        "id": "fixture-v1",
        "artifact": artifact.name,
        "sha256": hashlib.sha256(artifact.read_bytes()).hexdigest(),
        "features": CONTEXT_FEATURES,
        "schema_version": 2,
        "sklearn_version": sklearn.__version__,
        "threshold": 0.5,
        "independent_validation": {"independent": False, "f1": None, "fpr": None},
    }
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps(manifest))
    return path


def test_shadow_artifact_contract_and_missing_features(tmp_path):
    path = make_bundle(tmp_path)
    model = ShadowModel(str(path))
    assert model.status == "ready"
    good = model.predict({"feature_schema_version": 2, **dict.fromkeys(CONTEXT_FEATURES, 0.2)})
    assert good["status"] == "ok" and 0 <= good["score"] <= 1
    assert model.predict({"feature_schema_version": 1})["status"] == "incompatible_features"
    assert (
        model.predict(
            {"feature_schema_version": 2, **dict.fromkeys(CONTEXT_FEATURES, float("nan"))}
        )["status"]
        == "inference_failed"
    )
    artifact = tmp_path / "model.pkl"
    artifact.write_bytes(artifact.read_bytes() + b"tampered")
    assert ShadowModel(str(path)).status == "invalid_artifact"


def test_development_metrics_cannot_pass_production_gates(tmp_path):
    model = ShadowModel(str(make_bundle(tmp_path)))
    gates = promotion_gates(
        model.manifest,
        {
            "samples": 1000,
            "successful": 1000,
            "observed_days": 7,
            "failure_rate": 0,
            "p95_latency_ms": 3,
        },
    )
    assert not all(g["passed"] for g in gates)
    assert not next(g for g in gates if g["id"] == "independent")["passed"]
    assert not next(g for g in gates if g["id"] == "quality")["passed"]
