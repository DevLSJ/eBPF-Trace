"""Deployment-owned HGB/IF bundles; shadow predictions never authorize a response."""

import hashlib
import json
import time
from pathlib import Path

import joblib
import numpy as np
import sklearn
from sklearn.ensemble import HistGradientBoostingClassifier, IsolationForest
from threadpoolctl import threadpool_limits

from collector.feature_schema import CONTEXT_FEATURES


class ShadowModel:
    def __init__(self, manifest_path=""):
        self.model = None
        self.manifest = {}
        self.status = "not_configured"
        if not manifest_path:
            return
        try:
            path = Path(manifest_path).resolve()
            manifest = json.loads(path.read_text())
            artifact = path.parent / manifest["artifact"]
            if artifact.resolve().parent != path.parent or artifact.suffix != ".pkl":
                raise ValueError("Artifact must be a local sibling .pkl")
            digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
            if digest != manifest["sha256"] or manifest["features"] != CONTEXT_FEATURES:
                raise ValueError("Artifact or feature contract mismatch")
            if (
                manifest["sklearn_version"] != sklearn.__version__
                or manifest["schema_version"] != 2
            ):
                raise ValueError("Runtime version mismatch")
            if not isinstance(manifest["threshold"], (float, int)) or not np.isfinite(
                manifest["threshold"]
            ):
                raise ValueError("Invalid threshold")
            if not manifest.get("id") or len(manifest["id"]) > 80:
                raise ValueError("Invalid model ID")
            # Only server-admin provisioned files; no HTTP upload/deserialization endpoint exists.
            model = joblib.load(artifact)
            if not isinstance(model, (HistGradientBoostingClassifier, IsolationForest)):
                raise ValueError("Unsupported estimator")
            if model.n_features_in_ != len(CONTEXT_FEATURES):
                raise ValueError("Feature count mismatch")
            self.model, self.manifest, self.status = model, manifest, "ready"
        except Exception:
            self.status = "invalid_artifact"

    def predict(self, features):
        started = time.perf_counter()
        if self.model is None:
            return {"status": self.status, "score": None, "predicted_attack": None, "latency_ms": 0}
        if features.get("feature_schema_version") != 2 or any(
            features.get(k) is None for k in CONTEXT_FEATURES
        ):
            return {
                "status": "incompatible_features",
                "score": None,
                "predicted_attack": None,
                "latency_ms": 0,
            }
        try:
            values = np.array([[features[k] for k in CONTEXT_FEATURES]], dtype=float)
            if not np.isfinite(values).all():
                raise ValueError("Non-finite observation")
            with threadpool_limits(limits=1):
                if isinstance(self.model, IsolationForest):
                    score = float(-self.model.decision_function(values)[0])
                else:
                    classes = self.model.classes_.tolist()
                    score = float(self.model.predict_proba(values)[0, classes.index(1)])
            if not np.isfinite(score):
                raise ValueError("Non-finite prediction")
            return {
                "status": "ok",
                "score": score,
                "predicted_attack": score >= self.manifest["threshold"],
                "latency_ms": (time.perf_counter() - started) * 1000,
            }
        except Exception:
            return {
                "status": "inference_failed",
                "score": None,
                "predicted_attack": None,
                "latency_ms": (time.perf_counter() - started) * 1000,
            }


def promotion_gates(manifest, statistics):
    validation = manifest.get("independent_validation", {})
    return [
        {
            "id": "schema",
            "label": "피처 스키마 2와 모델 해시",
            "passed": manifest.get("schema_version") == 2,
        },
        {
            "id": "independent",
            "label": "새 공격 실행·별도 환경 검증",
            "passed": validation.get("independent") is True,
        },
        {
            "id": "coverage",
            "label": "선언한 공격 유형의 시험 근거",
            "passed": bool(validation.get("attack_types"))
            and not validation.get("missing_attack_types", []),
        },
        {
            "id": "quality",
            "label": "독립 시험 F1 ≥ 0.80 · FPR ≤ 0.05",
            "passed": (validation.get("f1") or 0) >= 0.8
            and validation.get("fpr") is not None
            and validation["fpr"] <= 0.05,
        },
        {
            "id": "shadow",
            "label": "실시간 Shadow 7일·1,000개 관측",
            "passed": statistics.get("observed_days", 0) >= 7
            and statistics.get("successful", 0) >= 1000,
        },
        {
            "id": "features",
            "label": "누락·오류 비율 ≤ 1%",
            "passed": statistics.get("samples", 0) > 0
            and statistics.get("failure_rate", 1) <= 0.01,
        },
        {
            "id": "latency",
            "label": "p95 추론 지연 ≤ 100ms",
            "passed": statistics.get("p95_latency_ms") is not None
            and statistics["p95_latency_ms"] <= 100,
        },
        {
            "id": "review",
            "label": "운영 오탐 사건의 독립 검토",
            "passed": validation.get("operator_reviewed") is True,
        },
    ]
