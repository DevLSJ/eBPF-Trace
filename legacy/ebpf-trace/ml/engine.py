import logging
from pathlib import Path

import joblib
import numpy as np

from ml.rule_engine import RuleEngine

logger = logging.getLogger(__name__)
FEATURE_NAMES = [
    "pkt_rate",
    "byte_rate",
    "syn_ratio",
    "port_entropy",
    "flow_duration",
    "avg_pkt_size",
]


class DetectionEngine:
    def __init__(self, model_path: str = "", scaler_path: str = "", thresholds=None):
        self.rules = RuleEngine(thresholds)
        self.model = self.scaler = None
        if model_path and scaler_path:
            try:
                if not Path(model_path).is_file() or not Path(scaler_path).is_file():
                    raise FileNotFoundError("Model/scaler artifacts not available")
                # Only load deployment-owned artifacts, never uploaded pickle files.
                self.model, self.scaler = joblib.load(model_path), joblib.load(scaler_path)
                self.scaler.transform(np.zeros((1, 6)))
            except Exception:
                self.model = self.scaler = None
                logger.warning("ML artifacts unavailable; rule-based detection active")

    @property
    def mode(self):
        return "hybrid" if self.model is not None else "rules_only"

    def analyze(self, features: dict, use_ml: bool = True) -> dict:
        rule = self.rules.detect(features)
        score = None
        if use_ml and self.model is not None:
            try:
                values = np.array([[features[key] for key in FEATURE_NAMES]], dtype=float)
                # sklearn's decision boundary is 0; shift it to the API's -0.1.
                decision = self.model.decision_function(self.scaler.transform(values))[0]
                score = float(np.clip(decision - 0.1, -1, 0))
            except Exception:
                logger.exception("Inference failed; retaining rule result")
        severity = None
        if rule == "SYN_FLOOD":
            severity = "critical"
        elif rule == "PORT_SCAN":
            severity = "critical" if score is not None and score < -0.5 else "high"
        elif rule in {"TRAFFIC_SPIKE", "LARGE_FLOW"}:
            severity = "medium"
        if score is not None and score < self.rules.thresholds.anomaly_threshold:
            ml_severity = "high" if score < -0.5 else "medium" if score < -0.3 else "low"
            ranks = {None: 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
            if ranks[ml_severity] > ranks[severity]:
                severity = ml_severity
        return {"attack_type": rule or "ANOMALY", "severity": severity, "anomaly_score": score}
