import joblib
import numpy as np
import pytest
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

from backend.core.schemas import Thresholds
from ml.engine import FEATURE_NAMES, DetectionEngine
from ml.rule_engine import RuleEngine


def features(**overrides):
    return {
        "pkt_rate": 10,
        "byte_rate": 600,
        "syn_ratio": 0.1,
        "port_entropy": 0,
        "flow_duration": 1000,
        "avg_pkt_size": 60,
        "port_cnt": 1,
        **overrides,
    }


@pytest.mark.parametrize(
    "values,expected",
    [
        ({"pkt_rate": 999, "syn_ratio": 1}, None),
        ({"pkt_rate": 1000, "syn_ratio": 1}, "SYN_FLOOD"),
        ({"pkt_rate": 1250, "syn_ratio": 0.8}, "SYN_FLOOD"),
        ({"pkt_rate": 1250, "syn_ratio": 0.79}, None),
        ({"source_pkt_rate": 1200, "source_syn_rate": 1200}, "SYN_FLOOD"),
        ({"port_cnt": 20, "port_entropy": 4.32}, "PORT_SCAN"),
        ({"port_cnt": 19, "port_entropy": 4.25}, None),
        ({"pkt_rate": 10000, "syn_ratio": 0}, "TRAFFIC_SPIKE"),
        ({"byte_rate": 12500000}, "LARGE_FLOW"),
    ],
)
def test_rule_boundaries(values, expected):
    assert RuleEngine(Thresholds()).detect(features(**values)) == expected


def test_model_missing_and_rule_severity():
    engine = DetectionEngine("missing", "missing")
    assert engine.mode == "rules_only"
    assert engine.analyze(features())["severity"] is None
    assert engine.analyze(features(byte_rate=12500001))["severity"] == "medium"
    assert engine.analyze(features(pkt_rate=1000, syn_ratio=1))["anomaly_score"] is None


def test_real_model_score_range_and_boundary(tmp_path):
    data = np.random.default_rng(42).normal(size=(200, 6))
    scaler = StandardScaler().fit(data)
    model = IsolationForest(random_state=42).fit(scaler.transform(data))
    joblib.dump(model, tmp_path / "model.pkl")
    joblib.dump(scaler, tmp_path / "scaler.pkl")
    engine = DetectionEngine(str(tmp_path / "model.pkl"), str(tmp_path / "scaler.pkl"))
    for sample in (data[0], np.full(6, 1000)):
        values = dict(zip(FEATURE_NAMES, np.abs(sample)))
        result = engine.analyze(values)
        assert -1 <= result["anomaly_score"] <= 0
        expected = np.clip(
            model.decision_function(scaler.transform([np.abs(sample)]))[0] - 0.1, -1, 0
        )
        assert result["anomaly_score"] == pytest.approx(expected)
