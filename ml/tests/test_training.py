import numpy as np
import pandas as pd
import pytest

from ml.engine import FEATURE_NAMES
from ml.preprocess import load_features, preprocess
from ml.train_model import train_model
from ml.validate import validate


def test_training_uses_benign_only_and_held_out_evaluation(tmp_path):
    rng = np.random.default_rng(42)
    benign = np.abs(rng.normal(1, 0.1, (300, 6)))
    benign[:, 2] = 0.1
    attacks = np.abs(rng.normal(100, 5, (100, 6)))
    attacks[:, 2], attacks[:, 3] = 1, 6
    frame = pd.DataFrame(np.concatenate([benign, attacks]), columns=FEATURE_NAMES)
    frame["Label"] = ["BENIGN"] * 300 + ["SYN_FLOOD"] * 100
    path = tmp_path / "synthetic_fixture.csv"
    frame.to_csv(path, index=False)
    summary = preprocess(path, tmp_path, allow_random_split=True)
    assert summary["training_rows"] == 210
    assert summary["held_out_rows"] == 120
    train_model(tmp_path)
    metrics = validate(tmp_path)
    assert metrics["tp"] + metrics["fn"] == 30
    assert 0 <= metrics["fpr"] <= 1
    assert metrics["deployment_eligible"] is False


def test_incompatible_cic_features_fail_explicitly(tmp_path):
    path = tmp_path / "raw_cic.csv"
    pd.DataFrame({"Flow Bytes/s": [3], "Label": ["BENIGN"]}).to_csv(path, index=False)
    with pytest.raises(ValueError, match="Missing live-compatible features"):
        load_features(path)


def test_minute_resolution_evaluation_never_approves_runtime(tmp_path):
    import json

    from ml.artifacts import sha256
    from ml.evaluate_dataset import evaluate

    rng = np.random.default_rng(42)
    values = np.abs(rng.normal(1, 0.1, (600, 6)))
    values[:, 2] = 0.1
    values[1::2, :] = [100, 100, 1, 6, 100, 100]
    frame = pd.DataFrame(values, columns=FEATURE_NAMES)
    frame['timestamp'] = 1499385600 + np.arange(600, dtype=float)
    frame['flow_started_at'] = frame.timestamp
    frame.loc[0, 'flow_started_at'] += 0.0000002384185791015625
    frame['Label'] = ['BENIGN', 'DDoS'] * 300
    frame['label_status'] = 'matched_time_5tuple'
    source = tmp_path / 'labeled.csv.gz'
    frame.to_csv(source, index=False)
    evidence = {'output_sha256': sha256(source), 'timestamp_uncertainty_seconds': 60}
    (tmp_path / 'labeled.csv.gz.labels.json').write_text(json.dumps(evidence))
    result = evaluate([source], tmp_path / 'model', tmp_path / 'report.json')
    assert result['performance']['f1'] > 0.8
    assert result['deployment_approved'] is False
    assert result['performance']['deployment_eligible'] is False
    assert result['split']['rounded_timestamp_rows'] == 1
    version = json.loads((tmp_path / 'model' / 'model_version.json').read_text())
    assert version['validated'] is False
    evidence['output_sha256'] = 'changed'
    (tmp_path / 'labeled.csv.gz.labels.json').write_text(json.dumps(evidence))
    with pytest.raises(ValueError, match='join evidence'):
        evaluate([source], tmp_path / 'other', tmp_path / 'other.json')
