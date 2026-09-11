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
    summary = preprocess(path, tmp_path)
    assert summary["training_rows"] == 210
    assert summary["held_out_rows"] == 120
    train_model(tmp_path)
    metrics = validate(tmp_path)
    assert metrics["tp"] + metrics["fn"] == 30
    assert 0 <= metrics["fpr"] <= 1


def test_incompatible_cic_features_fail_explicitly(tmp_path):
    path = tmp_path / "raw_cic.csv"
    pd.DataFrame({"Flow Bytes/s": [3], "Label": ["BENIGN"]}).to_csv(path, index=False)
    with pytest.raises(ValueError, match="Missing live-compatible features"):
        load_features(path)
