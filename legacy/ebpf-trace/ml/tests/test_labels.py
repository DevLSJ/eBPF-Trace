import csv
import json
import zipfile

import numpy as np
import pandas as pd
import pytest

from ml.engine import FEATURE_NAMES
from ml.labels import REQUIRED, join_labels
from ml.preprocess import load_features, preprocess


def test_zip_labels_join_both_directions_and_reject_conflicts(tmp_path):
    labels = tmp_path / "labels.zip"
    header = ",".join(REQUIRED) + "\n"
    data = header + "192.0.2.1,192.0.2.2,5000,80,6,2017-07-07 00:00:00,10000000,BENIGN\n"
    data += "192.0.2.1,192.0.2.2,5000,80,6,2017-07-07 00:00:05,2000000,PortScan\n"
    with zipfile.ZipFile(labels, "w") as archive:
        archive.writestr("nested/Friday.csv", data)
    features = tmp_path / "features.csv"
    # UTC 2017-07-07; first sample reverses the CIC direction.
    start = 1499385600
    rows = [{"src_ip": "192.0.2.2", "dst_ip": "192.0.2.1", "src_port": 80,
             "dst_port": 5000, "protocol": 6, "timestamp": start + ts,
             "window_start": start + ts - 1, "window_end": start + ts, "Label": "UNLABELED"}
            for ts in (2, 6, 20)]
    pd.DataFrame(rows).to_csv(features, index=False)
    out = tmp_path / "joined.csv"
    summary = join_labels(features, labels, out, "UTC", "%Y-%m-%d %H:%M:%S")
    with out.open() as stream:
        result = list(csv.DictReader(stream))
    assert [row["Label"] for row in result] == ["BENIGN", "AMBIGUOUS", "UNLABELED"]
    assert summary["counts"] == {"label_rows": 2, "matched": 1, "ambiguous": 1, "unlabeled": 1}


def test_unknown_labels_are_never_attacks(tmp_path):
    frame = pd.DataFrame(np.ones((5, 6)), columns=FEATURE_NAMES)
    frame["Label"] = ["BENIGN", None, "UNLABELED", "AMBIGUOUS", "PortScan"]
    path = tmp_path / "features.csv"
    frame.to_csv(path, index=False)
    _, labels = load_features(path)
    assert labels.tolist() == [False, True]
    with pytest.raises(ValueError, match="timestamps required"):
        preprocess(path, tmp_path)


def test_temporal_split_purges_source_overlap_and_long_lived_flows(tmp_path):
    frame = pd.DataFrame(np.ones((500, 6)), columns=FEATURE_NAMES)
    frame["timestamp"] = np.arange(500, dtype=float)
    frame["flow_started_at"] = frame.timestamp
    frame.loc[450:459, "flow_started_at"] = 1
    frame["Label"] = ["BENIGN" if i % 2 == 0 else "PortScan" for i in range(500)]
    frame["label_status"] = "matched_time_5tuple"
    path = tmp_path / "features.csv"
    frame.to_csv(path, index=False)
    result = preprocess(path, tmp_path)
    assert result["deployment_eligible"] is True
    assert result["purged_rows"] == 30
    assert result["training_rows"] == 170
    assert result["held_out_rows"] == 130
    assert json.loads((tmp_path / "preprocessing.json").read_text())["split_policy"] == "purged_time_10s_new_flows"
