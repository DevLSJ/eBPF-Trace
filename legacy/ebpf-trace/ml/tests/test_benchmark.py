import copy
import json

import numpy as np
import pandas as pd
import pytest

from collector.feature_schema import CONTEXT_FEATURES
from ml.artifacts import sha256
from ml.benchmark import PROTOCOL, Reservoir, benchmark, calibrate, partitions


def test_tuple_direction_is_normalized_and_boundary_context_is_purged():
    frame = pd.DataFrame([dict(src_ip='192.0.2.1', dst_ip='192.0.2.2', src_port=5000,
                              dst_port=80, protocol=6, timestamp=t, flow_started_at=t)
                          for t in range(0, 12000, 60)])
    first, _, _ = partitions(frame)
    reverse = frame.copy()
    reverse[['src_ip', 'dst_ip']] = frame[['dst_ip', 'src_ip']].to_numpy()
    reverse[['src_port', 'dst_port']] = frame[['dst_port', 'src_port']].to_numpy()
    second, _, _ = partitions(reverse)
    np.testing.assert_array_equal(first, second)
    assert len(set(first[first >= 0])) == 1  # This tuple cannot cross partitions.
    assert (first[frame.timestamp % 300 == 0] == -1).all()
    frame['flow_started_at'] = 0
    assert (partitions(frame)[0] == -1).all()


def test_calibration_respects_fpr_and_can_reject_every_sample():
    truth = np.array([False, False, True, True])
    threshold, metrics, _ = calibrate(truth, np.array([.1, .2, .8, .9]))
    assert threshold == .8 and metrics['f1'] == 1 and metrics['fpr'] == 0
    threshold, metrics, _ = calibrate(truth, np.array([1., 1., 1., 1.]))
    assert threshold > 1 and metrics['fp'] == metrics['tp'] == 0


def test_reservoir_bounds_training_memory():
    reservoir = Reservoir(50, 42)
    for index in range(10):
        reservoir.add(np.full((100, len(CONTEXT_FEATURES)), index, dtype=np.float32))
    assert reservoir.seen == 1000 and len(reservoir.x) == 50
    assert len(np.unique(reservoir.x[:, 0])) > 1


def test_benchmark_fits_calibrates_then_reports_frozen_candidates(tmp_path):
    rng = np.random.default_rng(42)
    size = 2000
    values = rng.uniform(0.1, 0.3, (size, len(CONTEXT_FEATURES)))
    attacks = np.arange(size) % 2 == 1
    values[attacks, :2] += 100
    frame = pd.DataFrame(values, columns=CONTEXT_FEATURES)
    frame['Label'] = np.where(attacks, 'PortScan', 'BENIGN')
    frame['label_status'] = 'matched_packet_evidence'
    frame['feature_schema_version'] = 2
    frame['src_ip'], frame['dst_ip'] = '192.0.2.1', '192.0.2.2'
    frame['src_port'], frame['dst_port'], frame['protocol'] = np.arange(size) + 1000, 80, 6
    frame['timestamp'] = 1499200000 + np.arange(size) * 40
    frame['flow_started_at'] = frame.timestamp
    source = tmp_path / 'capture.csv.gz'
    frame.to_csv(source, index=False)
    evidence = tmp_path / 'capture.csv.gz.labels.json'
    evidence.write_text(json.dumps({'output_sha256': sha256(source)}))
    protocol = copy.deepcopy(PROTOCOL)
    protocol['training_cap_benign'] = 200
    protocol['training_cap_per_label'] = 100
    protocol['candidates'] = [protocol['candidates'][0], protocol['candidates'][-1]]
    protocol['candidates'][0]['trees'] = 10
    protocol['candidates'][1]['iterations'] = 10
    report = benchmark([source], tmp_path / 'model', tmp_path / 'report.json', protocol)
    assert report['deployment_approved'] is False
    assert report['selection_partition'] == 'calibration'
    assert len(report['candidates']) == 2
    assert report['attack_coverage'] == {'matched_attack_types': ['PORTSCAN'],
                                       'tested_attack_types': ['PORTSCAN'], 'missing_test_attack_types': []}
    assert report['split']['matched_distribution'] == {'BENIGN': 1000, 'PORTSCAN': 1000}
    assert report['split']['counts']['context_or_lifetime_purged'] > 0
    selection = json.loads((tmp_path / 'model/selection.json').read_text())
    assert all('performance' not in item for item in selection['candidates'])
    assert all(item['calibration']['fpr'] <= .05 for item in report['candidates'])
    evidence.write_text(json.dumps({'output_sha256': 'wrong'}))
    with pytest.raises(ValueError, match='join evidence'):
        benchmark([source], tmp_path / 'other', tmp_path / 'bad.json', protocol)
