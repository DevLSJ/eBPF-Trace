import csv
import gzip
import json

import numpy as np
import pandas as pd
import pytest

from ml.alignment import resolve_segment
from ml.artifacts import sha256
from ml.labels import REQUIRED, canonical, join_labels


def resolve(times, directions, duration, fwd, back, direction=1):
    times, directions = np.array(times), np.array(directions)
    prefix = np.concatenate(([0], np.cumsum(directions)))
    return resolve_segment(times, directions, prefix, 0, duration, fwd, back, direction)


def test_packet_signature_requires_unique_counts_duration_direction():
    assert resolve([10, 15, 20], [1, 0, 1], 10, 2, 1)[0] == (10, 20)
    assert resolve([10, 15, 20], [1, 0, 1], 10, 1, 2)[0] is None
    assert resolve([10, 15, 20], [1, 0, 1], 13, 2, 1)[0] is None
    assert resolve([10, 15, 20], [0, 1, 0], 10, 2, 1, 0)[0] == (10, 20)
    assert resolve([10, 15, 20, 100, 105, 110], [1, 0, 1, 1, 0, 1], 10, 2, 1)[1] == 'multiple_packet_segments'
    assert resolve([10], [1], 0, 1, 0)[0] == (10, 10)
    assert resolve([10, 10], [1, 1], 0, 1, 0)[0] is None
    assert resolve([60_000_000], [1], 0, 1, 0)[0] is None


def test_second_precision_signature_does_not_search_the_rest_of_the_minute():
    times, directions = np.array([500_000, 2_000_000]), np.array([1, 1])
    prefix = np.array([0, 1, 2])
    assert resolve_segment(times, directions, prefix, 0, 0, 1, 0, 1, 1_000_000)[0] == (500_000, 500_000)
    assert resolve_segment(times, directions, prefix, 0, 0, 1, 0, 1)[1] == 'multiple_packet_segments'


def test_alignment_provenance_and_unresolved_conflict_are_preserved(tmp_path):
    labels = tmp_path / 'labels.csv'
    with labels.open('w') as stream:
        writer = csv.writer(stream)
        writer.writerow(REQUIRED)
        writer.writerows([
            ['192.0.2.1', '192.0.2.2', 1, 2, 6, '1970-01-01 00:00:00', 1000000, 'BENIGN'],
            ['192.0.2.1', '192.0.2.2', 1, 2, 6, '1970-01-01 00:00:00', 1000000, 'PortScan'],
        ])
    features = tmp_path / 'features.csv'
    pd.DataFrame([dict(src_ip='192.0.2.2', dst_ip='192.0.2.1', src_port=2, dst_port=1, protocol=6,
                       timestamp=30, window_start=30, window_end=30, Label='UNLABELED')]).to_csv(features, index=False)
    manifest = dict(features_sha256=sha256(features), source_sha256={'labels.csv': sha256(labels)})
    key = canonical('192.0.2.1', '192.0.2.2', 1, 2, 6)
    entries = [dict(flow=key, start=0, end=1, label='BENIGN', uncertainty=60, method='signature_mismatch'),
               dict(flow=key, start=30, end=31, label='PortScan', uncertainty=0, method='unique_packet_signature')]
    alignment = tmp_path / 'intervals.gz'
    def write():
        with gzip.open(alignment, 'wt') as stream:
            stream.write(json.dumps({'manifest': manifest}) + '\n')
            for row in entries:
                stream.write(json.dumps(row) + '\n')
    write()
    output = tmp_path / 'result.csv'
    def join():
        return join_labels(features, labels, output, 'UTC', '%Y-%m-%d %H:%M:%S', alignment=alignment)
    assert join()['counts']['ambiguous'] == 1
    entries[0].update(start=0, end=1, uncertainty=0, method='unique_packet_signature')
    write()
    result = join()
    assert result['counts']['matched_packet_evidence'] == 1
    assert pd.read_csv(output).Label.tolist() == ['PortScan']
    entries.pop(0)
    write()
    with pytest.raises(ValueError, match='every valid label'):
        join()
    manifest['features_sha256'] = 'changed'
    write()
    with pytest.raises(ValueError, match='provenance'):
        join()
