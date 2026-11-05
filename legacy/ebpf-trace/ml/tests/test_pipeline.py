import csv
import gzip
import json

import pytest

from ml.artifacts import sha256
from ml.cic_profile import timestamp as cic_timestamp
from ml.labels import REQUIRED, canonical
from ml.pipeline import PIPELINE_FILES, ROOT, prepare, prepare_day, seal, seal_day

DAY = 'Monday'
FLOW = ('192.0.2.1', '198.51.100.2', 1234, 80, 6)
START = cic_timestamp('03/07/2017 09:00:00')


def fingerprint():
    return {name: sha256(ROOT / name) for name in PIPELINE_FILES}


def build_day(tmp_path):
    """A prepared day whose capture is a stand-in file, so no PCAP parsing is needed."""
    captures, labels = tmp_path / 'pcap', tmp_path / 'labels'
    directory, reports = tmp_path / 'data', tmp_path / 'reports'
    for path in (captures, labels, directory):
        path.mkdir(parents=True)
    capture = captures / f'{DAY}-WorkingHours.pcap'
    capture.write_bytes(b'stand-in capture')
    label_csv = labels / f'{DAY}-WorkingHours.pcap_ISCX.csv'
    with label_csv.open('w', encoding='cp1252', newline='') as stream:
        writer = csv.writer(stream)
        writer.writerow(REQUIRED)
        writer.writerow([*FLOW, '03/07/2017 09:00:00', 1_000_000, 'BENIGN'])
    features = directory / f'{DAY.lower()}-features.csv.gz'
    with gzip.open(features, 'wt', newline='') as stream:
        writer = csv.writer(stream)
        writer.writerow(['src_ip', 'dst_ip', 'src_port', 'dst_port', 'protocol',
                         'timestamp', 'window_start', 'window_end', 'pkt_rate', 'Label'])
        writer.writerow([*FLOW, START + 1, START, START + 1, 12.0, 'UNLABELED'])
    intervals = directory / f'{DAY.lower()}-intervals.jsonl.gz'
    manifest = {'capture_sha256': sha256(capture), 'features_sha256': sha256(features),
                'source_sha256': {label_csv.name: sha256(label_csv)}, 'duration_tolerance_us': 2}
    with gzip.open(intervals, 'wt') as stream:
        stream.write(json.dumps({'manifest': manifest}) + '\n')
        stream.write(json.dumps({'flow': canonical(*FLOW), 'start': START, 'end': START + 1,
                                 'label': 'BENIGN', 'uncertainty': 0,
                                 'method': 'unique_packet_signature'}) + '\n')
    report = {'complete': True, 'sha256': sha256(capture), 'source': capture.name,
              'counts': {'feature_rows': 1}, 'elapsed_seconds': 0.5}
    (directory / f'{DAY.lower()}-ready.json').write_text(json.dumps({
        'identity': {'capture_sha256': sha256(capture),
                     'label_sha256': {label_csv.name: sha256(label_csv)},
                     'pipeline_sha256': fingerprint()},
        'capture_report': report, 'label_report': {'features_sha256': sha256(features)}}))
    return dict(captures=captures, capture=capture, labels=labels, directory=directory,
                reports=reports, features=features, intervals=intervals,
                record=directory / f'{DAY.lower()}-ready.json')


def run(paths, capture=True, code=None):
    return prepare_day(DAY, str(paths['capture']) if capture else None, str(paths['labels']),
                       str(paths['directory']), str(paths['reports']), code or fingerprint())


def test_preparation_then_sealing_records_derived_digests(tmp_path):
    paths = build_day(tmp_path)
    summary = run(paths)
    assert summary['matched_rows'] == 1 and summary['capture_verified'] is True
    sealed = seal_day(DAY, paths['directory'], paths['labels'])
    assert sealed['feature_rows'] == 1 and sealed['coverage'] == 1
    assert sealed['capture']['sha256'] == sha256(paths['capture'])
    block = json.loads(paths['record'].read_text())['sealed']
    assert block['sha256'] == {'features': sha256(paths['features']),
                               'intervals': sha256(paths['intervals']),
                               'aligned': sha256(paths['directory'] / f'{DAY.lower()}-aligned.csv.gz')}
    assert block['capture_name'] == paths['capture'].name


def test_sealed_day_resumes_and_relabels_without_the_capture(tmp_path):
    paths = build_day(tmp_path)
    run(paths)
    seal_day(DAY, paths['directory'], paths['labels'])
    paths['capture'].unlink()

    resumed = run(paths, capture=False)
    assert resumed['resumed'] is True and resumed['capture_verified'] is False
    assert resumed['source'] == f'{DAY}-WorkingHours.pcap'

    # A label-stage code change must still rebuild the join from the sealed features.
    changed = {**fingerprint(), 'ml/labels.py': 'changed'}
    rejoined = run(paths, capture=False, code=changed)
    assert rejoined['resumed'] is False and rejoined['matched_rows'] == 1
    record = json.loads(paths['record'].read_text())
    assert record['identity']['pipeline_sha256']['ml/labels.py'] == 'changed'
    assert record['sealed']['sha256']['aligned'] == record['output_sha256']


def test_capture_free_runs_refuse_unsealed_tampered_or_replayable_work(tmp_path):
    paths = build_day(tmp_path)
    run(paths)
    with pytest.raises(ValueError, match='run --seal'):
        run(paths, capture=False)

    seal_day(DAY, paths['directory'], paths['labels'])
    paths['capture'].unlink()
    with gzip.open(paths['features'], 'at', newline='') as stream:
        stream.write('\n')
    with pytest.raises(ValueError, match='changed after sealing'):
        run(paths, capture=False)

    fresh = build_day(tmp_path / 'replay')
    run(fresh)
    seal_day(DAY, fresh['directory'], fresh['labels'])
    fresh['capture'].unlink()
    replay = {**fingerprint(), 'ml/replay.py': 'changed'}
    with pytest.raises(ValueError, match='capture is unavailable'):
        run(fresh, capture=False, code=replay)


def test_sealing_rejects_artifacts_that_no_longer_match_their_record(tmp_path):
    paths = build_day(tmp_path)
    run(paths)
    with gzip.open(paths['features'], 'at', newline='') as stream:
        stream.write('\n')
    with pytest.raises(ValueError, match='Features changed after preparation'):
        seal_day(DAY, paths['directory'], paths['labels'])

    paths = build_day(tmp_path / 'second')
    run(paths)
    (paths['directory'] / f'{DAY.lower()}-intervals.jsonl.gz').unlink()
    with pytest.raises(ValueError, match='Missing derived artifacts'):
        seal_day(DAY, paths['directory'], paths['labels'])


def test_prepare_reports_capture_provenance_and_requires_a_seal(tmp_path):
    paths = build_day(tmp_path)
    run(paths)
    status = seal(paths['directory'], paths['labels'], paths['reports'], days=[DAY])
    assert status['status'] == 'complete'
    audit = json.loads((paths['reports'] / 'evaluation' / 'sealed.json').read_text())
    assert audit['totals']['matched_rows'] == 1 and audit['limitations']

    paths['capture'].unlink()
    result = prepare(paths['captures'], paths['labels'], paths['directory'], paths['reports'],
                     days=[DAY], workers=1)
    assert result['status'] == 'complete' and result['capture_provenance'] == {DAY: 'sealed'}
    assert result['completed'][0]['capture_verified'] is False

    record = paths['directory'] / f'{DAY.lower()}-ready.json'
    record.write_text(json.dumps({k: v for k, v in json.loads(record.read_text()).items()
                                  if k != 'sealed'}))
    with pytest.raises(ValueError, match='no sealed derived record'):
        prepare(paths['captures'], paths['labels'], paths['directory'], paths['reports'],
                days=[DAY], workers=1)
