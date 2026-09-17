"""Recover sub-minute CIC flow intervals from unique packet-count/time evidence.

A match requires a unique contiguous bidirectional packet segment, the exact
forward/backward packet counts, forward first packet and duration within 2 µs.
Unresolved records retain their full 60-second uncertainty. Labels never guide
the choice of a packet segment. No payload or packet is transmitted or retained.
"""

import argparse
import csv
import gzip
import json
import math
import struct
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

import numpy as np

from ml.artifacts import sha256
from ml.cic_profile import timestamp
from ml.labels import REQUIRED, UNKNOWN, canonical, csv_sources
from ml.pcap import decode, packets

PACKET = struct.Struct('<qB')
DTYPE = np.dtype([('time', '<i8'), ('forward', 'u1')])


def orientation(src, dst, sport, dport):
    return int((str(src), int(sport)) <= (str(dst), int(dport)))


def resolve_segment(times, directions, prefix, base, duration, forward, backward, direction):
    total = forward + backward
    if total <= 0 or forward <= 0:
        return None, 'invalid_packet_counts'
    lo, hi = np.searchsorted(times, [base, base + 60_000_000])
    starts = np.arange(lo, min(hi, len(times) - total + 1))
    if not len(starts):
        return None, 'no_packet_segment'
    ends = starts + total - 1
    count = prefix[ends + 1] - prefix[starts]
    if direction == 0:
        count = total - count
    valid = ((directions[starts] == direction) & (count == forward)
             & (np.abs(times[ends] - times[starts] - duration) <= 2))
    starts = starts[valid]
    if len(starts) != 1:
        return None, 'multiple_packet_segments' if len(starts) else 'signature_mismatch'
    index = int(starts[0])
    return (int(times[index]), int(times[index + total - 1])), 'unique_packet_signature'


def align(capture, labels, features, day, output, report_path):
    capture, output, report_path = Path(capture), Path(output), Path(report_path)
    if output.resolve() in (capture.resolve(), Path(features).resolve(), Path(labels).resolve()):
        raise ValueError('Alignment output must not overwrite inputs')
    records, counts, sources = defaultdict(list), Counter(), []
    for name, stream in csv_sources(labels, 'cp1252', day):
        sources.append(name)
        reader = csv.DictReader(stream)
        reader.fieldnames = [field.strip() for field in reader.fieldnames or []]
        if not {*REQUIRED, 'Total Fwd Packets', 'Total Backward Packets'} <= set(reader.fieldnames):
            raise ValueError(f'Missing packet signature fields: {name}')
        for row in reader:
            counts['label_rows'] += 1
            if all(not (row.get(k) or '').strip() for k in REQUIRED):
                counts['empty_label_rows'] += 1
                continue
            try:
                duration = float(row['Flow Duration'])
                if not math.isfinite(duration) or duration < 0 or not duration.is_integer():
                    raise ValueError('Invalid duration')
                label = row['Label'].strip()
                if label.upper() in UNKNOWN:
                    raise ValueError('Unknown label')
                start = round(timestamp(row['Timestamp']) * 1e6)
                fwd, back = int(row['Total Fwd Packets']), int(row['Total Backward Packets'])
                if fwd < 1 or back < 0:
                    raise ValueError('Invalid packet count')
                key = canonical(*(row[field] for field in REQUIRED[:5]))
                direction = orientation(*(row[field] for field in REQUIRED[:4]))
                records[key].append((start, int(duration), fwd, back, direction, label))
            except (ValueError, TypeError, AttributeError):
                counts['invalid_label_rows'] += 1
    if not sources:
        raise ValueError('No label files for the requested day')
    print(f'{day}: indexed {sum(map(len, records.values())):,} labels / {len(records):,} tuples', flush=True)
    traces = {}
    with capture.open('rb') as stream:
        for packet in packets(stream):
            counts['capture_packets'] += 1
            decoded, _ = decode(packet)
            if decoded is not None:
                flow, _ = decoded
                key = canonical(*flow)
                if key in records:
                    trace = traces.setdefault(key, bytearray())
                    trace.extend(PACKET.pack(round(packet.timestamp * 1e6), orientation(*flow[:4])))
                    counts['indexed_packets'] += 1
            if counts['capture_packets'] % 2_000_000 == 0:
                print(f'{day}: read {counts["capture_packets"]:,} packets', flush=True)
    source_paths = list(Path(labels).rglob('*')) if Path(labels).is_dir() else [Path(labels)]
    manifest = {
        'schema_version': 1, 'policy': 'unique bidirectional packet counts + duration + minute + direction',
        'generated_at': datetime.now(timezone.utc).isoformat(), 'sources': sources,
        'capture_sha256': sha256(capture), 'features_sha256': sha256(features),
        'source_sha256': {p.name: sha256(p) for p in source_paths
                          if p.name in sources or p.suffix.lower() == '.zip'},
        'duration_tolerance_us': 2, 'timezone': 'America/Halifax',
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    resolved_labels, unresolved_labels = Counter(), Counter()
    with gzip.open(output, 'wt') as dest:
        dest.write(json.dumps({'manifest': manifest}) + '\n')
        for key, flows in records.items():
            array = np.frombuffer(traces.get(key, b''), dtype=DTYPE)
            if len(array) and np.any(np.diff(array['time']) < 0):
                array = np.sort(array, order='time', kind='stable')
            times, directions = array['time'], array['forward']
            prefix = np.concatenate(([0], np.cumsum(directions, dtype=np.int64)))
            for base, duration, fwd, back, direction, label in flows:
                interval, method = resolve_segment(times, directions, prefix, base, duration, fwd, back, direction)
                counts[method] += 1
                if interval:
                    start, end = interval
                    resolved_labels[label] += 1
                else:
                    start, end = base, base + duration
                    unresolved_labels[label] += 1
                dest.write(json.dumps({'flow': key, 'start': start / 1e6, 'end': end / 1e6,
                                       'label': label, 'uncertainty': 0 if interval else 60,
                                       'method': method}) + '\n')
    summary = {**manifest, 'counts': dict(counts), 'resolved_distribution': dict(resolved_labels),
               'unresolved_distribution': dict(unresolved_labels), 'intervals_sha256': sha256(output)}
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(summary, indent=2) + '\n')
    return summary


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('capture')
    parser.add_argument('labels')
    parser.add_argument('--features', required=True)
    parser.add_argument('--day', choices=['Thursday', 'Friday'], required=True)
    parser.add_argument('--output', required=True)
    parser.add_argument('--report', required=True)
    args = parser.parse_args()
    print(json.dumps(align(args.capture, args.labels, args.features, args.day, args.output, args.report), indent=2))
