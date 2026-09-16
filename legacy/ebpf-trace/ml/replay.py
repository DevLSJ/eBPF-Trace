"""Offline capture → Collector-compatible snapshots and an auditable rule report.

Replay emits per-flow snapshots at 100 ms and dirty-map flushes at one second.
It shares FeatureCalculator, but cannot reproduce live thread/ring scheduling.
No traffic is transmitted and an absent ground truth stays UNLABELED.
"""

import argparse
import csv
import gzip
import hashlib
import json
import time
from collections import Counter, OrderedDict
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path

from collector.features import FeatureCalculator, Snapshot
from ml.pcap import decode, packets
from ml.rule_engine import RuleEngine

FLOW_FIELDS = ["src_ip", "dst_ip", "src_port", "dst_port", "protocol"]


class Replay:
    def __init__(self, max_flows=65536):
        self.calculator = FeatureCalculator(max_flows)
        self.flows = OrderedDict()
        self.dirty = OrderedDict()
        self.max_flows = max_flows
        self.last_flush = None
        self.evictions = 0

    def emit(self, key, now):
        snapshot, _ = self.flows[key]
        self.dirty.pop(key, None)
        features = self.calculator.compute(snapshot, now)
        if features is not None:
            return {"timestamp": now,
                    "window_start": max(now - 1, snapshot.first_seen_ns / 1e9),
                    "window_end": snapshot.last_seen_ns / 1e9,
                    "flow_started_at": snapshot.first_seen_ns / 1e9,
                    **dict(zip(FLOW_FIELDS, key)), **features, "Label": "UNLABELED"}

    def flush(self, now):
        for key in list(self.dirty):
            row = self.emit(key, now)
            if row is not None:
                yield row

    def add(self, key, syn, length, now):
        if self.last_flush is None:
            self.last_flush = now
        if now - self.last_flush >= 1:
            # Flush BEFORE this packet; idle time must not inflate old traffic.
            yield from self.flush(self.last_flush + 1)
            self.last_flush = now
        ns = int(now * 1e9)
        snapshot, exported = self.flows.get(key, (Snapshot(*key, 0, 0, 0, ns, ns), None))
        snapshot = replace(snapshot, pkt_cnt=snapshot.pkt_cnt + 1,
                           byte_cnt=snapshot.byte_cnt + length,
                           syn_cnt=snapshot.syn_cnt + syn, last_seen_ns=ns)
        self.flows[key] = (snapshot, exported)
        self.flows.move_to_end(key)
        self.dirty[key] = None
        if len(self.flows) > self.max_flows:
            oldest = next(iter(self.flows))
            if oldest in self.dirty:
                row = self.emit(oldest, now)
                if row is not None:
                    yield row
            self.flows.pop(oldest)
            self.evictions += 1
        if exported is None or now - exported >= 0.1:
            self.flows[key] = (snapshot, now)
            row = self.emit(key, now)
            if row is not None:
                yield row


def analyze(source, output, report_path, max_packets=None):
    source, output, report_path = Path(source), Path(output), Path(report_path)
    if source.resolve() in (output.resolve(), report_path.resolve()):
        raise ValueError("Outputs must not overwrite the capture")
    replay, rules = Replay(), RuleEngine()
    counts, detections, protocols, minutes = Counter(), Counter(), Counter(), {}
    first = last = watermark = None
    started = time.monotonic()
    output.parent.mkdir(parents=True, exist_ok=True)
    opener = gzip.open if output.suffix == ".gz" else open
    with source.open("rb") as stream, opener(output, "wt", newline="") as target:
        writer = None

        def write(rows):
            nonlocal writer
            for row in rows:
                if writer is None:
                    writer = csv.DictWriter(target, fieldnames=list(row))
                    writer.writeheader()
                writer.writerow(row)
                counts["feature_rows"] += 1
                detected = rules.detect(row)
                if detected:
                    detections[detected] += 1

        complete = True
        for packet in packets(stream):
            counts["packets"] += 1
            counts["wire_bytes"] += packet.wire_length
            if packet.timestamp is not None:
                first = packet.timestamp if first is None else min(first, packet.timestamp)
                last = packet.timestamp if last is None else max(last, packet.timestamp)
            decoded, reason = decode(packet)
            if decoded is None:
                counts[reason] += 1
            else:
                key, syn = decoded
                now = packet.timestamp
                if watermark is not None and now < watermark:
                    counts["out_of_order"] += 1
                    now = watermark  # Explicitly report scheduling clamps, retain packet counts.
                watermark = now
                counts["eligible_packets"] += 1
                protocols["TCP" if key[-1] == 6 else "UDP"] += 1
                bucket = minutes.setdefault(int(now // 60) * 60, [0, 0])
                bucket[0] += 1
                bucket[1] += packet.wire_length
                write(replay.add(key, syn, packet.wire_length, now))
            if counts["packets"] % 1_000_000 == 0:
                print(f"Processed {counts['packets']:,} packets", flush=True)
            if max_packets and counts["packets"] >= max_packets:
                complete = False
                break
        if watermark is not None:
            write(replay.flush(watermark))
    digest = None
    if complete:
        with source.open("rb") as stream:
            digest = hashlib.file_digest(stream, "sha256").hexdigest()
    report = {
        "schema_version": 1, "source": source.name, "source_bytes": source.stat().st_size,
        "sha256": digest, "complete": complete, "generated_at": datetime.now(timezone.utc).isoformat(),
        "started_at": first, "ended_at": last, "counts": dict(counts),
        "protocols": dict(protocols), "rule_detections": dict(detections),
        "thresholds": rules.thresholds.model_dump(), "flow_evictions": replay.evictions,
        "label_status": "unavailable", "model_validated": False,
        "feature_policy": "100ms per-flow snapshots + 1s dirty flush; shared FeatureCalculator",
        "limitations": ["Rule counts are feature-window alerts, not unique attacks or ground truth.",
                        "Capture replay does not reproduce live kernel/reader scheduling.",
                        "Out-of-order capture timestamps are clamped and counted.",
                        "No label CSV supplied; accuracy, F1 and FPR are not measured."],
        "traffic_minutes": [{"timestamp": ts, "packets": value[0], "bytes": value[1]}
                            for ts, value in sorted(minutes.items())],
        "elapsed_seconds": round(time.monotonic() - started, 2),
    }
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(report, indent=2) + "\n")
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source")
    parser.add_argument("--output")
    parser.add_argument("--report")
    parser.add_argument("--max-packets", type=int)
    args = parser.parse_args()
    if args.max_packets is not None and args.max_packets < 1:
        parser.error("--max-packets must be positive")
    stem = Path(args.source).stem.lower()
    result = analyze(args.source, args.output or f"ml/data/{stem}-features.csv.gz",
                     args.report or f"ml/reports/{stem}.json", args.max_packets)
    print(json.dumps({key: value for key, value in result.items() if key != "traffic_minutes"},
                     indent=2))
