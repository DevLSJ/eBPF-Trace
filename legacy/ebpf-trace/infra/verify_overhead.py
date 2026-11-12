"""Measure native XDP CPU delta with bounded UDP in an isolated VM-only veth lab.

No route to the internet is created. This measures kernel + ring-reader overhead,
not the ML/backend stack. Existing Collector services are left running.
"""

import argparse
import json
import os
import socket
import statistics
import struct
import subprocess
import sys
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
NAMESPACE, WATCH, PROBE = "ebpf-cpu-lab", "ec-watch", "ec-probe"


def command(*args):
    return subprocess.run(args, capture_output=True, text=True, check=True)


def sender(destination, duration, pps):
    source = bytes.fromhex(
        Path(f"/sys/class/net/{PROBE}/address").read_text().strip().replace(":", "")
    )
    target = bytes.fromhex(destination.replace(":", ""))
    payload = b"ebpf-overhead-test".ljust(64, b".")
    udp = struct.pack("!HHHH", 40000, 9999, 8 + len(payload), 0)
    ip = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        20 + len(udp) + len(payload),
        1,
        0,
        64,
        17,
        0,
        socket.inet_aton("10.201.0.1"),
        socket.inet_aton("10.201.0.2"),
    )
    checksum = sum(struct.unpack("!10H", ip))
    while checksum >> 16:
        checksum = (checksum & 65535) + (checksum >> 16)
    ip = ip[:10] + struct.pack("!H", (~checksum) & 65535) + ip[12:]
    frame = target + source + b"\x08\x00" + ip + udp + payload
    with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3)) as channel:
        channel.bind((PROBE, 0))
        started = time.monotonic()
        sent = 0
        batch = 20
        while time.monotonic() - started < duration:
            for _ in range(batch):
                channel.send(frame)
            sent += batch
            delay = started + sent / pps - time.monotonic()
            if delay > 0:
                time.sleep(delay)
    return {"packets_sent": sent, "actual_pps": round(sent / (time.monotonic() - started), 2)}


def measure(attached, target, duration, pps):
    import psutil

    from collector.reader import RingBufferReader

    reader = process = thread = None
    stop = threading.Event()
    ring_events = []
    try:
        if attached:
            reader = RingBufferReader(WATCH, lambda snapshot: ring_events.append(snapshot.pkt_cnt))

            def poll():
                while not stop.is_set():
                    reader.poll()

            thread = threading.Thread(target=poll)
            thread.start()
        process = subprocess.Popen(
            [
                "ip",
                "netns",
                "exec",
                NAMESPACE,
                sys.executable,
                str(Path(__file__).resolve()),
                "--send",
                target,
                "--duration",
                str(duration),
                "--pps",
                str(pps),
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        samples = [psutil.cpu_percent(interval=1) for _ in range(duration)]
        stdout, stderr = process.communicate(timeout=5)
        if process.returncode:
            raise RuntimeError(stderr)
        result = json.loads(stdout)
        result.update(
            xdp=attached,
            cpu_mean_pct=round(statistics.mean(samples[1:]), 2),
            samples_pct=samples[1:],
            ring_events=len(ring_events),
        )
        if reader:
            result["kernel_packets"] = sum(
                value.pkt_cnt for value in reader.bpf["flow_stats_map"].values()
            )
        return result
    finally:
        if process is not None and process.poll() is None:
            process.terminate()
            process.communicate(timeout=5)
        stop.set()
        if thread:
            thread.join(timeout=2)
        if reader:
            reader.close()


def verify(duration, pps):
    if os.geteuid() != 0:
        raise SystemExit("Run with sudo using the VM Collector Python")
    if NAMESPACE in command("ip", "netns", "list").stdout:
        raise SystemExit("Lab namespace already exists; refusing to overwrite it")
    for name in (WATCH, PROBE):
        if subprocess.run(["ip", "link", "show", name], capture_output=True).returncode == 0:
            raise SystemExit("Lab interface already exists; refusing to overwrite it")
    namespace_created = link_created = False
    try:
        command("ip", "netns", "add", NAMESPACE)
        namespace_created = True
        command("ip", "link", "add", WATCH, "type", "veth", "peer", "name", PROBE)
        link_created = True
        command("ip", "link", "set", PROBE, "netns", NAMESPACE)
        command("ip", "address", "add", "10.201.0.2/30", "dev", WATCH)
        command("ip", "link", "set", WATCH, "up")
        command(
            "ip", "netns", "exec", NAMESPACE, "ip", "address", "add", "10.201.0.1/30", "dev", PROBE
        )
        command("ip", "netns", "exec", NAMESPACE, "ip", "link", "set", PROBE, "up")
        assert "default" not in command("ip", "netns", "exec", NAMESPACE, "ip", "route").stdout
        target = json.loads(command("ip", "-j", "link", "show", WATCH).stdout)[0]["address"]
        trials = []
        for order in ((False, True), (True, False), (False, True)):
            for attached in order:
                trials.append(measure(attached, target, duration, pps))
        baseline = statistics.mean(row["cpu_mean_pct"] for row in trials if not row["xdp"])
        enabled = statistics.mean(row["cpu_mean_pct"] for row in trials if row["xdp"])
        accurate = all(row["actual_pps"] >= pps * 0.95 for row in trials)
        received = all(
            row.get("kernel_packets", row["packets_sent"]) == row["packets_sent"] for row in trials
        )
        return {
            "scope": "VM isolated veth; UDP 106-byte frames; XDP + ring reader only",
            "target_pps": pps,
            "seconds_per_trial": duration,
            "trials": trials,
            "baseline_cpu_pct": round(baseline, 2),
            "xdp_cpu_pct": round(enabled, 2),
            "cpu_delta_percentage_points": round(enabled - baseline, 2),
            "rate_achieved": accurate,
            "packets_accounted": received,
            "passed": accurate and received and enabled - baseline <= 5,
        }
    finally:
        if link_created:
            command("ip", "link", "delete", WATCH)
        if namespace_created:
            command("ip", "netns", "delete", NAMESPACE)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--send")
    parser.add_argument("--duration", type=int, default=6, choices=range(3, 31))
    parser.add_argument("--pps", type=int, default=10_000, choices=range(1, 10_001))
    args = parser.parse_args()
    report = (
        sender(args.send, args.duration, args.pps) if args.send else verify(args.duration, args.pps)
    )
    print(json.dumps(report, indent=2), flush=True)
    raise SystemExit(0 if report.get("passed", True) else 1)
