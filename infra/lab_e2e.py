"""Bounded hping3/nmap tests in a temporary VM namespace with no external route."""

import json
import os
import subprocess
import tempfile
import time
import urllib.request
from datetime import datetime
from pathlib import Path

ROOT = Path("/home/ubuntu/ebpf-project")
NAMESPACE, WATCH, PROBE = "ebpf-trace-lab", "et-watch", "et-probe"


def command(*args):
    return subprocess.run(args, check=True, capture_output=True, text=True)


def events():
    with urllib.request.urlopen(
        "http://127.0.0.1:18000/api/events?page_size=100", timeout=5
    ) as response:
        return json.load(response)["items"]


def wait_event(kind, start, timeout=8):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        for event in events():
            detected = datetime.fromisoformat(event["detected_at"]).timestamp()
            if (
                event["flow"]["src_ip"] == "10.200.0.1"
                and event["attack_type"] == kind
                and detected >= start
            ):
                return {
                    "event_id": event["event_id"],
                    "latency_ms": round((detected - start) * 1000, 2),
                }
        time.sleep(0.1)
    raise TimeoutError(f"No {kind} event arrived")


def main():
    if os.geteuid() != 0:
        raise SystemExit("Run with sudo inside the Ubuntu VM")
    if NAMESPACE in command("ip", "netns", "list").stdout:
        raise SystemExit("Lab namespace already exists; refusing to modify it")
    for interface in (WATCH, PROBE):
        if subprocess.run(["ip", "link", "show", interface], capture_output=True).returncode == 0:
            raise SystemExit("Lab interface already exists; refusing to modify it")
    environment = dict(os.environ)
    environment.update(
        dict(
            line.split("=", 1)
            for line in (ROOT / ".env.collector").read_text().splitlines()
            if "=" in line
        )
    )
    namespace_created = link_created = False
    collector = None
    try:
        command("ip", "netns", "add", NAMESPACE)
        namespace_created = True
        command("ip", "link", "add", WATCH, "type", "veth", "peer", "name", PROBE)
        link_created = True
        command("ip", "link", "set", PROBE, "netns", NAMESPACE)
        command("ip", "addr", "add", "10.200.0.2/30", "dev", WATCH)
        command("ip", "link", "set", WATCH, "up")
        command(
            "ip", "netns", "exec", NAMESPACE, "ip", "addr", "add", "10.200.0.1/30", "dev", PROBE
        )
        command("ip", "netns", "exec", NAMESPACE, "ip", "link", "set", PROBE, "up")
        command("ip", "netns", "exec", NAMESPACE, "ip", "link", "set", "lo", "up")
        assert "default" not in command("ip", "netns", "exec", NAMESPACE, "ip", "route").stdout
        with tempfile.TemporaryDirectory(prefix="ebpf-lab-") as temp:
            environment.update(IFACE=WATCH, OUTBOX_PATH=str(Path(temp) / "outbox.db"))
            with open(Path(temp) / "collector.log", "w+") as log:
                collector = subprocess.Popen(
                    [str(ROOT / ".venv-collector/bin/python"), "-m", "collector.main"],
                    cwd=ROOT,
                    env=environment,
                    stdout=log,
                    stderr=log,
                )
                for _ in range(100):
                    log.seek(0)
                    if "Collector connected" in log.read():
                        break
                    if collector.poll() is not None:
                        log.seek(0)
                        raise RuntimeError(log.read())
                    time.sleep(0.1)
                else:
                    raise TimeoutError("Lab collector startup timeout")
                start = time.time()
                command(
                    "ip",
                    "netns",
                    "exec",
                    NAMESPACE,
                    "hping3",
                    "-S",
                    "-k",
                    "-s",
                    "40000",
                    "-p",
                    "80",
                    "-i",
                    "u500",
                    "-c",
                    "2400",
                    "10.200.0.2",
                )
                syn = wait_event("SYN_FLOOD", start)
                time.sleep(10.2)  # Separate both the SYN and ten-second port windows.
                start = time.time()
                command(
                    "ip",
                    "netns",
                    "exec",
                    NAMESPACE,
                    "nmap",
                    "-sS",
                    "-Pn",
                    "-n",
                    "-p",
                    "1-30",
                    "--max-retries",
                    "0",
                    "10.200.0.2",
                )
                scan = wait_event("PORT_SCAN", start)
                report = {
                    "environment": "isolated veth namespace; no default route",
                    "syn_flood": syn,
                    "port_scan": scan,
                    "passed": syn["latency_ms"] <= 3000 and scan["latency_ms"] <= 5000,
                }
                print(json.dumps(report, indent=2))
                collector.terminate()
                collector.wait(timeout=10)
                collector = None
    finally:
        if collector is not None:
            collector.terminate()
            collector.wait(timeout=10)
        if link_created:
            command("ip", "link", "delete", WATCH)
        if namespace_created:
            command("ip", "netns", "delete", NAMESPACE)


if __name__ == "__main__":
    main()
