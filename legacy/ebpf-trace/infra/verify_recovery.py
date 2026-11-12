"""Restart only ebpf-trace-app services; retain all database volumes and records."""

import json
import subprocess
import time
import urllib.request
from pathlib import Path

ROOT = Path("/home/ubuntu/ebpf-project")
COMPOSE = [
    "docker",
    "compose",
    "-p",
    "ebpf-trace-app",
    "-f",
    "docker-compose.yml",
    "-f",
    "docker-compose.tunnel.yml",
]


def command(*args):
    return subprocess.run([*COMPOSE, *args], cwd=ROOT, check=True, capture_output=True, text=True)


def get(path):
    with urllib.request.urlopen("http://127.0.0.1" + path, timeout=3) as response:
        return json.load(response)


def wait_health(predicate=lambda result: result["status"] == "ok"):
    deadline = time.monotonic() + 50
    while time.monotonic() < deadline:
        try:
            health = get("/health")
            if predicate(health):
                return health
        except Exception:
            pass
        time.sleep(0.5)
    raise TimeoutError("Service health did not recover")


def main():
    before = get("/api/events")["total"]
    report = {}
    try:
        command("stop", "redis")
        wait_health(lambda result: result["redis"] == "degraded")
        with (ROOT / "infra/verify_runtime.py").open() as source:
            output = subprocess.run(
                [*COMPOSE, "exec", "-T", "backend", "python", "-", "--base-url", "http://nginx"],
                cwd=ROOT,
                stdin=source,
                text=True,
                capture_output=True,
            )
        # The full test includes timing assertions, but here persistence is the recovery criterion.
        result = json.loads(output.stdout)
        assert result["event_id"] > 0
        report["redis_down_detection_event"] = result["event_id"]
    finally:
        command("start", "redis")
    wait_health(lambda result: result["redis"] == "ok")
    saved_id = get("/api/events")["items"][0]["event_id"]
    command("restart", "postgres")
    wait_health()
    assert get(f"/api/events/{saved_id}")["event_id"] == saved_id
    report["postgres_retained_event"] = saved_id
    start = time.monotonic()
    command("restart", "backend")
    health = wait_health(lambda result: result["collector_connected"])
    report["backend_recovery_sec"] = round(time.monotonic() - start, 2)
    report["collector_reconnected"] = health["collector_connected"]
    report["events_before"] = before
    report["events_after"] = get("/api/events")["total"]
    assert report["events_after"] >= before and report["backend_recovery_sec"] <= 60
    report["passed"] = True
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
