"""Prepare project-scoped VM settings from an EC2 .env transferred over SSH."""

import os
from pathlib import Path


def write_once(path, values):
    if path.exists():
        print(f"Retained {path}")
        return
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w") as output:
        output.write("".join(f"{key}={value}\n" for key, value in values.items()))


def main():
    root = Path("/home/ubuntu/ebpf-project")
    credentials = dict(
        line.split("=", 1)
        for line in (root / ".secrets/backend.env").read_text().splitlines()
        if line and not line.startswith("#") and "=" in line
    )
    write_once(
        root / ".env.collector",
        {
            "COLLECTOR_TOKEN": credentials["COLLECTOR_TOKEN"],
            "COLLECTOR_WS_URL": "ws://127.0.0.1:18000/ws/collector",
            "REDIS_URL": "redis://127.0.0.1:16379/0",
            "IFACE": "enp0s1",
            "OUTBOX_PATH": str(root / "collector-outbox.db"),
        },
    )
    write_once(root / ".env.tunnel", {"EC2_HOST": "52.62.165.10"})


if __name__ == "__main__":
    main()
