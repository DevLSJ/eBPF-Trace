"""Run existing tests through an SSH tunnel, keeping EC2 passwords out of logs."""

import os
import subprocess
import sys
from pathlib import Path
from urllib.parse import quote

host = "ubuntu@52.62.165.10"
ssh = ["ssh", "-i", str(Path("don forget.pem").resolve()), "-o", "BatchMode=yes", host]
remote = subprocess.run(
    ssh
    + [
        "awk -F= '/^(DEV_POSTGRES_PASSWORD|COLLECTOR_TOKEN)=/ {print}' /home/ubuntu/ebpf-project/.env"
    ],
    text=True,
    capture_output=True,
    check=True,
)
settings = dict(line.split("=", 1) for line in remote.stdout.splitlines())
env = {
    **os.environ,
    "TEST_DATABASE_URL": "postgresql+asyncpg://ebpf_test:"
    + quote(settings["DEV_POSTGRES_PASSWORD"], safe="")
    + "@127.0.0.1:25432/ebpf_test",
    "COLLECTOR_TOKEN": settings["COLLECTOR_TOKEN"],
    "TEST_REDIS_URL": "redis://127.0.0.1:26379/0",
}
if "--runtime" in sys.argv:
    result = subprocess.run(
        [sys.executable, "infra/verify_runtime.py", "--base-url", "http://127.0.0.1:18080"], env=env
    )
else:
    result = subprocess.run([sys.executable, "-m", "pytest", "-q"], env=env)
raise SystemExit(result.returncode)
