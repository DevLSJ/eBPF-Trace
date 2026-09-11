"""Export only the collector credential for transport to the VM over SCP."""

import os
from pathlib import Path

values = dict(
    line.split("=", 1)
    for line in Path(".env").read_text().splitlines()
    if line and not line.startswith("#") and "=" in line
)
directory = Path(".secrets")
directory.mkdir(mode=0o700, exist_ok=True)
path = directory / "collector.env"
with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "w") as output:
    output.write("COLLECTOR_TOKEN=" + values["COLLECTOR_TOKEN"] + "\n")
print("Collector-only credential exported with mode 0600")
