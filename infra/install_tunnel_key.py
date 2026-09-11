"""Authorize a VM public key for exactly two loopback TCP forwards on EC2."""

import os
import sys
from pathlib import Path

key = sys.stdin.read().strip()
if not key.startswith("ssh-ed25519 ") or "\n" in key:
    raise SystemExit("Expected one OpenSSH ed25519 public key")
directory = Path.home() / ".ssh"
directory.mkdir(mode=0o700, exist_ok=True)
path = directory / "authorized_keys"
existing = path.read_text() if path.exists() else ""
if key.split()[1] not in existing:
    restrictions = 'restrict,port-forwarding,command="/bin/false",permitopen="127.0.0.1:80",permitopen="127.0.0.1:16379"'
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600), "a") as output:
        if existing and not existing.endswith("\n"):
            output.write("\n")
        output.write(f"{restrictions} {key}\n")
print("Tunnel public key present; only web/Redis loopback forwards are allowed")
