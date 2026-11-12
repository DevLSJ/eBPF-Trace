"""Opt in to HTTPS and the restricted public demo identity; preserve existing secrets."""

import argparse
import ipaddress
import os
import re
import shutil
import tempfile
import time
from pathlib import Path


def configure(path, host, proxy_subnet):
    path = Path(path).resolve(strict=True)
    if not re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?", host):
        raise ValueError("A plain DNS hostname is required")
    network = ipaddress.ip_network(proxy_subnet, strict=True)
    if not network.is_private or network.prefixlen == 0:
        raise ValueError("Trust only the private proxy network")
    values = {
        "HTTPS_ENABLED": "true",
        "PUBLIC_HOST": host,
        "PUBLIC_BASE_URL": f"https://{host}",
        "ALLOWED_ORIGINS": f"https://{host}",
        "TRUSTED_PROXY_CIDRS": str(network),
        "OPS_TEST_ACCOUNT_MODE": "true",
        "OPS_ALLOW_INSECURE_LOCAL": "false",
        "OPS_NOTIFICATIONS_ENABLED": "false",
        "SLACK_ENABLED": "false",
        "RESPONSE_LIVE_ENABLED": "false",
    }
    lines = [line for line in path.read_text().splitlines() if line.split("=", 1)[0] not in values]
    backup = path.with_name(f"{path.name}.before-public-test-{time.time_ns()}")
    shutil.copy2(path, backup)
    backup.chmod(0o600)
    with tempfile.NamedTemporaryFile(mode="w", dir=path.parent, delete=False) as target:
        target.write(
            "\n".join([*lines, *(f"{key}={value}" for key, value in values.items())]) + "\n"
        )
    os.chmod(target.name, 0o600)
    os.replace(target.name, path)
    print(f"Public test configuration saved; private backup: {backup}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--env-file", required=True)
    parser.add_argument("--host", required=True)
    parser.add_argument("--proxy-subnet", required=True)
    args = parser.parse_args()
    configure(args.env_file, args.host, args.proxy_subnet)
