"""Fail before pulling/unpacking images when the Docker filesystem is too full."""

import argparse
import shutil
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--minimum-mib", type=int, default=900)
    args = parser.parse_args()
    root = subprocess.check_output(
        ["docker", "info", "--format", "{{.DockerRootDir}}"], text=True
    ).strip()
    free = shutil.disk_usage(root).free // (1024 * 1024)
    print(f"Docker filesystem available: {free} MiB; required: {args.minimum_mib} MiB")
    if free < args.minimum_mib:
        raise SystemExit("Insufficient deployment space; existing services were not changed")


if __name__ == "__main__":
    main()
