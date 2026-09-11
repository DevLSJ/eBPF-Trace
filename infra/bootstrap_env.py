"""Generate first-deploy secrets without printing them or replacing existing configuration."""

import os
import secrets
from pathlib import Path


def main():
    path = Path(".env")
    if path.exists():
        print("Existing .env retained")
        return
    values = {
        "POSTGRES_USER": "ebpf",
        "POSTGRES_PASSWORD": secrets.token_urlsafe(32),
        "POSTGRES_DB": "ebpf_ids",
        "DEV_POSTGRES_PASSWORD": secrets.token_urlsafe(32),
        "COLLECTOR_TOKEN": secrets.token_urlsafe(32),
        "ADMIN_TOKEN": secrets.token_urlsafe(32),
        "REDIS_URL": "redis://redis:6379/0",
        "SLACK_WEBHOOK_URL": "",
        "DOCKERHUB_USERNAME": "local",
        "IMAGE_TAG": "dev",
    }
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w") as output:
        output.write("".join(f"{key}={value}\n" for key, value in values.items()))
    print("Created .env with independent random service credentials (mode 0600)")


if __name__ == "__main__":
    main()
