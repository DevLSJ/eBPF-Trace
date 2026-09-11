"""Interactive, non-echoing project-local credentials setup (never tracked by Git)."""

import configparser
import getpass
import os
import sys
from pathlib import Path
from urllib.parse import urlparse

directory = Path(__file__).resolve().parents[1] / ".secrets"
directory.mkdir(mode=0o700, exist_ok=True)
os.chmod(directory, 0o700)

if "--aws" in sys.argv:
    access_key = getpass.getpass("AWS access key: ")
    secret_key = getpass.getpass("AWS secret key: ")
    configuration = configparser.ConfigParser()
    configuration["ebpf-trace"] = {
        "aws_access_key_id": access_key,
        "aws_secret_access_key": secret_key,
    }
    with os.fdopen(
        os.open(directory / "aws-credentials", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "w"
    ) as output:
        configuration.write(output)
    print("Project-local AWS profile saved (0600)")
if "--slack" in sys.argv:
    webhook = getpass.getpass("Slack webhook: ")
    if urlparse(webhook).hostname != "hooks.slack.com" or not webhook.startswith("https://"):
        raise SystemExit("Expected an HTTPS Slack webhook")
    with os.fdopen(
        os.open(directory / "slack.env", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "w"
    ) as output:
        output.write("SLACK_WEBHOOK_URL=" + webhook + "\n")
    print("Project-local Slack configuration saved (0600)")
