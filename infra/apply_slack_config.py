"""Update only SLACK_WEBHOOK_URL in the deployment .env from a secure upload."""

import os
from pathlib import Path

path = Path(".env")
new_line = Path(".secrets/slack.env").read_text().strip()
if not new_line.startswith("SLACK_WEBHOOK_URL=https://hooks.slack.com/") or "\n" in new_line:
    raise SystemExit("Invalid Slack configuration file")
lines = [
    line for line in path.read_text().splitlines() if not line.startswith("SLACK_WEBHOOK_URL=")
]
lines.append(new_line)
temporary = Path(".secrets/runtime.env.tmp")
with os.fdopen(os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "w") as output:
    output.write("\n".join(lines) + "\n")
temporary.replace(path)
print("Slack configuration updated; other deployment values retained")
