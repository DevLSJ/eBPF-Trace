"""Use only the eBPF project's AWS profile without modifying global AWS configuration."""

import os
import subprocess
import sys
from pathlib import Path

credentials = Path(__file__).resolve().parents[1] / ".secrets/aws-credentials"
environment = {
    **os.environ,
    "AWS_SHARED_CREDENTIALS_FILE": str(credentials),
    "AWS_PROFILE": "ebpf-trace",
    "AWS_DEFAULT_REGION": "ap-southeast-2",
    "AWS_PAGER": "",
}
raise SystemExit(subprocess.run(["aws", *sys.argv[1:]], env=environment).returncode)
