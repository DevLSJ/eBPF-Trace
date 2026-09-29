#!/usr/bin/env bash
set -euo pipefail
docker rm -f victim pkg-reqeusts >/dev/null 2>&1 || true
docker ps -aq --filter label=supplyguard.demo | xargs -r docker rm -f >/dev/null
echo "demo containers removed"
