#!/usr/bin/env bash
# Ubuntu VM runner. Docker builds execute on EC2; the VM needs no Docker daemon.
set -euo pipefail
if [ "$#" -ne 2 ]; then
  echo "Usage: $0 <repository-url> <runner-registration-token>"
  exit 1
fi
repo_url="$1"
registration_token="$2"
runner_dir="${RUNNER_DIR:-/home/ubuntu/actions-runner}"
runner_version="${RUNNER_VERSION:-2.337.0}"
case "$(uname -m)" in
  aarch64) runner_arch=arm64 ;;
  x86_64) runner_arch=x64 ;;
  *) echo "Unsupported runner architecture"; exit 1 ;;
esac
sudo apt-get update
sudo apt-get install -y curl jq git ca-certificates clang llvm libelf-dev libbpf-dev \
  "linux-headers-$(uname -r)" "linux-tools-$(uname -r)" \
  python3-bpfcc python3-venv bpfcc-tools bpftrace redis-tools nmap hping3
sudo sysctl -w kernel.perf_event_paranoid=-1 net.core.bpf_jit_enable=1
mkdir -p "$runner_dir"
cd "$runner_dir"
if [ ! -f .runner ]; then
  archive="actions-runner-linux-${runner_arch}-${runner_version}.tar.gz"
  curl -fSL "https://github.com/actions/runner/releases/download/v${runner_version}/${archive}" -o "$archive"
  tar -xzf "$archive"
  ./config.sh --url "$repo_url" --token "$registration_token" --name ebpf-linux-vm \
    --labels ebpf --work _work --unattended
fi
if [ ! -f .service ]; then
  sudo ./svc.sh install ubuntu
fi
sudo ./svc.sh start
sudo ./svc.sh status
echo "Python 3.14 and Node 24 are installed per job by GitHub Actions setup actions."
