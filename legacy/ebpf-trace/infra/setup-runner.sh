#!/usr/bin/env bash
# =============================================================================
# setup-runner.sh — GitHub Actions Self-Hosted Runner 설치 스크립트
#
# 대상 서버 : Linux VM Ubuntu (192.168.64.2)
# 실행 방법 :
#   chmod +x setup-runner.sh
#   ./setup-runner.sh <GITHUB_REPO_URL> <RUNNER_TOKEN>
#
# 예시 :
#   ./setup-runner.sh https://github.com/YourOrg/eBPF-trace ghp_xxxxxxxxxxxx
#
# Runner Token 발급 위치:
#   GitHub 레포 → Settings → Actions → Runners → New self-hosted runner
#   "Configure" 단계에서 표시되는 --token 값을 사용
# =============================================================================

set -euo pipefail

# ─── 인자 검증 ──────────────────────────────────────────────────────────────
if [ "$#" -lt 2 ]; then
  echo "Usage: $0 <GITHUB_REPO_URL> <RUNNER_TOKEN>"
  echo "Example: $0 https://github.com/YourOrg/eBPF-trace AXXXXXXXXXXX"
  exit 1
fi

REPO_URL="$1"
RUNNER_TOKEN="$2"
RUNNER_VERSION="2.317.0"          # 안정 버전 (필요 시 최신으로 교체)
RUNNER_DIR="$HOME/actions-runner"
RUNNER_NAME="ebpf-linux-vm"       # GitHub Actions에서 표시될 runner 이름
RUNNER_LABELS="self-hosted,Linux,ARM64,ebpf"  # 워크플로우 runs-on 레이블과 일치

echo "========================================================"
echo " eBPF-trace GitHub Actions Self-Hosted Runner 설치"
echo " 대상 레포 : $REPO_URL"
echo " Runner 디렉토리 : $RUNNER_DIR"
echo "========================================================"

# ─── 1. 시스템 패키지 업데이트 & 필수 도구 설치 ───────────────────────────
echo ""
echo "[1/7] 시스템 패키지 업데이트 중..."
sudo apt-get update -qq
sudo apt-get install -y --no-install-recommends \
  curl \
  jq \
  tar \
  git \
  ca-certificates \
  apt-transport-https \
  gnupg \
  lsb-release

# ─── 2. Docker 설치 (없을 경우만) ─────────────────────────────────────────
echo ""
echo "[2/7] Docker 설치 확인 중..."
if ! command -v docker &>/dev/null; then
  echo "Docker 미설치 — 설치를 시작합니다."
  curl -fsSL https://download.docker.com/linux/ubuntu/gpg \
    | sudo gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg

  echo \
    "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] \
    https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" \
    | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

  sudo apt-get update -qq
  sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin

  # ubuntu 사용자를 docker 그룹에 추가 (재로그인 없이 적용)
  sudo usermod -aG docker "$USER"
  newgrp docker <<'DOCKERGRP'
    echo "Docker 그룹 적용 완료"
DOCKERGRP
  echo "Docker 설치 완료: $(docker --version)"
else
  echo "Docker 이미 설치됨: $(docker --version)"
fi

# docker compose v2 확인
if ! docker compose version &>/dev/null; then
  sudo apt-get install -y docker-compose-plugin
fi
echo "Docker Compose: $(docker compose version)"

# ─── 3. Python 3.11 및 Node.js 20 설치 (CI 잡에서 사용) ──────────────────
echo ""
echo "[3/7] Python 3.11 및 Node.js 20 설치 확인 중..."

# Python 3.11
if ! python3.11 --version &>/dev/null 2>&1; then
  sudo add-apt-repository -y ppa:deadsnakes/ppa
  sudo apt-get update -qq
  sudo apt-get install -y python3.11 python3.11-venv python3.11-dev python3-pip
fi
echo "Python: $(python3.11 --version)"

# Node.js 20 (NodeSource)
if ! node --version &>/dev/null 2>&1; then
  curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
  sudo apt-get install -y nodejs
fi
echo "Node.js: $(node --version)"
echo "npm: $(npm --version)"

# ─── 4. BCC / eBPF 도구 설치 (eBPF 에이전트 CI 검증용) ───────────────────
echo ""
echo "[4/7] BCC / eBPF 도구 설치 확인 중..."
if ! dpkg -l | grep -q bpfcc-tools; then
  sudo apt-get install -y \
    linux-headers-$(uname -r) \
    bpfcc-tools \
    python3-bpfcc \
    libbpf-dev \
    bpftrace || echo "⚠  BCC 설치 실패 — 커널 버전 불일치 가능성. eBPF 에이전트 테스트는 수동 실행 필요."
fi

# ─── 5. Runner 바이너리 다운로드 ──────────────────────────────────────────
echo ""
echo "[5/7] GitHub Actions Runner v${RUNNER_VERSION} 다운로드 중..."
mkdir -p "$RUNNER_DIR"
cd "$RUNNER_DIR"

RUNNER_ARCHIVE="actions-runner-linux-arm64-${RUNNER_VERSION}.tar.gz"
if [ ! -f "$RUNNER_ARCHIVE" ]; then
  curl -fsSL \
    "https://github.com/actions/runner/releases/download/v${RUNNER_VERSION}/${RUNNER_ARCHIVE}" \
    -o "$RUNNER_ARCHIVE"
fi

tar xzf "$RUNNER_ARCHIVE"
echo "Runner 압축 해제 완료"

# ─── 6. Runner 구성 (config.sh) ───────────────────────────────────────────
echo ""
echo "[6/7] Runner 구성 중..."

# 이미 구성된 경우 재구성 방지
if [ -f ".runner" ]; then
  echo "Runner가 이미 구성되어 있습니다. 재구성하려면 ./config.sh remove 후 다시 실행하세요."
else
  ./config.sh \
    --url "$REPO_URL" \
    --token "$RUNNER_TOKEN" \
    --name "$RUNNER_NAME" \
    --labels "$RUNNER_LABELS" \
    --work "_work" \
    --unattended \
    --replace
fi

# ─── 7. systemd 서비스로 등록 (부팅 시 자동 실행) ─────────────────────────
echo ""
echo "[7/7] systemd 서비스 등록 중..."

# Runner 제공 install 스크립트 사용
sudo ./svc.sh install "$USER"
sudo ./svc.sh start

# 서비스 상태 확인
sleep 2
sudo ./svc.sh status

echo ""
echo "========================================================"
echo "✅ Self-Hosted Runner 설치 및 등록 완료!"
echo ""
echo "   Runner 이름   : $RUNNER_NAME"
echo "   Labels        : $RUNNER_LABELS"
echo "   Runner 디렉토리: $RUNNER_DIR"
echo ""
echo "GitHub → Settings → Actions → Runners 에서"
echo "'$RUNNER_NAME' 이 Idle(초록) 상태인지 확인하세요."
echo ""
echo "[유용한 명령어]"
echo "  상태 확인 : sudo $RUNNER_DIR/svc.sh status"
echo "  로그 확인 : sudo journalctl -u actions.runner.*.service -f"
echo "  서비스 중지: sudo $RUNNER_DIR/svc.sh stop"
echo "  Runner 제거: cd $RUNNER_DIR && ./config.sh remove --token <TOKEN>"
echo "========================================================"
