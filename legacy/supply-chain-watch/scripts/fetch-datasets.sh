#!/usr/bin/env bash
# 외부 평가 데이터 내려받기 (Phase 3 정적 분석 평가용). 결과는 data/ 아래, git 추적 제외.
#
#   bash scripts/fetch-datasets.sh            # 4개 모두 (큰 데이터셋은 일부만)
#   bash scripts/fetch-datasets.sh zizmor     # 하나만: zizmor | guarddog | ossf | datadog | benign-pypi
#   OSSF_LIMIT=500 DATADOG_LIMIT=100 bash scripts/fetch-datasets.sh datadog   # 개수 늘리기
#
# 안전 규칙 (CLAUDE.md §5-5, data/README.md):
# - datadog 샘플은 실제 악성 패키지다. 암호 zip 그대로 두고 풀지 않는다. 설치·실행 금지.
# - data/ 는 .gitignore 대상. 커밋·push 하지 않는다.
set -euo pipefail
cd "$(dirname "$0")/.."

DATA=data
OSSF_LIMIT="${OSSF_LIMIT:-300}"          # ecosystem별 OSV 보고서 개수
DATADOG_LIMIT="${DATADOG_LIMIT:-300}"    # ecosystem별 악성 패키지 zip 개수 (2026-10-12 사용자 결정: 300)
BENIGN_PYPI_LIMIT="${BENIGN_PYPI_LIMIT:-300}"  # 정상 대조군 PyPI 휠 개수
mkdir -p "$DATA"

log() { printf '▶ %s\n' "$*"; }

# 얕고(blob 지연) 빈 체크아웃으로 받은 뒤, 필요한 경로만 sparse로 꺼낸다.
clone_sparse() {
  local name=$1 url=$2
  local dir="$DATA/$name"
  if [ -d "$dir/.git" ]; then
    log "$name: 이미 있음 → 최신으로 갱신"
    git -C "$dir" fetch --depth 1 --filter=blob:none origin HEAD >/dev/null 2>&1
    git -C "$dir" reset --hard FETCH_HEAD >/dev/null
  else
    log "$name: $url 받는 중"
    git clone --depth 1 --filter=blob:none --no-checkout --quiet "$url" "$dir"
  fi
  git -C "$dir" sparse-checkout init --no-cone >/dev/null
}

# 디렉토리 전체 체크아웃
checkout_dirs() {
  local dir="$DATA/$1"; shift
  printf '%s\n' "$@" | sed 's#$#/**#' | git -C "$dir" sparse-checkout set --no-cone --stdin
  git -C "$dir" checkout --quiet HEAD
}

# 큰 디렉토리에서 파일 N개만, 고정 시드 무작위 표본 (트리 목록은 blob 없이도 볼 수 있다)
checkout_sample() {
  local dir="$DATA/$1" limit=$2 pattern=$3; shift 3
  local list
  list=$(for prefix in "$@"; do
    # head가 먼저 닫으면 앞쪽이 SIGPIPE로 끝나므로 실패로 보지 않는다
    git -C "$dir" ls-tree -r --name-only HEAD -- "$prefix" | grep -E "$pattern" \
      | python3 -I -c 'import random,sys; xs=sys.stdin.read().split(); random.Random(20261012).shuffle(xs); print("\n".join(xs))' \
      | head -n "$limit" || true
  done)
  printf '%s\n' "$list" "$EXTRA_PATHS" | grep -v '^$' | git -C "$dir" sparse-checkout set --no-cone --stdin
  git -C "$dir" checkout --quiet HEAD
}

record() {
  local name=$1 url=$2
  local sha files
  sha=$(git -C "$DATA/$name" rev-parse --short HEAD)
  files=$(git -C "$DATA/$name" ls-files -t | grep -vc '^S ' || true)  # S = sparse로 안 꺼낸 파일
  printf '%s\t%s\t%s\t%s files\t%s\n' "$name" "$url" "$sha" "$files" "$(date +%F)" >> "$DATA/SOURCES.tsv.tmp"
  log "$name: 완료 (커밋 ${sha}, 파일 ${files}개)"
}

fetch_zizmor() {
  local url=https://github.com/zizmorcore/zizmor
  clone_sparse zizmor "$url"
  checkout_dirs zizmor crates/zizmor/tests/integration/test-data
  record zizmor "$url"
}

fetch_guarddog() {
  local url=https://github.com/DataDog/guarddog
  clone_sparse guarddog "$url"
  # 룰 정의(소스·메타데이터 휴리스틱)와 테스트 예시
  checkout_dirs guarddog tests guarddog/analyzer
  record guarddog "$url"
}

fetch_ossf() {
  local url=https://github.com/ossf/malicious-packages
  clone_sparse ossf "$url"
  EXTRA_PATHS="README.md" checkout_sample ossf "$OSSF_LIMIT" '\.json$' osv/malicious/npm osv/malicious/pypi
  record ossf "$url"
}

fetch_datadog() {
  local url=https://github.com/DataDog/malicious-software-packages-dataset
  clone_sparse datadog "$url"
  # manifest는 전체 목록(이름·버전)이라 함께 받는다. zip은 ecosystem별 N개만.
  EXTRA_PATHS=$'README.md\nsamples/npm/manifest.json\nsamples/pypi/manifest.json' \
    checkout_sample datadog "$DATADOG_LIMIT" '\.zip$' samples/npm samples/pypi
  record datadog "$url"
}

fetch_benign_pypi() {
  log "benign-pypi: 다운로드 상위 PyPI 패키지 휠 ${BENIGN_PYPI_LIMIT}개 (설치·실행 안 함)"
  # engine 환경(certifi 포함) 파이썬으로 실행
  uv run --quiet --project apps/engine python -I scripts/fetch_benign_pypi.py "$DATA/benign-pypi" "$BENIGN_PYPI_LIMIT"
  printf 'benign-pypi\thttps://pypi.org (top-pypi-packages 30일)\t-\t%s files\t%s\n' "$(ls "$DATA/benign-pypi" | wc -l | tr -d ' ')" "$(date +%F)" >> "$DATA/SOURCES.tsv.tmp"
}

EXTRA_PATHS=""
targets=("$@")
[ ${#targets[@]} -eq 0 ] && targets=(zizmor guarddog ossf datadog benign-pypi)

: > "$DATA/SOURCES.tsv.tmp"
for t in "${targets[@]}"; do
  case "$t" in
    zizmor) fetch_zizmor ;;
    guarddog) fetch_guarddog ;;
    ossf) fetch_ossf ;;
    datadog) fetch_datadog ;;
    benign-pypi) fetch_benign_pypi ;;
    *) echo "알 수 없는 대상: $t (zizmor|guarddog|ossf|datadog|benign-pypi)" >&2; exit 1 ;;
  esac
done

# 출처 기록: 같은 이름은 최신 줄로 교체
touch "$DATA/SOURCES.tsv"
cut -f1 "$DATA/SOURCES.tsv.tmp" | while read -r n; do
  grep -v "^$n	" "$DATA/SOURCES.tsv" > "$DATA/SOURCES.tsv.new" || true
  mv "$DATA/SOURCES.tsv.new" "$DATA/SOURCES.tsv"
done
cat "$DATA/SOURCES.tsv.tmp" >> "$DATA/SOURCES.tsv"
rm -f "$DATA/SOURCES.tsv.tmp"
log "출처 기록: $DATA/SOURCES.tsv"
du -sh "$DATA"/*/ 2>/dev/null || true
