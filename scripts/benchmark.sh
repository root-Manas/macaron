#!/usr/bin/env bash
set -euo pipefail

TARGET="${1:-example.com}"
BIN="${2:-./macaron}"
OUT="${3:-benchmark.md}"

run_case() {
  local name="$1"
  shift
  local start end dur
  start=$(date +%s)
  $BIN scan "$TARGET" "$@" > /tmp/macaron_bench_${name}.log 2>&1 || true
  end=$(date +%s)
  dur=$((end-start))
  echo "| $name | ${dur}s |"
}

{
  echo "# Benchmark Snapshot"
  echo
  echo "Target: $TARGET"
  echo
  echo "| Profile | Duration |"
  echo "|---|---:|"
  run_case passive --profile passive
  run_case balanced --profile balanced
  run_case aggressive --profile aggressive --stages subdomains,http,ports,urls,vulns
} > "$OUT"

echo "Wrote $OUT"
