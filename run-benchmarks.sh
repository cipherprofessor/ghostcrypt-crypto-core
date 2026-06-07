#!/usr/bin/env bash
# Build and run the GhostCrypt crypto-core benchmarks, then emit a compact
# summary (bench-summary.txt) that can be pasted straight into the paper.
#
# Usage:
#   ./run-benchmarks.sh              # core paths
#   ./run-benchmarks.sh --pq         # also benchmark the post-quantum hybrid KEM
#
# Requires a Rust toolchain (https://rustup.rs). First run compiles deps
# (OpenMLS etc.) and may take a few minutes; later runs are fast.

set -euo pipefail
cd "$(dirname "$0")"

# Plain string (not an array) so it works on macOS's older bash under `set -u`.
FEATURES=""
[[ "${1:-}" == "--pq" ]] && FEATURES="--features post-quantum"

LOG="bench-output.txt"
SUMMARY="bench-summary.txt"

echo "==> cargo version"; cargo --version
echo "==> running benchmarks (this can take a few minutes on first build)"
# Tee full Criterion output to a log we can re-parse.
cargo bench --bench crypto_bench $FEATURES 2>&1 | tee "$LOG"

echo "==> building summary"
{
  echo "GhostCrypt crypto-core benchmark summary"
  echo "host: $(uname -sm)    date: $(date -u +%Y-%m-%dT%H:%MZ)"
  echo "rustc: $(rustc --version)"
  echo "profile: bench (release; note Cargo.toml sets opt-level=z, lto=true for the shipping lib)"
  echo "----------------------------------------------------------------"
  printf "%-42s %s\n" "benchmark" "median (point estimate)"
  echo "----------------------------------------------------------------"
} > "$SUMMARY"

# Criterion prints the benchmark id on one line, then a line like:
#   time:   [1.2345 us 1.2400 us 1.2460 us]
# We pair each id with the middle (median) value.
awk '
  # Case 1: benchmark id on its own line, then a "time:" line below it.
  /^[A-Za-z0-9_]+\/[A-Za-z0-9_]+/ && $0 !~ /time:/ { name=$1; next }
  # Case 2: id and "time:" on the SAME line (Criterion does this for short names).
  /^[A-Za-z0-9_]+\/[A-Za-z0-9_]+.*time:/ { name=$1 }
  /time:/ {
    match($0, /\[/); s=substr($0, RSTART+1); gsub(/\]/, "", s);
    n=split(s, a, " ");
    # a = (low unit mid unit high unit) -> median value=a[3], unit=a[4]
    if (n>=4 && name!="") { printf "%-42s %s %s\n", name, a[3], a[4]; name="" }
  }
' "$LOG" >> "$SUMMARY"

echo "----------------------------------------------------------------" >> "$SUMMARY"
echo "Full detail + HTML report: target/criterion/report/index.html" >> "$SUMMARY"

echo
echo "==================  $SUMMARY  =================="
cat "$SUMMARY"
echo "================================================"
echo "Paste $SUMMARY back to finalize the paper's benchmark table."
