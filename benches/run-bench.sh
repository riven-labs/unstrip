#!/usr/bin/env bash
# Benchmark unstrip against a corpus of real Go binaries.
#
# Usage: bash benches/run-bench.sh <unstrip-binary> <corpus-dir> [output-dir]
#
# Produces:
#   bench-results/<binary>/info.txt
#   bench-results/<binary>/buildinfo.txt
#   bench-results/<binary>/types-count.txt
#   bench-results/<binary>/itabs-count.txt
#   bench-results/<binary>/timings.json    (from hyperfine)
#
# Requires `hyperfine` on PATH. Skips per-feature timing if it's not present.

set -euo pipefail

UNSTRIP=${1:?unstrip binary path required}
CORPUS=${2:?corpus dir required}
OUT=${3:-bench-results}

mkdir -p "$OUT"

shopt -s nullglob
binaries=("$CORPUS"/*.stripped "$CORPUS"/*.stripped.exe)
if [ ${#binaries[@]} -eq 0 ]; then
    echo "no .stripped binaries found in $CORPUS"
    exit 1
fi

have_hyperfine=0
if command -v hyperfine >/dev/null 2>&1; then
    have_hyperfine=1
fi

for bin in "${binaries[@]}"; do
    name=$(basename "$bin")
    dir="$OUT/$name"
    mkdir -p "$dir"
    size=$(stat -c%s "$bin" 2>/dev/null || stat -f%z "$bin")
    echo "=== $name ($(numfmt --to=iec-i --suffix=B "$size" 2>/dev/null || echo "${size} bytes")) ==="

    "$UNSTRIP" "$bin" --info             > "$dir/info.txt"      2> "$dir/info.err"      || echo "  info failed"
    "$UNSTRIP" "$bin" --buildinfo        > "$dir/buildinfo.txt" 2> "$dir/buildinfo.err" || echo "  buildinfo failed"
    "$UNSTRIP" "$bin" --fingerprint      > "$dir/fingerprint.txt" 2> "$dir/fingerprint.err" || echo "  fingerprint failed"

    fc=$("$UNSTRIP" "$bin" 2>/dev/null | wc -l || echo 0)
    echo "$fc" > "$dir/function-count.txt"

    tc=$("$UNSTRIP" "$bin" --types 2>/dev/null | grep -c "^0x" || echo 0)
    echo "$tc" > "$dir/types-count.txt"

    ic=$("$UNSTRIP" "$bin" --itabs 2>/dev/null | wc -l || echo 0)
    echo "$ic" > "$dir/itabs-count.txt"

    echo "  size=$size functions=$fc types=$tc itabs=$ic"

    if [ "$have_hyperfine" = "1" ]; then
        hyperfine --warmup 1 --runs 3 -i --export-json "$dir/timings.json" \
            -n functions   "$UNSTRIP $bin > /dev/null" \
            -n info        "$UNSTRIP $bin --info > /dev/null" \
            -n buildinfo   "$UNSTRIP $bin --buildinfo > /dev/null" \
            -n types       "$UNSTRIP $bin --types > /dev/null" \
            -n itabs       "$UNSTRIP $bin --itabs > /dev/null" \
            -n fingerprint "$UNSTRIP $bin --fingerprint > /dev/null" \
            -n behavioral  "$UNSTRIP $bin --fingerprint --behavioral > /dev/null" \
            > "$dir/hyperfine.txt" 2>&1 || echo "  hyperfine partial fail (one or more features errored)"
    fi
done

echo
echo "results in $OUT/"
