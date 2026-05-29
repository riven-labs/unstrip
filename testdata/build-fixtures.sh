#!/usr/bin/env bash
# Build the stripped Go binaries used by the integration tests.
# Requires the `go` toolchain on $PATH. Optional: `garble` on $PATH for the
# obfuscation-detection fixture.

set -euo pipefail

cd "$(dirname "$0")"

GO=${GO:-go}
GARBLE=${GARBLE:-garble}

if ! command -v "$GO" >/dev/null 2>&1; then
    echo "go toolchain not found on PATH; set GO=/path/to/go" >&2
    exit 1
fi

echo "go version: $($GO version)"

build_hello() {
    local goos=$1
    local goarch=$2
    local out=$3
    echo "building $out ($goos/$goarch)"
    GOOS=$goos GOARCH=$goarch "$GO" build -ldflags='-s -w' -o "$out" hello.go
}

build_hello_pie() {
    local out=$1
    echo "building $out (linux/amd64 PIE)"
    GOOS=linux GOARCH=amd64 "$GO" build -buildmode=pie -ldflags='-s -w' -o "$out" hello.go
}

build_hello linux   amd64 hello.linux-amd64.stripped
build_hello linux   arm64 hello.linux-arm64.stripped
build_hello darwin  amd64 hello.darwin-amd64.stripped
build_hello darwin  arm64 hello.darwin-arm64.stripped
build_hello windows amd64 hello.windows-amd64.stripped.exe
build_hello_pie     hello.linux-amd64.pie.stripped

# A fixture with real third-party deps so we can exercise buildinfo, itabs,
# and type recovery against something richer than `hello`.
if [ -d depsdemo ]; then
    echo "building depsdemo.linux-amd64.stripped"
    (cd depsdemo && GOOS=linux GOARCH=amd64 "$GO" build -ldflags='-s -w' -o ../depsdemo.linux-amd64.stripped .)
else
    echo "depsdemo/ not present; skipping the deps fixture"
fi

# Optional: garble-built fixture for obfuscation-detection tests.
if command -v "$GARBLE" >/dev/null 2>&1 && [ -d depsdemo ]; then
    echo "building depsdemo.garbled.stripped"
    (cd depsdemo && "$GARBLE" -literals build -ldflags='-s -w' -o ../depsdemo.garbled.stripped .)
fi

echo "done. fixtures written to $(pwd)"
