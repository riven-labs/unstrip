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

# Per-version fixtures: the same hello.go built with specific Go releases, to
# pin parser behavior across the supported range. The pclntab magic and the
# moduledata layout differ between releases, so each version is its own case.
# Each build is optional; the integration test skips a version it can't find.
# Install a release with, e.g.:
#   go install golang.org/dl/go1.20.14@latest && go1.20.14 download
build_hello_version() {
    local gobin=$1
    local out=$2
    if command -v "$gobin" >/dev/null 2>&1; then
        echo "building $out ($("$gobin" version | awk '{print $3}'))"
        GOOS=linux GOARCH=amd64 "$gobin" build -ldflags='-s -w' -o "$out" hello.go
    else
        echo "$gobin not installed; skipping $out"
    fi
}

build_hello_version go1.18.10 hello.go118.stripped
build_hello_version go1.19.13 hello.go119.stripped
build_hello_version go1.20.14 hello.go120.stripped
build_hello_version go1.21.13 hello.go121.stripped
build_hello_version go1.22.0 hello.go122.stripped
build_hello_version go1.23.0 hello.go123.stripped
build_hello_version go1.24.0 hello.go124.stripped
build_hello_version go1.25.0 hello.go125.stripped
build_hello_version go1.26.0 hello.go126.stripped

# featureset.go is a richer program (interfaces+itabs, generics, struct methods,
# goroutines, crypto) built with every release, so the tests pin type, itab, and
# signature recovery across the whole range, not just function names. Same
# optional-skip contract as hello above.
build_featureset_version() {
    local gobin=$1
    local out=$2
    if command -v "$gobin" >/dev/null 2>&1; then
        echo "building $out ($("$gobin" version | awk '{print $3}'))"
        GOOS=linux GOARCH=amd64 "$gobin" build -ldflags='-s -w' -o "$out" featureset.go
    else
        echo "$gobin not installed; skipping $out"
    fi
}

build_featureset_version go1.18.10 featureset.go118.stripped
build_featureset_version go1.19.13 featureset.go119.stripped
build_featureset_version go1.20.14 featureset.go120.stripped
build_featureset_version go1.21.13 featureset.go121.stripped
build_featureset_version go1.22.0 featureset.go122.stripped
build_featureset_version go1.23.0 featureset.go123.stripped
build_featureset_version go1.24.0 featureset.go124.stripped
build_featureset_version go1.25.0 featureset.go125.stripped
build_featureset_version go1.26.0 featureset.go126.stripped

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

# Optional: a reflected program built with garble, used to test recovery on
# obfuscated binaries: the magic is rewritten (structural pclntab discovery) and
# the moduledata uses the toolchain's layout. garble needs a matching Go
# toolchain; for Go 1.26 set GOTOOLCHAIN=local with a writable 1.26 GOROOT on
# PATH (see the garble notes). Skips when garble or the module is absent.
if command -v "$GARBLE" >/dev/null 2>&1 && [ -d gtest ]; then
    echo "building gtest.garbled.stripped"
    (cd gtest && GOOS=linux GOARCH=amd64 "$GARBLE" build -ldflags='-s -w' -o ../gtest.garbled.stripped .)
fi

echo "done. fixtures written to $(pwd)"
