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

# Cross-width and cross-endian featureset builds (interfaces+itabs+types), to
# pin moduledata, itab, and type recovery on a 32-bit pointer width (386) and a
# big-endian byte order (s390x), not just 64-bit little-endian amd64.
build_featureset() {
    local goos=$1
    local goarch=$2
    local out=$3
    echo "building $out ($goos/$goarch)"
    GOOS=$goos GOARCH=$goarch "$GO" build -ldflags='-s -w' -o "$out" featureset.go
}

build_featureset linux 386   featureset.linux-386.stripped
build_featureset linux s390x featureset.linux-s390x.stripped

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

build_hello_version go1.16.15 hello.go116.stripped
build_hello_version go1.17.13 hello.go117.stripped
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

# typeset.go is featureset's interface/itab/struct content without generics, so it
# builds on Go 1.16 and 1.17 (which featureset cannot). It pins type and itab
# recovery on the pre-1.18 moduledata layout. Same optional-skip contract.
build_typeset_version() {
    local gobin=$1
    local out=$2
    if command -v "$gobin" >/dev/null 2>&1; then
        echo "building $out ($("$gobin" version | awk '{print $3}'))"
        GOOS=linux GOARCH=amd64 "$gobin" build -ldflags='-s -w' -o "$out" typeset.go
    else
        echo "$gobin not installed; skipping $out"
    fi
}

build_typeset_version go1.16.15 typeset.go116.stripped
build_typeset_version go1.17.13 typeset.go117.stripped

# typeset.go again with Go 1.2 to 1.15, which share one pclntab layout (magic
# 0xfffffffb) but differ in _func, moduledata (types from 1.7, textsectmap from
# 1.8) and itab (fun moved in 1.10). Go 1.8 and older Windows builds keep the
# pclntab inside .text. Writes typeset.go1NN.<goos>-<goarch>.stripped[.exe].
# A release is taken from ~/sdk/goX.Y.Z (where `goX.Y.Z download` puts it,
# and where a go.dev/dl archive can be unpacked by hand) or from its
# `goX.Y.Z` wrapper on PATH.
# Go 1.5 cross-compiles to every target below; Go 1.4 and older build only for
# the host, so their Linux fixtures need a Linux host (or WSL) with the
# linux-amd64 archive. Same optional-skip contract.
build_typeset_old() {
    local version=$1
    local sdk="$HOME/sdk/go$version"
    local gobin goroot
    if [ -x "$sdk/bin/go" ] || [ -x "$sdk/bin/go.exe" ]; then
        # An unpacked archive of Go 1.4 or older reports its compiled-in
        # GOROOT, not where it sits, so name it.
        gobin="$sdk/bin/go"
        goroot=$sdk
    elif command -v "go$version" >/dev/null 2>&1; then
        gobin="go$version"
        goroot=$("$gobin" env GOROOT)
    else
        echo "go$version not installed; skipping its typeset fixtures"
        return
    fi
    local tag minor hostos
    tag=go$(echo "$version" | awk -F. '{print $1 $2}')
    minor=$(echo "$version" | cut -d. -f2)
    hostos=$(GOROOT=$goroot "$gobin" env GOHOSTOS)
    local target
    for target in linux/amd64 linux/386 windows/amd64 windows/386; do
        local goos=${target%/*}
        local goarch=${target#*/}
        if [ "$minor" -lt 5 ] && { [ "$goos" != "$hostos" ] || [ "$goarch" != amd64 ]; }; then
            continue
        fi
        local out="typeset.$tag.$goos-$goarch.stripped"
        if [ "$goos" = windows ]; then
            out="$out.exe"
        fi
        echo "building $out (go$version)"
        GOROOT=$goroot GOOS=$goos GOARCH=$goarch CGO_ENABLED=0 GO111MODULE=off \
            "$gobin" build -ldflags='-s -w' -o "$out" typeset.go
    done
}

for version in 1.2.2 1.3.3 1.4.3 1.5.4 1.6.4 1.7.6 1.8.7 1.9.7 1.10.8 1.11.13 \
    1.12.17 1.13.15 1.14.15 1.15.15; do
    build_typeset_old "$version"
done

# funcinfo.go pins the per-function metadata readers (line table, ArgInfo,
# open-coded defers, inline tree, wrapper funcID) on each release whose layout
# differs: 1.17 (pre-1.18 _func, Go 1.14 defer record), 1.18 (no startLine,
# 20-byte inline records), 1.20 (1.20+ _func, Go 1.18 defer record), 1.22 (Go
# 1.22 defer record), and the toolchain on PATH. It has no generics so it builds
# with Go 1.17. Same optional-skip contract.
build_funcinfo_version() {
    local gobin=$1
    local out=$2
    if command -v "$gobin" >/dev/null 2>&1; then
        echo "building $out ($("$gobin" version | awk '{print $3}'))"
        GOOS=linux GOARCH=amd64 CGO_ENABLED=0 GOFLAGS=-trimpath \
            "$gobin" build -ldflags='-s -w' -o "$out" funcinfo.go
    else
        echo "$gobin not installed; skipping $out"
    fi
}

build_funcinfo_version go1.17.13 funcinfo.go117.stripped
build_funcinfo_version go1.18.10 funcinfo.go118.stripped
build_funcinfo_version go1.20.14 funcinfo.go120.stripped
build_funcinfo_version go1.22.12 funcinfo.go122.stripped
build_funcinfo_version "$GO" funcinfo.go126.stripped

# methodset.go pins method-table recovery for every kind a named type with
# methods can have (func, map, chan, array, slice, float, string, pointer): each
# kind puts its UncommonType at a different offset, and maps switched to the
# swiss-table MapType in Go 1.24. Built with each release whose map or method
# layout matters (1.17, 1.18, 1.20, 1.22 old maps; 1.24 and the toolchain on
# PATH swiss maps). No generics so it builds with Go 1.17. Same optional-skip
# contract.
build_methodset_version() {
    local gobin=$1
    local out=$2
    if command -v "$gobin" >/dev/null 2>&1; then
        echo "building $out ($("$gobin" version | awk '{print $3}'))"
        GOOS=linux GOARCH=amd64 CGO_ENABLED=0 GOFLAGS=-trimpath \
            "$gobin" build -ldflags='-s -w' -o "$out" methodset.go
    else
        echo "$gobin not installed; skipping $out"
    fi
}

build_methodset_version go1.17.13 methodset.go117.stripped
build_methodset_version go1.18.10 methodset.go118.stripped
build_methodset_version go1.20.14 methodset.go120.stripped
build_methodset_version go1.22.12 methodset.go122.stripped
build_methodset_version go1.24.13 methodset.go124.stripped
build_methodset_version "$GO" methodset.go126.stripped

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

# strlits.go puts string literals in each shape the compiler emits, for the
# `--strings` literal pairing: amd64 and arm64 on ELF, PE and Mach-O, 386
# (which has no instruction scanner yet), and Go 1.15 for the stack ABI. The
# Go 1.15 build comes from ~/sdk/go1.15.15 or the go1.15.15 wrapper and is
# skipped when neither is there.
build_strlits() {
    local goos=$1
    local goarch=$2
    local out=$3
    echo "building $out ($goos/$goarch)"
    GOOS=$goos GOARCH=$goarch CGO_ENABLED=0 GO111MODULE=off         "$GO" build -ldflags='-s -w' -o "$out" strlits.go
}

build_strlits linux   amd64 strlits.linux-amd64.stripped
build_strlits linux   arm64 strlits.linux-arm64.stripped
build_strlits linux   386   strlits.linux-386.stripped
build_strlits windows amd64 strlits.windows-amd64.stripped.exe
build_strlits darwin  arm64 strlits.darwin-arm64.stripped

if [ -x "$HOME/sdk/go1.15.15/bin/go" ] || [ -x "$HOME/sdk/go1.15.15/bin/go.exe" ]; then
    echo "building strlits.go115.linux-amd64.stripped (go1.15.15)"
    GOROOT="$HOME/sdk/go1.15.15" GOOS=linux GOARCH=amd64 CGO_ENABLED=0 GO111MODULE=off         "$HOME/sdk/go1.15.15/bin/go" build -ldflags='-s -w' -o strlits.go115.linux-amd64.stripped strlits.go
elif command -v go1.15.15 >/dev/null 2>&1; then
    echo "building strlits.go115.linux-amd64.stripped (go1.15.15)"
    GOOS=linux GOARCH=amd64 CGO_ENABLED=0 GO111MODULE=off         go1.15.15 build -ldflags='-s -w' -o strlits.go115.linux-amd64.stripped strlits.go
else
    echo "go1.15.15 not installed; skipping strlits.go115.linux-amd64.stripped"
fi

# typeid/ holds types that reference each other and two packages named sync,
# for type identity and Go-syntax rendering. The binary run with `dump`
# prints the reflect view the tests restate. Go 1.12 (a map record without a
# hasher) and Go 1.15 builds come from ~/sdk or the goX.Y.Z wrapper and are
# skipped when neither is there.
build_typeid() {
    local go=$1
    local goos=$2
    local goarch=$3
    local out=$4
    echo "building $out ($goos/$goarch, $("$go" version | cut -d' ' -f3))"
    (cd typeid && GOOS=$goos GOARCH=$goarch CGO_ENABLED=0 GO111MODULE=on         "$go" build -ldflags='-s -w' -o "../$out" .)
}

build_typeid "$GO" linux   amd64 typeid.linux-amd64.stripped
build_typeid "$GO" linux   arm64 typeid.linux-arm64.stripped
build_typeid "$GO" linux   386   typeid.linux-386.stripped
build_typeid "$GO" windows amd64 typeid.windows-amd64.stripped.exe
build_typeid "$GO" darwin  arm64 typeid.darwin-arm64.stripped

for version in 1.12.17 1.15.15; do
    short=go$(echo "$version" | cut -d. -f1-2 | tr -d .)
    out=typeid.$short.linux-amd64.stripped
    if [ -x "$HOME/sdk/go$version/bin/go" ] || [ -x "$HOME/sdk/go$version/bin/go.exe" ]; then
        GOROOT="$HOME/sdk/go$version" build_typeid "$HOME/sdk/go$version/bin/go" linux amd64 "$out"
    elif command -v "go$version" >/dev/null 2>&1; then
        build_typeid "go$version" linux amd64 "$out"
    else
        echo "go$version not installed; skipping $out"
    fi
done

# Optional: a reflected program built with garble, used to test recovery on
# obfuscated binaries: the magic is rewritten (structural pclntab discovery) and
# the moduledata uses the toolchain's layout. garble needs a matching Go
# toolchain; for Go 1.26 set GOTOOLCHAIN=local with a writable 1.26 GOROOT on
# PATH (see the garble notes). Skips when garble or the module is absent.
if command -v "$GARBLE" >/dev/null 2>&1 && [ -d gtest ]; then
    echo "building gtest.garbled.stripped"
    (cd gtest && GOOS=linux GOARCH=amd64 "$GARBLE" build -ldflags='-s -w' -o ../gtest.garbled.stripped .)
fi

# Plain build of the same reflected program: its Account struct carries json
# tags, so the struct-tag recovery test has a clean fixture.
if [ -d gtest ]; then
    echo "building gtest.plain.stripped"
    (cd gtest && GOOS=linux GOARCH=amd64 "$GO" build -ldflags='-s -w' -o ../gtest.plain.stripped .)
fi

echo "done. fixtures written to $(pwd)"
