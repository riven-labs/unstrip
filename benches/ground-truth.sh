#!/usr/bin/env bash
# Build unstripped equivalents of the corpus binaries, then diff `nm`'s
# symbol list against unstrip's recovered functions.
#
# Reports per binary:
#   - count of functions nm sees (ground truth)
#   - count unstrip recovers
#   - missing-from-unstrip count (functions in nm not in unstrip)
#   - extra-in-unstrip count (recovered functions not in nm; usually runtime helpers nm doesn't bother emitting)
#   - match rate
#
# Output: a markdown table on stdout.

set -u

UNSTRIP="${UNSTRIP:-$HOME/unstrip-target/release/unstrip}"
WORKDIR="$HOME/ground-truth"
mkdir -p "$WORKDIR"

emit_row() {
    local name="$1" nm_count="$2" unstrip_count="$3" missing="$4" extra="$5"
    local rate=0
    if [ "$nm_count" -gt 0 ]; then
        rate=$(echo "scale=2; ($nm_count - $missing) * 100 / $nm_count" | bc)
    fi
    echo "| $name | $nm_count | $unstrip_count | $missing | $extra | ${rate}% |"
}

build_and_compare() {
    local name="$1" stripped_path="$2" unstripped_path="$3"
    if [ ! -f "$unstripped_path" ]; then
        echo "skip: $name (no unstripped binary)" >&2
        return
    fi
    local nm_list="$WORKDIR/${name}.nm.txt"
    local unstrip_list="$WORKDIR/${name}.unstrip.txt"
    # nm: print only T (global text) symbols. The 't' (local text) entries
    # are compiler-emitted helpers and trampolines that pclntab doesn't
    # always carry, so comparing against T-only is the fair baseline for
    # "did we recover every function the linker named?"
    nm --defined-only "$unstripped_path" 2>/dev/null | awk '$2 == "T" {print $3}' | sort -u > "$nm_list"
    "$UNSTRIP" "$stripped_path" 2>/dev/null | awk '{print $2}' | sort -u > "$unstrip_list"
    local nm_count=$(wc -l < "$nm_list")
    local unstrip_count=$(wc -l < "$unstrip_list")
    local missing=$(comm -23 "$nm_list" "$unstrip_list" | wc -l)
    local extra=$(comm -13 "$nm_list" "$unstrip_list" | wc -l)
    emit_row "$name" "$nm_count" "$unstrip_count" "$missing" "$extra"
}

echo "| Binary | nm functions (truth) | unstrip recovered | missing | extra | match rate |"
echo "| --- | ---: | ---: | ---: | ---: | ---: |"

# Build hello unstripped (we already have stripped)
TESTDATA=/mnt/c/Users/mdaif/Documents/Projects/Riven/Public/unstrip/testdata
go build -o "$WORKDIR/hello.unstripped" "$TESTDATA/hello.go" 2>/dev/null
build_and_compare hello "$HOME/corpus/hello.linux-amd64.stripped" "$WORKDIR/hello.unstripped"

# hello with go1.18
~/go/bin/go1.18 build -o "$WORKDIR/hello.go118.unstripped" "$TESTDATA/hello.go" 2>/dev/null
build_and_compare hello.go118 "$HOME/corpus/hello.go118.stripped" "$WORKDIR/hello.go118.unstripped"

# inline3
(cd "$TESTDATA/inline3" && go build -o "$WORKDIR/inline3.unstripped" . 2>/dev/null)
build_and_compare inline3 "$HOME/corpus/inline3.linux-amd64.stripped" "$WORKDIR/inline3.unstripped"

# complex
(cd "$TESTDATA/complex" && go build -o "$WORKDIR/complex.unstripped" . 2>/dev/null)
build_and_compare complex "$HOME/corpus/complex.linux-amd64.stripped" "$WORKDIR/complex.unstripped"

# depsdemo
(cd "$TESTDATA/depsdemo" && go build -o "$WORKDIR/depsdemo.unstripped" . 2>/dev/null)
build_and_compare depsdemo "$HOME/corpus/depsdemo.rebuild1.stripped" "$WORKDIR/depsdemo.unstripped"

# OSS tools: rebuild without -s -w using go install
echo "building unstripped OSS tools..." >&2
go install filippo.io/mkcert@v1.4.4 2>/dev/null && cp "$HOME/go/bin/mkcert" "$WORKDIR/mkcert.unstripped"
build_and_compare mkcert "$HOME/corpus/mkcert.linux-amd64.stripped" "$WORKDIR/mkcert.unstripped"

go install github.com/cli/cli/v2/cmd/gh@v2.55.0 2>/dev/null && cp "$HOME/go/bin/gh" "$WORKDIR/gh.unstripped"
build_and_compare gh "$HOME/corpus/gh.linux-amd64.stripped" "$WORKDIR/gh.unstripped"

go install github.com/caddyserver/caddy/v2/cmd/caddy@v2.8.4 2>/dev/null && cp "$HOME/go/bin/caddy" "$WORKDIR/caddy.unstripped"
build_and_compare caddy "$HOME/corpus/caddy.linux-amd64.stripped" "$WORKDIR/caddy.unstripped"

go install helm.sh/helm/v3/cmd/helm@v3.15.4 2>/dev/null && cp "$HOME/go/bin/helm" "$WORKDIR/helm.unstripped"
build_and_compare helm "$HOME/corpus/helm.linux-amd64.stripped" "$WORKDIR/helm.unstripped"

# Sliver client (no -s -w)
if [ -d "$HOME/sliver-src" ]; then
    (cd "$HOME/sliver-src" && GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -mod=vendor -trimpath -o "$WORKDIR/sliver-client.unstripped" ./client 2>/dev/null)
    build_and_compare sliver-client "$HOME/corpus/sliver-client.linux-amd64.stripped" "$WORKDIR/sliver-client.unstripped"
fi
