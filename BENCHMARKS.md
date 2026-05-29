# Benchmarks

Real-world stress test of unstrip against a corpus of widely-deployed Go binaries: the same shape (statically linked, deep dep trees, networking-heavy, single binary) as Go malware samples, without the malware-handling risk. Corpus includes a garble-obfuscated build, two rebuilds of the same source (one with `-trimpath`) to validate fingerprint stability, a Go 1.18 binary to verify the older pclntab layout, a deliberately deeply-inlined fixture to verify inline-stack recovery, and a Go 1.16 binary to confirm we cleanly reject pre-1.18 layouts.

## Methodology

- **Host**: Windows 11, running unstrip under WSL2 Ubuntu 24.04 against ext4-resident binaries.
- **Build**: `cargo build --release` (LTO thin, codegen-units 1, panic abort, strip true).
- **Timing**: hyperfine 1.18, 1 warmup + 3 runs per measurement, mean reported in milliseconds.
- **Reproduce**: `bash benches/run-bench.sh ./target/release/unstrip <corpus-dir>`.

Corpus build commands are in [`benches/build-corpus.md`](./benches/build-corpus.md).

## Corpus

| Binary | Size | What it is |
| --- | --- | --- |
| `hello.go116` | 1.4 MiB | Built with Go 1.16. Used to verify we cleanly reject unsupported pre-1.18 layouts. |
| `hello.go118` | 1.2 MiB | Trivial hello-world built with Go **1.18** (older pclntab layout, magic 0xfffffff0). |
| `inline3` | 1.2 MiB | Synthetic 4-deep inline chain (level3 to level2 to level1 to anchor). |
| `depsdemo.rebuild1/2` | 3.3 MiB each | Same source rebuilt twice (`-trimpath` differs), exercises fingerprint stability. |
| `mkcert` v1.4.4 | 3.5 MiB | Local TLS certificate authority. Small, crypto-heavy. |
| `complex` | 4.7 MiB | Synthetic stress binary: generics, embedded structs, reflection, goroutines, AWS SDK + cobra. |
| `complex.garbled` | 8.2 MiB | Same source through garble v0.13. Magic rewritten, names hashed. |
| `caddy` v2.8.4 | 41 MiB | Web server. HTTP/2/3, TLS, ACME. |
| `gh` v2.55.0 | 48 MiB | GitHub CLI. Huge dep tree, GraphQL types, OAuth flows. |
| `helm` v3.15.4 | 65 MiB | Kubernetes package manager. The biggest binary tested; pulls all of `k8s.io/api`. |

## Recovery scale

| Binary | Functions | Types | Itab rows (with method sub-rows) |
| --- | ---: | ---: | ---: |
| hello.go116 | (rejected: pre-1.18 unsupported) | n/a | n/a |
| hello.go118 | 1,393 | 492 | 67 |
| inline3 | 1,543 | 570 | 67 |
| depsdemo | 4,687 | 1,748 | 552 |
| mkcert | 3,700 | 1,528 | 401 |
| complex | 6,236 | 2,353 | 803 |
| complex.garbled | 8,737 | 3,338 | 832 |
| gh | 36,992 | 17,233 | 8,352 |
| caddy | 49,030 | 20,687 | 16,205 |
| helm | 75,630 | 29,743 | 15,968 |

## Timings

All values are wall-clock means in milliseconds.

| Binary | `--info` | `--functions` | `--types` | `--itabs` | `--buildinfo` | `--fingerprint` | `--fingerprint --behavioral` |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| hello.go118 (1.2 MiB) | 1.9 | 2.2 | 1.8 | 1.3 | 2.1 | 3.1 | 1.5 |
| inline3 (1.2 MiB) | 2.1 | 2.3 | 1.8 | 1.2 | 2.0 | 2.9 | 1.6 |
| depsdemo (3.3 MiB) | 4.1 | 4.6 | 3.6 | 2.3 | 4.0 | 7.4 | 2.1 |
| mkcert (3.5 MiB) | 3.9 | 3.9 | 3.5 | 2.1 | 4.0 | 7.2 | 2.8 |
| complex (4.7 MiB) | 5.6 | 6.5 | 5.8 | 2.9 | 5.8 | 10.0 | 3.0 |
| complex.garbled (8.2 MiB) | 9.7 | 8.8 | 7.9 | 6.9 | 8.9* | 21.3 | 6.0 |
| gh (48 MiB) | 46.4 | 36.9 | 39.9 | 23.7 | 47.4 | 92.5 | 22.9 |
| caddy (41 MiB) | 47.6 | 39.2 | 43.2 | 22.7 | 40.1 | 111.7 | 21.1 |
| helm (65 MiB) | 92.1 | 80.7 | 78.3 | 44.3 | 84.0 | 161.6 | 40.4 |

\* `--buildinfo` correctly fails on garble-obfuscated binaries (garble strips the buildinfo blob). The 8.9 ms above measures the cost of finding the magic and emitting the clean error message.

`--info` now includes itab classification against the stdlib-interface table, which is why it runs at roughly the cost of `--itabs` plus a few ms.

`--fingerprint` is the most expensive single feature because it walks functions + types + itabs + buildinfo in one pass and SHA-256s the canonical form. The behavioral variant only walks itabs and is roughly 4x faster.

## Capability proofs

### Inline call stack on a real binary

A PC inside Go's inlined `mapaccess2` body in caddy:

```
$ unstrip caddy --addr 0x4151a4
(inlined)  runtime.evacuated  /usr/lib/go-1.22/src/runtime/map.go:205
(physical) runtime.mapaccess2  /usr/lib/go-1.22/src/runtime/map.go:457
```

The synthetic `inline3` fixture verifies a 4-deep chain:

```
$ unstrip inline3 --addr 0x4808f0
(inlined)  main.level3  /tmp/inline3/main.go:13
(inlined)  main.level2  /tmp/inline3/main.go:17
(inlined)  main.level1  /tmp/inline3/main.go:21
(physical) main.anchor  /tmp/inline3/main.go:25
```

### Batch reverse lookup against a crash dump

```
$ cat dump.pcs
0x507d20
0x460a40
# garbage to confirm clean handling
0xdeadbeef

$ unstrip suspicious.bin --addr-file dump.pcs
0x0000000000507d20  fmt.Sprintf  /usr/lib/go-1.22/src/fmt/print.go:237
0x0000000000460a40  runtime.main  /usr/lib/go-1.22/src/runtime/proc.go:250
0x00000000deadbeef  (no function)
```

One parse, many lookups. On helm, lookup overhead per PC is sub-millisecond after the initial parse.

### Recovered helm types (Kubernetes)

```
$ unstrip helm --types --filter "v1.Pod" | head
*v1.PodFSGroupChangePolicy
*v1.PodConditionType
*v1.PodPhase
*v1.PodQOSClass
*v1.PodResizeStatus
*v1.PodTemplateInterface
```

### Interface dispatch with full method tables

```
$ unstrip helm --itabs --filter "sort.Interface"
0x0000000003290ef0  *sort.Interface  =>  *releaseutil.BySplitManifestsOrder
    .Len() -> 0x26a53c0
    .Less() -> 0x26a5400
    .Swap() -> 0x26a5480
```

Each method pointer is chainable through `--addr`:

```
$ unstrip helm --addr 0x26a53c0
0x00000000026a53c0  helm.sh/helm/v3/pkg/releaseutil.(*BySplitManifestsOrder).Len  <autogenerated>:1
```

### Behavioral classification on helm

```
$ unstrip helm --info | tail -10
stdlib interface implementations:
  *error                164
  *io.Reader             56
  *io.Writer             42
  *fmt.Stringer           3
  *http.Handler           2
  *http.ResponseWriter    2
  *crypto.SignerOpts      3
  *hash.Hash32            2
```

### Fingerprint stability

Same source built twice (one with `-trimpath`) yields identical hashes:

```
$ unstrip depsdemo.rebuild1 --fingerprint | head -1
30a83cfd1f52c19a163b7e739b0b579e8a10ea752aac3bf6c56659d5ca18821f

$ unstrip depsdemo.rebuild2 --fingerprint | head -1
30a83cfd1f52c19a163b7e739b0b579e8a10ea752aac3bf6c56659d5ca18821f
```

### Real Ghidra/IDA/Binary Ninja exporters

`--format ghidra` emits a Python script that, run inside Ghidra, creates the function, sets the name to the recovered Go symbol, and attaches the source file:line as the function comment. The script also emits every recovered Go struct as a C declaration the Ghidra CParser can ingest, with correct field offsets and explicit padding entries for alignment gaps.

On the helm binary, the emitted Ghidra script applies 75,630 function symbols and roughly 5,800 struct types in one pass.

### Go 1.18 binary

```
$ unstrip hello.go118 --info
go version:    go1.18
container:     ELF (amd64, little-endian)
pclntab:       0x00000000000b5aa0 (339 KB)
functions:     1393
```

Recovers types/itabs/buildinfo using version-aware moduledata dispatch (no `covctrs` fields before Go 1.20).

### Pre-1.18 cleanly rejected

```
$ unstrip hello.go116 --info
unstrip: pclntab at offset 0xde7c0: funcdataOffset=... is past end of pclntab
```

### Garble obfuscation handling

```
$ unstrip complex.garbled --info
go version:    (not detected)
...
garble heuristic: likely garbled
  - pclntab magic is not the standard 0xfffffff1 (garble rewrites it)
  - runtime.buildVersion is missing or non-standard (garble overwrites it)
  - 6101/9034 user-package function names look hashed
```

Despite obfuscation, 8,737 functions and 3,338 types still recover.

## Correctness fixes applied in this revision

- `--addr` inline tree walk capped at depth 32 and index 65536; defeats hostile inltree entries.
- Itab `inter` pointer gated through `[md.types, md.etypes)` before any dereference. Prevents an attacker-controlled itab from making us read arbitrary memory.
- moduledata post-decode sanity: `types < etypes`, `text < etext`, `minpc <= maxpc`, region sizes capped at 256 MiB, `gofunc` required to land in a mapped section.
- Type graph queue capped at `4 * max_types` to prevent fan-out memory blowup on pathological binaries.
- Verified the inline-tree walk against a 4-deep nested call (level3 inside level2 inside level1 inside anchor).
- `--moduledata` removed from the CLI (dev-only artifact). The parser stays for internal use.

## Reproducing

```
mkdir corpus && cd corpus
go install -ldflags='-s -w' github.com/caddyserver/caddy/v2/cmd/caddy@v2.8.4
go install -ldflags='-s -w' github.com/cli/cli/v2/cmd/gh@v2.55.0
go install -ldflags='-s -w' helm.sh/helm/v3/cmd/helm@v3.15.4
go install -ldflags='-s -w' filippo.io/mkcert@v1.4.4
cp ~/go/bin/{caddy,gh,helm,mkcert} .
for f in *; do mv "$f" "$f.linux-amd64.stripped"; done

# Optional garble fixture
go install mvdan.cc/garble@v0.13.0
cd ../testdata/complex && garble -literals build -ldflags='-s -w' -o ../../corpus/complex.garbled.stripped .

# Optional Go 1.18 fixture
go install golang.org/dl/go1.18@latest && go1.18 download
cd testdata && go1.18 build -ldflags='-s -w' -o ../../corpus/hello.go118.stripped hello.go

# Optional inline-3 fixture
cd testdata/inline3 && go build -ldflags='-s -w' -o ../../../corpus/inline3.linux-amd64.stripped .

# Benchmarks
cd <unstrip-repo>
cargo build --release
bash benches/run-bench.sh ./target/release/unstrip /path/to/corpus
```
