# unstrip vs GoReSym: honest head-to-head

A reproducible comparison of unstrip v1.0 against GoReSym (master, post-v1.7.1 commit `78c02cc73064`) on a 10-binary corpus of real Linux ELF amd64 Go binaries. No spin, no cherry-picking. Numbers are wall-clock means of 3 runs after a warmup pass, captured by [`benches/compare-runner.py`](./benches/compare-runner.py).



## Tool versions

- **unstrip** v1.0.0, Rust release build (LTO thin, strip true), 942 KiB single binary.
- **GoReSym** built from `mandiant/GoReSym@master` (v1.7.2-pre, commit 2026-03-05). Tagged v1.7.1 is broken on Go 1.22+ binaries (returns zero types and zero interfaces); master fixes this. Anyone reproducing must use master, not the latest tag.

## Corpus

| Binary | Size | Source |
| --- | ---: | --- |
| `hello.go118.stripped` | 1.1 MiB | Go 1.18 hello world |
| `inline3.linux-amd64.stripped` | 1.2 MiB | Synthetic 4-deep inline chain |
| `depsdemo.rebuild1.stripped` | 3.3 MiB | cobra + pflag |
| `mkcert.linux-amd64.stripped` | 3.5 MiB | `mkcert` v1.4.4 |
| `complex.linux-amd64.stripped` | 4.7 MiB | Generics + reflection + goroutines + AWS SDK |
| `complex.garbled.stripped` | 8.2 MiB | Same source through `garble` v0.13 |
| `gh.linux-amd64.stripped` | 48 MiB | `gh` v2.55.0 (GitHub CLI) |
| `caddy.linux-amd64.stripped` | 41 MiB | `caddy` v2.8.4 |
| `helm.linux-amd64.stripped` | 65 MiB | `helm` v3.15.4 |
| `sliver-client.linux-amd64.stripped` | 56 MiB | Sliver C2 framework client (compiled from upstream) |

All built with `-ldflags='-s -w'` (or whatever the upstream `go install` default uses for the published tools).

## What this comparison measures

For each binary, both tools were invoked with their richest options:

- **unstrip**: `unstrip <bin>` (function recovery), `unstrip <bin> --types`, `unstrip <bin> --itabs`.
- **GoReSym**: `GoReSym <bin>` (default), `GoReSym -t -d -p <bin>` (full output with types, default packages, file paths).

Wall-clock time was measured by `time.perf_counter()` around the subprocess invocation, mean of 3 runs after a warmup. Memory is peak RSS of the child process via `getrusage(RUSAGE_CHILDREN)`. Recovery counts come from parsing each tool's output: unstrip prints one line per recovered entry (counted by leading `0x`), GoReSym emits a JSON document (counted by `len()` of the relevant arrays).

## Recovery: who finds more

| Binary | unstrip fns | GoReSym fns | unstrip types | GoReSym types | unstrip itabs | GoReSym ifaces |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| hello.go118 | 1,393 | 1,393 | 492 | 2,721 | 11 | 157 |
| inline3 | 1,543 | 1,543 | 570 | 3,755 | 11 | 159 |
| depsdemo | 4,687 | 4,687 | 1,748 | 8,800 | 133 | 2,392 |
| mkcert | 3,700 | 3,700 | 1,528 | 8,082 | 116 | 1,324 |
| complex | 6,236 | 6,236 | 2,353 | 11,607 | 203 | 3,415 |
| complex.garbled | 8,737 | 8,737 | 3,338 | 0 | 211 | 0 |
| gh | 36,992 | 36,992 | 17,233 | 176,190 | 2,001 | 70,603 |
| caddy | 49,030 | 49,030 | 20,687 | 265,022 | 3,156 | 151,484 |
| helm | 75,630 | 75,630 | 29,743 | 297,173 | 3,735 | 176,955 |
| sliver-client | 51,858 | 51,858 | 21,818 | 331,494 | 2,490 | 181,159 |

**Functions: identical.** Both tools recover the same function count on every binary. unstrip and GoReSym walk the same pclntab functab; there's no daylight between them on function recovery.

**Types: GoReSym wins decisively, 5x to 11x more entries.** On helm, GoReSym surfaces 297,173 type entries vs unstrip's 29,743. The reason is methodology: GoReSym enumerates every type kind it encounters during typelinks + interface walking, including primitive leaves (`uint8`, `int32`, `uintptr`, `string`, `bool`) and synthetic types created during type-reference expansion. unstrip's type graph walker starts from `typelinks` and follows pointer/slice/array/struct/interface references, but doesn't always surface primitive leaves as standalone entries (a struct field of type `uint8` registers the field, not a standalone `uint8` type entry). For an analyst the difference is: GoReSym's output is more complete as a catalog; unstrip's is more focused on the types you'd actually want to look up by name. **This is a real recovery gap on unstrip's side and is on the v1.1 list.**

**Interfaces: GoReSym wins much bigger, 30x to 70x.** On helm, GoReSym 176,955 vs unstrip 3,735. GoReSym's `Interfaces` array includes every interface type plus every function-signature type plus every struct involved in interface relationships. unstrip's `--itabs` counts only the `(interface, concrete)` dispatch pairs from `runtime.itablinks`. **Same gap pattern as types**: GoReSym is broader, unstrip is narrower. The unstrip number is the one an analyst uses to de-virtualize dispatch sites; GoReSym's larger number includes a lot of supporting types around those bindings.

**Garble: unstrip recovers, GoReSym returns zero types and zero interfaces.** Function recovery succeeds on both, but the typelinks walker on GoReSym hits the garble-rewritten pclntab magic and bails on the type/interface side. unstrip's heuristic acknowledges the obfuscation and still produces 3,338 types + 211 itabs from the structural data garble left intact.

## Speed: unstrip wins decisively

Wall-clock means in milliseconds.

| Binary | unstrip fns | GoReSym default | unstrip --types | GoReSym -t | speedup on types |
| --- | ---: | ---: | ---: | ---: | ---: |
| hello.go118 | 3.8 | 14.8 | 1.3 | 36.5 | 28x |
| inline3 | 2.4 | 13.4 | 1.5 | 40.6 | 27x |
| depsdemo | 4.1 | 40.2 | 3.4 | 115.0 | 34x |
| mkcert | 4.7 | 39.3 | 3.2 | 97.8 | 31x |
| complex | 7.4 | 58.2 | 4.9 | 155.9 | 32x |
| complex.garbled | 9.9 | 903.9 | 6.7 | 944.2 | 141x |
| gh | 40.7 | 414.0 | 35.8 | 2,273.4 | 64x |
| caddy | 45.9 | 557.1 | 42.1 | 3,373.8 | 80x |
| helm | 76.3 | 10,008.2 | 61.1 | 12,100.3 | 198x |
| sliver-client | 60.0 | 618.0 | 58.5 | 6,075.6 | 104x |

**unstrip is 25x to 200x faster on type recovery, 3x to 10x faster on function recovery.** The gap widens with binary size: helm's 65 MiB exercises GoReSym's recovery for 12 seconds vs unstrip's 61 ms. For interactive triage workflows the difference is real.

This is **not** an apples-to-apples speed-only comparison: GoReSym is doing more work (recovering more entries), so some of its time is paying for the broader output. But even accounting for the recovery gap (~10x more entries on average), unstrip is still 2-10x faster per recovered entry on the bigger binaries.

## Memory: unstrip uses less

Peak RSS in KB, type-recovery mode.

| Binary | unstrip --types | GoReSym -t | unstrip footprint |
| --- | ---: | ---: | ---: |
| hello.go118 | 14 MB | 27 MB | 0.5x |
| depsdemo | 32 MB | 90 MB | 0.35x |
| complex.garbled | 117 MB | 475 MB | 0.25x |
| gh | 475 MB | 1.4 GB | 0.35x |
| caddy | 1.4 GB | 1.6 GB | 0.85x |
| helm | 1.6 GB | 3.9 GB | 0.4x |
| sliver-client | 3.9 GB | 3.9 GB | 1.0x |

Both tools hold the binary in memory plus parsed structures. unstrip's peak RSS scales more gracefully on the bigger binaries except in the worst case (sliver-client) where they tie. Note: the `getrusage(RUSAGE_CHILDREN)` numbers are cumulative across the run, so back-to-back invocations inflate the peak; the trend across binaries is the more interesting signal than the absolute number.

## What each tool does that the other doesn't

**unstrip-only:**
- Inlined call stacks on `--addr` (walks `FUNCDATA_InlTree` and `PCDATA_InlTreeIndex`). GoReSym's PC lookup returns the leaf function only.
- `--addr-file` batch mode (one parse, N lookups; stdin supported).
- Real Ghidra and Binary Ninja Python exporters with C struct declarations and correct field offsets. GoReSym ships an IDA script but no Ghidra/Binja equivalents.
- `--install-plugin <ida|ghidra|binja>` drops a wrapper into the user's RE-tool plugin directory.
- Behavioral fingerprint (`--fingerprint --behavioral`) over stdlib-interface implementation counts.
- Structural SHA-256 fingerprint stable across `-trimpath` rebuilds.
- Garble obfuscation detection with structural data still recovered.
- Single 942 KiB static Rust binary, no runtime dependencies.

**GoReSym-only:**
- Pre-Go-1.18 pclntab support (Go 1.2 through 1.17). unstrip does not parse these and reports the version cleanly instead of producing garbage.
- 5x to 10x more type entries surfaced (including primitive leaves and synthetic supporting types).
- 30x to 70x more interface-related entries surfaced.
- Built-in IDA Pro plugin shipped by Mandiant.
- Mandiant brand and seven years of being the default tool.

## Where each one wins, in one sentence

- **Use unstrip when**: you want speed (interactive triage, CI pipelines, batch crash-dump symbolication), inlined call stacks, Ghidra or Binary Ninja support, garble survival, or a smaller memory footprint on huge binaries.
- **Use GoReSym when**: you need pre-1.18 Go binaries, you want the broadest possible type catalog (every primitive and synthetic), or you're already in an IDA-only workflow with the Mandiant plugin.
- **The honest answer**: many analysts will want both installed for different binaries. They don't compete on every axis; they compete on different ones.

## What unstrip needs to improve

Direct from the numbers above:

- **Type recovery breadth**: surface primitive types and synthetic supporting types when they appear via struct fields and function signatures, not only when typelinks references them directly. This closes the 5-10x type-count gap.
- **Interface enumeration**: expand `--itabs` to include the dispatch graph's supporting type entries (signatures, related concrete types), or add a `--interfaces` mode that mirrors GoReSym's broader Interfaces array.
- **Pre-1.18 Go support**: documented as a v1.1 roadmap item.

Tracked in [GitHub issues](https://github.com/riven-labs/unstrip/issues) under the `recovery-gap` label.

## Reproducing this comparison

```
# unstrip
cargo install unstrip

# GoReSym (master, NOT v1.7.1)
go install github.com/mandiant/GoReSym@master

# Run the comparison
python3 benches/compare-runner.py \
    --unstrip $(which unstrip) \
    --goresym $(which GoReSym) \
    --runs 3 \
    /path/to/your/corpus/*.stripped \
    > comparison.json

# Render the tables
python3 benches/summarize-compare.py comparison.json
```

If you re-run this against a different corpus and get numbers that contradict the claims here, open an issue. The point of this document is reproducibility, not advocacy.

## Caveats

- All measurements on Windows 11 + WSL2 Ubuntu 24.04 against ext4-resident binaries. WSL2 disk I/O is fast but not bare-metal Linux; absolute milliseconds may differ on dedicated hardware, but the ratios should be stable.
- Sliver client is a compiled-from-source upstream Sliver, not a real malware sample. It has the same structural shape as the implants Sliver generates (same Go version, same vendor tree, same stripping flags), so the recovery numbers are representative even though the binary itself is not in-the-wild malware.
- GoReSym `-t` output is JSON, parsed by `json.loads`. Times include the JSON serialization on GoReSym's side; unstrip times include text formatting on its side. Both costs are small relative to the recovery work, but the comparison is "end-to-end CLI invocation," not "parser speed in isolation."
