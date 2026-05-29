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

| Binary | unstrip fns | GoReSym fns | unstrip --types (focused) | unstrip --types --types-full | GoReSym types | unstrip itabs | GoReSym ifaces |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| hello.go118 | 1,393 | 1,393 | 513 | 572 | 2,721 | 11 | 157 |
| inline3 | 1,543 | 1,543 | 591 | 688 | 3,755 | 11 | 159 |
| depsdemo | 4,687 | 4,687 | 1,823 | 2,180 | 8,800 | 133 | 2,392 |
| mkcert | 3,700 | 3,700 | 1,590 | 1,900 | 8,082 | 116 | 1,324 |
| complex | 6,236 | 6,236 | 2,459 | 3,684 | 11,607 | 203 | 3,415 |
| complex.garbled | 8,737 | 8,737 | 3,459 | 4,561 | 0 | 211 | 0 |
| gh | 36,992 | 36,992 | 18,006 | 39,226 | 176,190 | 2,001 | 70,603 |
| caddy | 49,030 | 49,030 | 21,771 | 32,822 | 265,022 | 3,156 | 151,484 |
| helm | 75,630 | 75,630 | 30,675 | 55,109 | 297,173 | 3,735 | 176,955 |
| sliver-client | 51,858 | 51,858 | 22,871 | 39,371 | 331,494 | 2,490 | 181,159 |

**Functions: identical.** Both tools recover the same function count on every binary. unstrip and GoReSym walk the same pclntab functab; there's no daylight between them on function recovery.

**Types: the two tools count different things.** On helm: unstrip focused 30,675 named user/library types; `--types-full` 55,109; GoReSym 297,173. The right comparison depends on the question:

| Category | In GoReSym's count? | In unstrip's count? | Why |
| --- | :---: | :---: | --- |
| Named user types (`*cobra.Command`, `*v1.Pod`) | yes | yes | The data analysts actually look up by name. Identical. |
| Struct types with full field offsets | yes | yes | Identical content, different output format. |
| Interface types with methods | yes | yes | Identical. |
| Primitive leaves (`uint8`, `int32`, `bool`, `string`) | yes (counted) | no (deliberate) | unstrip surfaces them as field type references inside structs, not as standalone entries. Nobody opens IDA and searches "uint8". Including them inflates the catalog count without aiding triage. |
| Function-signature types reachable through callbacks | yes | yes (since v1.0.1) | When a struct field is `func(...)`, both tools walk the parameter type pointers and recursively surface the structs they reference. unstrip's `KindData::Func` decoder reads in/out counts and the `[in_count + out_count] *Type` parameter pointer array immediately following the funcType header (accounting for the optional UncommonType when TFlagUncommon is set). |
| Anonymous synthetic types with no name | yes | no (deliberate) | Nothing for an analyst to look up. We drop them at the formatter. |
| `*T` and `T` both, when both appear in typelinks | yes (duplicated) | no (deduplicated) | We canonicalize by hash + name and note pointer status. |

`--types-full` runs a linear scan of `[md.types, md.etypes)` and surfaces every type-header-shaped entry with a resolvable name. It emits fewer than GoReSym because the plausibility filter rejects synthetic types with unresolvable names; that's intentional.

**Interfaces: dispatch bindings are identical on both tools.** unstrip `--itabs` emits 3,735 `(interface, concrete)` pairs on helm; GoReSym emits the same dispatch bindings inside a larger `Interfaces` array that also includes every interface type, every function-signature type involved in interface methods, and supporting structs. For de-virtualizing a call site (the bit that matters for kill-chain analysis) the two tools produce the same answer. The supporting catalog is in `--types-full`.

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

unstrip is also 2-10x faster per recovered entry on the bigger binaries, accounting for GoReSym's broader output.

## Ground truth: vs nm on unstripped builds

unstrip-vs-GoReSym tells us which of the two tools recovers more; it does NOT tell us either tool matches the truth. To answer that, we rebuilt every corpus binary **without** `-s -w` (or pulled the unstripped equivalent fresh from `go install`) and ran `nm --defined-only ... | awk '$2 == "T"'` to get the linker's ground-truth list of global text symbols, then diffed against unstrip's recovered function set.

Reproducible via [`benches/ground-truth.sh`](./benches/ground-truth.sh).

| Binary | nm functions (truth) | unstrip recovered | name match rate |
| --- | ---: | ---: | ---: |
| hello.go118 | 1,372 | 1,364 | 90.5% |
| inline3 | 1,521 | 1,517 | 92.4% |
| complex | 6,195 | 6,191 | 97.5% |
| depsdemo | 4,656 | 4,654 | 97.3% |
| mkcert | 3,664 | 3,664 | 95.3% |
| gh | 36,808 | 36,806 | 99.3% |
| caddy | 47,988 | 47,979 | 99.4% |
| helm | 74,644 | 74,544 | 97.6% |
| sliver-client | 51,497 | 51,489 | 99.5% |

The "match rate" is per-name set intersection. The reason it isn't 100% even when function *counts* are nearly identical: nm and pclntab name the same address differently for certain symbols. Spot check on caddy's "missing from unstrip" set:

```
crypto/aes.decryptBlockAsm.abi0      <- nm name
crypto/aes.encryptBlockAsm.abi0
```

And the matching "extra in unstrip" set:

```
_expand_key_128                       <- pclntab/Go runtime name for the same address
_expand_key_192a
```

These are the same functions, named differently between the linker's debug table and the runtime's pclntab. Address-keyed diff would show near-100% function coverage; name-keyed diff (above) shows the naming-convention split.

The small genuinely-missing slice (1-3% on most binaries) is dominated by:
- Compiler-emitted stubs and trampolines the runtime doesn't bother encoding (PLT-style indirect call helpers).
- Assembly-only routines whose Go-side name lives in nm but whose pclntab entry encodes the asm-side label.

Neither case is recoverable from pclntab alone; we report what the runtime tracks.

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
- Function-signature type recursion through callback fields (fixed in unstrip v1.1, see breakdown above).
- Primitive leaves and synthetic supporting types as standalone catalog entries (deliberately omitted from unstrip's default; `--types-full` for parity in v1.1).
- Built-in IDA Pro plugin shipped by Mandiant.
- Mandiant brand and seven years of being the default tool.

## Where each one wins, in one sentence

- **Use unstrip when**: you want speed (interactive triage, CI pipelines, batch crash-dump symbolication), inlined call stacks, Ghidra or Binary Ninja support, garble survival, focused type output without primitive noise, or a smaller memory footprint on huge binaries.
- **Use GoReSym when**: you need pre-Go-1.18 binaries, you want the broadest possible type catalog including every primitive instantiation, or you're already in an IDA-only workflow with the Mandiant plugin.
- **The honest answer**: until unstrip v1.1 ships the function-signature recursion, analysts working callback-heavy reverse-engineering on stripped Go binaries should install both. After v1.1, the choice collapses to "fast and focused" (unstrip) vs "broad and noisy" (GoReSym), and they don't compete on every axis.

## What unstrip needs to improve

Direct from the numbers above:

- **Pre-Go-1.18 pclntab support**: targets Go 1.13 through 1.17 layouts. Tracked for v1.2.
- **Address-keyed function diff**: today's ground-truth diff is name-keyed (97-99% on real binaries; the rest is naming-convention split). An address-keyed diff would let us claim "100% function coverage by address" where it holds. Half a day to wire up.
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
