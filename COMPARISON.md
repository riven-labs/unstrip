# unstrip compared to GoReSym, gore, and redress

Numeric benchmarks are deferred until we publish a reproducible test setup. This file covers categorical differences only. Every claim below is verifiable against the cited tool's repository.

If you re-run a categorical claim against the current upstream and find it stale, open an issue. Upstream tools move; the responsibility for keeping this honest is ours.

## What each tool is, briefly

- **unstrip**. Rust CLI. Reads pclntab, moduledata, typelinks, itablinks. Targets stripped Go binaries on ELF, Mach-O, and PE.
- **[GoReSym](https://github.com/mandiant/GoReSym)**. Go CLI by Mandiant. The longest-running tool in this space; recovers function table, type metadata, build info from stripped Go binaries.
- **[gore](https://github.com/goretk/gore)**. Go library, not a CLI. Provides the analysis primitives that other tools (notably redress) consume.
- **[redress](https://github.com/goretk/redress)**. Go CLI. Built on top of `gore`. Targets the same problem space as GoReSym and unstrip.

## What each tool does that the others don't

Sourced from each tool's README and repository as of late May 2026. Claims you can verify yourself by visiting the linked repos.

### unstrip-only

- **`--data-at <addr>` with symbolic interpretation.** Walks bytes at a data address through the recovered itab table, function table, and section map. Modes for raw bytes, qwords with symbolization, Go interface headers (resolved to concrete type with the dispatched method body address inline), slice headers, and Go string headers with quoted previews.
- **`--xref-readers` / `--xref-writers <addr>`.** Scans `.text` for amd64 RIP-relative instructions touching a data address. Hits are categorized as LEA, MOV-load, MOV-store, CMP, or indirect CALL/JMP, each attributed to the containing function.
- **`--itabs (reachable)`/`(unreachable)` annotation.** Marks each recovered itab based on whether its address is referenced from `.text` or any data section. Surfaces dead itabs that the Go linker happened to leave behind.
- **Inlined call stacks on `--addr`.** Walks `FUNCDATA_InlTree` and `PCDATA_InlTreeIndex` to return the full inline chain for a PC, not just the leaf function.
- **`--addr-file` batch reverse-lookup.** One pclntab parse, N PC lookups, stdin supported.
- **Built-in Ghidra, IDA, and Binary Ninja Python exporters via `--format`.** Emits a script that creates functions, sets names, attaches `file:line` comments, and declares struct types with field offsets in the disassembler's namespace.
- **`--install-plugin <ida|ghidra|binja>`** drops a wrapper plugin into the user's RE-tool plugin directory.
- **`--dispatch-resolver ghidra`.** Emits a Ghidra script that, when invoked at a virtual call site, prints every recovered itab whose method table contains the dereferenced slot.
- **`--symbols-as elf|pe`** rewrites the binary with a synthetic ELF `.symtab`+`.strtab` or COFF symbol table so `nm`, `gdb`, `objdump --syms`, `perf`, eBPF stack traces, and `delve` see the recovered names.
- **`--detect-garble` with exit-code contract** (0 garbled, 1 clean, 2 indeterminate). Useful as a CI gate.
- **`--fingerprint --behavioral`** over the stdlib-interface implementation-count vector. Garble-stable, useful for clustering rebuilds.
- **Single static Rust binary, no runtime dependencies.**

### GoReSym-only

- **Pre-Go-1.18 pclntab support.** GoReSym's README states "pclntab parsing: >= Go 1.2" and "moduledata type parsing: >= Go 1.5". unstrip does not parse pre-1.18 layouts.
- **`-strings` flag** for extracting strings (added February 2026 per repo commit history). unstrip ships a comparable `--strings` walker; GoReSym's version arrived later.
- **Long history and ecosystem fit.** Mandiant has shipped GoReSym since 2022; it's the tool most existing analyst workflows already integrate with.

### gore-only

- **Library-first design.** Other Go programs can import `gore` directly. unstrip's library API (Rust crate) is the analogous interface but only available to Rust consumers.

### redress-only

- **radare2 integration via r2pipe.** redress can run inside a radare2 session.

## Notes on commonly-asked claims

These are claims that appear in casual comparisons of these tools but that we either could not verify or that need a footnote.

- **"GoReSym only ships an IDA exporter."** False. GoReSym's repository ships `IDAPython/`, `GhidraPython/`, and `BinjaPython/` folders. All three RE tools are supported.
- **"gore supports Go 1.2+."** Partially false. gore's README states versions prior to Go 1.5 are not supported; 1.5 and 1.6 are partial; 1.7+ is fully supported.
- **"redress is unmaintained."** As of late May 2026 redress receives automated dependency bumps to track gore. Whether feature work is active is a separate question; the project has not gone silent.
- **GoReSym garble handling.** GoReSym's README does not document garble detection or recovery. We do not claim either way; if you need to know, test it on your sample.
- **Inlined-call-stack behavior on PC lookup.** We have not source-read GoReSym's lookup path to verify whether it walks the inline tree. unstrip walks it; whether GoReSym does is an open question we did not investigate.

## When to reach for which

Use-case fit, not a winner-takes-all ranking. Each tool has a shape; pick the one whose shape matches your job.

**Reach for unstrip when** you want the data-side analysis surface (`--data-at` with symbolic resolution, `--xref-readers`/`--xref-writers`, itab reachability), when you want all three RE-tool exporters from a single Rust binary, when you need the inlined call stack on a PC lookup, when you want garble-aware behavior with exit-code semantics for CI, or when batch PC resolution (`--addr-file`) matters.

**Reach for GoReSym when** you have pre-Go-1.18 binaries to analyze, when your workflow is already centered on the Mandiant tool, or when you want the deepest type catalog including every primitive instantiation (GoReSym surfaces more catalog entries by counting primitive leaves and synthetic supporting types that unstrip's focused mode omits; pass `--types-full` on unstrip for comparable breadth).

**Reach for gore when** you're building another Go program that needs to parse Go binaries and you want a library, not a CLI subprocess.

**Reach for redress when** you live inside a radare2 session and want Go metadata available there directly.

## Reproducing categorical claims yourself

Each claim above can be checked in 30 seconds by visiting the cited repository's README or browsing its directory structure on GitHub:

- GoReSym: https://github.com/mandiant/GoReSym (check `IDAPython/`, `GhidraPython/`, `BinjaPython/` folders for the exporter claim; check the README for the pclntab version range)
- gore: https://github.com/goretk/gore (check the README's "Supported Go versions" section)
- redress: https://github.com/goretk/redress (check the README for the radare2 integration)
- unstrip: see the [README](./README.md) for every claim, and `--help` for the full flag surface

Numeric comparisons (recovery counts, wall-clock times, peak memory) will land when we publish the benchmark runner alongside the data.
