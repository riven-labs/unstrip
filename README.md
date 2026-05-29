# unstrip

> Recover symbols, types, interfaces, and module info from stripped Go binaries.

`strip` removes Go's symbol table but leaves the runtime metadata the program uses to print stack traces and to drive reflection: `.gopclntab`, the moduledata struct, the typelinks table, the itab table, and the buildinfo blob. `unstrip` reads all of it and gives you back what the linker tried to take away: function names with source files and line numbers, every Go type the program ships with its full struct layout, every `(interface, concrete)` pair the runtime uses to dispatch, and the module dependency tree.

It works on ELF, Mach-O, and PE; amd64 and arm64; non-PIE and PIE binaries; Go 1.18 through 1.25. It detects when the binary was processed by [garble](https://github.com/burrowers/garble) and tells you so, and still recovers what it can.

## Install

```
cargo install unstrip
```

Prebuilt binaries for Linux, macOS, and Windows are on the [releases page](https://github.com/riven-labs/unstrip/releases).

## Use

```
unstrip ./samples/hello.stripped
```

Function names, source files, line numbers, one function per line:

```
$ unstrip ./samples/hello.stripped
0x0000000000460a40  runtime.main                       runtime/proc.go
0x0000000000482560  main.main                          main.go
0x00000000004824a0  main.greet                         main.go
0x0000000000482520  main.parseFlags                    main.go
...
```

### Container, version, garble check

```
$ unstrip hello.stripped --info
go version:    go1.22.2
container:     ELF (amd64, little-endian)
pclntab:       0x00000000000c0c40 (405 KB)
functions:     1556
text start:    0x0000000000401000
ptr size:      8
quantum:       1
```

When the binary's been obfuscated, `--info` says so instead of pretending the symbols are real:

```
$ unstrip suspicious.bin --info
go version:    (not detected)
...
garble suspicion: 80%
  - pclntab magic is not the standard 0xfffffff1, garble rewrites it to defeat parsers
  - runtime.buildVersion is (missing), garble overwrites it
```

### Module dependency tree

```
$ unstrip ./samples/myapp --buildinfo
go version:    go1.22.2
path:          example.com/myapp
main module:   example.com/myapp  v1.4.2

dependencies (12)
  github.com/spf13/cobra          v1.8.0
  github.com/aws/aws-sdk-go-v2    v1.30.5
  github.com/jmespath/go-jmespath v0.4.0
  ...

build settings
  buildmode      exe
  GOOS           linux
  vcs            git
  vcs.revision   3f8a912...
  vcs.modified   false
```

### Types

This is the part that surprises people. From a stripped binary, with no debug info, with no debugging tooling installed:

```
$ unstrip ./samples/myapp --types --filter cobra.Command
0x00000000005c01a0  struct     size=728     *cobra.Command
    +0000  Use: type@0x589ec0
    +0010  Aliases: type@0x588960
    +0028  SuggestFor: type@0x588960
    +0040  Short: type@0x589ec0
    +0050  GroupID: type@0x589ec0
    ...
    +02c8  TraverseChildren: type@0x58a2c0
    +02c9  Hidden: type@0x58a2c0
    +02ca  SilenceErrors: type@0x58a2c0
    +02d0  SuggestionsMinimumDistance: type@0x58a100
```

Full struct layouts, including unexported fields. Field types are cross-referenced by address so you can navigate the type graph. JSON output is wired for tooling.

### Interfaces

The `(interface, concrete)` pairs the runtime uses for dispatch, what your dynamic dispatch sites actually go to:

```
$ unstrip ./samples/myapp --itabs --filter Writer
0x00000000005a18c8  *io.Writer        =>  *os.File
0x00000000005a1948  *io.Writer        =>  *bytes.Buffer
0x00000000005a19a8  *io.Writer        =>  *gzip.Writer
0x00000000005a1a08  *io.StringWriter  =>  *bufio.Writer
```

### Reverse PC lookup, with inline call stacks

For use inside a debugger, a crash dump parser, or a disassembly comment generator. When the PC lands in inlined code, you get the full call stack from the inline tree, not just the leaf:

```
$ unstrip caddy --addr 0x4151a4
(inlined)  runtime.evacuated  /usr/lib/go-1.22/src/runtime/map.go:205
(physical) runtime.mapaccess2  /usr/lib/go-1.22/src/runtime/map.go:457
```

For batch lookups against a crash dump, use `--addr-file`. One parse, N lookups:

```
$ cat crash.txt | unstrip suspicious.bin --addr-file -
(inlined)  io.copyBuffer  /usr/lib/go-1.22/src/io/io.go:418
(physical) io.Copy        /usr/lib/go-1.22/src/io/io.go:388
0x000000000045a200  net.(*conn).Read  /usr/lib/go-1.22/src/net/net.go:179
0x00000000004b8c40  main.handleClient  /tmp/build/main.go:42
```

If the runtime addresses came from an ASLR-rebased process, pass `--rebase <DELTA>` (the difference between actual load base and link-time preferred base) and unstrip translates back to the link-time VA on disk.

### Apply to your RE tool of choice

`--format ida`, `--format ghidra`, or `--format binja` emits a Python script that, run inside that tool, applies every recovered function (with file:line as a function comment) **and every recovered struct type** as a C declaration the tool's parser can ingest:

```
$ unstrip ./samples/myapp --format ghidra > apply.py
# In Ghidra: Window -> Script Manager -> Run apply.py
```

Function names sanitize down to valid disassembler labels; the original Go name (with parens, brackets, generics arguments) is preserved as a function comment.

### Behavioral classification

`--info` includes a count of stdlib interface implementations the binary ships. Useful for fast triage: "does this binary speak HTTP, do crypto, write files?"

```
stdlib interface implementations:
  *error            142
  *io.Reader         47
  *io.Writer         38
  *http.Handler      14
  *net.Conn          11
  *crypto.Signer      3
  ...
```

For clustering related binaries, `--fingerprint --behavioral` hashes that count vector into a SHA-256. Two binaries with the same stdlib-interface shape produce the same behavioral hash. Coarser than the regular fingerprint; use as a clustering signal, not a unique ID. Not garble-stable (garble v0.13+ renames stdlib interface types too).

## How it works

Every Go binary built since 1.2 carries a `pclntab`, a self-describing table that maps program counters to function names, source files, and lines. The runtime uses it for stack traces, so `strip` leaves it alone.

`unstrip` does five things, layered:

1. **Find the pclntab.** Look up `.gopclntab` / `__gopclntab` by name; if the section table's stripped or the section was renamed, fall back to a magic-byte scan with a structural sanity filter (so we don't false-positive on random `0xfffffff1` sequences inside other data).
2. **Walk the function table.** For each function entry, resolve the name through the funcnametab, the file through the cutab -> filetab indirection, and the start line through the pcln pc-value table.
3. **Find the moduledata.** Scan `.noptrdata` / `.data` for a pointer to the pclntab, that's the first field of `runtime.firstmoduledata`. Verify by checking that the next five slice headers all point inside the pclntab (the corroborating-references trick that defeats false positives).
4. **Walk the type graph.** Start from `typelinks` (the linker's list of every type the program references), parse each `_type` header, resolve its name through the names blob relative to `moduledata.types`, decode kind-specific extra data (pointer.elem, slice.elem, struct fields, ...), and follow the references to pull in types `typelinks` itself missed. Same trick for `itablinks`.
5. **Parse buildinfo.** Locate the `\xff Go buildinf:` marker, decode the inline string format introduced in Go 1.18, strip the 16-byte sentinel framing, parse the tab-separated `path`/`mod`/`dep`/`build` records.

No relocations. No rewriting. Read-only output you pipe into your real tools.

## Scope

What works:

- Go 1.18, 1.19, 1.20, 1.21, 1.22, 1.23, 1.24, 1.25
- ELF, Mach-O, and PE containers
- amd64 and arm64
- PIE and non-PIE
- Garble-obfuscated binaries (detected and flagged; structural data still recovered)
- Function names, file paths, line numbers
- Full type recovery (names, kinds, sizes, struct fields with offsets and embedded flags)
- Interface ↔ concrete-type recovery via itabs
- Module dependency tree, build settings, VCS info
- PC-to-symbol reverse lookup
- IDA, Ghidra, Binary Ninja, JSON, and human-readable output

What's out of scope, and where to look instead:

- **Go < 1.18**: pre-1.18 pclntab layouts are unsupported. Use [GoReSym](https://github.com/mandiant/GoReSym) for those.
- **Rust and Swift binaries**: planned for v2. There is no good equivalent for either today.
- **Generic ELF symbol recovery**: not this tool. Use `eu-unstrip` from elfutils.
- **Decompilation**: not this tool. This gives you names; a decompiler gives you code.
- **32-bit Go targets**: parser assumes 64-bit pointers. Wire when there's demand.

## Status

v1.0.0.

Tested against:

- **Linux ELF amd64 & arm64, non-PIE & PIE**. Go 1.22, verified function addresses byte-for-byte against `nm` on the unstripped equivalent
- **Windows PE amd64**. Go 1.25, function recovery + types + itabs verified by content (no `nm` cross-check)
- **Mach-O**, code path exercised, but no fixture has been built on macOS yet; please file an issue if it breaks
- **garble v0.13**, heuristic detection works, structural recovery survives

Known gaps in v1.0:

- Type recovery surfaces struct package paths as `_pkg_path` (read-and-discarded). Function-type argument types (in/out parameter type pointers) aren't enumerated, you get the count + variadic flag but not the signature types.
- Multi-module binaries (Go plugins, shared libs), only `runtime.firstmoduledata` is parsed; the `moduledata.next` chain is not walked. Most real binaries are single-module, so this matters for plugins specifically.
- Pre-Go-1.18 pclntab layout (Go 1.13-1.17) is unsupported (different magic, different header field positions).

If `unstrip` can't recover symbols from a binary in the supported matrix, that's a bug, open an issue with the binary attached if you can share it, or the Go version and target triple if you can't.

## Performance

Real-world numbers: on a stripped 65 MiB helm binary (75,630 functions, 29,743 types, 3,735 itabs), every feature runs in under 100 ms, see [`BENCHMARKS.md`](./BENCHMARKS.md) for the full corpus and per-feature timings.

## License

MIT. See [`LICENSE`](./LICENSE) for the full text. Contact: mohamed@riven-labs.com.

---

A [Riven Labs](https://github.com/riven-labs) project.
