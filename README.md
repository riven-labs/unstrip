# unstrip

[![Crates.io](https://img.shields.io/crates/v/unstrip.svg)](https://crates.io/crates/unstrip)
[![CI](https://github.com/riven-labs/unstrip/actions/workflows/ci.yml/badge.svg)](https://github.com/riven-labs/unstrip/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.85%2B-orange.svg)](https://www.rust-lang.org)
[![Go versions](https://img.shields.io/badge/go-1.18--1.25-00ADD8.svg)](https://go.dev)
[![Platforms](https://img.shields.io/badge/platforms-linux%20%7C%20macos%20%7C%20windows-lightgrey.svg)](#install)

> Recover function names, types, and interface dispatch tables from stripped Go binaries, with inlined call stacks the leaf-only tools miss.

Stripped Go binaries still carry `pclntab`, moduledata, typelinks, and itablinks because the runtime needs them for stack traces and reflection. `unstrip` reads all of it: every function with file and line, every type with full struct layout, every `(interface, concrete)` pair the dispatcher uses, and the module dependency tree. ELF, Mach-O, PE. amd64 and arm64. Go 1.18 through 1.25.

## Install

```
cargo install unstrip
```

Prebuilt binaries for Linux, macOS, and Windows are on the [releases page](https://github.com/riven-labs/unstrip/releases).

## Quick start

```
unstrip ./bin                       # function names, files, lines
unstrip ./bin --info                # container, Go version, garble heuristic
unstrip ./bin --format ghidra > apply.py    # Python script for Ghidra Script Manager
```

`unstrip -h` prints a one-screen cheat sheet. `unstrip --help` lists every flag grouped by section. The full reference with one paragraph per flag lives in [docs/USAGE.md](./docs/USAGE.md).

## Why unstrip

- Inlined call stacks, not just leaf functions: `--addr` returns the full inline tree from funcdata.
- Built-in Ghidra, IDA, and Binary Ninja Python exporters via `--format`, with C struct decls and correct field offsets.
- `--data-at <addr>` interprets bytes at a data address through the recovered itab table and function table: iface headers resolve to concrete type + dispatched method body, slice headers expand to ptr/len/cap with the data pointer symbolized, string headers print a quoted preview.
- 1.4 MiB static Rust binary, no runtime deps.
- Go 1.18 through 1.25, ELF + Mach-O + PE, amd64 + arm64, PIE + non-PIE, one tool.

## Compared to

Categorical comparison against GoReSym, gore, and redress lives in [COMPARISON.md](./COMPARISON.md). Headline: similar core function recovery; the tools differ on what they include in the type catalog, on which RE-tool integrations they ship, and on how they handle obfuscated binaries.

A short verified-only table follows. The longer differences and the "when to reach for which" guidance are in COMPARISON.md.

| Capability                              | unstrip          | GoReSym    | redress  | gore     |
|-----------------------------------------|------------------|------------|----------|----------|
| CLI vs library                          | CLI              | CLI        | CLI      | library  |
| Go 1.18 through 1.25                    | yes              | yes        | yes      | yes      |
| Pre-Go-1.18                             | no               | Go 1.2+    | Go 1.5+  | Go 1.5+  |
| Ghidra + IDA + Binja exporters          | yes              | yes        | no       | no       |
| Inlined call stacks on PC lookup        | yes              | unverified | no       | no       |
| `--data-at` symbolic data inspection    | yes              | no         | no       | no       |
| Static binary, no runtime deps          | yes (Rust)       | yes (Go)   | yes (Go) | n/a      |

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
garble heuristic: likely garbled
  - pclntab magic is not the standard 0xfffffff1 (garble rewrites it)
  - runtime.buildVersion is missing or non-standard (garble overwrites it)
  - 554/4310 user-package function names look hashed
```

For a structured verdict and exit-code semantics (0 garbled, 1 clean, 2 indeterminate), use `--detect-garble`.

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

From a stripped binary, no debug info, no SDK installed:

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

For a menu-item install instead of running the script every time:

```
unstrip --install-plugin ida      # ~/.idapro/plugins/, registers as Edit -> Plugins -> Load Go symbols (unstrip), Ctrl-Shift-G
unstrip --install-plugin ghidra   # ~/ghidra_scripts/, run from Script Manager
```

A Binary Ninja installer (`--install-plugin binja`) drops the wrapper into the Binary Ninja plugins directory and registers a menu item under Plugins -> Load Go symbols (unstrip).

### Bake symbols into a runnable binary

`--symbols-as elf` writes a new ELF with a populated `.symtab` + `.strtab` built from the recovered functions. The result is a strict superset of the input that still runs, but `nm`, `gdb`, `objdump --syms`, `perf`, `addr2line`, eBPF stack traces, and `delve` all see the names.

```
$ nm helm
nm: helm: no symbols

$ unstrip --symbols-as elf -o helm.symbols helm
wrote 75630 symbols to helm.symbols

$ nm helm.symbols | head -3
0000000000401000 T fatalf
00000000004012b0 T _cgo_get_context_function
00000000004011e0 T _cgo_set_stacklo

$ gdb -q helm.symbols -ex 'info functions main.main' -ex quit
0x00000000027f50e0  main.main
0x00000000027f53a0  main.main.func1
```

Use `--in-place --yes` to overwrite the input file. Today supports ELF64 little-endian only; Mach-O and PE rewrite ships later.

### Port symbols between builds

`--diff <OLD_BINARY>` is a name-port helper, not a structural binary differ. It pairs functions across two builds in two passes: first by exact address match (`identical`), then by exact Go symbol name at a new address (`renamed`). Everything else falls into `added` or `removed`. It does not hash basic blocks, fingerprint control-flow graphs, or follow functions across inlining, splitting, or compiler-driven renames. If a function was inlined away, renamed by the toolchain, or restructured, this tool will report it as `removed` plus `added` rather than matching it.

For real structural diffing across optimization and inlining changes, reach for BinDiff or Diaphora. `--diff` here exists for the narrow but common case where you annotated v1.0 in your disassembler, v1.1 just shipped, and you want the symbol names you already recovered to land on the obvious counterparts in the new build:

```
$ unstrip ./malware-v1.1.bin --diff ./malware-v1.0.bin
old:        4687 functions
new:        4823 functions

identical:  4421
renamed:    198
moved addr: 12 (same address, different name)
added:      192 (in new, not in old)
removed:    68 (in old, not in new)
```

Pair with `--port-symbols ida|ghidra|binja` to emit a script that renames every paired function in the new binary using whatever name it had in the old one:

```
$ unstrip ./malware-v1.1.bin --diff ./malware-v1.0.bin --port-symbols ghidra > port.py
# In Ghidra (with v1.1 loaded): Script Manager -> port.py
```

### Cross-references and call graph

`--xrefs` scans `.text` for direct CALL/BL targets and resolves each pair against the recovered function set. Combined with `--from`, `--to`, `--depth`, or `--callgraph`, it answers the questions an analyst opens IDA to ask:

```
$ unstrip ./helm --xrefs --from main.main --depth 1 | head
main.main -> github.com/spf13/cobra.(*Command).ExecuteC
main.main -> main.newRootCmd
main.main -> main.warning
main.main -> os.Exit

$ unstrip ./helm --xrefs --to crypto/rsa.SignPSS
crypto/tls.(*signOpts).Sign -> crypto/rsa.SignPSS

$ unstrip ./helm --xrefs --callgraph > graph.dot && dot -Tsvg graph.dot -o graph.svg
```

250,000+ caller-callee edges enumerated on a 65 MiB helm binary in under 300 ms. Direct calls only; virtual dispatch through itabs lives in `--itabs`.

### Targeted xref by symbol

`--xref <SYMBOL>` answers "who calls this," scoped to one target. Faster than building the whole graph when you only have one question, and grouped by caller so the output reads the way a human reads xrefs in IDA:

```
$ unstrip ./helm --xref runtime.mallocgc | head
runtime.makechan @ 0x000000000040a260:
  0x000000000040a2ee  direct
  0x000000000040a340  direct
  0x000000000040a380  direct
runtime.convT @ 0x000000000040fb00:
  0x000000000040fb29  direct
```

Accepts a function name (resolved through pclntab) or a hex address (`0x...`). When the target is an interface-method implementation, indirect dispatch sites of the form `CALL [rip+itab+slot]` are reported alongside direct calls with the resolved itab and method name carried inline. The compiler usually loads the slot pointer into a register first; those register-indirect sites do not show up here because resolving them requires basic-block tracking we deliberately don't ship. In practice the indirect-itab scanner finds matches on hand-written assembly and unusual codegen; expect zero hits from stock Go compiler output. The strict-encoding hits that do appear carry zero false positives.

amd64 only today.

### Goroutines and deferred calls

`--goroutines` lists every `runtime.newproc` and `runtime.deferproc` call site in `.text` and resolves the target function the goroutine or deferred call will run when possible. Surfaces the control flow hidden behind `go func() { ... }` and `defer` in Go programs that other tools don't:

```
$ unstrip ./sliver-client --goroutines | head
0x0000000000424798  runtime.newproc         -> runtime.runFinalizers (0x424880)        runtime/mfinal.go:169
0x00000000004259c0  runtime.newproc         -> (target unresolved)                     runtime/mgc.go:209
0x00000000004479d5  runtime.newproc         -> runtime.forcegchelper (0x447a00)        runtime/proc.go:360
0x000000000045e480  runtime.newproc         -> runtime.ensureSigM.func1 (0x4767e0)     runtime/signal_unix.go:1061
0x000000000049c4ae  runtime.newproc         -> (target unresolved)                     sync/waitgroup.go:235
```

When the target resolves (40-50% of sites in real binaries), you see exactly which function the goroutine runs. When the LEA pattern doesn't match the heuristic (the funcval came from a register or stack slot), the call site and source file:line still show so you can open the source. amd64 and arm64 only today.

### Dispatch resolver for Ghidra

`--dispatch-resolver ghidra` emits a Ghidra Python script that embeds the recovered itab dispatch table and, when invoked at a virtual call site, prints every `(interface, concrete impl)` pair whose method table contains the dereferenced slot:

```
$ unstrip ./target --dispatch-resolver ghidra > unstrip_dispatch.py
# Inside Ghidra: Script Manager -> add unstrip_dispatch.py
# Place cursor on `CALL qword ptr [reg + 0x18]` and run the action.
# Output (console):
#   unstrip dispatch: looking for itabs with a method at slot 3 (offset 0x18)
#     io.Writer => *os.File :: Write -> 0x4b9020
#     io.Writer => *bytes.Buffer :: Write -> 0x4c1a40
#     io.Writer => *bufio.Writer :: Write -> 0x4cd900
#   unstrip dispatch: 3 candidates
```

This turns virtual dispatch through an itab, the worst class of stripped-Go reversing target, into a five-second lookup. The slot-offset heuristic pulls the integer scalar from the call's second operand; combined with the itab table unstrip already recovers, you get the candidate target set without re-running any analysis. amd64 today; arm64 BLR/BR-through-register support is straightforward to add once we have a test fixture.

### Capabilities

`--capabilities` matches the recovered types, itabs, and function names against a curated rule set and reports what the binary appears to do. First-pass answer to "what is this?":

```
$ unstrip ./sliver-client --capabilities
[crypto]
  TLS client/server
  X.509 / PKI
  RSA, ECDSA, AES
[network]
  HTTP server, HTTP client, gRPC, DNS, raw TCP, raw UDP
[offensive-hint]
  shell command execution
  raw socket / ICMP
  Sliver C2 implant
[process]
  child process spawn
  syscall direct invocation
  signal handling
[serialization]
  JSON encoding
  Protocol Buffers
```

The rules cover HTTP servers and clients, TLS, X.509, RSA/ECDSA/AES, AWS/GCP/Azure SDKs, Kubernetes client, Docker/containerd, SQL/SQLite/Postgres/Redis/MongoDB, JSON/proto/YAML, file and child-process operations, raw sockets, and known offensive frameworks (Sliver). Each match includes up to five evidence strings showing exactly which recovered type or function triggered it.

### Triage hints

`--info` includes a count of stdlib interface implementations the binary ships. Useful for the first-pass question "does this binary speak HTTP, do crypto, write files?"

```
stdlib interface implementations:
  *error            142
  *io.Reader         47
  *io.Writer         38
  *http.Handler      14
  *net.Conn          11
  *crypto.Signer      3
```

(`--fingerprint --behavioral` exists for hashing that counter into a SHA-256; coarser than `--fingerprint` and not garble-stable, included for completeness.)

### Inlined call graph (library API)

For tools that want to consume unstrip's recovery from Rust, the `unstrip::inline` module exposes the inlined call graph the compiler recorded in `FUNCDATA_InlTree`. One `Node` per physical function; one `Edge` per inlined call site the compiler kept after optimization:

```rust
use unstrip::gobin::GoBinary;
use unstrip::inline::{inline_callgraph, EdgeKind, NodeKind};
use unstrip::moduledata::ModuleData;
use unstrip::pclntab::Pclntab;

let bin = GoBinary::open("./target")?;
let md = ModuleData::locate(&bin)?;
let pcln = Pclntab::parse(&bin)?.with_gofunc(md.gofunc);
let graph = inline_callgraph(&bin, &pcln)?;

for e in &graph.edges {
    if matches!(e.kind, EdgeKind::Inlined) {
        let caller = graph.node(e.from).unwrap();
        let callee = graph.node(e.to).unwrap();
        println!("{} -> {} @ 0x{:x}", caller.name, callee.name, e.call_site);
    }
}
```

`NodeKind::Physical` nodes are real pclntab functions with their entry PC as `addr`. `NodeKind::AnonymousInline` nodes carry their parent's PC plus the inline-tree start line, and their `addr` is a synthetic high-bit-tagged ID (`Node::is_anonymous_addr`) so they cannot collide with a real text VA. Anonymous-inline records appear when the compiler kept the inlined call's topology but the binary was built with `-tiny`, `-ldflags=-s -w`, or garble's name obfuscation, all of which zero the callee's `name_off`. The topology is intact in all these cases; only the name is gone.

The `runtime.inlinedCall` record is byte-identical across Go 1.20 through 1.26 (the layout has not drifted since `startLine` was added in Go 1.20). The decoder runs unchanged across that range. Garble's `entryoff` XOR rewrite does not touch the inline-tree FUNCDATA section, so the decoder also runs unchanged on garble-obfuscated binaries; callee names come back obfuscated, not stripped.

For direct (non-inlined) call edges and full-graph traversal, use `--xrefs` (CLI) or `unstrip::xrefs` (library). `EdgeKind::Direct` is reserved on the inlined call graph for a future fold of those edges; today only `EdgeKind::Inlined` is emitted by `inline_callgraph`.

## How it works

Every Go binary built since 1.2 carries a `pclntab`, a self-describing table that maps program counters to function names, source files, and lines. The runtime uses it for stack traces, so `strip` leaves it alone.

`unstrip` does five things, layered:

1. **Find the pclntab.** Look up `.gopclntab` / `__gopclntab` by name; if the section table's stripped or the section was renamed, fall back to a magic-byte scan with a structural sanity filter (so we don't false-positive on random `0xfffffff1` sequences inside other data).
2. **Walk the function table.** For each function entry, resolve the name through the funcnametab, the file through the cutab -> filetab indirection, and the start line through the pcln pc-value table.
3. **Find the moduledata.** Scan `.noptrdata` / `.data` for a pointer to the pclntab, that's the first field of `runtime.firstmoduledata`. Verify by checking that the next five slice headers all point inside the pclntab (the corroborating-references trick that defeats false positives).
4. **Walk the type graph.** Start from `typelinks` (the linker's list of every type the program references), parse each `_type` header, resolve its name through the names blob relative to `moduledata.types`, decode kind-specific extra data (pointer.elem, slice.elem, struct fields, ...), and follow the references to pull in types `typelinks` itself missed. Same trick for `itablinks`.
5. **Parse buildinfo.** Locate the `\xff Go buildinf:` marker, decode the inline string format introduced in Go 1.18, strip the 16-byte sentinel framing, parse the tab-separated `path`/`mod`/`dep`/`build` records.

No relocations. No rewriting. Read-only output. Pipe it into IDA, Ghidra, gdb, or a script.

## Scope

What works:

- Go 1.18 through 1.25
- ELF, Mach-O, and PE containers
- amd64 and arm64
- PIE and non-PIE
- Garble-obfuscated binaries (detected and flagged; structural data still recovered)
- Function names, file paths, line numbers
- Full type recovery (names, kinds, sizes, struct fields with offsets and embedded flags)
- Interface to concrete type recovery via itabs
- Module dependency tree, build settings, VCS info
- PC-to-symbol reverse lookup with inlined call stacks
- IDA, Ghidra, Binary Ninja, JSON, and human-readable output

Tested against: Linux ELF amd64 and arm64 (PIE and non-PIE), Windows PE amd64, on Go versions in the supported range. Mach-O code paths are exercised by unit tests; the integration suite has no macOS-built fixture yet. Open an issue if it breaks. Garble heuristic detection works and structural recovery survives the default mode (string literals, inline trees, and the funcdata array all stay walkable).

What's out of scope, and where to look instead:

- **Go < 1.18**: pre-1.18 pclntab layouts are unsupported. Use [GoReSym](https://github.com/mandiant/GoReSym) for those.
- **Generic ELF symbol recovery**: not this tool. Use `eu-unstrip` from elfutils.
- **Decompilation**: not this tool. This gives you names; a decompiler gives you code.

Known gaps in v1.0:

- Type recovery surfaces struct package paths as `_pkg_path` (read-and-discarded). Function-type argument types (in/out parameter type pointers) aren't enumerated, you get the count + variadic flag but not the signature types.
- Multi-module binaries (Go plugins, shared libs): only `runtime.firstmoduledata` is parsed; the `moduledata.next` chain is not walked. Most real binaries are single-module, so this matters for plugins specifically.

## Roadmap

Work we have not landed in v1.0. Ordered roughly by how often we expect it to come up.

Pre-Go-1.18 pclntab parsing. The Go 1.13 through 1.17 layouts are different enough that the current parser does not even try. GoReSym covers the older corpus; we do not yet. Until we do, that is the gap.

Multi-module binaries. `runtime.firstmoduledata` is parsed; the `next` pointer is not walked. Go plugins (`-buildmode=plugin`) and shared libraries built across multiple modules will surface only the first module. Most binaries are single-module so this has not bitten yet.

Method and interface-method signature recovery. The binary carries full parameter and return types for every method on a named type (in the `_type.uncommon().methods` table) and for every interface-method implementation (in the itab method tables). Recovering them means walking tables we already parse and resolving each method's `mtyp` funcType to a Go-syntax signature. Free functions are a different problem: they do not appear in those tables, and the compiler emits no signature record for them unless they are stored reflectively. For free functions in stripped binaries, the signature is unrecoverable without DWARF.

i386 and 32-bit arm. The pclntab layout drifts on 32-bit targets. No demand yet; the day a 32-bit IoT Go binary becomes a real corpus problem, this jumps to the top.

`--symbols-as` for Mach-O. ELF and PE write today. The Mach-O equivalent (`LC_SYMTAB` patching) ships once we have a tested fixture; we do not currently have one we can publish.

arm64 for `--xref` indirect-itab dispatch. The amd64 decoder catches `CALL [reg + slot*8]`. arm64 needs the equivalent `LDR` + `BLR` pattern walker.

Rust binary symbol recovery. Not an unstrip mode. If we build it, it ships as a separate tool. DWARF parsing is its own problem and conflating the two would be a mistake.

## Contributing

PRs welcome. Read [CONTRIBUTING.md](./CONTRIBUTING.md) before opening one. Good first issues are tagged [`good first issue`](https://github.com/riven-labs/unstrip/labels/good%20first%20issue). For vulnerability reports see [SECURITY.md](./SECURITY.md).

If `unstrip` can't recover symbols from a binary in the supported matrix, that's a bug. Open an issue with the binary attached if you can share it, or the Go version and target triple if you can't.

## License

MIT. See [`LICENSE`](./LICENSE) for the full text. Contact: mohamed@riven-labs.com.

---

A [Riven Labs](https://github.com/riven-labs) project.
