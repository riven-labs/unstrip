# unstrip

[![Crates.io](https://img.shields.io/crates/v/unstrip.svg)](https://crates.io/crates/unstrip)
[![CI](https://github.com/riven-labs/unstrip/actions/workflows/ci.yml/badge.svg)](https://github.com/riven-labs/unstrip/actions/workflows/ci.yml)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)
[![Rust](https://img.shields.io/badge/rust-1.85%2B-orange.svg)](https://www.rust-lang.org)
[![Go versions](https://img.shields.io/badge/go-1.2--1.27-00ADD8.svg)](https://go.dev)
[![Platforms](https://img.shields.io/badge/platforms-linux%20%7C%20macos%20%7C%20windows-lightgrey.svg)](#install)

> Recover function names, method signatures, types, and interface dispatch tables from stripped Go binaries, with inlined call stacks the leaf-only tools miss.

Stripped Go binaries still carry `pclntab`, moduledata, typelinks, and itablinks because the runtime needs them for stack traces and reflection. `unstrip` reads all of it: every function with file and line, every method with its Go-syntax signature where the linker kept the type record, every type with full struct layout, every `(interface, concrete)` pair the dispatcher uses, and the module dependency tree. ELF, Mach-O, PE. amd64, arm64, and 386. Go 1.2 through 1.27 (types and itabs from Go 1.7).

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

Method signatures attached to recovered symbols. Every method on a type the Go linker emitted a `_type` record for gets a Go-syntax signature like `(_0 []uint8) (int, error)` appended to its name in the default listing, in `--addr` lookups, and in the Ghidra/IDA/Binja exporter comments. IDA applies reflection prototypes to methods too; GoReSym, gore, and redress do not attach signatures to functions (see [COMPARISON.md](./COMPARISON.md)).

Inlined call stacks, not just leaf functions. `--addr` returns the full inline tree from `FUNCDATA_InlTree`, so a PC that lands in inlined code resolves to the chain that led there, with file and line for every frame.

Built-in Ghidra, IDA, and Binary Ninja Python exporters via `--format`, with C struct decls and correct field offsets. One Rust binary emits scripts for all three RE tools; `--install-plugin <ida|ghidra|binja>` drops a wrapper plugin into the user's plugin directory.

`--data-at <addr>` interprets bytes at a data address through the recovered itab table and function table. Iface headers resolve to concrete type plus dispatched method body. Slice headers expand to ptr/len/cap with the data pointer symbolized. String headers print a quoted preview.

`--xref <symbol>` enumerates every call site targeting a function, on amd64 and arm64 binaries alike. Direct CALL/BL coverage is solid on both. Indirect dispatch is reported only in the `CALL [rip+itab+slot]` form, which stock Go codegen does not emit (see [Targeted xref by symbol](#targeted-xref-by-symbol)).

A 1.4 MiB static Rust binary, no runtime deps. Go 1.2 through 1.27, ELF + Mach-O + PE, amd64 + arm64 + 386, PIE + non-PIE, one tool.

## Compared to

Categorical comparison against GoReSym, gore, and redress lives in [COMPARISON.md](./COMPARISON.md). Headline: similar core function recovery; the tools differ on what they include in the type catalog, on which RE-tool integrations they ship, and on how they handle obfuscated binaries.

A short verified-only table follows. The longer differences and the "when to reach for which" guidance are in COMPARISON.md.

| Capability                              | unstrip              | GoReSym    | redress  | gore     |
|-----------------------------------------|----------------------|------------|----------|----------|
| CLI vs library                          | CLI                  | CLI        | CLI      | library  |
| Go 1.18 through 1.25                    | yes                  | yes        | yes      | yes      |
| Pre-Go-1.18                             | Go 1.2+ (types 1.7+) | Go 1.2+    | Go 1.5+  | Go 1.5+  |
| Signatures attached to functions        | yes                  | no         | no       | no       |
| Ghidra + IDA + Binja exporters          | yes                  | yes        | no       | no       |
| Inlined call stacks on PC lookup        | yes                  | unverified | no       | no       |
| `--data-at` symbolic data inspection    | yes                  | no         | no       | no       |
| `--xref` on amd64 and arm64             | yes                  | n/a        | n/a      | n/a      |
| Static binary, no runtime deps          | yes (Rust)           | yes (Go)   | yes (Go) | n/a      |

## Use

```
unstrip ./samples/hello.stripped
```

Function names, source files, line numbers, one function per line. Methods on types the binary carries a `_type` record for get their Go-syntax signature appended:

```
$ unstrip ./crypto-pipeline.stripped
0x00000000004b3f20  main.(*HashingReader).Read                                                    main.go
0x00000000004b4000  main.(*CountingWriter).Write(_0 []uint8) (int, error)                         main.go
0x00000000004b4280  main.(*AesGcm).Encrypt(_0 []uint8) ([]uint8, error)                           main.go
0x00000000004b4820  main.(*Pipeline).ProcessFrame                                                 main.go
0x00000000004b4a40  main.(*Pipeline).StreamThrough                                                main.go
0x0000000000465b40  errors.(*errorString).Error() string                                          errors/errors.go
0x0000000000479e00  os.(*File).Write(_0 []uint8) (int, error)                                     os/file.go
0x00000000004b4d40  main.main                                                                     main.go
...
```

Parameter names are not in the binary; positional placeholders (`_0`, `_1`, ...) keep the shape correct. Coverage scope and what to expect:

- **Methods that implement an interface** (`CountingWriter.Write`, `AesGcm.Encrypt`, `errorString.Error`, `os.File.Write` above): signatures recover reliably, from the interface's declared funcType. An `(itab thunk)` marker flags a `(*T).M` wrapper the compiler generated for a value-receiver method (file `<autogenerated>`) that an itab dispatches through.
- **Methods on types reached only through internal calls** (`HashingReader.Read`, `Pipeline.ProcessFrame`, `Pipeline.StreamThrough` above): the Go linker may have elided the type's `_type` record because no runtime path needs it. The function name is recovered from `pclntab`; the signature is not in the binary. unstrip prints the bare name for those.
- **Free top-level functions** (`main.main`, `main.NewAesGcm`, etc.): never had per-function signature records to begin with. Bare names.

Pass `--no-signatures` for the older shorter listing.

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

For a structured verdict and exit-code semantics (0 garbled, 1 clean, 2 indeterminate, 3 error), use `--detect-garble`.

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
0x00000000005a18c8  io.Writer        =>  *os.File
0x00000000005a1948  io.Writer        =>  *bytes.Buffer
0x00000000005a19a8  io.Writer        =>  *gzip.Writer
0x00000000005a1a08  io.StringWriter  =>  *bufio.Writer
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

The Ghidra script is Python 3 (`@runtime PyGhidra`), so Ghidra has to be started with PyGhidra (`support/pyghidraRun`); Ghidra 12 ships no Jython.

Function names sanitize down to valid disassembler labels; the original Go name (with parens, brackets, generics arguments) is preserved as a function comment. Struct names become C identifiers (`errors.errorString` is declared as `errors_errorString`). The declarations carry sizes and offsets, not Go types: integer and pointer fields get a C type of the right width (pointers are `void *`), and strings, slices, interfaces, and nested structs are byte arrays of their size.

For a menu-item install instead of running the script every time:

```
unstrip --install-plugin ida      # ~/.idapro/plugins/, registers as Edit -> Plugins -> Load Go symbols (unstrip), Ctrl-Shift-G
unstrip --install-plugin ghidra   # ~/ghidra_scripts/, run from Script Manager
```

A Binary Ninja installer (`--install-plugin binja`) drops the wrapper into the Binary Ninja plugins directory and registers a menu item under Plugins -> Load Go symbols (unstrip).

### Bake symbols into a runnable binary

`--symbols-as elf` writes a new ELF with a populated `.symtab` + `.strtab` built from the recovered functions. The result is a strict superset of the input that still runs, but `nm`, `gdb`, `objdump --syms`, `perf`, `addr2line`, and eBPF stack traces see the names. `delve` does not: it needs DWARF, which this does not write.

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

Use `--in-place --yes` to overwrite the input file. `--symbols-as pe` does the same for PE. ELF32 (386, arm), big-endian ELF, and Mach-O are not supported.

### Port symbols between builds

`--diff <OLD_BINARY>` is a name-port helper, not a structural binary differ. It pairs functions across two builds in two passes: first by recovered Go symbol name (`identical` at the same address, `moved` at a new one), then, for what is left, by a masked-code signature that is unique on both sides (`renamed`: same code, different name). Everything else falls into `added` or `removed`. It does not hash basic blocks, fingerprint control-flow graphs, or follow functions across inlining, splitting, or compiler-driven renames. If a function was inlined away or restructured, this tool will report it as `removed` plus `added` rather than matching it. Two garble builds of the same source with different seeds pair poorly: every name is a different hash, and on a Go 1.27 test build the code pass matched none of 2,112 functions.

For real structural diffing across optimization and inlining changes, reach for BinDiff or Diaphora. `--diff` here exists for the narrow case where you want each function of the new build paired with its counterpart in the old one, and the old build's recovered names carried over:

```
$ unstrip ./malware-v1.1.bin --diff ./malware-v1.0.bin
old:        4699 functions
new:        4823 functions

identical:  4421
moved:      12 (same name, new address)
renamed:    198 (same code, different name)
added:      192 (in new, not in old)
removed:    68 (in old, not in new)
```

Pair with `--port-symbols ida|ghidra|binja` to emit a script that renames every paired function in the new binary using the name unstrip recovered for it in the old one. The names come from the old binary's pclntab, not from an annotated database, so they only add information where the new build's own names are hashed or missing:

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

On a 61 MiB kubectl, `--xrefs` takes about 2 s end to end, 24 MB of text output included. Direct calls only; virtual dispatch through itabs lives in `--itabs`.

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

amd64 and arm64. Direct-CALL coverage is solid on both; indirect-itab on arm64 catches the canonical `LDR Xt, [Xn, #slot]; BLR Xt` pair but misses other dispatch patterns the compiler emits, pending a real disassembler integration.

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

When the target resolves, you see exactly which function the goroutine runs. Resolution is partial: on a Go 1.26 test program 4 of 34 sites resolve on amd64 and 7 of 34 on arm64; a funcval built in a heap object several instructions before the call is not followed. When the LEA pattern doesn't match the heuristic (the funcval came from a register or stack slot), the call site and source file:line still show so you can open the source. amd64 and arm64 only today.

### Dispatch resolver for Ghidra

`--dispatch-resolver ghidra` emits a Ghidra Python script that embeds the recovered itab dispatch table and, when invoked at an interface method call, prints every `(interface, concrete impl)` pair with a method in the slot that call reads:

```
$ unstrip ./target --dispatch-resolver ghidra > unstrip_dispatch.py
# Inside Ghidra (started with PyGhidra): Script Manager -> add unstrip_dispatch.py
# Place the cursor on the CALL RDX that follows MOV RDX, qword ptr [RDX + 0x18]
# and run the script.
# Output (console):
#   unstrip dispatch: looking for itabs with a method at slot 0 (offset 0x18)
#     io.Writer => *os.File :: Write -> 0x4b9020
#     io.Writer => *bytes.Buffer :: Write -> 0x4c1a40
#     error => *errors.errorString :: Error -> 0x4a3e60
#     ...
```

Go compiles an interface call as a load from the itab (`MOV reg, [itab + 0x18 + 8*slot]` on amd64, `ldr xN, [xM, #0x18 + 8*slot]` on arm64) followed by a call through the register. The script walks back from the call, within straight-line code, to that load and turns its offset into the method slot. It does not know which itab the register holds, so it lists every itab with a method in that slot; the method name and signature narrow it down. 64-bit programs only. The script is Python 3 and needs a PyGhidra-launched Ghidra.


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

The rules cover HTTP servers and clients, TLS, X.509, RSA/ECDSA/AES, AWS/GCP/Azure SDKs, Kubernetes client, Docker/containerd, SQL/SQLite/Postgres/Redis/MongoDB, JSON/proto/YAML, file and child-process operations, raw sockets, and known offensive frameworks (Sliver). Each match includes up to five evidence strings showing exactly which recovered type or function triggered it. Rules match on names, so they report what the binary links, not what it runs: stdlib-only hits such as `syscall.Socket` fire in any program that uses `net`, and on a garbled build the hashed names hide most framework rules (the Sliver rule does not fire on a garbled Sliver implant).

### Triage hints

`--info` includes a count of stdlib interface implementations the binary ships. Useful for the first-pass question "does this binary speak HTTP, do crypto, write files?"

```
stdlib interface implementations:
  error          142
  io.Reader      47
  io.Writer      38
  http.Handler   14
  net.Conn       11
  crypto.Signer  3
```

(`--fingerprint --behavioral` hashes those counts into a SHA-256. Programs that implement the same stdlib interfaces the same number of times hash alike, so it clusters coarsely; garble renames the interfaces, so a garbled build does not hash like its plain build.)

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

The `runtime.inlinedCall` record has two layouts: the 20-byte record of Go 1.16 through 1.19 and the 16-byte record Go 1.20 introduced with `startLine`. The decoder reads both; `start_line` is 0 on the older one, which does not carry it. Garble's `entryoff` XOR rewrite does not touch the inline-tree FUNCDATA section, so the decoder also runs unchanged on garble-obfuscated binaries; callee names come back obfuscated, not stripped.

For direct (non-inlined) call edges and full-graph traversal, use `--xrefs` (CLI) or `unstrip::xrefs` (library). `EdgeKind::Direct` is reserved on the inlined call graph for a future fold of those edges; today only `EdgeKind::Inlined` is emitted by `inline_callgraph`.

### Per-function metadata (library API)

`Pclntab` also reads what the runtime keeps per function: the line table, SP deltas, any PCDATA table, the innermost inlined call at a PC, the raw `_func` fields, FUNCDATA_ArgInfo, open-coded defer records, stack objects, and the args/locals pointer maps. Each reader takes the `FuncEntry` that `func_entry_at` returns and follows the binary's pclntab layout (Go 1.16/1.17, 1.18/1.19, 1.20+) and pointer size. On Go 1.2 to 1.15 the line table, SP deltas, PCDATA tables and `_func` fields read, while the readers built on funcdata (the inline tree, ArgInfo, defer records, stack objects, pointer maps) return `None`:

```rust
let pcln = Pclntab::parse(&bin)?.with_gofunc(md.gofunc);

if let Some(func) = pcln.func_entry_at(pc) {
    for span in pcln.line_table(&func) {
        println!("0x{:x}..0x{:x} {}:{}", span.pc_lo, span.pc_hi, span.file, span.line);
    }
    if let Some(leaf) = pcln.inline_leaf(&func, pc) {
        println!("inlined {} called from 0x{:x}", leaf.func_name, leaf.parent_pc);
    }
    if let Some(args) = pcln.arg_info(&func) {
        println!("{} argument components", args.len());
    }
}
```

`stack_objects`, `pointer_maps`, `open_coded_defer_info`, and `is_wrapper` follow the same pattern; `parse_arg_info` and `parse_open_defer_info` decode raw record bytes.

## How it works

Every Go binary built since 1.2 carries a `pclntab`, a self-describing table that maps program counters to function names, source files, and lines. The runtime uses it for stack traces, so `strip` leaves it alone.

`unstrip` does five things, layered:

1. **Find the pclntab.** Look up `.gopclntab` / `__gopclntab` by name; if the section table's stripped or the section was renamed, fall back to a magic-byte scan with a structural sanity filter (so we don't false-positive on random `0xfffffff1` sequences inside other data).
2. **Walk the function table.** For each function entry, resolve the name through the funcnametab, the file through the cutab -> filetab indirection (Go 1.2 to 1.15 have no cutab: the file index goes straight to the file table), and the start line through the pcln pc-value table.
3. **Find the moduledata.** Scan `.noptrdata` / `.data` for a pointer to the pclntab, that's the first field of `runtime.firstmoduledata`. Verify by checking that the next five slice headers all point inside the pclntab (the corroborating-references trick that defeats false positives).
4. **Walk the type graph.** Start from `typelinks` (the linker's list of every type the program references; Go 1.27 dropped it, so there the descriptors are walked back to back from the start of the types region, as the runtime does), parse each `_type` header, resolve its name through the names blob relative to `moduledata.types`, decode kind-specific extra data (pointer.elem, slice.elem, struct fields, ...), and follow the references to pull in types `typelinks` itself missed. Same trick for `itablinks`, or the in-place itab walk on Go 1.27. Every record is read at the binary's pointer size.
5. **Parse buildinfo.** Locate the `\xff Go buildinf:` marker, decode the inline string format introduced in Go 1.18 (or, before 1.18, the two pointers to the version and modinfo string headers), strip the 16-byte sentinel framing, parse the tab-separated `path`/`mod`/`dep`/`build` records.

No relocations. No rewriting. Read-only output. Pipe it into IDA, Ghidra, gdb, or a script.

## Scope

What works:

- Go 1.2 through 1.27 for functions, files and lines; Go 1.7 through 1.27 for types, itabs and method signatures
- ELF, Mach-O, and PE containers
- amd64, arm64, and 386 (on 386 the table readers; the instruction scanners decode amd64 and arm64 only)
- PIE and non-PIE
- Garble-obfuscated binaries (detected and flagged; structural data still recovered)
- Function names, file paths, line numbers
- Method signatures in Go syntax for every method whose type the Go linker kept
- Full type recovery (names, kinds, sizes, struct fields with offsets and embedded flags)
- Interface to concrete type recovery via itabs
- Module dependency tree, build settings, VCS info
- PC-to-symbol reverse lookup with inlined call stacks
- Direct CALL/BL call-site enumeration on amd64 and arm64
- IDA, Ghidra, Binary Ninja, JSON, and human-readable output

Tested against: Linux ELF amd64 and arm64 (PIE and non-PIE), Windows PE amd64, Linux ELF and Windows PE 386, and Mach-O amd64 and arm64 (cross-compiled darwin builds in the integration suite), on Go versions in the supported range. Open an issue if it breaks. Garble heuristic detection works and structural recovery survives the default mode (string literals, inline trees, and the funcdata array all stay walkable).

What's out of scope, and where to look instead:

- **Types before Go 1.7**: Go 1.2 to 1.6 binaries give functions, files and lines only. Their moduledata has no types region (Go 1.5 and 1.6 list type pointers instead). Use [GoReSym](https://github.com/mandiant/GoReSym) for Go 1.5 and 1.6 types.
- **Go 1.0 and 1.1**: the symbol table before the Go 1.2 pclntab is not read.
- **A Go program carried as data** (a dropper's payload, an installer, an executable with a Go binary in its data): reported, not read in place. When the file's only pclntab is the carried program's, parsing fails with `EmbeddedGoImage`, which gives its file offset, its length when its header is intact, and its GOOS/GOARCH; parse `bytes[offset..offset + len]` to read it.
- **Generic ELF symbol recovery**: not this tool. Use `eu-unstrip` from elfutils.
- **Decompilation**: not this tool. This gives you names; a decompiler gives you code.

Known gaps:

- Type recovery reads struct package paths and discards them, so two types with one name in different packages (`sync.Mutex` and `internal/sync.Mutex`) print the same name.
- Free top-level function signatures: the binary records signatures for methods (on types reached at runtime) but not for free top-level functions; their signatures are absent without DWARF.
- `--buildinfo` fails on Go 1.13 to 1.15 binaries (the version string header it points at is not in the file), and Go 1.2 and 1.3 binaries carry no version string to report.
- Method tables of named map types are not found before Go 1.14, whose map type record has a different size.

## Roadmap

Work we have not landed yet. Ordered roughly by how often we expect it to come up.

Funcdata before Go 1.16. Go 1.2 to 1.15 binaries read their functions, files, lines, types and itabs, but the inline tree, open-coded defer records, stack objects and pointer maps those releases wrote use older record layouts that the decoders do not read yet.

Free-function signature recovery. Methods ship today (we walk `_type.uncommon().methods` and the itab method tables). Free top-level functions do not appear in either table, so their signatures are absent from a stripped binary unless the compiler emitted a `funcType` for reflection or interface storage. Closing that gap means either reading DWARF when present or recognizing reflective uses and back-resolving.

32-bit arm, and the instruction scanners on i386. The table readers (pclntab, moduledata, buildinfo, types, itabs, method tables, funcdata) handle i386 on Go 1.17 to 1.27, and the pclntab, type and itab readers also on Go 1.7 to 1.15 (the pclntab reader from Go 1.5); the call, goroutine and data-reference scanners decode amd64 and arm64 code only, and 32-bit arm is untested.

`--symbols-as` for Mach-O. ELF and PE write today. The Mach-O equivalent (`LC_SYMTAB` patching) ships once we have a tested fixture; we do not currently have one we can publish.

Rust binary symbol recovery. Not an unstrip mode. If we build it, it ships as a separate tool. DWARF parsing is its own problem and conflating the two would be a mistake.

## Safety posture

unstrip parses attacker-controlled bytes. We treat that as the default operating assumption.

What we do:

- Every offset read is bounds-checked against the source slice; reads that would run past the end return an error rather than panicking.
- Every length field decoded from the binary is range-capped at a sane ceiling (function counts, type counts, method counts, slice lengths). A binary that claims `nfunc = 0xffffffff` rejects rather than allocating.
- `Result`-returning APIs throughout the library; no `unwrap()` on attacker-controlled paths.
- Per-type recovery is best-effort; one malformed record drops that record, not the whole pass.

What we do not claim:

- `fuzz/` holds cargo-fuzz targets for the container parser and the recovery passes, but we do not run a fuzzing campaign in CI. The bounds-checking discipline above is the main defense.
- Garble-obfuscated inputs are detected and flagged, but garble's full transform surface evolves; an obfuscator update that goes further than current behavior may produce output we mis-parse before we patch.
- Mach-O is covered by cross-compiled darwin amd64 and arm64 fixtures, not by binaries built on macOS or a full version matrix.

If you find a crash, an out-of-bounds read, or any other safety issue: see [SECURITY.md](./SECURITY.md) for the private reporting contact.

## Contributing

PRs welcome. Read [CONTRIBUTING.md](./CONTRIBUTING.md) before opening one. Good first issues are tagged [`good first issue`](https://github.com/riven-labs/unstrip/labels/good%20first%20issue). For vulnerability reports see [SECURITY.md](./SECURITY.md).

If `unstrip` can't recover symbols from a binary in the supported matrix, that's a bug. Open an issue with the binary attached if you can share it, or the Go version and target triple if you can't.

## License

Dual-licensed under MIT or Apache-2.0 at your option. Pick whichever fits your downstream needs:

- [`LICENSE-MIT`](./LICENSE-MIT)
- [`LICENSE-APACHE`](./LICENSE-APACHE)

Contact: mohamed@riven-labs.com.

---

A [Riven Labs](https://github.com/riven-labs) project. relift, Riven's Go decompiler, is built on unstrip: unstrip reads the Go metadata, and relift lifts the code on top of it. Download relift from [riven-labs.com/relift](https://www.riven-labs.com/relift).
