# unstrip usage reference

The full flag list with one paragraph per flag explaining when and how to use it. `unstrip -h` gives a one-screen cheat sheet of common invocations; `unstrip --help` gives the same flag list as below but condensed. Use this file when you want the longer "why" behind a flag.

Sections match the groupings in `--help`.

- [Analysis modes](#analysis-modes)
- [Mode modifiers](#mode-modifiers)
- [Output](#output)
- [Rewrite the binary](#rewrite-the-binary)
- [RE-tool integration](#re-tool-integration)

---

## Analysis modes

Each flag below picks a single analysis. They are mutually exclusive in spirit; pass one at a time.

### `--info`

Container, Go version, pclntab geometry, garble heuristic verdict. The fastest "what is this binary?" answer. Reads only what's needed to identify the file; cheap to run on a queue of suspicious binaries.

### `--buildinfo`

Parses the buildinfo blob that `runtime/debug.ReadBuildInfo` reads. Outputs the module dep tree and build settings (`-trimpath`, `-buildmode`, `-ldflags`, VCS revision when present). Works on stripped binaries, unlike `go version -m`.

### `--types`

Walks the typelinks table plus references reachable from it, prints recovered type names with kind and size, struct fields and interface methods. By default it omits primitive leaves (`uint8`, `int32`, ...) and other catalog padding; pass `--types-full` if you want one-for-one parity with GoReSym's count.

Types print in Go syntax, as `reflect.Type.String()` gives them: a field as `+0018  Items []main.Item` with its offset and struct tag, an embedded field as its bare type, an interface method as `Handle([]uint8) ([]uint8, error)`. When two named types share a name in different packages (from Go 1.24 `sync.Mutex` holds an `internal/sync.Mutex`), both print with their import path, and so does every type that mentions one (`[]*internal/sync.Mutex`). A reference to a type outside the recovered set prints as `type@0x...`.

`--format json` adds what identifies a type beyond its name: `pkg_path` (the import path of a named type), `named`, `align`, `field_align`, and `methods`, the type's method table with each method's name, method type address and the `ifn` (interface call) and `tfn` (direct call) entry addresses. A part the linker dropped as unreachable is left out.

### `--itabs`

Recovers `(interface, concrete) -> method set` pairs from `runtime.itablinks`. Tags each entry as `(reachable)` if its address is referenced from `.text` or any data section, `(unreachable)` otherwise. The `.text` scan is amd64 only; on other architectures every entry reads `(reachability unknown)`. Useful for spotting dead itabs the linker left behind and for de-virtualizing calls in a disassembler.

### `--strings`

The program's string literals, each as its address, length and bytes, with the instructions that use it:

```
$ unstrip testdata/strlits.linux-amd64.stripped --strings --filter host.strlits
0x00000000004cd531      27  "static-host.strlits.example"
    0x00000000004a29ae  main.main+0xae  header
    0x000000000058a160  .data  static header
0x00000000004cda41      28  "dynamic-host.strlits.example"
    0x00000000004a26d5  main.build+0x35  store
```

Go packs its literals end to end with no terminator, so the bytes alone do not say where one ends.
A literal is reported only where the binary pairs a pointer with a length: two consecutive argument or result registers at a call or return (`registers`), two adjacent words stored off one base (`store`), or a `{pointer, length}` header in an initialized global or a read-only composite literal (`static header`, with any code that loads the header's address listed as `header`).
Each pair must also fit the linker's string table, which is sorted by length and packed; a pair that does not is dropped, not guessed at.
A literal the code never pairs with its length, such as a lookup table indexed byte by byte, is not reported.

Text that is not valid UTF-8 prints as `hex:...`.
`--filter` matches the text.
The toolchain version and module info strings are marked `[buildinfo]`.
In JSON (`-f json`) each literal has `addr`, `len`, `text` (or `hex`), `origin`, `uses` (`pc`, `function_addr`, `function`, `site`) and `headers`, and the report says whether the code was scanned, whether calls were read with the register ABI, and how many pairs were dropped and why.

amd64 and arm64.
On 386 there is no instruction scanner yet, so nothing is reported; `--strings --strings-runs` still prints the printable runs.
Garble's default mode leaves literals in place; `-literals` replaces most of them with code that builds them at run time, and what remains (including the encrypted bytes) is reported as it is.

### `--capabilities`

Matches the recovered types, itabs, and functions against a curated pattern set and reports what the binary appears to do: HTTP server, AWS S3 client, child-process spawn, raw socket, Sliver implant, and so on. First-pass triage answer to "what does this thing do?".

### `--reflect-names`

Recovers the table garble keeps so that reflection still returns original names, and prints each obfuscated -> original pair. On a binary without one it says so. Pass `--degarble` to apply the names to other output.

### `--fingerprint`

Stable structural sha256 over the user-package surface: functions, types, itabs, deps. Same source rebuilt with different flags or on a different host produces the same hash. Useful for clustering malware families across recompiles.

### `--goroutines`

Lists every `runtime.newproc` and `runtime.deferproc` call site in `.text`, resolving the target function when the LEA/ADRP pattern decodes. Surfaces the control flow hidden behind `go func() { ... }` and `defer`. amd64 and arm64 only.

### `--xrefs`

Builds a static call graph from direct `CALL` / `BL` scans in `.text`. Direct calls only; virtual dispatch through itabs lives in `--itabs`. Combine with `--from`, `--to`, `--depth`, and `--callgraph`.

### `--xref <SYMBOL>`

Lists every call site targeting the given symbol. Accepts a function name (resolved through pclntab) or a hex address (`0x...`). Output groups call sites under their containing function. amd64 and arm64. Direct-CALL coverage is solid on both; indirect-itab on arm64 catches the canonical `LDR Xt, [Xn, #slot]; BLR Xt` pair but misses other dispatch patterns Go's compiler emits.

### `--xref-readers <ADDR>` / `--xref-writers <ADDR>`

Scans `.text` for amd64 RIP-relative instructions touching the given data address. Readers cover LEA, MOV-load, CMP-against-memory, and CALL/JMP through a memory pointer. Writers cover MOV-store. Each hit reports the containing function plus the instruction PC and kind.

### `--data-at <ADDR>`

Inspects bytes at a data address. The interpretation is set by `--data-as`:

- `bytes` (default): hex+ASCII dump.
- `qwords`: 8-byte little-endian values.
- `ptrs`: pointer-sized values (8 bytes, 4 on a 32-bit binary), each resolved against the recovered function table, itab table, and section map.
- `ifaces`: Go interface headers (16 bytes; 8 on 32-bit), with the itab resolved to a concrete type and the dispatched method body address inline.
- `slice-header`: slice headers (`ptr + len + cap`; 24 bytes, 12 on 32-bit).
- `string`: Go string headers (`ptr + len`) with a printable preview of the pointed-to bytes.

Length is controlled by `--data-len` (bytes) or `--data-count` (records); the two are mutually exclusive. Defaults: 64 for `bytes`/`qwords`/`ptrs`, one record for `ifaces`/`string`/`slice-header` (16, 16 and 24 bytes on 64-bit).

### `--addr <PC>`

PC -> function, file, line, plus the inline call stack walked from `FUNCDATA_InlTree` and `PCDATA_InlTreeIndex`. The PC must be a link-time VA, the address as your disassembler shows it when the binary is loaded at its preferred base. For a runtime PC from an ASLR-rebased process, pass the delta via `--rebase`.

### `--addr-file <PATH>`

Batch reverse-lookup. Reads PCs from a file (one per line; `#`-comments allowed, blank lines skipped). Use `-` for stdin. Re-uses one parsed pclntab, so 200 lookups cost about the same as one.

### `--diff <OLD_BINARY>`

Compares the binary you're running unstrip on against an older build passed here, reports identical / moved / renamed / added / removed counts. Pair with `--port-symbols` to emit a script that renames functions in the new binary to whatever names they had in the old one.

### `--detect-garble`

Runs the garble obfuscation heuristic and prints the verdict and its signals. Independent of `--info` / `--buildinfo` so CI can gate on the exit code: 0 garbled, 1 clean, 2 indeterminate, 3 when the file could not be read as a Go binary.

---

## Mode modifiers

These flags only make sense alongside one of the analysis modes above.

- `--types-full`: with `--types`, also surface every type descriptor in the `[md.types, md.etypes)` region the focused walk missed. A candidate is kept only when its header holds together (alignment, kind, size and pointer data for the kind, a printable name, references inside the region).
- `--behavioral`: with `--fingerprint`, hash only the stdlib-interface implementation-count vector. Coarser. Not garble-stable: garble renames the interfaces, so a garbled build hashes differently from its plain build.
- `--degarble`: relabel hashed names from garble's recovered reflected-name table (see `--reflect-names`), where known. Applies to function, type, and itab output.
- `--rebase <DELTA>`: with `--addr`, subtract this offset (the `actual_load_base - preferred_load_base` delta) so you can pass a runtime PC instead of a link-time VA. Hex (`0x` prefix) or decimal.
- `--data-as <KIND>`: with `--data-at`, the interpretation. See `--data-at` above.
- `--data-len <N>` / `--data-count <N>`: with `--data-at`, bytes vs records. Mutually exclusive. The actual read is clamped to the containing section's file-backed range.
- `--strings-runs`: with `--strings`, print the printable runs of the read-only sections (`.rodata` and `.noptrdata` on ELF, `__rodata` and `__noptrdata` on Mach-O, `.rdata` on PE) instead of literals, as unstrip 2.1 and earlier did. A run often holds many literals glued together. Works on every architecture.
- `--strings-min <N>`: with `--strings`, the minimum length in bytes. Default 1 for literals, 8 for runs (below that runs are mostly struct-field-name fragments).
- `--strings-max <N>`: with `--strings`, cap the number of literals or runs emitted. Default unlimited.
- `--from <FUNCNAME>` / `--to <FUNCNAME>`: with `--xrefs`, filter to callers/callees of a named function. Combine with `--depth` for transitive walks.
- `--depth <N>`: with `--xrefs --from`/`--to`, transitive depth. Default 1.
- `--max-nodes <N>`: with `--xrefs --from`/`--to`, BFS node cap so a deep traversal on a large binary cannot blow memory. Default 5000. Output includes a `truncated` flag in JSON or a warning line in text when the cap is hit.
- `--callgraph`: with `--xrefs`, emit Graphviz dot format. With `--from` or `--to`, only the edges that traversal walks to `--depth`. Pipe to `dot -Tsvg -o callgraph.svg`.
- `--goroutines-show <KIND>`: with `--goroutines`, restrict by resolution state. `all` (default), `resolved`, or `unresolved`. The `unresolved` set is the one worth eyeballing in a disassembler.
- `--no-itab-reachability`: with `--itabs`, skip the `(reachable)/(unreachable)` annotation. On architectures without a code scanner (anything but amd64) the annotation is `(reachability unknown)`. Useful on large binaries where the scan is not free, or for scripted consumers that prefer the raw JSON shape.

---

## Output

- `-f, --format <FORMAT>`: `text` (default), `json`, `ida`, `ghidra`, `binja`. The disassembler formats emit a runnable script. `--format ghidra > apply.py` produces a Ghidra script (PyGhidra) that creates functions, sets names, attaches the Go name, signature and `file:line` as comments, declares typed struct types at the recorded field offsets, applies method prototypes with Go ABI storage, and labels itabs, type descriptors and moduledata. The IDA and Binary Ninja scripts do the same without prototypes. Each script prints its counts and `unstrip: done, N failures`.
- `--filter <STRING>`: substring filter. With `--types` matches type name, or the name with its import path; with `--itabs` matches interface name, concrete name, or any interface-method name (method-column matching is where the signal usually lives in garble-default binaries); otherwise matches function name.
- `--show <value|pointer|both>`: hides or shows the `pkg.(*T).M` wrappers Go's compiler generates for value-receiver methods, which the binary marks as wrappers (file `<autogenerated>`). Methods declared on `*T` are not wrappers. `both` (default) shows everything. `value` hides the wrappers, except in the default listing those an itab dispatches through. `pointer` shows only the wrappers. Applies to the default listing, `--itabs` (an itab whose every slot is a wrapper), and `--xrefs`.
- `--no-garble-warning`: suppress the auto garble warning that fires on `--info`/`--buildinfo` when the heuristic returns confidence >= 0.9. Useful for CI that treats stderr as fatal.
- `--no-signatures`: skip method-signature recovery. The default listing appends a Go-syntax signature (`(_0 []uint8) (int, error)`) to every method on a type the Go linker emitted a `_type` record for (every interface-method implementation, plus any type reached through reflection or stored as `any`). Methods on types the linker elided for dead-code reasons stay bare; pass this flag to drop signatures everywhere for diff-friendly output or the smallest column width.

---

## Rewrite the binary

This is the destructive surface. By default unstrip writes a new file next to the input; only `--in-place --yes` mutates the input.

### `--symbols-as <elf|pe>`

Writes a new binary with a populated symbol table built from the recovered functions. For ELF the result has a synthetic `.symtab` + `.strtab` so `nm`, `gdb`, `objdump --syms`, `perf`, and eBPF stack traces see the symbols (`delve` needs DWARF and does not). ELF input must be little-endian ELF64; ELF32 (386, arm) is refused. For PE the result has a populated COFF symbol table referenced from `IMAGE_FILE_HEADER` so `dumpbin /symbols` and WinDbg pick it up. Pass the format that matches the input container.

- `-o, --output <PATH>`: write the result here. Default: `<input>.symbols` next to the input.
- `--in-place`: overwrite the input file. Refuses to run without `--yes`. Mutually exclusive with `--output`.
- `--yes`: confirm a destructive operation.

---

## RE-tool integration

### `--install-plugin <ida|ghidra|binja>`

Drops a wrapper plugin into the user's RE-tool plugin directory. IDA gets a menu item under Edit -> Plugins; Ghidra gets a script under Script Manager; Binary Ninja gets a Plugins menu item. The wrapper shells out to the unstrip binary on `$PATH`, so make sure unstrip is installed. Overrides the default install path via `$UNSTRIP_PLUGIN_DIR` if set.

### `--dispatch-resolver <ghidra>`

Emits a Ghidra script (Python 3, PyGhidra) that, when invoked at an interface method call (cursor on the `CALL reg` or `blr xN` that follows the itab method load), finds that load, turns its offset into the method slot (`(offset - 0x18) / 8`), and prints every recovered itab with a method in that slot. 64-bit programs only. Useful for de-virtualizing dispatch in a stripped Go program inside Ghidra. Only Ghidra is supported today.

### `--port-symbols <ida|ghidra|binja>`

With `--diff`, emit a port-symbols script for the chosen RE tool instead of the text/json report. The script applies the names unstrip recovered from the OLD binary's pclntab at the paired addresses in the binary you're running unstrip on. It does not read names you added in a disassembler database. Functions pair by name, then by unique masked code (see `--diff`), so two garble builds with different seeds pair poorly.
