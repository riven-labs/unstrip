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

Walks the typelinks table plus references reachable from it, prints recovered type names with kind, size, and struct fields. By default it omits primitive leaves (`uint8`, `int32`, ...) and other catalog padding; pass `--types-full` if you want one-for-one parity with GoReSym's count.

### `--itabs`

Recovers `(interface, concrete) -> method set` pairs from `runtime.itablinks`. Tags each entry as `(reachable)` if its address is referenced from `.text` or any data section, `(unreachable)` otherwise. Useful for spotting dead itabs the linker left behind and for de-virtualizing calls in a disassembler.

### `--strings`

Printable string literals from the binary's read-only data regions (`.rodata` / `.noptrdata` on ELF; `__rodata` / `__noptrdata` on Mach-O; `.rdata` on PE). Pair with `--filter "https://"` or `--filter "_NO_"` to narrow the output. Garble does not rewrite string literals in its default mode, so this is often the surface that identifies an obfuscated binary when symbols are hashed.

### `--capabilities`

Matches the recovered types, itabs, and functions against a curated pattern set and reports what the binary appears to do: HTTP server, AWS S3 client, child-process spawn, raw socket, Sliver implant, and so on. First-pass triage answer to "what does this thing do?".

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
- `ptrs`: same as `qwords` but each value is resolved against the recovered function table, itab table, and section map.
- `ifaces`: 16-byte Go interface headers, with the itab resolved to a concrete type and the dispatched method body address inline.
- `slice-header`: 24-byte slice headers (`ptr + len + cap`).
- `string`: Go string headers (`ptr + len`) with a printable preview of the pointed-to bytes.

Length is controlled by `--data-len` (bytes) or `--data-count` (records); the two are mutually exclusive. Defaults: 64 for `bytes`/`qwords`/`ptrs`, 16 for `ifaces`/`string`, 24 for `slice-header`.

### `--addr <PC>`

PC -> function, file, line, plus the inline call stack walked from `FUNCDATA_InlTree` and `PCDATA_InlTreeIndex`. The PC must be a link-time VA, the address as your disassembler shows it when the binary is loaded at its preferred base. For a runtime PC from an ASLR-rebased process, pass the delta via `--rebase`.

### `--addr-file <PATH>`

Batch reverse-lookup. Reads PCs from a file (one per line; `#`-comments allowed, blank lines skipped). Use `-` for stdin. Re-uses one parsed pclntab, so 200 lookups cost about the same as one.

### `--diff <OLD_BINARY>`

Compares the binary you're running unstrip on against an older build passed here, reports identical / renamed / added / removed counts. Pair with `--port-symbols` to emit a script that renames functions in the new binary to whatever names they had in the old one.

### `--detect-garble`

Runs the garble obfuscation heuristic and prints a verdict to stderr. Independent of `--info` / `--buildinfo` so CI can gate on the exit code (exits 0 with `is_garbled=true|false`; the heuristic itself does not fail the run).

---

## Mode modifiers

These flags only make sense alongside one of the analysis modes above.

- `--types-full`: with `--types`, also surface every type-header-shaped entry in the `[md.types, md.etypes)` region the focused walk missed.
- `--behavioral`: with `--fingerprint`, hash only the stdlib-interface implementation-count vector. Coarser, but garble-stable.
- `--rebase <DELTA>`: with `--addr`, subtract this offset (the `actual_load_base - preferred_load_base` delta) so you can pass a runtime PC instead of a link-time VA. Hex (`0x` prefix) or decimal.
- `--data-as <KIND>`: with `--data-at`, the interpretation. See `--data-at` above.
- `--data-len <N>` / `--data-count <N>`: with `--data-at`, bytes vs records. Mutually exclusive. The actual read is clamped to the containing section's file-backed range.
- `--strings-min <N>`: with `--strings`, the minimum printable-run length. Default 8. Below that the output is dominated by struct-field-name fragments and other non-literal noise.
- `--strings-max <N>`: with `--strings`, cap the number of runs emitted. Default unlimited.
- `--from <FUNCNAME>` / `--to <FUNCNAME>`: with `--xrefs`, filter to callers/callees of a named function. Combine with `--depth` for transitive walks.
- `--depth <N>`: with `--xrefs --from`/`--to`, transitive depth. Default 1.
- `--max-nodes <N>`: with `--xrefs --from`/`--to`, BFS node cap so a deep traversal on a large binary cannot blow memory. Default 5000. Output includes a `truncated` flag in JSON or a warning line in text when the cap is hit.
- `--callgraph`: with `--xrefs`, emit Graphviz dot format. Pipe to `dot -Tsvg -o callgraph.svg`.
- `--goroutines-show <KIND>`: with `--goroutines`, restrict by resolution state. `all` (default), `resolved`, or `unresolved`. The `unresolved` set is the one worth eyeballing in a disassembler.
- `--no-itab-reachability`: with `--itabs`, skip the `(reachable)/(unreachable)` annotation. Useful on large binaries where the scan is not free, or for scripted consumers that prefer the raw JSON shape.

---

## Output

- `-f, --format <FORMAT>`: `text` (default), `json`, `ida`, `ghidra`, `binja`. The disassembler formats emit a runnable script. `--format ghidra > apply.py` produces a Ghidra script that creates functions, sets names, attaches `file:line` comments, and declares struct types with field offsets.
- `--filter <STRING>`: substring filter. With `--types` matches type name; with `--itabs` matches interface name, concrete name, or any interface-method name (method-column matching is where the signal usually lives in garble-default binaries); otherwise matches function name.
- `--show <value|pointer|both>`: hides or shows Go's autogenerated pointer-receiver method thunks. `both` (default) shows everything. `value` collapses to value methods and free functions. `pointer` does the inverse. Applies to the default listing, `--itabs`, and `--xrefs`.
- `--no-garble-warning`: suppress the auto garble warning that fires on `--info`/`--buildinfo` when the heuristic returns confidence >= 0.9. Useful for CI that treats stderr as fatal.
- `--no-signatures`: skip method-signature recovery. The default listing appends a Go-syntax signature (`(_0 []uint8) (int, error)`) to every method on a type the Go linker emitted a `_type` record for (every interface-method implementation, plus any type reached through reflection or stored as `any`). Methods on types the linker elided for dead-code reasons stay bare; pass this flag to drop signatures everywhere for diff-friendly output or the smallest column width.

---

## Rewrite the binary

This is the destructive surface. By default unstrip writes a new file next to the input; only `--in-place --yes` mutates the input.

### `--symbols-as <elf|pe>`

Writes a new binary with a populated symbol table built from the recovered functions. For ELF the result has a synthetic `.symtab` + `.strtab` so `nm`, `gdb`, `objdump --syms`, `perf`, eBPF stack traces, and `delve` see the symbols. For PE the result has a populated COFF symbol table referenced from `IMAGE_FILE_HEADER` so `dumpbin /symbols` and WinDbg pick it up. Pass the format that matches the input container.

- `-o, --output <PATH>`: write the result here. Default: `<input>.symbols` next to the input.
- `--in-place`: overwrite the input file. Refuses to run without `--yes`. Mutually exclusive with `--output`.
- `--yes`: confirm a destructive operation.

---

## RE-tool integration

### `--install-plugin <ida|ghidra|binja>`

Drops a wrapper plugin into the user's RE-tool plugin directory. IDA gets a menu item under Edit -> Plugins; Ghidra gets a script under Script Manager; Binary Ninja gets a Plugins menu item. The wrapper shells out to the unstrip binary on `$PATH`, so make sure unstrip is installed. Overrides the default install path via `$UNSTRIP_PLUGIN_DIR` if set.

### `--dispatch-resolver <ghidra>`

Emits a Ghidra script that, when invoked at a virtual call site (cursor on a `CALL [reg + slot*8]` instruction), prints every recovered itab whose method table contains the dereferenced slot. Useful for de-virtualizing dispatch in a stripped Go program inside Ghidra. Only Ghidra is supported today.

### `--port-symbols <ida|ghidra|binja>`

With `--diff`, emit a port-symbols script for the chosen RE tool instead of the text/json report. The script applies the names from the OLD binary at their new addresses in the binary you're running unstrip on. Useful for tracking a malware family across rebuilds: name everything in v1 inside your disassembler, then port the names into v2 mechanically.
