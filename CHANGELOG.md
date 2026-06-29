# Changelog

All notable changes are documented in this file.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Unreleased changes accumulate under `## [Unreleased]` until a tag is cut.

## [Unreleased]

### Added

- Parse the Go 1.16 and 1.17 pclntab (magic `0xfffffffa`). The header has no
  textStart, the functab entries are pointer-sized with absolute entry PCs, and
  the `_func` struct leads with a uintptr entry, all of which differ from Go
  1.18+. The reader branches on the magic and recovers the function table (names,
  entry addresses, file and line) for these releases, on ELF through the named
  section and on PE by locating the header in the magic scan. `functions`,
  `lookup`, and code-signature identification now work on a Go 1.16/1.17 binary
  that before reported no functions. Type and itab recovery still need the
  1.16/1.17 moduledata and are unchanged for now.

### Changed

- A Go 1.2 to 1.15 binary is named honestly instead of read as a non-Go
  container. The pclntab locator knows the Go 1.16 through 1.20+ header shapes,
  so an older binary used to fall through to "no pclntab section found". A shallow
  recognizer, consulted only after the magic and structural scans fail, validates
  the version-independent header prefix and returns `UnsupportedPclntabVersion`
  with the named release, so a caller reports which Go built the binary rather
  than implying it is not Go.

- A container whose header goblin cannot parse now yields a best-effort probe
  (format, size, whole-file entropy, and the PE machine when the COFF header
  outlives a zeroed PE signature) instead of a bare parse error, so a sample with
  a deliberately damaged header still gets a summary.

### Fixed

- The functab walk bounds every offset, so a hostile or corrupt pclntab (a huge
  nfunc, a funcoff past the table, an out-of-range entry index) returns no entry
  instead of overflowing a usize. A property test runs thousands of mutated
  headers through parse, functions, and lookup for every layout, so a crafted
  pclntab cannot crash the reader.

## [1.1.0] - 2026-06-26

### Added

- `--reflect-names` recovers garble's obfuscated-to-original reflected-name
  dictionary from the data the runtime keeps for reflection. `--degarble`
  relabels the hashed identifiers in the function, type, and itab output
  back to those names where they are known.
- Parses the Go 1.26 moduledata layout. Recovery is now exercised across
  Go 1.18 through 1.26, including PIE address rebasing and arm64 type
  recovery.
- Recovers itabs and reads moduledata on 32-bit and big-endian binaries.
  Pointer size and byte order come from the container header instead of an
  assumed 64-bit little-endian. Type-graph recovery still requires 64-bit
  little-endian and reports a clear error rather than returning a wrong
  answer on anything else.
- Selects the matching slice from a Mach-O universal (fat) binary, and
  locates moduledata through the Mach-O `go_module` section.
- Recovers struct field tags into the type catalog.
- Recovers the ELF load base from the program headers when an ELF has had
  its section table stripped, so addresses still resolve.
- Finds the pclntab structurally when its magic has been rewritten,
  validating each candidate by layout instead of trusting the magic bytes.
- A container probe names packed and non-Go inputs by reason, so a file
  that is not a Go binary fails with an explanation instead of a misparse.
- `--fingerprint` emits a stable structural hash for clustering recompiles
  of the same source. `--behavioral` narrows it to the stdlib-interface
  method-set vector, which stays stable under garble.
- libfuzzer targets covering the parser entry points.

### Changed

- `--diff` matches functions by identity (name, then code signature)
  instead of by address, so a rebuild that moves code still lines the two
  binaries up.
- The export generator records which tool produced the output, in both the
  Ghidra metadata and the stats lines, so an export driven by another tool
  is not labeled as unstrip.
- `--buildinfo` degrades when the modinfo blob is stripped, reporting what
  it can recover instead of failing.
- `Pclntab` derives `Clone`.

### Fixed

- Bounds and overflow checks across the parsers for attacker-crafted
  headers: cutab index arithmetic, moduledata section offsets, PE section
  address arithmetic, the Mach-O fat-arch count, section file ranges, and
  moduledata slice extents are all verified or saturated before use.
- `--data-at` reads NOBITS sections without panicking and rejects
  implausible string headers.
- The pcHeader scan accepts a zero `textStart`.
- Pre-1.18 pclntab layouts fail with an honest version error instead of a
  partial misread.

## [1.0.0] - 2026-06-01

First public release.

### Added

- `--xref` runs on arm64 binaries (was amd64-only). Direct-CALL
  recognition is fully covered (BL with sign-extended 26-bit
  offset). Indirect-itab dispatch is recognized via the canonical
  `LDR Xt, [Xn, #slot]; BLR Xt` pair where slot equals the recovered
  itab slot offset; other arm64 dispatch shapes the compiler emits
  are silently skipped pending a real disassembler integration.
- `ModuleData::locate_all` walks `runtime.firstmoduledata.next` to
  return every chained module in a binary. On disk most binaries have a
  single moduledata so the returned vector usually has length 1; the
  chain shows up at runtime when a host loads a plugin or shared
  library, and any future on-disk multi-module fixture will now walk
  cleanly. The walker recognizes `next` structurally (each chained
  moduledata starts with a pcHeader pointer whose target carries the
  pclntab magic), so no version-specific tail-field offset table is
  needed.
- Method-signature recovery. The default function listing, `--addr`,
  and `--xrefs` now append a Go-syntax signature like
  `(_0 []uint8) (int, error)` to every method whose mtyp resolves to a
  funcType record. Two paths feed the recovery: every type's
  `_type.uncommon().methods` table, and every itab's method table.
  Disable with `--no-signatures`. Argument names are not in the binary;
  positional placeholders (`_0`, `_1`, ...) keep the shape correct.
  Coverage scope: methods on types the Go linker emitted a `_type`
  record for (every interface-method implementation, plus any type
  reached through reflection or stored as `any`) recover reliably.
  Methods on types the linker elided because nothing at runtime
  needed the type record stay bare. Free top-level functions are
  always bare. JSON output gains an optional `signature` field per
  function.
- `--xref <SYMBOL>` finds every call site that targets the given function
  name or hex address, grouped by containing caller. Scanner 1 resolves
  direct `CALL rel32` sites; Scanner 2 adds direct `CALL [rip+itab+slot]`
  indirect dispatch sites for any interface-method implementation,
  carrying the resolved itab address and interface method name inline.
- `--data-at <ADDR>` inspects bytes at a data address through every
  recovery map the binary has: function table, itab table, section map.
  Six interpretation modes: `bytes`, `qwords`, `ptrs` (qwords plus
  symbolize each value), `ifaces` (16-byte Go iface header resolved
  through the itab table, with the dispatched method body address
  inline), `slice-header`, `string` (with quoted preview). `--data-count
  N` reads N records instead of N bytes for the structured modes.
- `--xref-readers <ADDR>` and `--xref-writers <ADDR>` scan `.text` for
  RIP-relative instructions touching a data address. Five-kind taxonomy:
  `lea`, `mov-load`, `mov-store`, `cmp`, `call-indirect`.
- `--strings` walks read-only sections for printable runs with
  `--strings-min` and substring filter via `--filter`.
- `--info` prints a section map with `(ptr|noptr, ro|rw)` classification
  for every Go-relevant section.
- `--show value|pointer|both` hides Go's autogenerated pointer-receiver
  method thunks (or shows only thunks). Applies to the function listing,
  `--itabs` concrete column, and `--xrefs`. Itab-dispatched pointer
  thunks stay visible under `--show value` with an `(itab thunk)`
  marker.
- `--itabs` annotates each row with `(reachable)` or `(unreachable)`
  based on whether the itab address is referenced from `.text` or any
  data section. Suppress with `--no-itab-reachability`.
- `--buildinfo` synthesizes a fallback record from the pclntab magic
  byte when the modinfo blob is stripped. The synthesized `go_version`
  encodes the inference inline so downstream consumers cannot mistake
  the guess for ground truth.
- `unstrip::inline::inline_callgraph` reconstructs the inlined-call
  graph from a stripped Go binary's `FUNCDATA_InlTree`. Anonymous-inline
  nodes are preserved as first-class structural recoveries when callee
  names have been stripped (garble `-tiny`, `-ldflags=-s -w`).
- `docs/USAGE.md` reference with one paragraph per flag.
- `CONTRIBUTING.md` with development setup and PR conventions.
- `SECURITY.md` with the vulnerability reporting contact.
- `CODE_OF_CONDUCT.md` and GitHub issue / PR templates for the
  community-onboarding surface.
- README `Safety posture` section: what the parser does to defend
  against attacker-crafted bytes, and where it does not yet claim
  coverage (structured fuzzing, garble-update resilience, Mach-O
  integration fixture matrix).

### Changed

- `--info` and `--detect-garble` share one unified verdict. The two
  heuristics previously contradicted each other on the same input.
  `--detect-garble` defines exit-code semantics: `0` garbled, `1` clean,
  `2` indeterminate.
- `--itabs --filter` matches against interface-method names in addition
  to interface and concrete names.
- `--xrefs` text output is indented by depth-from-root. Truncation
  footer lands on stdout so piping through `less` does not hide it.
- `--help` output grouped into sections (`Analysis modes`, `Mode
  modifiers`, `Output`, `Rewrite the binary`, `RE-tool integration`).
  `-h` prints a one-screen cheat sheet of common invocations.
