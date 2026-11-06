# Changelog

All notable changes are documented in this file.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Unreleased changes accumulate under `## [Unreleased]` until a tag is cut.

## [Unreleased]

## [2.0.0] - 2026-11-06

### Breaking changes

- The structs unstrip returns are `#[non_exhaustive]`, so new fields no longer
  need a major release: `ModuleData`, `ContainerProbe`, `SectionInfo`,
  `GoBinary`, `Section`, `Function`, `FuncEntry`, `InlineFrame`, `Type`,
  `StructField`, `InterfaceMethod`, `Itab`, `ItabMethod`, `BuildInfo`, `Module`,
  `Replace`, `Setting`, `RecoveredMethod`, `CallSite`, `CallEdge`, `XrefNode`,
  `XrefResult`, `DataXref`, `DataRow`, `ItabMethodEntry`, `GoroutineSpawn`,
  `InlinedCall`, `CallGraph`, `Node`, `Edge`, `Capability`,
  `CapabilityReport`, `Fingerprint`, `Components`, `BehavioralFingerprint`,
  `GarbleReport`, `GarbleVerdict`, `GarbleAssessment`, `Signal`,
  `ReflectNames`, `DiffReport`, `Pairing`, `GoString`, and `InstallReport`,
  plus the new `FuncFields`, `LineSpan`, `InlineLeaf`, `OpenDeferInfo`,
  `StackObject`, and `PointerMaps`. A struct literal or an exhaustive
  destructuring pattern of any of them no longer compiles outside the crate:
  use the values the crate returns, and add `..` to patterns. Field access is
  unchanged.
- These enums are `#[non_exhaustive]`: `Error`, `moduledata::Layout`,
  `NameEnc`, `gobin::Container`, `Arch`, `SectionKind`, `types::KindData`,
  `output::Format`, `export::Target`, `callsites::Target`, `CallKind`,
  `dataview::As`, `dataview::Symbol`, `dataxref::Kind`, `goroutines::Resolution`,
  `garble::Verdict`, `diff::MatchKind`, `inline::NodeKind`, `inline::EdgeKind`,
  and the new `ArgComp` and `OpenDeferFormat`. A `match` on one of them from
  outside the crate needs a wildcard arm. Constructing their variants is
  unchanged.
- `ModuleData` has the new `typedesclen`, `itaboffset`, and `itabsize` fields,
  `ContainerProbe` the new `declared_size` and `import_count`, and
  `moduledata::Layout` the new `V127` variant.
- `moduledata::Layout`'s variants run oldest to newest (`Pre118` first), which
  changes their discriminants. Code that cast a `Layout` to an integer gets
  different values.

### Added

- `Default` for `Type`, `StructField` and `FuncEntry` (and `KindName`,
  `KindData`), so code that builds these values by hand starts from
  `Default::default()` and sets the fields it needs.

- Go 1.27 support. Go 1.27 dropped `moduledata.typelinks` and `itablinks`; the
  new `Layout::V127` reads its moduledata (the new `typedesclen`, `itaboffset`,
  and `itabsize` fields), and `ModuleData::type_addrs` and
  `ModuleData::itab_addrs` return the type and itab addresses on every layout,
  walking the types region in place on Go 1.27 as the runtime does. A Go 1.27
  binary used to have no moduledata, and so no types, itabs, or gofunc-relative
  funcdata.

- GOARCH=386 binaries. Type-graph recovery, method tables, itabs, build info,
  stack objects, garble's reflected-name table, the C struct declarations of the
  exporters, and the `--data-at` `ptrs`, `ifaces`, `slice-header`, and `string`
  views all read at the binary's pointer size. Checked on Go 1.17 to 1.27 Linux
  and Windows builds. The call, goroutine, and data-reference scanners still
  decode amd64 and arm64 code only; big-endian targets are still refused by type
  recovery.

- Per-function metadata readers on `Pclntab`, for the Go 1.16/1.17, 1.18/1.19,
  and 1.20+ layouts. Each takes the `FuncEntry` that `func_entry_at(pc)` returns:
  - `line_table` returns the per-PC source positions as `LineSpan { pc_lo,
    pc_hi, file, line }`, increasing and merged where adjacent; PCs with no
    resolvable file or a non-positive line are left out.
  - `sp_delta_at` reads the pcsp table; `pcdata_value` reads any PCDATA table.
  - `inline_leaf` returns the innermost inlined call at a PC as `InlineLeaf`.
  - `func_fields` decodes the fixed `_func` fields (`FuncFields`; `start_line`
    only on Go 1.20+), and `funcdata` the address of a funcdata slot.
  - `arg_info` decodes FUNCDATA_ArgInfo as the runtime's traceback printer
    walks it (`ArgComp`), and `arg_live_first` reads the first tracked spill
    slot from FUNCDATA_ArgLiveInfo.
  - `open_coded_defer_info` decodes FUNCDATA_OpenCodedDeferInfo in all three
    formats (Go 1.14 to 1.17, 1.18 to 1.21, 1.22+).
  - `stack_objects` and `stack_object_mask` read FUNCDATA_StackObjects and each
    object's pointer mask; `pointer_maps` and `stack_map_index` read the args
    and locals pointer bitmaps and the bitmap index at a PC.
  - `is_wrapper` checks the funcID against the binary's own FuncIDWrapper.
  - `parse_arg_info` and `parse_open_defer_info` decode raw record bytes, and
    the FUNCDATA_* and PCDATA_* index constants are exported.

- `ModuleData::is_pointer_word` tells whether a package variable's word holds a
  pointer, from the `gcdata` and `gcbss` GC programs expanded as the runtime
  does. `ModuleData::text_addr` maps a text offset to an address through
  `textsectmap`, and `ModuleData::itab_fun_offset` gives where an itab's method
  slots start.

- `ContainerProbe::declared_size`, the end of the section and segment data the
  headers describe (larger than the file when it is truncated), and
  `ContainerProbe::import_count`, the number of functions a PE imports.

### Changed

- An ELF whose section header table points outside the file (damaged on purpose,
  or a truncated download) is read from its program headers, as the loader maps
  it, instead of failing to open. The probe names its architecture and segments.

- `UnsupportedPclntabVersion` names Go 1.16 as the oldest release that is read.

### Fixed

- Build info on Go 1.17 and older: `BuildInfo::parse` now decodes the
  pre-Go-1.18 format (two pointers to the version and modinfo string headers),
  so those binaries report their Go version and modules.
- Struct field offsets on Go 1.16 to 1.18, which store `offset<<1 | embedded`,
  are decoded; the encoding is picked from the pclntab magic and the build
  version.
- Itab type names honor `TFlagExtraStar`, so a value type is no longer listed as
  a pointer (`*main.Shape = *main.Circle`).
- Method tables of named func types were read 4 bytes early, which produced
  thousands of nameless methods on every Go 1.23+ binary and some fabricated
  signatures. Methods of named map types are recovered on every map layout,
  including Go 1.27's `MapType`, and a method table with a nameless method or an
  offset outside its region is rejected as a whole.
- Itab method slots on 32-bit Go 1.23+: `fun[0]` is at 12, not 16, since Go 1.23
  dropped the pad after `hash`.
- The type-name encoding probe read the 64-bit `_type` layout and could garble
  every itab and type name of a 32-bit binary.
- Inline frames and inline trees on Go 1.16 to 1.19: `lookup_inline` and
  `decode_inline_tree` read the Go 1.20+ `_func` and `inlinedCall` layouts.
  Both now read each layout, and `lookup_inline` walks the inline tree on every
  supported release (`InlinedCall::start_line` is 0 before Go 1.20).
- pc-value tables honor the pclntab quantum (it was taken as 1, wrong on arm64),
  and a table offset of 0 means no table, as in the runtime.
- ELF NOBITS and Mach-O zero-fill sections (`.bss`, `.noptrbss`) have no file
  bytes; reads used to return whatever another section kept at that offset.
- A garbled binary whose Go version was overwritten no longer reports a bogus
  version such as `go1.go`, and the garble report flags the overwrite.
- The inline-tree docs no longer claim parentPc is -1 for top-level entries.

## [1.2.0] - 2026-07-01

### Added

- Parse the Go 1.16 and 1.17 pclntab (magic `0xfffffffa`). The header has no
  textStart, the functab entries are pointer-sized with absolute entry PCs, and
  the `_func` struct leads with a uintptr entry, all of which differ from Go
  1.18+. The reader branches on the magic and recovers the function table (names,
  entry addresses, file and line) for these releases, on ELF through the named
  section and on PE by locating the header in the magic scan. `functions`,
  `lookup`, and code-signature identification now work on a Go 1.16/1.17 binary
  that before reported no functions.

- Recover types and itabs on the Go 1.16/1.17 moduledata. Go 1.18 inserted
  `rodata` and `gofunc` after `etypes`; the new `Layout::Pre118`, selected from
  the pclntab magic, skips them so `types::recover_all` and `itabs::recover_all`
  reach the right `types`, `typelinks`, and `itablinks`.

- Decode pre-1.17 type-name lengths. Go 1.17 switched the runtime `name` length
  from a 2-byte big-endian prefix to a varint (1.18+ kept the varint), but Go
  1.16 and 1.17 share the pclntab magic, so the encoding is detected per binary by
  probing type names with both forms and keeping the one that decodes. With this,
  go1.16 type, field, and itab names resolve, not just their structure; go1.17 and
  1.18+ stay on the varint path unchanged.

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
