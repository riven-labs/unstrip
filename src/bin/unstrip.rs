use std::io::{self, BufWriter, Write};
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, ValueEnum};

use unstrip::buildinfo::BuildInfo;
use unstrip::export;
use unstrip::gobin::GoBinary;
use unstrip::itabs;
use unstrip::moduledata::ModuleData;
use unstrip::output::{detect_garble, detect_go_version, write_functions, write_info, Format};
use unstrip::pclntab::Pclntab;
use unstrip::types;

#[derive(Parser)]
#[command(
    name = "unstrip",
    version,
    about = "Recover symbols from stripped Go binaries.",
    long_about = None,
)]
struct Args {
    /// Path to the binary to analyze. Omit when using --install-plugin.
    binary: Option<PathBuf>,

    /// Output format.
    #[arg(short, long, value_enum, default_value_t = OutFormat::Text)]
    format: OutFormat,

    /// Print container and pclntab metadata, then exit.
    #[arg(long)]
    info: bool,

    /// Parse the Go buildinfo blob (module dep tree, build settings), then exit.
    #[arg(long)]
    buildinfo: bool,

    /// Recover Go type information (names, kinds, sizes, struct fields), then exit.
    /// Default mode (`Focused`) walks typelinks plus child references and
    /// omits primitive leaves (`uint8`, `int32`, ...) and other catalog-
    /// padding. For GoReSym-shape catalog breadth, also pass `--types-full`.
    #[arg(long)]
    types: bool,

    /// With `--types`, also surface every type-header-shaped entry
    /// in the `[md.types, md.etypes)` region the focused walk missed.
    /// Produces a much larger catalog including primitive leaves. Use when
    /// you want one-for-one parity with GoReSym's type count.
    #[arg(long)]
    types_full: bool,

    /// Recover (interface, concrete) pairs from runtime.itablinks, then exit.
    #[arg(long)]
    itabs: bool,

    /// Compute a stable structural fingerprint (sha256) of the binary's
    /// user-package surface, functions, types, itabs, deps. Same source
    /// rebuilt with different flags/host produces the same hash. Useful for
    /// clustering malware families across recompiles.
    #[arg(long)]
    fingerprint: bool,

    /// With --fingerprint, hash only the stdlib-interface implementation-count
    /// vector. Garble-stable: garble doesn't rename stdlib types, so a
    /// garbled rebuild produces the same behavioral hash. Coarser than the
    /// regular fingerprint; use as a clustering signal, not a unique ID.
    #[arg(long)]
    behavioral: bool,

    /// Reverse-lookup mode: given a single PC, print the containing function name,
    /// file, and line, then exit. PC must be a link-time VA, the address as your
    /// disassembler shows it when the binary is loaded at its preferred base, not a
    /// runtime address from a process where ASLR has rebased it. Use --rebase to
    /// translate runtime addresses.
    #[arg(long, value_name = "PC")]
    addr: Option<String>,

    /// Subtract this offset from --addr before lookup. Use when --addr is a
    /// runtime PC from a process where ASLR rebased the binary: pass the delta
    /// (actual_load_base - preferred_load_base) and unstrip translates back to
    /// the link-time VA on disk. Hex (0x prefix) or decimal.
    #[arg(long, value_name = "DELTA")]
    rebase: Option<String>,

    /// Batch reverse-lookup: read PCs from a file (one per line, `#`-comments
    /// allowed, blank lines skipped) and print one resolution per line. Use
    /// `-` for stdin. Re-uses one parsed pclntab, so 200 lookups cost about
    /// the same as 1.
    #[arg(long, value_name = "PATH")]
    addr_file: Option<String>,

    /// Install a wrapper plugin into the user's RE-tool plugin directory.
    /// IDA gets a menu item under Edit -> Plugins; Ghidra gets a script
    /// under Script Manager; Binary Ninja gets a Plugins menu item. The
    /// wrapper shells out to this binary on PATH, so install unstrip too.
    /// Overrides the default install path via $UNSTRIP_PLUGIN_DIR if set.
    #[arg(long, value_name = "ida|ghidra|binja")]
    install_plugin: Option<String>,

    /// Write a new binary containing a populated symbol table built from
    /// the recovered functions. For ELF the result has a synthetic
    /// `.symtab` + `.strtab` so `nm`, `gdb`, `objdump --syms`, `perf`,
    /// eBPF stack traces, and `delve` see the symbols. For PE the result
    /// has a populated COFF symbol table referenced from the
    /// IMAGE_FILE_HEADER so `dumpbin /symbols` and WinDbg pick it up.
    /// Pass `elf` for ELF inputs and `pe` for PE inputs.
    #[arg(long, value_name = "elf|pe")]
    symbols_as: Option<String>,

    /// With `--symbols-as`, write the result to this path. Defaults to
    /// `<input>.symbols` next to the input.
    #[arg(long, short = 'o', value_name = "PATH")]
    output: Option<PathBuf>,

    /// With `--symbols-as`, overwrite the input file in place. Mutually
    /// exclusive with `--output`. Refuses to run without an explicit
    /// `--yes` confirmation since this rewrites the original file.
    #[arg(long)]
    in_place: bool,

    /// Confirm a destructive operation (currently only `--in-place`).
    #[arg(long)]
    yes: bool,

    /// List every `runtime.newproc` and `runtime.deferproc` call site
    /// in `.text`, resolving the target function the goroutine or
    /// deferred call will run when possible. Surfaces the control flow
    /// hidden behind `go func() { ... }` and `defer` in Go programs.
    /// amd64 and arm64 only today.
    #[arg(long)]
    goroutines: bool,

    /// With `--goroutines`, restrict output to a subset by resolution
    /// state. `all` prints every call site (default). `resolved` keeps
    /// only sites where the funcval entry PC decoded. `unresolved` keeps
    /// only sites where the LEA/ADRP pattern was missing or the funcval
    /// pointer landed outside any mapped section. The unresolved set is
    /// the one worth eyeballing in IDA, since something stopped the
    /// heuristic from naming the goroutine body.
    #[arg(long, requires = "goroutines", value_enum, default_value_t = GoroutinesShow::All)]
    goroutines_show: GoroutinesShow,

    /// Compare this binary's recovered functions against another binary
    /// passed as the positional argument. Reports identical / renamed /
    /// added / removed counts. Pair with `--port-symbols ida|ghidra|binja`
    /// to emit a script that renames functions in the new binary
    /// according to whatever names they had in the old one.
    #[arg(long, value_name = "OLD_BINARY")]
    diff: Option<PathBuf>,

    /// Match the recovered types, itabs, and functions against a curated
    /// set of patterns and report what the binary appears to do: HTTP
    /// server, AWS S3, child-process spawn, raw socket, Sliver implant,
    /// etc. First-pass triage answer to "what is this binary?".
    #[arg(long)]
    capabilities: bool,

    /// Emit an RE-tool script that surfaces the recovered itab dispatch
    /// table when invoked at a virtual call site, then exit. Only Ghidra
    /// is supported today: run the resulting script in the Script Manager,
    /// then place the cursor on a `CALL [reg + slot*8]` instruction and
    /// invoke "Unstrip: Resolve dispatch at cursor" from Tools to see every
    /// recovered (interface, concrete) pair whose method table contains
    /// that slot.
    #[arg(long, value_name = "ghidra")]
    dispatch_resolver: Option<String>,

    /// With `--diff`, emit a port-symbols script for the chosen RE tool
    /// instead of the text/json report. The script applies the names
    /// from the OLD binary at their new addresses in the binary you're
    /// running unstrip on.
    #[arg(long, value_name = "ida|ghidra|binja")]
    port_symbols: Option<String>,

    /// Build a static call graph by scanning `.text` for direct CALL/BL
    /// targets resolved against the recovered function set. Direct
    /// calls only; virtual dispatch through itabs lives in `--itabs`.
    /// Combine with `--from`, `--to`, `--depth`, or `--callgraph dot`.
    #[arg(long)]
    xrefs: bool,

    /// With `--xrefs`, list only callers and callees reachable from
    /// this function name. Combine with `--depth` to expand transitively.
    #[arg(long, value_name = "FUNCNAME")]
    from: Option<String>,

    /// With `--xrefs`, list only functions that call this one. Combine
    /// with `--depth`.
    #[arg(long, value_name = "FUNCNAME")]
    to: Option<String>,

    /// With `--xrefs --from`/`--to`, transitive depth. Default 1.
    #[arg(long, default_value_t = 1)]
    depth: usize,

    /// With `--xrefs --from`/`--to`, cap the BFS at this many discovered
    /// nodes. A deep traversal on a large binary will otherwise blow
    /// memory. Output includes a `truncated` flag (JSON) or a warning
    /// line (text) when the cap is hit. Default 5000.
    #[arg(long, default_value_t = 5000, value_name = "N")]
    max_nodes: usize,

    /// With `--xrefs`, emit Graphviz dot format suitable for
    /// `dot -Tsvg -o callgraph.svg`. Otherwise text (caller -> callee).
    #[arg(long)]
    callgraph: bool,

    /// Filter recovered output by substring. With --types, matches type
    /// name. With --itabs, matches interface name, concrete name, or
    /// any interface-method name (method-column matching is what the
    /// signal usually lives in on garble-default binaries). Default
    /// (functions list) matches function name.
    #[arg(long)]
    filter: Option<String>,

    /// Run the garble obfuscation name-shape heuristic and print a verdict
    /// to stderr. Independent of --info / --buildinfo so scripts can gate
    /// on exit code (exits 0 with `is_garbled=true|false` printed; the
    /// heuristic itself does not fail the run).
    #[arg(long)]
    detect_garble: bool,

    /// Suppress the auto garble warning that fires on --info / --buildinfo
    /// when the heuristic returns confidence >= 0.9. Useful for CI that
    /// parses stdout and treats stderr as fatal.
    #[arg(long)]
    no_garble_warning: bool,
}

#[derive(Copy, Clone, ValueEnum, PartialEq, Eq, Debug)]
enum GoroutinesShow {
    All,
    Resolved,
    Unresolved,
}

#[derive(Copy, Clone, ValueEnum, PartialEq, Eq, Debug)]
enum OutFormat {
    Text,
    Json,
    Ida,
    Ghidra,
    Binja,
}

impl OutFormat {
    fn as_plain(self) -> Option<Format> {
        match self {
            OutFormat::Text => Some(Format::Text),
            OutFormat::Json => Some(Format::Json),
            _ => None,
        }
    }
}

fn main() -> ExitCode {
    let args = Args::parse();
    match run(args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("unstrip: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run(args: Args) -> Result<(), Box<dyn std::error::Error>> {
    // --install-plugin doesn't need a binary; handle it first.
    if let Some(target) = &args.install_plugin {
        let t = match target.as_str() {
            "ida" => export::Target::Ida,
            "ghidra" => export::Target::Ghidra,
            "binja" | "binaryninja" => export::Target::BinaryNinja,
            other => {
                return Err(format!(
                    "--install-plugin must be ida, ghidra, or binja (got {other:?})"
                )
                .into())
            }
        };
        let report = unstrip::plugin::install(t)?;
        let stdout = io::stdout();
        let mut out = stdout.lock();
        writeln!(out, "installed: {}", report.installed_at.display())?;
        writeln!(out, "{}", report.activation_step)?;
        return Ok(());
    }

    let binary_path = args.binary.as_ref().ok_or_else(|| {
        "missing binary path (or use --install-plugin to install a wrapper)".to_string()
    })?;
    let bin = GoBinary::open(binary_path)?;
    let pcln = Pclntab::parse(&bin)?;

    let stdout = io::stdout();
    let mut out = BufWriter::new(stdout.lock());

    if let Some(target) = &args.symbols_as {
        if target != "elf" && target != "pe" {
            return Err(format!("--symbols-as supports `elf` or `pe`, got {target:?}").into());
        }
        let functions = pcln.functions()?;
        let out_path = match (&args.output, args.in_place) {
            (Some(_), true) => return Err("--output and --in-place are mutually exclusive".into()),
            (Some(p), false) => p.clone(),
            (None, true) => {
                if !args.yes {
                    return Err("--in-place rewrites the input file; pass --yes to confirm".into());
                }
                binary_path.clone()
            }
            (None, false) => {
                let mut p = binary_path.clone();
                let mut fname = p.file_name().map(|f| f.to_os_string()).unwrap_or_default();
                fname.push(".symbols");
                p.set_file_name(fname);
                p
            }
        };
        let n = match (target.as_str(), bin.container) {
            ("elf", unstrip::gobin::Container::Elf) => unstrip::rewrite::write_symbols_as_elf(
                &bin,
                &functions,
                &out_path,
                Some(binary_path),
            )?,
            ("pe", unstrip::gobin::Container::Pe) => unstrip::rewrite::write_symbols_as_pe(
                &bin,
                &functions,
                &out_path,
                Some(binary_path),
            )?,
            (t, c) => {
                return Err(
                    format!("--symbols-as {t} requires a matching container, got {c:?}").into(),
                )
            }
        };
        writeln!(out, "wrote {} symbols to {}", n, out_path.display())?;
        out.flush()?;
        return Ok(());
    }

    if args.detect_garble {
        let funcs = pcln.functions().unwrap_or_default();
        let version = detect_go_version(&bin.bytes);
        let assessment =
            unstrip::garble::assess(&funcs, version.as_deref(), pcln.magic_is_official());
        match args.format {
            OutFormat::Json => {
                serde_json::to_writer_pretty(&mut out, &assessment)?;
                writeln!(out)?;
            }
            OutFormat::Text => {
                writeln!(
                    out,
                    "verdict: {:?}  confidence: {:.2}",
                    assessment.verdict, assessment.confidence
                )?;
                for s in &assessment.signals {
                    writeln!(
                        out,
                        "  [{}] {} -- {}",
                        if s.fired { "x" } else { " " },
                        s.id,
                        s.detail
                    )?;
                }
            }
            f => return Err(format!("--detect-garble does not support --format {:?}", f).into()),
        }
        out.flush()?;
        // Exit-code contract for --detect-garble (public, CI gating):
        //   0 = garbled, 1 = clean, 2 = indeterminate.
        // Bypass the run/main success path so the code lands on the
        // wire verbatim; no other handler needs custom exit semantics.
        std::process::exit(assessment.exit_code());
    }

    if args.info {
        let version = detect_go_version(&bin.bytes);
        let funcs = pcln.functions().unwrap_or_default();
        let report = detect_garble(&funcs, version.as_deref(), pcln.magic_is_official());
        maybe_warn_garbled(
            &funcs,
            version.as_deref(),
            pcln.magic_is_official(),
            args.no_garble_warning,
        );

        // Behavioral classification: classify itabs against the curated
        // stdlib interface list. Failure is non-fatal (no moduledata, etc.).
        let stdlib_counts: Vec<(&'static str, usize)> = ModuleData::locate(&bin)
            .ok()
            .and_then(|md| itabs::recover_all(&bin, &md).ok())
            .map(|itabs| unstrip::stdlib::classify_itabs(&itabs))
            .unwrap_or_default();

        match args.format {
            OutFormat::Json => {
                let payload = serde_json::json!({
                    "go_version": version,
                    "container": bin.container.as_str(),
                    "arch": bin.arch.as_str(),
                    "little_endian": bin.little_endian,
                    "pclntab_offset": bin.pclntab_offset,
                    "pclntab_size": bin.pclntab_size,
                    "pclntab_addr": bin.pclntab_addr,
                    "text_start": pcln.text_start(),
                    "ptr_size": pcln.ptrsize(),
                    "quantum": pcln.quantum(),
                    "functions": pcln.nfunc(),
                    "magic_is_official": pcln.magic_is_official(),
                    "garble_magic_rewritten": report.magic_rewritten,
                    "garble_version_overwritten": report.version_overwritten,
                    "garble_hashed_names": report.hashed_names,
                    "garble_verdict": report.verdict(),
                    "stdlib_interfaces": stdlib_counts.iter().map(|(name, count)| {
                        serde_json::json!({ "interface": name, "implementations": count })
                    }).collect::<Vec<_>>(),
                });
                serde_json::to_writer_pretty(&mut out, &payload)?;
                writeln!(out)?;
            }
            OutFormat::Text => {
                write_info(&mut out, &bin, &pcln, version.as_deref(), Some(&report))?;
                if !stdlib_counts.is_empty() {
                    writeln!(out)?;
                    writeln!(out, "stdlib interface implementations:")?;
                    let col = stdlib_counts
                        .iter()
                        .map(|(n, _)| n.len())
                        .max()
                        .unwrap_or(0);
                    for (name, count) in &stdlib_counts {
                        writeln!(out, "  {:<col$}  {}", name, count, col = col)?;
                    }
                }
            }
            f => return Err(format!("--info does not support --format {:?}", f).into()),
        }
        out.flush()?;
        return Ok(());
    }

    if let Some(path) = &args.addr_file {
        let raw = if path == "-" {
            let mut s = String::new();
            io::Read::read_to_string(&mut io::stdin(), &mut s)?;
            s
        } else {
            std::fs::read_to_string(path)?
        };
        let pcln_with_inline = match ModuleData::locate(&bin) {
            Ok(md) => pcln.with_gofunc(md.gofunc),
            Err(_) => pcln,
        };
        let rebase_delta = match &args.rebase {
            Some(s) => Some(parse_pc(s)?),
            None => None,
        };
        for (lineno, line) in raw.lines().enumerate() {
            let line = line.split('#').next().unwrap_or("").trim();
            if line.is_empty() {
                continue;
            }
            let raw_pc = match parse_pc(line) {
                Ok(v) => v,
                Err(e) => {
                    writeln!(out, "# line {}: {}", lineno + 1, e)?;
                    continue;
                }
            };
            let pc = match rebase_delta {
                Some(d) => match raw_pc.checked_sub(d) {
                    Some(v) => v,
                    None => {
                        writeln!(out, "0x{raw_pc:016x}  (underflow vs --rebase)")?;
                        continue;
                    }
                },
                None => raw_pc,
            };
            let frames = pcln_with_inline.lookup_inline(&bin, pc);
            if frames.is_empty() {
                writeln!(out, "0x{pc:016x}  (no function)")?;
                continue;
            }
            for (i, f) in frames.iter().enumerate() {
                let file = f.file.as_deref().unwrap_or("?");
                let line = f.line.map(|l| l.to_string()).unwrap_or_else(|| "?".into());
                let prefix = if frames.len() == 1 {
                    format!("0x{pc:016x} ")
                } else if i + 1 == frames.len() {
                    "(physical)".into()
                } else {
                    "(inlined) ".into()
                };
                writeln!(out, "{prefix} {}  {file}:{line}", f.name)?;
            }
        }
        out.flush()?;
        return Ok(());
    }

    if let Some(addr_str) = &args.addr {
        let raw_pc = parse_pc(addr_str)?;
        let pc = if let Some(rebase_str) = &args.rebase {
            let delta = parse_pc(rebase_str)?;
            raw_pc
                .checked_sub(delta)
                .ok_or_else(|| format!("--rebase {delta:#x} is larger than --addr {raw_pc:#x}"))?
        } else {
            raw_pc
        };

        // Try to enrich with the inline tree if moduledata is locatable.
        let pcln_with_inline = match ModuleData::locate(&bin) {
            Ok(md) => pcln.with_gofunc(md.gofunc),
            Err(_) => pcln,
        };
        let frames = pcln_with_inline.lookup_inline(&bin, pc);
        if frames.is_empty() {
            writeln!(out, "0x{pc:016x}  (no function covers this PC)")?;
        } else if frames.len() == 1 {
            let f = &frames[0];
            let file = f.file.as_deref().unwrap_or("?");
            let line = f.line.map(|l| l.to_string()).unwrap_or_else(|| "?".into());
            writeln!(out, "0x{pc:016x}  {}  {file}:{line}", f.name)?;
        } else {
            for (i, f) in frames.iter().enumerate() {
                let file = f.file.as_deref().unwrap_or("?");
                let line = f.line.map(|l| l.to_string()).unwrap_or_else(|| "?".into());
                let prefix = if i + 1 == frames.len() {
                    "(physical)"
                } else {
                    "(inlined) "
                };
                writeln!(out, "{prefix} {}  {file}:{line}", f.name)?;
            }
        }
        out.flush()?;
        return Ok(());
    }

    if args.fingerprint {
        if args.behavioral {
            let fp = unstrip::fingerprint::compute_behavioral(&bin)?;
            match args.format {
                OutFormat::Json => {
                    serde_json::to_writer_pretty(&mut out, &fp)?;
                    writeln!(out)?;
                }
                OutFormat::Text => {
                    writeln!(out, "{}", fp.sha256)?;
                    writeln!(out, "  stdlib interfaces:    {}", fp.interface_count)?;
                    writeln!(out, "  total implementations: {}", fp.total_implementations)?;
                    for (name, count) in &fp.counts {
                        writeln!(out, "  {:<30}  {}", name, count)?;
                    }
                }
                f => return Err(format!("--fingerprint does not support --format {:?}", f).into()),
            }
        } else {
            let fp = unstrip::fingerprint::compute(&bin, &pcln)?;
            match args.format {
                OutFormat::Json => {
                    serde_json::to_writer_pretty(&mut out, &fp)?;
                    writeln!(out)?;
                }
                OutFormat::Text => {
                    writeln!(out, "{}", fp.sha256)?;
                    writeln!(
                        out,
                        "  main module:    {}",
                        fp.components
                            .main_module_path
                            .as_deref()
                            .unwrap_or("(none)")
                    )?;
                    writeln!(
                        out,
                        "  user functions: {}",
                        fp.components.user_function_count
                    )?;
                    writeln!(out, "  user types:     {}", fp.components.user_type_count)?;
                    writeln!(out, "  itabs:          {}", fp.itab_count)?;
                    writeln!(out, "  deps:           {}", fp.dep_count)?;
                }
                f => return Err(format!("--fingerprint does not support --format {:?}", f).into()),
            }
        }
        out.flush()?;
        return Ok(());
    }

    if args.capabilities {
        let functions = pcln.functions().unwrap_or_default();
        let (types_v, itabs_v) = match ModuleData::locate(&bin) {
            Ok(md) => {
                let t = unstrip::types::recover_all(&bin, &md).unwrap_or_default();
                let i = itabs::recover_all(&bin, &md).unwrap_or_default();
                (t, i)
            }
            Err(_) => (Vec::new(), Vec::new()),
        };
        let report = unstrip::capabilities::compute(&functions, &types_v, &itabs_v);
        match args.format {
            OutFormat::Json => {
                serde_json::to_writer_pretty(&mut out, &report)?;
                writeln!(out)?;
            }
            OutFormat::Text => {
                if report.capabilities.is_empty() {
                    writeln!(out, "no capabilities matched.")?;
                } else {
                    let mut by_cat: std::collections::BTreeMap<
                        &str,
                        Vec<&unstrip::capabilities::Capability>,
                    > = std::collections::BTreeMap::new();
                    for c in &report.capabilities {
                        by_cat.entry(c.category).or_default().push(c);
                    }
                    for (cat, items) in by_cat {
                        writeln!(out, "[{cat}]")?;
                        for c in items {
                            writeln!(out, "  {} [{}]", c.name, c.rule_id)?;
                            for e in c.evidence.iter().take(3) {
                                writeln!(out, "      {e}")?;
                            }
                        }
                    }
                }
            }
            f => return Err(format!("--capabilities does not support --format {:?}", f).into()),
        }
        out.flush()?;
        return Ok(());
    }

    if let Some(target) = &args.dispatch_resolver {
        let md = ModuleData::locate(&bin)?;
        let itabs_v = itabs::recover_all(&bin, &md)?;
        let script = match target.as_str() {
            "ghidra" => unstrip::dispatch::write_ghidra(&itabs_v),
            other => {
                return Err(format!(
                    "--dispatch-resolver does not support '{}' yet (try 'ghidra')",
                    other
                )
                .into())
            }
        };
        out.write_all(script.as_bytes())?;
        out.flush()?;
        return Ok(());
    }

    if let Some(old_path) = &args.diff {
        let old_bin = GoBinary::open(old_path)?;
        let old_pcln = Pclntab::parse(&old_bin)?;
        let old_funcs = old_pcln.functions()?;
        let new_funcs = pcln.functions()?;
        let report = unstrip::diff::compute(&old_funcs, &new_funcs);

        if let Some(target) = &args.port_symbols {
            let t = match target.as_str() {
                "ida" => unstrip::export::Target::Ida,
                "ghidra" => unstrip::export::Target::Ghidra,
                "binja" | "binaryninja" => unstrip::export::Target::BinaryNinja,
                other => {
                    return Err(format!(
                        "--port-symbols must be ida, ghidra, or binja (got {other:?})"
                    )
                    .into());
                }
            };
            let script = unstrip::diff::write_port_script(t, &report);
            out.write_all(script.as_bytes())?;
            out.flush()?;
            return Ok(());
        }

        match args.format {
            OutFormat::Json => {
                serde_json::to_writer_pretty(&mut out, &report)?;
                writeln!(out)?;
            }
            OutFormat::Text => {
                writeln!(out, "old:        {} functions", report.old_total)?;
                writeln!(out, "new:        {} functions", report.new_total)?;
                writeln!(out)?;
                writeln!(out, "identical:  {}", report.identical)?;
                writeln!(out, "renamed:    {}", report.renamed)?;
                writeln!(
                    out,
                    "moved addr: {} (same address, different name)",
                    report.address_moved
                )?;
                writeln!(out, "added:      {} (in new, not in old)", report.added)?;
                writeln!(out, "removed:    {} (in old, not in new)", report.removed)?;
                writeln!(out)?;
                if let Some(needle) = &args.filter {
                    writeln!(out, "matching filter '{needle}':")?;
                    for p in &report.pairings {
                        let hit = p
                            .old_name
                            .as_deref()
                            .map(|n| n.contains(needle))
                            .unwrap_or(false)
                            || p.new_name
                                .as_deref()
                                .map(|n| n.contains(needle))
                                .unwrap_or(false);
                        if hit {
                            print_pairing(&mut out, p)?;
                        }
                    }
                }
            }
            f => return Err(format!("--diff does not support --format {:?}", f).into()),
        }
        out.flush()?;
        return Ok(());
    }

    if args.xrefs {
        let edges = unstrip::xrefs::find_calls(&bin, &pcln)?;

        if args.callgraph {
            // dot output: ignore --from/--to/--depth and emit the
            // full graph. For focused subgraphs use --from + --depth
            // and pipe text output into your own graph tool.
            out.write_all(unstrip::xrefs::to_dot(&edges).as_bytes())?;
            out.flush()?;
            return Ok(());
        }

        if !matches!(args.format, OutFormat::Text | OutFormat::Json) {
            return Err(format!("--xrefs does not support --format {:?}", args.format).into());
        }

        match (&args.from, &args.to) {
            (Some(from), None) => {
                let result = unstrip::xrefs::callees_from(&edges, from, args.depth, args.max_nodes);
                if matches!(args.format, OutFormat::Json) {
                    serde_json::to_writer_pretty(&mut out, &result)?;
                    writeln!(out)?;
                } else {
                    for node in &result.nodes {
                        writeln!(out, "{} -> {}", from, node.name)?;
                    }
                    if result.truncated {
                        eprintln!("warning: truncated at {} nodes", result.max_nodes);
                    }
                }
            }
            (None, Some(to)) => {
                let result = unstrip::xrefs::callers_of(&edges, to, args.depth, args.max_nodes);
                if matches!(args.format, OutFormat::Json) {
                    serde_json::to_writer_pretty(&mut out, &result)?;
                    writeln!(out)?;
                } else {
                    for node in &result.nodes {
                        writeln!(out, "{} -> {}", node.name, to)?;
                    }
                    if result.truncated {
                        eprintln!("warning: truncated at {} nodes", result.max_nodes);
                    }
                }
            }
            (Some(_), Some(_)) => {
                return Err("--from and --to are mutually exclusive".into());
            }
            (None, None) => {
                let pairs = unstrip::xrefs::forward_graph(&edges);
                if matches!(args.format, OutFormat::Json) {
                    serde_json::to_writer_pretty(&mut out, &edges)?;
                    writeln!(out)?;
                } else {
                    for (caller, callee) in pairs {
                        writeln!(out, "{} -> {}", caller, callee)?;
                    }
                }
            }
        }
        out.flush()?;
        return Ok(());
    }

    if args.goroutines {
        let spawns = unstrip::goroutines::find_spawns(&bin, &pcln)?;
        let filtered: Vec<&unstrip::goroutines::GoroutineSpawn> = spawns
            .iter()
            .filter(|s| match args.goroutines_show {
                GoroutinesShow::All => true,
                GoroutinesShow::Resolved => s.is_resolved(),
                GoroutinesShow::Unresolved => !s.is_resolved(),
            })
            .filter(|s| match &args.filter {
                Some(needle) => {
                    s.spawner.contains(needle)
                        || s.target_name
                            .as_deref()
                            .map(|n| n.contains(needle))
                            .unwrap_or(false)
                }
                None => true,
            })
            .collect();
        match args.format {
            OutFormat::Json => {
                serde_json::to_writer_pretty(&mut out, &filtered)?;
                writeln!(out)?;
            }
            OutFormat::Text => {
                write_goroutines(&mut out, &filtered)?;
                if matches!(args.goroutines_show, GoroutinesShow::All) {
                    let mut resolved = 0usize;
                    let mut no_lea = 0usize;
                    let mut unmapped = 0usize;
                    for s in &filtered {
                        match s.resolution {
                            unstrip::goroutines::Resolution::Resolved => resolved += 1,
                            unstrip::goroutines::Resolution::NoLeaPattern => no_lea += 1,
                            unstrip::goroutines::Resolution::FuncvalUnmapped => unmapped += 1,
                        }
                    }
                    let unresolved = no_lea + unmapped;
                    if resolved + unresolved > 0 {
                        writeln!(
                            out,
                            "{} resolved, {} unresolved ({} no-lea, {} unmapped)",
                            resolved, unresolved, no_lea, unmapped
                        )?;
                    }
                }
            }
            f => return Err(format!("--goroutines does not support --format {:?}", f).into()),
        }
        out.flush()?;
        return Ok(());
    }

    if args.itabs {
        let md = ModuleData::locate(&bin)?;
        let mut all = itabs::recover_all(&bin, &md)?;
        if let Some(needle) = &args.filter {
            // Match interface name, concrete name, OR any recovered
            // interface-method name. On garble-default binaries the
            // type columns are hashed but the method names survive
            // (garble can't rewrite a method that satisfies a stdlib
            // interface without breaking dispatch), so the method
            // column is the actual signal-bearing surface.
            all.retain(|it| {
                it.interface_name.contains(needle)
                    || it.concrete_name.contains(needle)
                    || it
                        .methods
                        .iter()
                        .any(|m| m.interface_method.contains(needle))
            });
        }
        match args.format {
            OutFormat::Json => {
                serde_json::to_writer_pretty(&mut out, &all)?;
                writeln!(out)?;
            }
            OutFormat::Text => write_itabs(&mut out, &all)?,
            f => return Err(format!("--itabs does not support --format {:?}", f).into()),
        }
        out.flush()?;
        return Ok(());
    }

    if args.types {
        let md = ModuleData::locate(&bin)?;
        let mode = if args.types_full {
            types::Mode::Full
        } else {
            types::Mode::Focused
        };
        let mut all = types::recover_with_mode(&bin, &md, mode)?;
        if let Some(needle) = &args.filter {
            all.retain(|t| t.name.contains(needle));
        }
        match args.format {
            OutFormat::Json => {
                serde_json::to_writer_pretty(&mut out, &all)?;
                writeln!(out)?;
            }
            OutFormat::Text => write_types(&mut out, &all)?,
            f => return Err(format!("--types does not support --format {:?}", f).into()),
        }
        out.flush()?;
        return Ok(());
    }

    if args.buildinfo {
        let funcs_for_warn = pcln.functions().unwrap_or_default();
        let version_for_warn = detect_go_version(&bin.bytes);
        maybe_warn_garbled(
            &funcs_for_warn,
            version_for_warn.as_deref(),
            pcln.magic_is_official(),
            args.no_garble_warning,
        );
        // When the modinfo blob has been stripped (garble's default
        // mode does this), fall back to the pclntab magic as a coarse
        // Go-version proxy. We deliberately encode "this is inferred,
        // not authoritative" INSIDE the value of go_version itself
        // (prefix `~`, suffix `(inferred from ...; modinfo wiped)`)
        // rather than as a sibling field, so downstream graders that
        // grep `go_version:` cannot mistake the guess for ground
        // truth. If the pclntab magic is also rewritten (garble does
        // this too), we propagate the original parse error rather
        // than inventing a guess from a hostile artifact.
        let info = match BuildInfo::parse(&bin) {
            Ok(info) => info,
            Err(orig) => match BuildInfo::from_pclntab_magic(pcln.magic()) {
                Some(info) => info,
                None => return Err(Box::new(orig)),
            },
        };
        match args.format {
            OutFormat::Json => {
                serde_json::to_writer_pretty(&mut out, &info)?;
                writeln!(out)?;
            }
            OutFormat::Text => write_buildinfo(&mut out, &info)?,
            f => return Err(format!("--buildinfo does not support --format {:?}", f).into()),
        }
        out.flush()?;
        return Ok(());
    }

    let mut functions = pcln.functions()?;
    if let Some(needle) = &args.filter {
        functions.retain(|f| f.name.contains(needle));
    }

    match args.format {
        OutFormat::Ida | OutFormat::Ghidra | OutFormat::Binja => {
            // For RE-tool exports, pull types too so the emitted script can
            // re-create struct layouts in the disassembler. If type recovery
            // fails (no moduledata, pre-1.18, etc.) we still emit functions.
            let types_for_export = ModuleData::locate(&bin)
                .ok()
                .and_then(|md| types::recover_all(&bin, &md).ok())
                .unwrap_or_default();
            let target = match args.format {
                OutFormat::Ida => export::Target::Ida,
                OutFormat::Ghidra => export::Target::Ghidra,
                OutFormat::Binja => export::Target::BinaryNinja,
                _ => unreachable!(),
            };
            export::write_script(&mut out, target, &functions, &types_for_export)?;
        }
        plain => {
            write_functions(&mut out, &bin, &pcln, &functions, plain.as_plain().unwrap())?;
        }
    }
    out.flush()?;
    Ok(())
}

/// Fire a one-line stderr warning when the unified garble assessment
/// returns a `Garbled` verdict. Routes through the same `assess()` path
/// `--detect-garble` uses so the warning and the explicit detector never
/// disagree on the same binary. Gated behind `--no-garble-warning`.
fn maybe_warn_garbled(
    functions: &[unstrip::pclntab::Function],
    go_version: Option<&str>,
    magic_is_official: bool,
    suppressed: bool,
) {
    if suppressed {
        return;
    }
    let a = unstrip::garble::assess(functions, go_version, magic_is_official);
    if a.is_garbled() && a.confidence >= 0.75 {
        eprintln!(
            "warning: this binary appears to be obfuscated with garble \
             (confidence {:.2}); reported symbols and build metadata are \
             not authoritative",
            a.confidence
        );
    }
}

fn parse_pc(s: &str) -> Result<u64, Box<dyn std::error::Error>> {
    let trimmed = s.trim();
    let (radix, body) = if let Some(rest) = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
    {
        (16, rest)
    } else {
        (10, trimmed)
    };
    let v =
        u64::from_str_radix(body, radix).map_err(|e| format!("could not parse PC '{s}': {e}"))?;
    Ok(v)
}

fn print_pairing<W: Write>(w: &mut W, p: &unstrip::diff::Pairing) -> io::Result<()> {
    use unstrip::diff::MatchKind;
    match p.kind {
        MatchKind::Identical => writeln!(
            w,
            "  =  0x{:x}  {}",
            p.old_addr.unwrap_or(0),
            p.old_name.as_deref().unwrap_or("?")
        ),
        MatchKind::Renamed => writeln!(
            w,
            "  R  0x{:x} -> 0x{:x}  {}",
            p.old_addr.unwrap_or(0),
            p.new_addr.unwrap_or(0),
            p.old_name.as_deref().unwrap_or("?")
        ),
        MatchKind::AddressMoved => writeln!(
            w,
            "  M  0x{:x}  {}  ->  {}",
            p.old_addr.unwrap_or(0),
            p.old_name.as_deref().unwrap_or("?"),
            p.new_name.as_deref().unwrap_or("?")
        ),
        MatchKind::Added => writeln!(
            w,
            "  +  0x{:x}  {}",
            p.new_addr.unwrap_or(0),
            p.new_name.as_deref().unwrap_or("?")
        ),
        MatchKind::Removed => writeln!(
            w,
            "  -  0x{:x}  {}",
            p.old_addr.unwrap_or(0),
            p.old_name.as_deref().unwrap_or("?")
        ),
    }
}

fn write_goroutines<W: Write>(
    w: &mut W,
    all: &[&unstrip::goroutines::GoroutineSpawn],
) -> io::Result<()> {
    if all.is_empty() {
        writeln!(w, "no goroutine spawn or defer call sites found")?;
        return Ok(());
    }
    let spawner_w = all
        .iter()
        .map(|s| s.spawner.len())
        .max()
        .unwrap_or(20)
        .min(30);
    for s in all {
        let target = match (&s.target_name, s.target_addr) {
            (Some(n), Some(addr)) => format!("{n} (0x{addr:x})"),
            (None, Some(addr)) => format!("(unnamed @ 0x{addr:x})"),
            (None, None) => {
                let reason = match s.resolution {
                    unstrip::goroutines::Resolution::NoLeaPattern => "no-lea-pattern",
                    unstrip::goroutines::Resolution::FuncvalUnmapped => "funcval-unmapped",
                    unstrip::goroutines::Resolution::Resolved => "unknown",
                };
                format!("(unresolved: {reason})")
            }
            (Some(n), None) => n.clone(),
        };
        let loc = match (&s.file, s.line) {
            (Some(f), Some(l)) => format!(" {f}:{l}"),
            (Some(f), None) => format!(" {f}"),
            _ => String::new(),
        };
        writeln!(
            w,
            "0x{:016x}  {:<spawner_w$}  -> {}{}",
            s.call_site,
            s.spawner,
            target,
            loc,
            spawner_w = spawner_w,
        )?;
    }
    Ok(())
}

fn write_itabs<W: Write>(w: &mut W, all: &[unstrip::Itab]) -> io::Result<()> {
    let iw = all
        .iter()
        .map(|i| i.interface_name.len())
        .max()
        .unwrap_or(20)
        .min(60);
    let cw = all
        .iter()
        .map(|i| i.concrete_name.len())
        .max()
        .unwrap_or(20)
        .min(60);
    for it in all {
        let marker = if it.incomplete { "  [INCOMPLETE]" } else { "" };
        writeln!(
            w,
            "0x{:016x}  {:<iw$}  =>  {:<cw$}{}",
            it.addr,
            it.interface_name,
            it.concrete_name,
            marker,
            iw = iw,
            cw = cw,
        )?;
        for m in &it.methods {
            writeln!(w, "    .{}() -> 0x{:x}", m.interface_method, m.concrete_fn,)?;
        }
    }
    Ok(())
}

fn write_types<W: Write>(w: &mut W, all: &[unstrip::Type]) -> io::Result<()> {
    let name_width = all.iter().map(|t| t.name.len()).max().unwrap_or(40).min(80);
    for t in all {
        writeln!(
            w,
            "0x{:016x}  {:<9}  size={:<6}  {:<name_w$}",
            t.addr,
            t.kind.as_str(),
            t.size,
            t.name,
            name_w = name_width,
        )?;
        match &t.kind_data {
            unstrip::types::KindData::Struct { fields } => {
                for f in fields {
                    let tag = if f.embedded { " (embedded)" } else { "" };
                    writeln!(
                        w,
                        "    +{:04x}  {}: type@0x{:x}{}",
                        f.offset, f.name, f.typ, tag
                    )?;
                }
            }
            unstrip::types::KindData::Interface { methods } => {
                for m in methods {
                    writeln!(w, "    .{}(): type@0x{:x}", m.name, m.typ)?;
                }
            }
            _ => {}
        }
    }
    Ok(())
}

fn write_buildinfo<W: Write>(w: &mut W, info: &BuildInfo) -> io::Result<()> {
    writeln!(w, "go version:    {}", info.go_version)?;
    if let Some(p) = &info.path {
        writeln!(w, "path:          {p}")?;
    }
    if let Some(m) = &info.main {
        let ver = if m.version.is_empty() {
            "(devel)"
        } else {
            &m.version
        };
        writeln!(w, "main module:   {}  {}", m.path, ver)?;
    }
    if !info.deps.is_empty() {
        writeln!(w)?;
        writeln!(w, "dependencies ({})", info.deps.len())?;
        let max_path = info
            .deps
            .iter()
            .map(|m| m.path.len())
            .max()
            .unwrap_or(0)
            .min(60);
        for m in &info.deps {
            writeln!(w, "  {:<path_w$}  {}", m.path, m.version, path_w = max_path)?;
        }
    }
    if !info.replaces.is_empty() {
        writeln!(w)?;
        writeln!(w, "replacements ({})", info.replaces.len())?;
        for r in &info.replaces {
            writeln!(
                w,
                "  {} {}  =>  {} {}",
                r.from.path, r.from.version, r.to.path, r.to.version
            )?;
        }
    }
    if !info.settings.is_empty() {
        writeln!(w)?;
        writeln!(w, "build settings")?;
        let max_key = info
            .settings
            .iter()
            .map(|s| s.key.len())
            .max()
            .unwrap_or(0)
            .min(30);
        for s in &info.settings {
            writeln!(w, "  {:<k$}  {}", s.key, s.value, k = max_key)?;
        }
    }
    Ok(())
}
