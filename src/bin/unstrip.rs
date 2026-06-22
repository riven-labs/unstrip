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
    long_about = "Recover symbols from stripped Go binaries.\n\nReference: https://github.com/riven-labs/unstrip/blob/main/docs/USAGE.md"
)]
struct Args {
    /// Path to the binary to analyze. Omit when using --install-plugin.
    binary: Option<PathBuf>,

    // ----- Analysis modes -----
    /// Container, Go version, garble heuristic.
    #[arg(long, help_heading = "Analysis modes")]
    info: bool,

    /// Module dep tree and build settings.
    #[arg(long, help_heading = "Analysis modes")]
    buildinfo: bool,

    /// Recover Go type names, kinds, sizes, struct fields.
    #[arg(long, help_heading = "Analysis modes")]
    types: bool,

    /// Recover (interface, concrete) pairs from runtime.itablinks.
    #[arg(long, help_heading = "Analysis modes")]
    itabs: bool,

    /// Recover printable string literals from read-only data.
    #[arg(long, help_heading = "Analysis modes")]
    strings: bool,

    /// Match recovered surface against a curated pattern set ("what is this binary?").
    #[arg(long, help_heading = "Analysis modes")]
    capabilities: bool,

    /// Recover garble's obfuscated-to-original reflected-name dictionary.
    #[arg(long, help_heading = "Analysis modes")]
    reflect_names: bool,

    /// Stable structural hash for clustering recompiles.
    #[arg(long, help_heading = "Analysis modes")]
    fingerprint: bool,

    /// List runtime.newproc / runtime.deferproc call sites.
    #[arg(long, help_heading = "Analysis modes")]
    goroutines: bool,

    /// Static call graph from direct CALL/BL scans.
    #[arg(long, help_heading = "Analysis modes")]
    xrefs: bool,

    /// Every call site targeting the given symbol (name or 0xADDR). amd64 and arm64.
    #[arg(long, value_name = "SYMBOL", help_heading = "Analysis modes")]
    xref: Option<String>,

    /// Every .text instruction READING the given data address. amd64 only.
    #[arg(long, value_name = "ADDR", help_heading = "Analysis modes")]
    xref_readers: Option<String>,

    /// Every .text instruction WRITING the given data address. amd64 only.
    #[arg(long, value_name = "ADDR", help_heading = "Analysis modes")]
    xref_writers: Option<String>,

    /// Inspect bytes at a data address with optional symbolic interpretation.
    #[arg(long, value_name = "ADDR", help_heading = "Analysis modes")]
    data_at: Option<String>,

    /// PC -> function, file, line, inline stack.
    #[arg(long, value_name = "PC", help_heading = "Analysis modes")]
    addr: Option<String>,

    /// Batch PC lookup; one PC per line. Use `-` for stdin.
    #[arg(long, value_name = "PATH", help_heading = "Analysis modes")]
    addr_file: Option<String>,

    /// Compare against an older build; report added/removed/renamed.
    #[arg(long, value_name = "OLD_BINARY", help_heading = "Analysis modes")]
    diff: Option<PathBuf>,

    /// Garble heuristic verdict to stderr; exit-code contract for CI.
    #[arg(long, help_heading = "Analysis modes")]
    detect_garble: bool,

    // ----- Mode modifiers -----
    /// Relabel hashed names from garble's recovered reflected-name table, where
    /// known. Applies to function, type, and itab output.
    #[arg(long, help_heading = "Mode modifiers")]
    degarble: bool,

    /// With --types: include primitive leaves (GoReSym-parity catalog).
    #[arg(long, help_heading = "Mode modifiers")]
    types_full: bool,

    /// With --fingerprint: hash only the stdlib-interface vector (garble-stable).
    #[arg(long, help_heading = "Mode modifiers")]
    behavioral: bool,

    /// With --addr: subtract this offset (use for runtime PCs from ASLR processes).
    #[arg(long, value_name = "DELTA", help_heading = "Mode modifiers")]
    rebase: Option<String>,

    /// With --data-at: interpretation.
    #[arg(long, value_enum, default_value_t = DataAs::Bytes,
          value_name = "bytes|qwords|ptrs|ifaces|slice-header|string",
          help_heading = "Mode modifiers")]
    data_as: DataAs,

    /// With --data-at: bytes to read. Mutually exclusive with --data-count.
    #[arg(
        long,
        value_name = "N",
        conflicts_with = "data_count",
        help_heading = "Mode modifiers"
    )]
    data_len: Option<usize>,

    /// With --data-at: records to read. Mutually exclusive with --data-len.
    #[arg(
        long,
        value_name = "N",
        conflicts_with = "data_len",
        help_heading = "Mode modifiers"
    )]
    data_count: Option<usize>,

    /// With --strings: minimum printable-run length.
    #[arg(
        long,
        value_name = "N",
        default_value_t = 8,
        help_heading = "Mode modifiers"
    )]
    strings_min: usize,

    /// With --strings: cap emitted runs. Default unlimited.
    #[arg(long, value_name = "N", help_heading = "Mode modifiers")]
    strings_max: Option<usize>,

    /// With --xrefs: filter to callers/callees reachable from this function.
    #[arg(long, value_name = "FUNCNAME", help_heading = "Mode modifiers")]
    from: Option<String>,

    /// With --xrefs: filter to functions that call this one.
    #[arg(long, value_name = "FUNCNAME", help_heading = "Mode modifiers")]
    to: Option<String>,

    /// With --xrefs --from/--to: transitive depth.
    #[arg(long, default_value_t = 1, help_heading = "Mode modifiers")]
    depth: usize,

    /// With --xrefs --from/--to: BFS node cap. Output flags truncation when hit.
    #[arg(
        long,
        default_value_t = 5000,
        value_name = "N",
        help_heading = "Mode modifiers"
    )]
    max_nodes: usize,

    /// With --xrefs: emit Graphviz dot format.
    #[arg(long, help_heading = "Mode modifiers")]
    callgraph: bool,

    /// With --goroutines: restrict by resolution state.
    #[arg(long, requires = "goroutines", value_enum, default_value_t = GoroutinesShow::All,
          help_heading = "Mode modifiers")]
    goroutines_show: GoroutinesShow,

    /// With --itabs: skip the (reachable)/(unreachable) annotation.
    #[arg(long, help_heading = "Mode modifiers")]
    no_itab_reachability: bool,

    // ----- Output -----
    /// Output format.
    #[arg(short, long, value_enum, default_value_t = OutFormat::Text, help_heading = "Output")]
    format: OutFormat,

    /// Substring filter; applies to types, itabs, functions.
    #[arg(long, help_heading = "Output")]
    filter: Option<String>,

    /// Hide Go-emitted pointer-receiver thunks (both|value|pointer).
    #[arg(long, value_enum, default_value_t = MethodShow::Both, value_name = "value|pointer|both",
          help_heading = "Output")]
    show: MethodShow,

    /// Suppress the auto garble warning on --info / --buildinfo.
    #[arg(long, help_heading = "Output")]
    no_garble_warning: bool,

    /// Skip method-signature recovery. Default lists every method with its
    /// Go-syntax signature appended (parameters and return types recovered
    /// from the type tables); this flag drops back to bare function names.
    #[arg(long, help_heading = "Output")]
    no_signatures: bool,

    // ----- Rewrite the binary -----
    /// Write a new binary with a populated symbol table (elf|pe).
    #[arg(long, value_name = "elf|pe", help_heading = "Rewrite the binary")]
    symbols_as: Option<String>,

    /// With --symbols-as: output path. Default: <input>.symbols.
    #[arg(
        long,
        short = 'o',
        value_name = "PATH",
        help_heading = "Rewrite the binary"
    )]
    output: Option<PathBuf>,

    /// With --symbols-as: overwrite the input. Requires --yes.
    #[arg(long, help_heading = "Rewrite the binary")]
    in_place: bool,

    /// Confirm a destructive operation.
    #[arg(long, help_heading = "Rewrite the binary")]
    yes: bool,

    // ----- RE-tool integration -----
    /// Drop a wrapper plugin into the RE tool's plugin directory.
    #[arg(
        long,
        value_name = "ida|ghidra|binja",
        help_heading = "RE-tool integration"
    )]
    install_plugin: Option<String>,

    /// Emit a Ghidra script that resolves itab dispatch at a call site.
    #[arg(long, value_name = "ghidra", help_heading = "RE-tool integration")]
    dispatch_resolver: Option<String>,

    /// With --diff: emit a script that renames functions to the OLD names.
    #[arg(
        long,
        value_name = "ida|ghidra|binja",
        help_heading = "RE-tool integration"
    )]
    port_symbols: Option<String>,
}

#[derive(Copy, Clone, ValueEnum, PartialEq, Eq, Debug)]
enum GoroutinesShow {
    All,
    Resolved,
    Unresolved,
}

#[derive(Copy, Clone, ValueEnum, PartialEq, Eq, Debug)]
enum DataAs {
    Bytes,
    Qwords,
    Ptrs,
    Ifaces,
    SliceHeader,
    String,
}

impl DataAs {
    fn to_module(self) -> unstrip::dataview::As {
        match self {
            DataAs::Bytes => unstrip::dataview::As::Bytes,
            DataAs::Qwords => unstrip::dataview::As::Qwords,
            DataAs::Ptrs => unstrip::dataview::As::Ptrs,
            DataAs::Ifaces => unstrip::dataview::As::Ifaces,
            DataAs::SliceHeader => unstrip::dataview::As::SliceHeader,
            DataAs::String => unstrip::dataview::As::String,
        }
    }

    fn default_len(self) -> usize {
        match self {
            DataAs::Bytes | DataAs::Qwords | DataAs::Ptrs => 64,
            DataAs::Ifaces | DataAs::String => 16,
            DataAs::SliceHeader => 24,
        }
    }

    /// Byte size of one record under this presentation. Drives the
    /// `--data-count N` conversion to a byte length so an operator
    /// can ask for "7 ifaces" without computing 16 * 7 themselves.
    fn record_size(self) -> usize {
        match self {
            DataAs::Bytes => 16,
            DataAs::Qwords | DataAs::Ptrs => 8,
            DataAs::Ifaces | DataAs::String => 16,
            DataAs::SliceHeader => 24,
        }
    }
}

#[derive(Copy, Clone, ValueEnum, PartialEq, Eq, Debug)]
enum MethodShow {
    /// Show every recovered function, including the autogenerated
    /// pointer-receiver thunks Go's compiler emits for interface
    /// satisfaction. Default.
    Both,
    /// Only value-receiver methods and free functions. Hides
    /// `pkg.(*Type).Method` entries.
    Value,
    /// Only pointer-receiver methods. Hides plain `pkg.Type.Method`
    /// and free functions.
    Pointer,
}

impl MethodShow {
    fn keeps(self, name: &str) -> bool {
        let is_ptr = name.contains(".(*");
        match self {
            MethodShow::Both => true,
            MethodShow::Value => !is_ptr,
            MethodShow::Pointer => is_ptr,
        }
    }

    /// Concrete-type names in --itabs use the leading-asterisk
    /// convention (`*main.xorMask` = pointer receiver, `main.xorMask`
    /// = value receiver). The function-name convention uses
    /// `pkg.(*Type).Method`; this overload routes the itab column to
    /// the right classifier.
    fn keeps_concrete(self, concrete: &str) -> bool {
        let is_ptr = concrete.starts_with('*');
        match self {
            MethodShow::Both => true,
            MethodShow::Value => !is_ptr,
            MethodShow::Pointer => is_ptr,
        }
    }
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

const SHORT_HELP: &str = "\
unstrip 1.0.0
Recover symbols from stripped Go binaries.

Usage
  unstrip <BINARY> [OPTIONS]

Examples
  unstrip <bin> --info                 what is this binary?
  unstrip <bin> --types                type catalog
  unstrip <bin> --itabs                interface dispatch table
  unstrip <bin> --format ghidra > apply.py
  unstrip <bin> --addr 0x4a3c40        PC -> function:file:line
  unstrip <bin> --data-at 0x520180 --data-as ifaces --data-count 4
  unstrip <bin> --symbols-as elf -o named.bin
  unstrip <new> --diff <old> --port-symbols ghidra > port.py

Analysis modes  --info --buildinfo --types --itabs --strings --capabilities
                --fingerprint --goroutines --xrefs --xref --xref-readers
                --xref-writers --data-at --addr --addr-file --diff
                --detect-garble
Rewrite         --symbols-as <elf|pe>  [-o PATH | --in-place --yes]
Integration     --install-plugin <ida|ghidra|binja>
                --dispatch-resolver ghidra
                --port-symbols <ida|ghidra|binja>

See `unstrip --help` for the full flag reference, modifiers, and notes.
Reference: https://github.com/riven-labs/unstrip/blob/main/docs/USAGE.md
";

fn main() -> ExitCode {
    // Hand-written `-h` cheat sheet; long `--help` stays clap-generated and
    // grouped via help_heading. Pattern: short form is one screen of examples,
    // long form is the full reference. Matches the git/cargo split.
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let has_short = argv.iter().any(|a| a == "-h");
    let has_long = argv.iter().any(|a| a == "--help");
    if has_short && !has_long {
        print!("{SHORT_HELP}");
        return ExitCode::SUCCESS;
    }

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
        let md_opt = ModuleData::locate(&bin).ok();
        let pcln_with_inline = match &md_opt {
            Some(md) => pcln.with_gofunc(md.gofunc),
            None => pcln,
        };
        let frames = pcln_with_inline.lookup_inline(&bin, pc);

        // Resolve the physical frame's signature when signatures are on
        // and moduledata is recoverable. The signature attaches to the
        // bottom-most (physical) frame; inlined frames above carry only
        // file:line.
        let signatures = if args.no_signatures {
            None
        } else {
            md_opt.as_ref().map(|md| compute_signatures(&bin, md))
        };
        let physical_sig = signatures
            .as_ref()
            .and_then(|s| s.get(&pc).cloned())
            .unwrap_or_default();

        if frames.is_empty() {
            writeln!(out, "0x{pc:016x}  (no function covers this PC)")?;
        } else if frames.len() == 1 {
            let f = &frames[0];
            let file = f.file.as_deref().unwrap_or("?");
            let line = f.line.map(|l| l.to_string()).unwrap_or_else(|| "?".into());
            writeln!(out, "0x{pc:016x}  {}{physical_sig}  {file}:{line}", f.name)?;
        } else {
            for (i, f) in frames.iter().enumerate() {
                let file = f.file.as_deref().unwrap_or("?");
                let line = f.line.map(|l| l.to_string()).unwrap_or_else(|| "?".into());
                let is_physical = i + 1 == frames.len();
                let prefix = if is_physical {
                    "(physical)"
                } else {
                    "(inlined) "
                };
                let sig = if is_physical {
                    physical_sig.as_str()
                } else {
                    ""
                };
                writeln!(out, "{prefix} {}{sig}  {file}:{line}", f.name)?;
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

    if let Some(addr_str) = &args.data_at {
        let addr = parse_pc(addr_str)?;
        // Resolve length from --data-count (records) or --data-len
        // (bytes); the clap conflict declaration guarantees at most
        // one is set. Records-mode multiplies by the per-mode record
        // size so 7 ifaces = 7 * 16 = 112 bytes without the operator
        // doing the math.
        let len = match (args.data_count, args.data_len) {
            (Some(n), _) => n.saturating_mul(args.data_as.record_size()),
            (None, Some(n)) => n,
            (None, None) => args.data_as.default_len(),
        };
        let mode = args.data_as.to_module();
        // Lazily pull itabs + functions for symbolization. Failures
        // here degrade gracefully: ptrs/ifaces still render the raw
        // hex via the Unmapped/Scalar fallback. We do not propagate.
        let functions = pcln.functions().unwrap_or_default();
        let itabs_v = match ModuleData::locate(&bin) {
            Ok(md) => itabs::recover_all(&bin, &md).unwrap_or_default(),
            Err(_) => Vec::new(),
        };
        let rows = unstrip::dataview::inspect(&bin, &pcln, &itabs_v, &functions, addr, len, mode)?;
        match args.format {
            OutFormat::Json => {
                serde_json::to_writer_pretty(&mut out, &rows)?;
                writeln!(out)?;
            }
            OutFormat::Text => {
                for r in &rows {
                    writeln!(out, "0x{:016x}  {}", r.addr, r.rendering)?;
                }
            }
            f => return Err(format!("--data-at does not support --format {f:?}").into()),
        }
        out.flush()?;
        return Ok(());
    }

    if let Some(symbol) = &args.xref {
        // Accept either a hex address (`0x...`) or a function name.
        // The parser tries address first because it's an unambiguous
        // prefix; anything else falls through to the pclntab lookup.
        let target = if symbol.starts_with("0x") || symbol.starts_with("0X") {
            unstrip::callsites::Target::Address(parse_pc(symbol)?)
        } else {
            unstrip::callsites::Target::Function(symbol.clone())
        };
        // Itabs feed Scanner 2 (indirect-itab dispatch sites). If
        // moduledata recovery fails we pass an empty slice; Scanner
        // 1's direct-call results still ship.
        let itabs_v = match ModuleData::locate(&bin) {
            Ok(md) => itabs::recover_all(&bin, &md).unwrap_or_default(),
            Err(_) => Vec::new(),
        };
        let hits = unstrip::callsites::find(&bin, &pcln, &itabs_v, &target)?;
        match args.format {
            OutFormat::Json => {
                serde_json::to_writer_pretty(&mut out, &hits)?;
                writeln!(out)?;
            }
            OutFormat::Text => {
                if hits.is_empty() {
                    writeln!(out, "No call sites found for {symbol}")?;
                } else {
                    // Group by caller so the listing reads the way a
                    // human reverse engineer reads xrefs: one header
                    // per containing function, call sites underneath.
                    let mut by_caller: std::collections::BTreeMap<
                        (Option<u64>, Option<String>),
                        Vec<&unstrip::callsites::CallSite>,
                    > = std::collections::BTreeMap::new();
                    for h in &hits {
                        by_caller
                            .entry((h.caller_addr, h.caller_name.clone()))
                            .or_default()
                            .push(h);
                    }
                    for ((caller_addr, caller_name), sites) in &by_caller {
                        let header = match (caller_addr, caller_name) {
                            (Some(addr), Some(name)) => {
                                format!("{name} @ 0x{addr:016x}:")
                            }
                            _ => "(no containing function):".to_string(),
                        };
                        writeln!(out, "{header}")?;
                        for s in sites {
                            let kind = match &s.kind {
                                unstrip::callsites::CallKind::Direct => "direct".to_string(),
                                unstrip::callsites::CallKind::IndirectItab {
                                    method_name,
                                    method_index,
                                    ..
                                } => match method_name {
                                    Some(n) => {
                                        format!("indirect-itab .{n}() [slot {method_index}]")
                                    }
                                    None => format!("indirect-itab [slot {method_index}]"),
                                },
                            };
                            writeln!(out, "  0x{:016x}  {kind}", s.call_site)?;
                        }
                    }
                }
            }
            f => return Err(format!("--xref does not support --format {f:?}").into()),
        }
        out.flush()?;
        return Ok(());
    }

    if args.xref_readers.is_some() || args.xref_writers.is_some() {
        let direction = match (args.xref_readers.is_some(), args.xref_writers.is_some()) {
            (true, true) => unstrip::dataxref::Direction::Both,
            (true, false) => unstrip::dataxref::Direction::Readers,
            (false, true) => unstrip::dataxref::Direction::Writers,
            (false, false) => unreachable!(),
        };
        let target_str = args
            .xref_readers
            .as_deref()
            .or(args.xref_writers.as_deref())
            .unwrap();
        let target = parse_pc(target_str)?;
        let hits = unstrip::dataxref::find_refs(&bin, &pcln, target, direction)?;
        match args.format {
            OutFormat::Json => {
                serde_json::to_writer_pretty(&mut out, &hits)?;
                writeln!(out)?;
            }
            OutFormat::Text => {
                if hits.is_empty() {
                    writeln!(
                        out,
                        "# 0 hits for {} reference(s) to 0x{:x}",
                        match direction {
                            unstrip::dataxref::Direction::Readers => "reader",
                            unstrip::dataxref::Direction::Writers => "writer",
                            unstrip::dataxref::Direction::Both => "reader/writer",
                        },
                        target,
                    )?;
                } else {
                    for h in &hits {
                        let kind = match h.kind {
                            unstrip::dataxref::Kind::Lea => "lea",
                            unstrip::dataxref::Kind::MovLoad => "mov-load",
                            unstrip::dataxref::Kind::MovStore => "mov-store",
                            unstrip::dataxref::Kind::Cmp => "cmp",
                            unstrip::dataxref::Kind::CallIndirect => "call-indirect",
                        };
                        let fname = h.function_name.as_deref().unwrap_or("(no function)");
                        writeln!(out, "0x{:016x}  {:<14}  {}", h.instruction_pc, kind, fname,)?;
                    }
                }
            }
            f => {
                return Err(format!(
                    "--xref-readers/--xref-writers does not support --format {f:?}"
                )
                .into())
            }
        }
        out.flush()?;
        return Ok(());
    }

    if args.strings {
        let opts = unstrip::strings::Options {
            min_len: args.strings_min,
            max: args.strings_max,
            filter: args.filter.clone(),
        };
        let recovered = unstrip::strings::extract(&bin, &opts);
        match args.format {
            OutFormat::Json => {
                serde_json::to_writer_pretty(&mut out, &recovered)?;
                writeln!(out)?;
            }
            OutFormat::Text => {
                for s in &recovered {
                    writeln!(out, "0x{:016x}  {:<14}  {}", s.addr, s.section, s.text)?;
                }
            }
            f => return Err(format!("--strings does not support --format {:?}", f).into()),
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

    if args.reflect_names {
        match unstrip::garble::recover_reflect_names(&bin) {
            Some(names) => {
                let mut pairs: Vec<(&str, &str)> = names.iter().collect();
                pairs.sort();
                match args.format {
                    OutFormat::Json => {
                        let map: std::collections::BTreeMap<&str, &str> =
                            pairs.iter().copied().collect();
                        serde_json::to_writer_pretty(&mut out, &map)?;
                        writeln!(out)?;
                    }
                    OutFormat::Text => {
                        writeln!(
                            out,
                            "recovered {} reflected names (obfuscated -> original)",
                            pairs.len()
                        )?;
                        for (obf, orig) in pairs {
                            writeln!(out, "  {obf}  ->  {orig}")?;
                        }
                    }
                    f => {
                        return Err(
                            format!("--reflect-names does not support --format {:?}", f).into()
                        )
                    }
                }
            }
            None => {
                writeln!(
                    out,
                    "no reflected-name table found (not garbled, or it carries none)"
                )?;
            }
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

        // Signatures: best-effort, default-on. We only need them for the
        // text path; JSON output omits the signature on xref nodes today.
        let xref_signatures = if args.no_signatures {
            std::collections::HashMap::new()
        } else {
            ModuleData::locate(&bin)
                .ok()
                .map(|md| compute_signatures(&bin, &md))
                .unwrap_or_default()
        };
        let sig_for_node = |n: &unstrip::xrefs::XrefNode| -> String {
            n.addr
                .and_then(|a| xref_signatures.get(&a))
                .cloned()
                .unwrap_or_default()
        };

        match (&args.from, &args.to) {
            (Some(from), None) => {
                let result = unstrip::xrefs::callees_from(&edges, from, args.depth, args.max_nodes);
                if matches!(args.format, OutFormat::Json) {
                    serde_json::to_writer_pretty(&mut out, &result)?;
                    writeln!(out)?;
                } else {
                    // Sort by depth so the BFS layering is visible at
                    // the top of the output; ties broken by name for
                    // stable ordering. Indent encodes depth from root.
                    let mut sorted: Vec<&unstrip::xrefs::XrefNode> = result
                        .nodes
                        .iter()
                        .filter(|n| args.show.keeps(&n.name))
                        .collect();
                    sorted.sort_by(|a, b| a.depth.cmp(&b.depth).then_with(|| a.name.cmp(&b.name)));
                    writeln!(out, "{}", from)?;
                    for node in sorted {
                        let sig = sig_for_node(node);
                        writeln!(out, "{}{}{sig}", "  ".repeat(node.depth), node.name)?;
                    }
                    if result.truncated {
                        // Truncation footer goes to STDOUT (same stream
                        // as the graph) so piping to `less` does not
                        // hide it. The whole point of the cap is that
                        // the operator must know they got truncated.
                        writeln!(
                            out,
                            "... (truncated at {} nodes; raise --max-nodes)",
                            result.max_nodes
                        )?;
                    }
                }
            }
            (None, Some(to)) => {
                let result = unstrip::xrefs::callers_of(&edges, to, args.depth, args.max_nodes);
                if matches!(args.format, OutFormat::Json) {
                    serde_json::to_writer_pretty(&mut out, &result)?;
                    writeln!(out)?;
                } else {
                    let mut sorted: Vec<&unstrip::xrefs::XrefNode> = result
                        .nodes
                        .iter()
                        .filter(|n| args.show.keeps(&n.name))
                        .collect();
                    sorted.sort_by(|a, b| a.depth.cmp(&b.depth).then_with(|| a.name.cmp(&b.name)));
                    writeln!(out, "{}", to)?;
                    for node in sorted {
                        let sig = sig_for_node(node);
                        writeln!(out, "{}{}{sig}", "  ".repeat(node.depth), node.name)?;
                    }
                    if result.truncated {
                        writeln!(
                            out,
                            "... (truncated at {} nodes; raise --max-nodes)",
                            result.max_nodes
                        )?;
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
                        if !args.show.keeps(&caller) || !args.show.keeps(&callee) {
                            continue;
                        }
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
        if args.degarble {
            if let Some(names) = unstrip::garble::recover_reflect_names(&bin) {
                names.relabel_itabs(&mut all);
            }
        }
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
        all.retain(|it| args.show.keeps_concrete(&it.concrete_name));
        // Reachability pass: one sweep over .text and the data
        // sections collecting every address worth treating as a
        // target, then mark each itab whose recorded address is in
        // the set. Defaults on; opt out for very large binaries or
        // scripted consumers that prefer the unannotated shape. The
        // annotation is `(reachable)` / `(unreachable)`, not
        // "live"/"unused": on well-formed Go binaries the linker
        // already dead-strips unreachable itabs, so the marker is a
        // reachability confirmation, not a dead-code finder.
        let reachable_set = if args.no_itab_reachability {
            None
        } else {
            Some(unstrip::dataxref::referenced_addresses(&bin).unwrap_or_default())
        };
        match args.format {
            OutFormat::Json => {
                serde_json::to_writer_pretty(&mut out, &all)?;
                writeln!(out)?;
            }
            OutFormat::Text => write_itabs(&mut out, &all, reachable_set.as_ref())?,
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
        if args.degarble {
            if let Some(names) = unstrip::garble::recover_reflect_names(&bin) {
                names.relabel_types(&mut all);
            }
        }
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
    if args.degarble {
        if let Some(names) = unstrip::garble::recover_reflect_names(&bin) {
            names.relabel_functions(&mut functions);
        }
    }
    if let Some(needle) = &args.filter {
        functions.retain(|f| f.name.contains(needle));
    }

    // Compute moduledata once and reuse for itab-thunk discovery, type
    // recovery, and signature recovery. If any step fails (no
    // moduledata, pre-1.18 layout, etc.) we still print the function
    // listing without the enrichment.
    let md_opt = ModuleData::locate(&bin).ok();
    let recovered_types = md_opt
        .as_ref()
        .and_then(|md| types::recover_all(&bin, md).ok())
        .unwrap_or_default();
    let recovered_itabs = md_opt
        .as_ref()
        .and_then(|md| itabs::recover_all(&bin, md).ok())
        .unwrap_or_default();

    // Itab-thunk set: every concrete-fn address an itab dispatches
    // through. Used for two related things below: (a) when --show
    // value would hide a pointer-receiver thunk row, keep it alive
    // if an itab actually dispatches there, and (b) annotate every
    // kept thunk with `(itab thunk)` so the operator sees the live
    // dispatch surface at a glance.
    let itab_thunks: std::collections::HashSet<u64> = recovered_itabs
        .iter()
        .flat_map(|it| it.methods.iter().map(|m| m.concrete_fn))
        .collect();

    // Method-signature recovery. Default-on; --no-signatures opts out
    // (useful for diff-friendly listings or when the operator wants the
    // smallest text-column width). The signature map is keyed by
    // function entry PC; the writer looks up each function and appends
    // its rendered Go-syntax signature when found.
    let signatures: Option<std::collections::HashMap<u64, String>> = match &md_opt {
        Some(md) if !args.no_signatures => Some(compute_signatures(&bin, md)),
        _ => None,
    };

    functions.retain(|f| args.show.keeps(&f.name) || itab_thunks.contains(&f.address));

    match args.format {
        OutFormat::Ida | OutFormat::Ghidra | OutFormat::Binja => {
            let target = match args.format {
                OutFormat::Ida => export::Target::Ida,
                OutFormat::Ghidra => export::Target::Ghidra,
                OutFormat::Binja => export::Target::BinaryNinja,
                _ => unreachable!(),
            };
            export::write_script(
                &mut out,
                target,
                &functions,
                &recovered_types,
                signatures.as_ref(),
                "unstrip",
            )?;
        }
        plain => {
            write_functions(
                &mut out,
                &bin,
                &pcln,
                &functions,
                plain.as_plain().unwrap(),
                Some(&itab_thunks),
                signatures.as_ref(),
            )?;
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

/// Build a PC -> Go-syntax-signature map for the whole binary. Best-effort:
/// returns an empty map when type or itab recovery fails. Callers should
/// pre-check `args.no_signatures` and skip this call entirely when the
/// operator opted out.
///
/// Uses `Mode::Full` for type recovery rather than `Mode::Focused`. The
/// focused walk follows typelinks and child references, which misses
/// types whose `_type` record was emitted into the typeinfo region but
/// not registered in `typelinks` (a real population in real binaries).
/// The linear scan in `Full` mode finds those extras and unlocks their
/// uncommon-table methods.
///
/// Note: there is a fundamental ceiling here. Go's linker omits the
/// `_type` record entirely for a struct that no runtime path needs
/// (never stored as `any`, never reflected on, never used as an
/// interface value). Methods on such types appear in pclntab (so the
/// function listing names them) but have no `_type.uncommon().methods`
/// entry, so their signatures are unrecoverable from a stripped binary
/// without DWARF.
fn compute_signatures(bin: &GoBinary, md: &ModuleData) -> std::collections::HashMap<u64, String> {
    let recovered_types = types::recover_with_mode(bin, md, types::Mode::Full).unwrap_or_default();
    let recovered_itabs = itabs::recover_all(bin, md).unwrap_or_default();
    let from_types = unstrip::funcsig::recover_methods_from_types(bin, md, &recovered_types);
    let from_itabs =
        unstrip::funcsig::recover_methods_from_itabs(&recovered_types, &recovered_itabs);
    let merged = unstrip::funcsig::merge_methods(from_types, from_itabs);
    let mut cache = unstrip::funcsig::TypeCache::new(bin, md);
    cache.seed_from(&recovered_types);
    unstrip::funcsig::signatures_by_pc(&merged, &mut cache)
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

fn write_itabs<W: Write>(
    w: &mut W,
    all: &[unstrip::Itab],
    reachable: Option<&std::collections::HashSet<u64>>,
) -> io::Result<()> {
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
        let mut markers = String::new();
        if it.incomplete {
            markers.push_str("  [INCOMPLETE]");
        }
        if let Some(reachable) = reachable {
            if reachable.contains(&it.addr) {
                markers.push_str("  (reachable)");
            } else {
                markers.push_str("  (unreachable)");
            }
        }
        writeln!(
            w,
            "0x{:016x}  {:<iw$}  =>  {:<cw$}{}",
            it.addr,
            it.interface_name,
            it.concrete_name,
            markers,
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
                    let embedded = if f.embedded { " (embedded)" } else { "" };
                    let struct_tag = if f.tag.is_empty() {
                        String::new()
                    } else {
                        format!("  `{}`", f.tag)
                    };
                    writeln!(
                        w,
                        "    +{:04x}  {}: type@0x{:x}{}{}",
                        f.offset, f.name, f.typ, embedded, struct_tag
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn method_show_classifies_function_names() {
        // Pointer-receiver methods carry `.(*` in the Go-mangled name.
        assert!(MethodShow::Both.keeps("internal/abi.(*Type).Kind"));
        assert!(MethodShow::Pointer.keeps("internal/abi.(*Type).Kind"));
        assert!(!MethodShow::Value.keeps("internal/abi.(*Type).Kind"));

        // Value-receiver methods and free functions do not.
        assert!(MethodShow::Both.keeps("main.main"));
        assert!(MethodShow::Value.keeps("main.main"));
        assert!(!MethodShow::Pointer.keeps("main.main"));

        assert!(MethodShow::Value.keeps("main.xorMask.Apply"));
        assert!(!MethodShow::Pointer.keeps("main.xorMask.Apply"));

        // Autogenerated type-equality helpers count as value-side.
        assert!(MethodShow::Value.keeps("type:.eq.runtime.TypeAssertionError"));
    }

    #[test]
    fn method_show_classifies_itab_concrete_names() {
        // --itabs concrete column uses the leading-asterisk convention.
        assert!(MethodShow::Pointer.keeps_concrete("*main.xorMask"));
        assert!(!MethodShow::Value.keeps_concrete("*main.xorMask"));

        assert!(MethodShow::Value.keeps_concrete("main.xorMask"));
        assert!(!MethodShow::Pointer.keeps_concrete("main.xorMask"));

        // Both keeps everything regardless of receiver shape.
        assert!(MethodShow::Both.keeps_concrete("*main.xorMask"));
        assert!(MethodShow::Both.keeps_concrete("main.xorMask"));
    }
}
