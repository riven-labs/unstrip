//! Day-2 measurement tool for the inline-tree decoder.
//!
//! For one binary (a "cell" in the probe corpus), decodes every function's
//! FUNCDATA_InlTree array, classifies every leaf into one of three
//! unresolved-name buckets:
//!
//!   A: name_off == 0
//!   B: name_off is out of range of the funcname table
//!   C: name_off resolves to an empty string
//!
//! and writes two CSV outputs:
//!
//!   --csv-out          aggregate row for the cell
//!   --csv-out + .funcs detail row per function
//!
//! Both files are appended-to if they exist (header only written when
//! creating). The cell_key column lets one driver script merge results
//! from many cells into a single CSV.

use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::Parser;
use unstrip::gobin::GoBinary;
use unstrip::inline::{decode_inline_tree, resolve_leaf_name, InlinedCall};
use unstrip::moduledata::ModuleData;
use unstrip::pclntab::Pclntab;

#[derive(Parser, Debug)]
#[command(about = "Inline-tree coverage measurement for one corpus cell")]
struct Args {
    /// Path to the Go binary to analyze.
    #[arg(long)]
    binary: PathBuf,
    /// Free-form cell identifier (e.g. "shfmt_124_default").
    #[arg(long)]
    cell_key: String,
    /// Aggregate CSV output path. A sibling `<csv-out>.funcs.csv` will
    /// also be written with one row per function.
    #[arg(long)]
    csv_out: PathBuf,
}

fn main() -> ExitCode {
    let args = Args::parse();
    match run(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

#[derive(Default, Debug, Clone, Copy)]
struct Buckets {
    a: u64, // name_off == 0
    b: u64, // out of range
    c: u64, // resolves to empty
}

fn run(args: &Args) -> Result<(), String> {
    let bin = GoBinary::open(&args.binary).map_err(|e| format!("open: {e}"))?;
    let md = ModuleData::locate(&bin).map_err(|e| format!("moduledata: {e}"))?;
    let pcln = Pclntab::parse(&bin)
        .map_err(|e| format!("pclntab: {e}"))?
        .with_gofunc(md.gofunc);

    let funcs = pcln
        .functions_with_offsets()
        .map_err(|e| format!("functab: {e}"))?;

    let detail_path =
        args.csv_out
            .with_extension(match args.csv_out.extension().and_then(|s| s.to_str()) {
                Some(ext) => format!("funcs.{ext}"),
                None => "funcs.csv".to_string(),
            });

    let agg_existed = args.csv_out.exists();
    let det_existed = detail_path.exists();
    let mut agg = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&args.csv_out)
        .map_err(|e| format!("open agg csv: {e}"))?;
    let mut det = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&detail_path)
        .map_err(|e| format!("open detail csv: {e}"))?;

    if !agg_existed {
        writeln!(
            agg,
            "cell_key,total_funcs,funcs_with_inltree,total_leaves,resolved_leaves,bucket_a_count,bucket_b_count,bucket_c_count"
        )
        .map_err(|e| e.to_string())?;
    }
    if !det_existed {
        writeln!(
            det,
            "cell_key,fn_addr,fn_name,has_inltree,leaf_count,resolved_count,bucket_a,bucket_b,bucket_c"
        )
        .map_err(|e| e.to_string())?;
    }

    let mut total_funcs: u64 = 0;
    let mut funcs_with_inltree: u64 = 0;
    let mut total_leaves: u64 = 0;
    let mut resolved_leaves: u64 = 0;
    let mut agg_buckets = Buckets::default();

    for f in &funcs {
        total_funcs += 1;
        // A decode failure (bounds-check tripped, gofunc unresolved, etc.) is
        // still data: we record it as zero leaves and skip aggregation. The
        // alternative (panic / abort the whole cell) would lose useful per-fn
        // coverage data when a single corrupt entry exists.
        let entries: Vec<InlinedCall> = decode_inline_tree(&bin, &pcln, f).unwrap_or_default();
        let has = !entries.is_empty();
        if has {
            funcs_with_inltree += 1;
        }
        let mut local = Buckets::default();
        let mut local_resolved: u64 = 0;
        for leaf in &entries {
            total_leaves += 1;
            if let Some(_name) = resolve_leaf_name(&pcln, leaf) {
                resolved_leaves += 1;
                local_resolved += 1;
            } else {
                let off = leaf.name_off;
                if off == 0 {
                    local.a += 1;
                    agg_buckets.a += 1;
                } else if off < 0
                    || (pcln
                        .funcname_off()
                        .checked_add(off as usize)
                        .map(|abs| abs >= pcln.data().len())
                        .unwrap_or(true))
                {
                    local.b += 1;
                    agg_buckets.b += 1;
                } else {
                    // name read returned Some("") - bucket C.
                    local.c += 1;
                    agg_buckets.c += 1;
                }
            }
        }
        writeln!(
            det,
            "{},{:#x},{},{},{},{},{},{},{}",
            csv_escape(&args.cell_key),
            f.address,
            csv_escape(&f.name),
            has as u8,
            entries.len(),
            local_resolved,
            local.a,
            local.b,
            local.c,
        )
        .map_err(|e| e.to_string())?;
    }

    writeln!(
        agg,
        "{},{},{},{},{},{},{},{}",
        csv_escape(&args.cell_key),
        total_funcs,
        funcs_with_inltree,
        total_leaves,
        resolved_leaves,
        agg_buckets.a,
        agg_buckets.b,
        agg_buckets.c,
    )
    .map_err(|e| e.to_string())?;

    eprintln!(
        "{}: {} funcs, {} with inltree, {} leaves ({} resolved, A={} B={} C={})",
        args.cell_key,
        total_funcs,
        funcs_with_inltree,
        total_leaves,
        resolved_leaves,
        agg_buckets.a,
        agg_buckets.b,
        agg_buckets.c,
    );
    Ok(())
}

/// Conservative CSV escape: quote fields containing comma, quote, CR, or LF;
/// double any embedded quotes. Function names from pclntab routinely contain
/// commas (generics) and quotes (struct-literal types), so this matters.
fn csv_escape(s: &str) -> String {
    if s.contains([',', '"', '\n', '\r']) {
        let escaped = s.replace('"', "\"\"");
        format!("\"{escaped}\"")
    } else {
        s.to_string()
    }
}
