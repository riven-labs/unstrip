use std::collections::HashMap;
use std::io::{self, Write};

use serde::Serialize;

use crate::gobin::GoBinary;
use crate::pclntab::{Function, Pclntab};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Format {
    Text,
    Json,
}

#[derive(Debug, Serialize)]
struct Report<'a> {
    container: &'a str,
    arch: &'a str,
    pclntab_offset: usize,
    pclntab_size: usize,
    text_start: u64,
    function_count: usize,
    functions: Vec<FunctionView<'a>>,
}

/// JSON-only view of a function with the optional recovered signature
/// attached. Built from `Function` plus an optional signature lookup so
/// the on-disk Function struct stays unchanged.
#[derive(Debug, Serialize)]
struct FunctionView<'a> {
    address: u64,
    /// The next function's entry: `address + size`.
    #[serde(skip_serializing_if = "Option::is_none")]
    end: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    size: Option<u64>,
    name: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    file: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    start_line: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    signature: Option<&'a str>,
}

pub fn write_functions<W: Write>(
    w: &mut W,
    bin: &GoBinary,
    pcln: &Pclntab<'_>,
    functions: &[Function],
    format: Format,
    itab_thunks: Option<&std::collections::HashSet<u64>>,
    signatures: Option<&HashMap<u64, String>>,
) -> io::Result<()> {
    match format {
        Format::Text => write_text(w, functions, itab_thunks, signatures),
        Format::Json => {
            let views: Vec<FunctionView<'_>> = functions
                .iter()
                .map(|f| FunctionView {
                    address: f.address,
                    end: f.size.and_then(|size| f.address.checked_add(size)),
                    size: f.size,
                    name: &f.name,
                    file: f.file.as_deref(),
                    start_line: f.start_line,
                    signature: signatures
                        .and_then(|s| s.get(&f.address))
                        .map(String::as_str),
                })
                .collect();
            let report = Report {
                container: bin.container.as_str(),
                arch: bin.arch.as_str(),
                pclntab_offset: bin.pclntab_offset,
                pclntab_size: bin.pclntab_size,
                text_start: pcln.text_start(),
                function_count: functions.len(),
                functions: views,
            };
            serde_json::to_writer_pretty(&mut *w, &report).map_err(io::Error::other)?;
            w.write_all(b"\n")
        }
    }
}

fn write_text<W: Write>(
    w: &mut W,
    functions: &[Function],
    itab_thunks: Option<&std::collections::HashSet<u64>>,
    signatures: Option<&HashMap<u64, String>>,
) -> io::Result<()> {
    let name_width = functions
        .iter()
        .map(|f| f.name.len())
        .max()
        .unwrap_or(40)
        .min(60);

    for f in functions {
        let file = f.file.as_deref().unwrap_or("");
        let mut name_col = f.name.clone();
        if let Some(sigs) = signatures {
            if let Some(sig) = sigs.get(&f.address) {
                name_col.push_str(sig);
            }
        }
        // Mark the compiler's `(*T).M` wrappers that are wired up as
        // itab dispatch targets. The operator who passed --show value
        // would normally hide every wrapper row; we keep the dispatched
        // ones and tag them so the operator can spot them at a glance.
        if let Some(thunks) = itab_thunks {
            if thunks.contains(&f.address) {
                name_col.push_str("  (itab thunk)");
            }
        }
        let size = match f.size {
            Some(size) => size.to_string(),
            None => "?".to_string(),
        };
        writeln!(
            w,
            "0x{addr:016x}  {size:>7}  {name:<name_width$}  {file}",
            addr = f.address,
            name = name_col,
            name_width = name_width,
            file = file,
        )?;
    }
    Ok(())
}

pub fn write_info<W: Write>(
    w: &mut W,
    bin: &GoBinary,
    pcln: &Pclntab<'_>,
    go_version: Option<&str>,
    garble_check: Option<&GarbleReport>,
) -> io::Result<()> {
    let version = go_version.unwrap_or("(not detected)");
    writeln!(w, "go version:    {version}")?;
    write_layout(w, bin, pcln)?;
    if let Some(report) = garble_check {
        if report.any() {
            writeln!(w)?;
            writeln!(
                w,
                "garble heuristic: {}",
                if report.verdict() {
                    "likely garbled"
                } else {
                    "indeterminate"
                }
            )?;
            if report.magic_rewritten {
                writeln!(
                    w,
                    "  - pclntab magic is not the standard 0xfffffff1 (garble rewrites it)"
                )?;
            }
            if report.version_overwritten {
                writeln!(
                    w,
                    "  - runtime.buildVersion is missing or non-standard (garble overwrites it)"
                )?;
            }
            if let Some((hashed, total)) = report.hashed_names {
                writeln!(
                    w,
                    "  - {hashed}/{total} user-package function names look hashed"
                )?;
            }
        }
    }

    write_section_map(w, bin)?;

    Ok(())
}

/// The `--info` report: the triage facts first, then where the Go tables
/// sit and the section map.
pub fn write_triage<W: Write>(
    w: &mut W,
    triage: &crate::triage::Triage,
    bin: &GoBinary,
    pcln: &Pclntab<'_>,
) -> io::Result<()> {
    let version = triage.go_version.as_deref().unwrap_or("(not detected)");
    writeln!(w, "go version:    {version}")?;
    let build_id = triage.build_id.as_deref().unwrap_or("(none)");
    writeln!(w, "build id:      {build_id}")?;
    if let Some(module) = &triage.main_module {
        let version = if module.version.is_empty() {
            "(devel)"
        } else {
            &module.version
        };
        writeln!(w, "main module:   {}  {version}", module.path)?;
    }
    let platform = match (&triage.goos, &triage.goarch) {
        (Some(goos), Some(goarch)) => format!("{goos}/{goarch}"),
        (None, Some(goarch)) => format!("?/{goarch}"),
        (Some(goos), None) => format!("{goos}/?"),
        (None, None) => "(not detected)".to_string(),
    };
    let from = match triage.platform_from {
        crate::triage::PlatformSource::BuildInfo => "",
        crate::triage::PlatformSource::EntryPoint => "  (from the entry point name)",
        crate::triage::PlatformSource::Container => "  (from the container)",
    };
    writeln!(w, "platform:      {platform}{from}")?;
    if let Some(cgo) = triage.cgo_enabled {
        writeln!(w, "cgo:           CGO_ENABLED={}", u8::from(cgo))?;
    }
    if let Some(vcs) = &triage.vcs {
        let mut line = vcs.system.clone().unwrap_or_else(|| "vcs".to_string());
        for part in [&vcs.revision, &vcs.time].into_iter().flatten() {
            line.push(' ');
            line.push_str(part);
        }
        if vcs.modified == Some(true) {
            line.push_str("  (modified)");
        }
        writeln!(w, "vcs:           {line}")?;
    }
    let garble = &triage.garble;
    let verdict = match garble.verdict {
        crate::garble::Verdict::Garbled => "garbled",
        crate::garble::Verdict::Clean => "clean",
        crate::garble::Verdict::Indeterminate => "indeterminate",
    };
    writeln!(
        w,
        "garble:        {verdict} (confidence {:.2})",
        garble.confidence
    )?;
    for signal in garble.signals.iter().filter(|s| s.fired) {
        writeln!(w, "  - {}", signal.detail)?;
    }
    writeln!(w)?;
    write_layout(w, bin, pcln)?;
    write_section_map(w, bin)
}

/// Container, pclntab placement and the table's header facts.
fn write_layout<W: Write>(w: &mut W, bin: &GoBinary, pcln: &Pclntab<'_>) -> io::Result<()> {
    let size_kb = bin.pclntab_size / 1024;
    writeln!(
        w,
        "container:     {} ({}, {})",
        bin.container.as_str(),
        bin.arch.as_str(),
        if bin.little_endian {
            "little-endian"
        } else {
            "big-endian"
        },
    )?;
    writeln!(
        w,
        "pclntab:       0x{:016x} ({} KB)",
        bin.pclntab_offset, size_kb,
    )?;
    writeln!(w, "functions:     {}", pcln.nfunc())?;
    writeln!(w, "text start:    0x{:016x}", pcln.text_start())?;
    writeln!(w, "ptr size:      {}", pcln.ptrsize())?;
    writeln!(w, "quantum:       {}", pcln.quantum())?;
    Ok(())
}

/// Print a one-row-per-section table covering the Go-relevant memory
/// regions: address range, file size, ptr/noptr classification (does
/// the GC scan it for pointers), and ro/rw classification. Sections
/// the classifier could not place fall under `(other)` and are
/// surfaced last so unusual layouts (UPX, manually-crafted ELFs) are
/// visible without polluting the common case.
fn write_section_map<W: Write>(w: &mut W, bin: &GoBinary) -> io::Result<()> {
    if bin.sections.is_empty() {
        return Ok(());
    }
    writeln!(w)?;
    writeln!(w, "sections:")?;
    for s in &bin.sections {
        // Suppress the ELF NULL section header (and any other zero-
        // length nameless entries the container loader surfaces) so
        // the table only shows real memory regions.
        if s.file_size == 0 && s.addr == 0 && s.name.is_empty() {
            continue;
        }
        let kind = match s.kind {
            crate::gobin::SectionKind::Text => "text",
            crate::gobin::SectionKind::ReadOnlyData => "rodata",
            crate::gobin::SectionKind::Data => "data",
            crate::gobin::SectionKind::NoPtrData => "noptrdata",
            crate::gobin::SectionKind::Bss => "bss",
            crate::gobin::SectionKind::Pclntab => "pclntab",
            crate::gobin::SectionKind::Other => "other",
        };
        let ptr_tag = match s.ptr_bearing() {
            Some(true) => "ptr",
            Some(false) => "noptr",
            None => "-",
        };
        let rw_tag = match s.writable() {
            Some(true) => "rw",
            Some(false) => "ro",
            None => "-",
        };
        writeln!(
            w,
            "  0x{:016x}..0x{:016x} {:>8} bytes  {:<10} ({}, {})  {}",
            s.addr,
            s.addr.saturating_add(s.file_size as u64),
            s.file_size,
            kind,
            ptr_tag,
            rw_tag,
            s.name,
        )?;
    }
    Ok(())
}

/// Three independent signals that a binary was processed by `garble`. This
/// is a smoke alarm, not structural analysis, it tells you why the names
/// look weird, nothing more. A real garble-recovery pass (string XOR,
/// seed extraction) is a separate effort.
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct GarbleReport {
    pub magic_rewritten: bool,
    pub version_overwritten: bool,
    /// Some((hashed_count, total_user_funcs)) when there were enough
    /// user-package funcs to evaluate, None otherwise.
    pub hashed_names: Option<(usize, usize)>,
}

impl GarbleReport {
    pub fn any(&self) -> bool {
        self.magic_rewritten
            || self.version_overwritten
            || self
                .hashed_names
                .map(|(h, t)| t > 0 && (h * 5) > (t * 2))
                .unwrap_or(false)
    }

    /// Verdict: any two of the three signals tripped is enough to call it.
    /// Magic rewrite alone is the strongest single signal and counts double.
    pub fn verdict(&self) -> bool {
        let mut hits = 0;
        if self.magic_rewritten {
            hits += 2;
        }
        if self.version_overwritten {
            hits += 1;
        }
        if let Some((h, t)) = self.hashed_names {
            if t > 0 && (h * 5) > (t * 2) {
                hits += 1;
            }
        }
        hits >= 2
    }
}

/// Compute garble-heuristic signals from the recovered functions and metadata.
/// The caller decides how to surface them; we return raw flags only.
pub fn detect_garble(
    functions: &[crate::pclntab::Function],
    go_version: Option<&str>,
    magic_is_official: bool,
) -> GarbleReport {
    let version_looks_real = go_version
        .map(|v| v.starts_with("go1.") && v.len() >= 6 && v.contains('.'))
        .unwrap_or(false);

    // Look at non-runtime function names. Garble leaves runtime.* alone but
    // hashes user-package names.
    let user_funcs: Vec<&str> = functions
        .iter()
        .map(|f| f.name.as_str())
        .filter(|n| {
            !n.starts_with("runtime.")
                && !n.starts_with("internal/")
                && !n.starts_with("sync.")
                && !n.starts_with("syscall.")
                && !n.starts_with("type:")
                && !n.starts_with("go:")
        })
        .collect();

    let hashed_names = if user_funcs.len() >= 20 {
        let hashy = user_funcs.iter().filter(|n| looks_garbled(n)).count();
        Some((hashy, user_funcs.len()))
    } else {
        None
    };

    GarbleReport {
        magic_rewritten: !magic_is_official,
        version_overwritten: !version_looks_real,
        hashed_names,
    }
}

/// A function name looks garbled if it has no package dot (suggesting the
/// package got renamed too), is short (< 8 chars), and is all alphanumeric.
fn looks_garbled(name: &str) -> bool {
    let last_dot = name.rfind('.').map(|i| &name[i + 1..]).unwrap_or(name);
    let pkg_part = name.rfind('.').map(|i| &name[..i]).unwrap_or("");
    if last_dot.len() > 10 {
        return false;
    }
    let identifier_chars = last_dot
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_');
    if !identifier_chars {
        return false;
    }
    // A real package path is usually "pkg.SubPkg" or "github.com/owner/repo.Func".
    // Garble produces single-segment hash packages with no slashes and short names.
    !pkg_part.contains('/') && pkg_part.len() < 16 && last_dot.len() < 8
}

/// The Go release that built `bin`, such as `go1.22.3`.
///
/// Read from the build info, which records `runtime.buildVersion`. When the
/// build info does not parse, the bytes are scanned with [`detect_go_version`].
/// None when the build info holds no release (garble blanks it) or the scan
/// finds none.
pub fn go_version(bin: &GoBinary) -> Option<String> {
    let info = crate::buildinfo::BuildInfo::parse(bin).ok();
    go_version_from(info.as_ref(), bin)
}

/// [`go_version`] for a caller that parsed the build info already: `info` is
/// None when it did not parse.
pub fn go_version_from(
    info: Option<&crate::buildinfo::BuildInfo>,
    bin: &GoBinary,
) -> Option<String> {
    match info {
        // The recorded string can carry experiments after a space
        // (`go1.21.0 X:nocoverageredesign`); the release is the first word.
        Some(bi) => {
            let first = bi.go_version.split_whitespace().next()?;
            if release_len(first.as_bytes()) != Some(first.len()) {
                return None;
            }
            Some(first.to_string())
        }
        None => detect_go_version(&bin.bytes),
    }
}

/// Scans the bytes for the first string that starts with a Go release (`go1.N`,
/// `go1.N.P`, `go1.NrcK`, `go1.NbetaK`) and returns the release. Go packs its
/// string literals end to end with no terminator, so the text after the release
/// belongs to the next literal (`go1.16.4hijackedhttp`) and is dropped. This is
/// a fallback for a binary whose build info does not parse: the first match can
/// be a version string some package carries, not the toolchain's. Prefer
/// [`go_version`].
pub fn detect_go_version(bytes: &[u8]) -> Option<String> {
    let marker = b"go1.";
    for (i, w) in bytes.windows(marker.len()).enumerate() {
        if w != marker {
            continue;
        }
        let Some(len) = release_len(&bytes[i..]) else {
            continue;
        };
        return std::str::from_utf8(&bytes[i..i + len])
            .ok()
            .map(str::to_string);
    }
    None
}

/// Length of the Go release string at the start of `b`: `go1.`, the minor
/// version, then a `.patch` or an `rcN`/`betaN` suffix, if any.
fn release_len(b: &[u8]) -> Option<usize> {
    let digits = |from: usize| {
        let n = b
            .get(from..)
            .unwrap_or(&[])
            .iter()
            .take_while(|c| c.is_ascii_digit())
            .count();
        (n > 0 && n <= 4).then_some(from + n)
    };
    if !b.starts_with(b"go1.") {
        return None;
    }
    let end = digits(4)?;
    let rest = &b[end..];
    if rest.starts_with(b".") {
        return digits(end + 1).or(Some(end));
    }
    for tag in [&b"rc"[..], b"beta"] {
        if rest.starts_with(tag) {
            return digits(end + tag.len()).or(Some(end));
        }
    }
    Some(end)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_go_version_in_blob() {
        let mut blob = Vec::new();
        blob.extend_from_slice(b"some preamble\x00\x00");
        blob.extend_from_slice(b"go1.22.3");
        blob.extend_from_slice(b"\x00trailing");
        assert_eq!(detect_go_version(&blob).as_deref(), Some("go1.22.3"));
    }

    #[test]
    fn ignores_partial_matches() {
        let blob = b"go1.\x00short";
        assert_eq!(detect_go_version(blob), None);
    }

    #[test]
    fn ignores_non_numeric_release() {
        assert_eq!(detect_go_version(b"\x00go1.go\x00"), None);
        assert_eq!(
            detect_go_version(b"go1.go\x00go1.21.4\x00").as_deref(),
            Some("go1.21.4")
        );
    }

    #[test]
    fn a_release_run_into_the_next_literal_is_cut_at_the_release() {
        assert_eq!(
            detect_go_version(b"\x00go1.23.0H9\x00").as_deref(),
            Some("go1.23.0")
        );
        assert_eq!(
            detect_go_version(b"go1.16.4hijackedhttp\x00").as_deref(),
            Some("go1.16.4")
        );
        assert_eq!(
            detect_go_version(b"\x00go1.22rc2\x00").as_deref(),
            Some("go1.22rc2")
        );
        assert_eq!(
            detect_go_version(b"\x00go1.21beta1 ").as_deref(),
            Some("go1.21beta1")
        );
    }
}
