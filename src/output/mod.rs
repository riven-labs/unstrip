use std::io::{self, Write};

use serde::Serialize;

use crate::gobin::GoBinary;
use crate::pclntab::{Function, Pclntab};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
    functions: &'a [Function],
}

pub fn write_functions<W: Write>(
    w: &mut W,
    bin: &GoBinary,
    pcln: &Pclntab<'_>,
    functions: &[Function],
    format: Format,
) -> io::Result<()> {
    match format {
        Format::Text => write_text(w, functions),
        Format::Json => {
            let report = Report {
                container: bin.container.as_str(),
                arch: bin.arch.as_str(),
                pclntab_offset: bin.pclntab_offset,
                pclntab_size: bin.pclntab_size,
                text_start: pcln.text_start(),
                function_count: functions.len(),
                functions,
            };
            serde_json::to_writer_pretty(&mut *w, &report).map_err(io::Error::other)?;
            w.write_all(b"\n")
        }
    }
}

fn write_text<W: Write>(w: &mut W, functions: &[Function]) -> io::Result<()> {
    let name_width = functions
        .iter()
        .map(|f| f.name.len())
        .max()
        .unwrap_or(40)
        .min(60);

    for f in functions {
        let file = f.file.as_deref().unwrap_or("");
        writeln!(
            w,
            "0x{addr:016x}  {name:<name_width$}  {file}",
            addr = f.address,
            name = f.name,
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
    let size_kb = bin.pclntab_size / 1024;
    let version = go_version.unwrap_or("(not detected)");
    writeln!(w, "go version:    {version}")?;
    writeln!(
        w,
        "container:     {} ({}, {})",
        bin.container.as_str(),
        bin.arch.as_str(),
        if bin.little_endian { "little-endian" } else { "big-endian" },
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
    if let Some(report) = garble_check {
        if report.any() {
            writeln!(w)?;
            writeln!(w, "garble heuristic: {}", if report.verdict() { "likely garbled" } else { "indeterminate" })?;
            if report.magic_rewritten {
                writeln!(w, "  - pclntab magic is not the standard 0xfffffff1 (garble rewrites it)")?;
            }
            if report.version_overwritten {
                writeln!(w, "  - runtime.buildVersion is missing or non-standard (garble overwrites it)")?;
            }
            if let Some((hashed, total)) = report.hashed_names {
                writeln!(w, "  - {hashed}/{total} user-package function names look hashed")?;
            }
        }
    }
    Ok(())
}

/// Three independent signals that a binary was processed by `garble`. This
/// is a smoke alarm, not structural analysis, it tells you why the names
/// look weird, nothing more. A real garble-recovery pass (string XOR,
/// seed extraction) is a separate effort.
#[derive(Debug, Clone, Default)]
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
            || self.hashed_names.map(|(h, t)| t > 0 && (h * 5) > (t * 2)).unwrap_or(false)
    }

    /// Verdict: any two of the three signals tripped is enough to call it.
    /// Magic rewrite alone is the strongest single signal and counts double.
    pub fn verdict(&self) -> bool {
        let mut hits = 0;
        if self.magic_rewritten { hits += 2; }
        if self.version_overwritten { hits += 1; }
        if let Some((h, t)) = self.hashed_names {
            if t > 0 && (h * 5) > (t * 2) { hits += 1; }
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
    let identifier_chars = last_dot.chars().all(|c| c.is_ascii_alphanumeric() || c == '_');
    if !identifier_chars {
        return false;
    }
    // A real package path is usually "pkg.SubPkg" or "github.com/owner/repo.Func".
    // Garble produces single-segment hash packages with no slashes and short names.
    !pkg_part.contains('/') && pkg_part.len() < 16 && last_dot.len() < 8
}

/// Scans the binary for the Go build version string. Go embeds it as
/// `runtime.buildVersion`'s data, prefixed by the marker byte sequence
/// "\xff Go buildinf:" in the buildinfo section. This is a quick scan, not
/// a full buildinfo parse, we just want the version string.
pub fn detect_go_version(bytes: &[u8]) -> Option<String> {
    let marker = b"go1.";
    for (i, w) in bytes.windows(marker.len()).enumerate() {
        if w != marker {
            continue;
        }
        let end = bytes[i..]
            .iter()
            .position(|&b| !is_version_char(b))
            .map(|p| i + p)
            .unwrap_or(bytes.len());
        if end - i < 5 || end - i > 20 {
            continue;
        }
        let s = std::str::from_utf8(&bytes[i..end]).ok()?;
        // Sanity: must have at least one dot after "go1."
        if s[3..].chars().filter(|&c| c == '.').count() >= 1 {
            return Some(s.to_string());
        }
    }
    None
}

fn is_version_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'.' || b == b'-' || b == b'+'
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
}
