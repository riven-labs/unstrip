//! Strings in a Go binary's read-only data, two ways.
//!
//! [`literals`] recovers the exact string literals the program uses, each
//! as `(address, length, bytes)` with the functions that use it. Go packs
//! literals end to end with no terminator, so their bounds come from the
//! code and data that pair a pointer with a length; see the `literals`
//! module for what counts as proof. This is what `--strings` prints.
//!
//! [`extract`] is the older walker: printable runs inside the read-only
//! sections (`.rodata` and `.noptrdata` on ELF, `__rodata` and
//! `__noptrdata` on Mach-O, `.rdata` on PE). A run often holds a dozen
//! literals glued together, but it needs no instruction scanner, so it
//! also works on 386. `--strings --strings-runs` prints it.
//!
//! Garble's default mode leaves literals alone (encrypting them is its
//! separate `-literals` mode), so both survive it.

mod literals;

use serde::Serialize;

use crate::gobin::{GoBinary, SectionKind};

pub use literals::{literals, Dropped, Header, Literal, Literals, Origin, Site, Use};

/// One recovered printable run, anchored to its link-time VA so callers
/// can cross-reference into xrefs / disasm.
#[derive(Debug, Clone, Serialize)]
#[non_exhaustive]
pub struct GoString {
    /// Link-time VA where the run starts.
    pub addr: u64,
    /// Name of the section it was found in (`.rodata`, `__rodata`, etc.)
    /// preserved verbatim from the container.
    pub section: String,
    /// The printable run, UTF-8. Containing NUL bytes are the run
    /// boundaries; this never contains them.
    pub text: String,
}

/// Options controlling extraction. `Options::default()` returns runs
/// of length >= 8 with no substring filter, what `--strings --strings-runs`
/// prints with no other flag.
#[derive(Debug, Clone)]
pub struct Options {
    /// Minimum printable-run length. Below this, runs are dropped to
    /// cut down on noise from short type-metadata fragments.
    pub min_len: usize,
    /// Maximum number of runs to emit. `None` means "all".
    pub max: Option<usize>,
    /// Substring filter; runs that do not contain it are dropped.
    /// Consistent with --filter everywhere else in unstrip.
    pub filter: Option<String>,
}

impl Default for Options {
    fn default() -> Self {
        Options {
            min_len: 8,
            max: None,
            filter: None,
        }
    }
}

/// Walk every read-only section in `bin` and emit every printable-ASCII
/// run that satisfies `opts`. Runs span NUL-terminated segments of the
/// section bytes; the addresses returned are link-time VAs.
///
/// Sections walked: every section classified as
/// [`SectionKind::ReadOnlyData`] or [`SectionKind::NoPtrData`]. The
/// pclntab and text sections are deliberately excluded: pclntab carries
/// its own string table (recovered by [`crate::pclntab`]) and text
/// contains instruction bytes that occasionally form printable runs but
/// are not literals.
pub fn extract(bin: &GoBinary, opts: &Options) -> Vec<GoString> {
    let mut out = Vec::new();
    for section in &bin.sections {
        if !matches!(
            section.kind,
            SectionKind::ReadOnlyData | SectionKind::NoPtrData
        ) {
            continue;
        }
        let end = section
            .file_offset
            .saturating_add(section.file_size)
            .min(bin.bytes.len());
        let slice = &bin.bytes[section.file_offset..end];
        extract_runs(slice, section.addr, &section.name, opts, &mut out);
        if let Some(cap) = opts.max {
            if out.len() >= cap {
                out.truncate(cap);
                return out;
            }
        }
    }
    out
}

/// Scan one byte slice for printable-ASCII runs.
///
/// A run ends at the first non-printable byte (anything outside
/// 0x20..=0x7E except `\t`, `\n`, `\r` which are not included to keep
/// runs compact and grep-friendly). The substring filter applies after
/// the run is otherwise accepted, so a 200-char run containing the
/// needle is kept whole, not cut down to the matching span: the
/// surrounding text is part of the identification signal.
fn extract_runs(
    slice: &[u8],
    section_addr: u64,
    section_name: &str,
    opts: &Options,
    out: &mut Vec<GoString>,
) {
    let mut i = 0usize;
    while i < slice.len() {
        let b = slice[i];
        if !is_printable(b) {
            i += 1;
            continue;
        }
        let start = i;
        while i < slice.len() && is_printable(slice[i]) {
            i += 1;
        }
        let len = i - start;
        if len < opts.min_len {
            continue;
        }
        let bytes = &slice[start..i];
        // All bytes are ASCII printable, so str::from_utf8 cannot fail.
        let text = std::str::from_utf8(bytes).expect("ASCII printable is UTF-8");
        if let Some(needle) = &opts.filter {
            if !text.contains(needle.as_str()) {
                continue;
            }
        }
        out.push(GoString {
            addr: section_addr + (start as u64),
            section: section_name.to_string(),
            text: text.to_string(),
        });
        if let Some(cap) = opts.max {
            if out.len() >= cap {
                return;
            }
        }
    }
}

#[inline]
fn is_printable(b: u8) -> bool {
    // ASCII printable, no whitespace except space. Excluding \t \n \r
    // keeps runs single-line and easy to grep.
    (0x20..=0x7E).contains(&b)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn opts(min_len: usize) -> Options {
        Options {
            min_len,
            ..Options::default()
        }
    }

    #[test]
    fn extracts_runs_above_min_len() {
        let mut out = Vec::new();
        // "hello" \0 "world" \0 "ab" (too short) \0 "longerstring"
        let data = b"hello\x00world\x00ab\x00longerstring\x00";
        extract_runs(data, 0x1000, ".rodata", &opts(5), &mut out);
        let texts: Vec<&str> = out.iter().map(|s| s.text.as_str()).collect();
        assert_eq!(texts, vec!["hello", "world", "longerstring"]);
        assert_eq!(out[0].addr, 0x1000);
        assert_eq!(out[1].addr, 0x1006);
        assert_eq!(out[2].addr, 0x100f);
    }

    #[test]
    fn drops_runs_below_min_len() {
        let mut out = Vec::new();
        extract_runs(b"abc\x00abcdefgh", 0, ".rodata", &opts(8), &mut out);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].text, "abcdefgh");
    }

    #[test]
    fn nonprintable_terminates_run() {
        // 0x01 is non-printable, should end the run after "abcd".
        let data = b"abcdefgh\x01ijklmnop";
        let mut out = Vec::new();
        extract_runs(data, 0, ".rodata", &opts(4), &mut out);
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].text, "abcdefgh");
        assert_eq!(out[1].text, "ijklmnop");
    }

    #[test]
    fn newline_terminates_run() {
        // \n is excluded so runs stay single-line.
        let data = b"line one is here\nline two follows here";
        let mut out = Vec::new();
        extract_runs(data, 0, ".rodata", &opts(4), &mut out);
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].text, "line one is here");
        assert_eq!(out[1].text, "line two follows here");
    }

    #[test]
    fn substring_filter_drops_non_matches() {
        let mut o = opts(4);
        o.filter = Some("usage".into());
        let data = b"random text here\x00usage: foo\x00more random\x00";
        let mut out = Vec::new();
        extract_runs(data, 0, ".rodata", &o, &mut out);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].text, "usage: foo");
    }

    #[test]
    fn max_cap_truncates_output() {
        let mut o = opts(4);
        o.max = Some(2);
        let data = b"first\x00second\x00third\x00fourth\x00";
        let mut out = Vec::new();
        extract_runs(data, 0, ".rodata", &o, &mut out);
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].text, "first");
        assert_eq!(out[1].text, "second");
    }
}
