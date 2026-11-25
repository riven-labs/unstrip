//! Instruction decoding for the code scanners: x86 in its amd64 and 386
//! modes, and AArch64. Each decoder models only what the scanners read.

pub(crate) mod arm64;
pub(crate) mod x86;

use crate::gobin::{GoBinary, SectionKind};

/// The bytes of the function at `addr`, `size` bytes long, cut at the end
/// of its text section.
pub(crate) fn function_code(bin: &GoBinary, addr: u64, size: u64) -> Option<&[u8]> {
    let section = bin.section_for_addr(addr)?;
    if section.kind != SectionKind::Text {
        return None;
    }
    let start = section.file_offset_of(addr)?;
    let section_end = section.file_offset.saturating_add(section.file_size);
    let end = start
        .saturating_add(usize::try_from(size).ok()?)
        .min(section_end)
        .min(bin.bytes.len());
    bin.bytes.get(start..end)
}
