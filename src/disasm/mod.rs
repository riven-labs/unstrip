//! Instruction decoding for the code scanners: x86 in its amd64 and 386
//! modes, and AArch64. Each decoder models only what the scanners read.

pub(crate) mod arm64;
pub(crate) mod x86;

use crate::gobin::{GoBinary, SectionKind};
use crate::pclntab::{Function, Pclntab};
use crate::Result;

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

/// Decodes every function in the function table as 386 code and hands each
/// one to `visit` with its bytes and its instructions in address order.
///
/// A function is decoded from its entry to the next function's entry, so
/// the walk never starts inside an instruction the way a byte sweep can. It
/// stops at the first instruction the decoder cannot size; that loses the
/// rest of the function and nothing else.
pub(crate) fn each_function_386(
    bin: &GoBinary,
    pcln: &Pclntab<'_>,
    mut visit: impl FnMut(&Function, &[u8], &[(u64, x86::Insn)]),
) -> Result<()> {
    let mut insns = Vec::new();
    for func in pcln.functions()? {
        let Some(code) = func
            .size
            .and_then(|size| function_code(bin, func.address, size))
        else {
            continue;
        };
        insns.clear();
        let mut off = 0usize;
        while off < code.len() {
            let pc = func.address + off as u64;
            let Some(insn) = x86::decode32(&code[off..], pc) else {
                break;
            };
            insns.push((pc, insn));
            off += insn.len;
        }
        visit(&func, code, &insns);
    }
    Ok(())
}
