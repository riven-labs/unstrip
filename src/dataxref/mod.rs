//! Static references from code to data addresses: the instructions that
//! load an address, read or write the memory there, compare against it, or
//! call through it.
//!
//! amd64 is a linear sweep for RIP-relative forms. 386 code is non-PIE and
//! names every global by its absolute address, so each function is decoded
//! from its entry and its absolute operands and immediates are read. arm64
//! builds an address from an `ADRP` page and the `ADD`, load or store right
//! after it, which adds the low 12 bits.

use serde::Serialize;

use crate::disasm::{self, x86};
use crate::error::Error;
use crate::gobin::{Arch, GoBinary, Section, SectionKind};
use crate::pclntab::{Function, Pclntab};
use crate::Result;

/// One static reference from `.text` to a data address.
#[derive(Debug, Clone, Serialize)]
#[non_exhaustive]
pub struct DataXref {
    /// Link-time VA of the instruction that issued the reference.
    pub instruction_pc: u64,
    /// Containing function (recovered from pclntab) if any.
    pub function_name: Option<String>,
    pub function_addr: Option<u64>,
    /// Resolved data target address.
    pub target_addr: u64,
    /// How the instruction touched the address.
    pub kind: Kind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum Kind {
    /// The address is loaded and no memory is read: `LEA r64, [rip+disp32]`
    /// on amd64; `LEA`, or a `MOV` or `PUSH` of the address as an immediate,
    /// on 386; `ADRP` and `ADD` on arm64.
    Lea,
    /// The memory is read: `MOV r64, [rip+disp32]` on amd64; `MOV`, `MOVZX`,
    /// `MOVSX`, an SSE move or `PUSH` from the address on 386; `ADRP` and a
    /// load on arm64.
    MovLoad,
    /// The memory is written: `MOV [rip+disp32], r64` on amd64; `MOV` or an
    /// SSE move to the address on 386; `ADRP` and a store on arm64.
    MovStore,
    /// `CMP r64, [rip+disp32]` or `CMP [rip+disp32], r64`, and on 386 also a
    /// `CMP` with the address as the immediate. Matters at type-assertion
    /// sites that compare an itab pointer in memory against an expected
    /// itab address.
    Cmp,
    /// `CALL [rip+disp32]` or `JMP [rip+disp32]` (`[disp32]` on 386):
    /// dispatch through a memory pointer.
    CallIndirect,
}

/// What `mode` slice to scan for. Most callers want both reads and
/// writes; the type lets either be queried in isolation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// Hits where the instruction READS the target (LEA, MOV-load,
    /// CMP, CALL/JMP-indirect).
    Readers,
    /// Hits where the instruction WRITES the target (MOV-store).
    Writers,
    /// Both.
    Both,
}

/// Find every static reference to `target` from `.text`. Pclntab is
/// consulted to attribute each hit to its containing function; if a
/// hit lies outside any known function, `function_name` is `None`.
///
/// amd64, arm64 and 386; other architectures return an error. On arm64
/// a hit is the instruction that completes the `ADRP` page (the `ADD`,
/// load or store), and on 386 only code in the function table is read.
pub fn find_refs(
    bin: &GoBinary,
    pcln: &Pclntab<'_>,
    target: u64,
    direction: Direction,
) -> Result<Vec<DataXref>> {
    if !bin.little_endian {
        return Err(Error::Xrefs(
            "only little-endian binaries supported today".into(),
        ));
    }
    let mut hits = Vec::new();
    match bin.arch {
        Arch::X86_64 => {
            let text = text_section(bin).ok_or_else(|| Error::Xrefs("no text section".into()))?;
            let text_bytes = &bin.bytes[text.file_offset..text.file_offset + text.file_size];
            scan_amd64(text_bytes, text.addr, target, direction, pcln, &mut hits);
        }
        Arch::X86 => refs_386(bin, pcln, |func, pc, addr, kind| {
            if addr == target && wants(direction, kind) {
                hits.push(DataXref {
                    instruction_pc: pc,
                    function_name: Some(func.name.clone()),
                    function_addr: Some(func.address),
                    target_addr: target,
                    kind,
                });
            }
        })?,
        Arch::Aarch64 => {
            let text = text_section(bin).ok_or_else(|| Error::Xrefs("no text section".into()))?;
            let text_bytes = &bin.bytes[text.file_offset..text.file_offset + text.file_size];
            refs_arm64(text_bytes, text.addr, |pc, addr, kind| {
                if addr == target && wants(direction, kind) {
                    hits.push(make_hit(pc, target, kind, pcln));
                }
            });
        }
        _ => {
            return Err(Error::Xrefs(format!(
                "data xref scan supports amd64, arm64 and 386 today; got {:?}",
                bin.arch
            )))
        }
    }
    Ok(hits)
}

/// The section literally named `.text`, or else the largest executable
/// one. Helm-class ELF binaries list `.init` and `.plt` before `.text`, so
/// the first executable section is not always the code.
fn text_section(bin: &GoBinary) -> Option<&Section> {
    bin.sections
        .iter()
        .find(|s| s.kind == SectionKind::Text && s.name.ends_with(".text"))
        .or_else(|| {
            bin.sections
                .iter()
                .filter(|s| s.kind == SectionKind::Text)
                .max_by_key(|s| s.file_size)
        })
}

/// Linear sweep over `.text` looking for RIP-relative instruction
/// encodings whose effective address resolves to `target`. False
/// positives are possible at byte alignments inside a longer
/// instruction; in practice on Go-compiled output these are rare
/// because the compiler emits a small consistent style. The same
/// trade-off applies to `xrefs::find_calls`.
fn scan_amd64(
    text_bytes: &[u8],
    text_start: u64,
    target: u64,
    direction: Direction,
    pcln: &Pclntab<'_>,
    out: &mut Vec<DataXref>,
) {
    let mut i = 0usize;
    while i + 7 <= text_bytes.len() {
        let b = text_bytes[i];

        // CALL [rip+disp32]: FF /2  with ModR/M mod=00, rm=101.
        // JMP [rip+disp32]:  FF /4  with ModR/M mod=00, rm=101.
        // These are 6-byte sequences: FF mod-r-m disp32.
        if b == 0xff && i + 6 <= text_bytes.len() {
            let modrm = text_bytes[i + 1];
            if modrm & 0xC7 == 0x05 {
                let reg = (modrm >> 3) & 0x7;
                if reg == 2 || reg == 4 {
                    let disp = read_i32(&text_bytes[i + 2..i + 6]);
                    let next_pc = text_start + (i as u64) + 6;
                    if next_pc.wrapping_add(disp as i64 as u64) == target
                        && wants(direction, Kind::CallIndirect)
                    {
                        out.push(make_hit(
                            text_start + i as u64,
                            target,
                            Kind::CallIndirect,
                            pcln,
                        ));
                    }
                }
                i += 6;
                continue;
            }
        }

        // REX.W + opcode + ModR/M(mod=00, rm=101) + disp32, total 7 bytes.
        // We require REX.W (0x48) so we are looking at 64-bit operand
        // forms only. Mixed-width loads/stores in Go-compiled output
        // are uncommon for the address-bearing sites that matter
        // (slice headers, iface pairs, itab pointers).
        if b == 0x48 && i + 7 <= text_bytes.len() {
            let op = text_bytes[i + 1];
            let modrm = text_bytes[i + 2];
            if modrm & 0xC7 == 0x05 {
                let kind = match op {
                    0x8D => Some(Kind::Lea),
                    0x8B => Some(Kind::MovLoad),
                    0x89 => Some(Kind::MovStore),
                    0x39 | 0x3B => Some(Kind::Cmp),
                    _ => None,
                };
                if let Some(kind) = kind {
                    let disp = read_i32(&text_bytes[i + 3..i + 7]);
                    let next_pc = text_start + (i as u64) + 7;
                    let referenced = next_pc.wrapping_add(disp as i64 as u64);
                    if referenced == target && wants(direction, kind) {
                        out.push(make_hit(text_start + i as u64, target, kind, pcln));
                    }
                    i += 7;
                    continue;
                }
            }
        }

        i += 1;
    }
}

fn wants(d: Direction, k: Kind) -> bool {
    let is_write = matches!(k, Kind::MovStore);
    match d {
        Direction::Readers => !is_write,
        Direction::Writers => is_write,
        Direction::Both => true,
    }
}

fn make_hit(pc: u64, target: u64, kind: Kind, pcln: &Pclntab<'_>) -> DataXref {
    let containing = pcln.lookup(pc);
    DataXref {
        instruction_pc: pc,
        function_name: containing.as_ref().map(|f| f.name.clone()),
        function_addr: containing.as_ref().map(|f| f.address),
        target_addr: target,
        kind,
    }
}

fn read_i32(b: &[u8]) -> i32 {
    i32::from_le_bytes(b[..4].try_into().unwrap())
}

/// One-shot sweep collecting every address `.text` instructions
/// reference RIP-relative AND every 8-byte little-endian value
/// inside the read/write data sections (`.data`, `.noptrdata`,
/// `.rodata`) that falls inside a known mapped section. Returns the
/// set of addresses; the caller decides what to match against (itab
/// table, function table, etc.).
///
/// Both passes matter for liveness checks: Go's linker writes itab
/// pointers into `.data`-resident iface tables, so an itab that is
/// only reachable through one of those tables is still live even
/// though no `.text` instruction LEAs its address directly. Without
/// the data-side scan, every itab used by the (itab,data) iface
/// layout would falsely show as unused.
///
/// The `.text` pass decodes amd64, arm64 and 386. On any other
/// architecture this is an error, not an empty set: a set without the code
/// references would call every itab the code loads unreferenced. On 386
/// the function table bounds the code, and a binary whose table does not
/// read is an error too. The data pass reads pointer-sized words.
pub fn referenced_addresses(bin: &GoBinary) -> Result<std::collections::HashSet<u64>> {
    let mut out = std::collections::HashSet::new();
    if !bin.little_endian || !matches!(bin.arch, Arch::X86_64 | Arch::Aarch64 | Arch::X86) {
        return Err(Error::Xrefs(format!(
            "no reference scanner for {}; only little-endian amd64, arm64 and 386 today",
            bin.arch.as_str()
        )));
    }
    let text = text_section(bin);
    match (bin.arch, text) {
        (Arch::X86_64, Some(text)) => scan_text_amd64(
            &bin.bytes[text.file_offset..text.file_offset + text.file_size],
            text.addr,
            &mut out,
        ),
        (Arch::Aarch64, Some(text)) => refs_arm64(
            &bin.bytes[text.file_offset..text.file_offset + text.file_size],
            text.addr,
            |_, addr, _| {
                out.insert(addr);
            },
        ),
        (Arch::X86, _) => {
            let pcln = Pclntab::parse(bin)?;
            disasm::each_function_386(bin, &pcln, |func, code, insns| {
                for &(pc, insn) in insns {
                    // Every absolute operand counts here, not only the ones
                    // `find_refs` reports: an itab added to or tested is
                    // still referenced.
                    out.extend(insn.mem_target);
                    let bytes = &code[(pc - func.address) as usize..][..insn.len];
                    if let (_, Some((addr, _))) = classify_386(bytes, &insn) {
                        if in_image(bin, addr) {
                            out.insert(addr);
                        }
                    }
                }
            })?;
        }
        _ => (),
    }

    // Map of plausible address bounds for cheap range filtering of
    // qword candidates from data sections.
    let mut bounds: Vec<(u64, u64)> = bin
        .sections
        .iter()
        .filter(|s| !s.name.is_empty() && s.file_size > 0)
        .map(|s| {
            (
                s.addr,
                s.addr.saturating_add(s.vmsize.max(s.file_size as u64)),
            )
        })
        .collect();
    bounds.sort();

    for s in &bin.sections {
        if !matches!(
            s.kind,
            SectionKind::Data | SectionKind::NoPtrData | SectionKind::ReadOnlyData
        ) {
            continue;
        }
        let end = s
            .file_offset
            .saturating_add(s.file_size)
            .min(bin.bytes.len());
        let slice = &bin.bytes[s.file_offset..end];
        if bin.pointer_size() == 4 {
            for word in slice.chunks_exact(4) {
                let v = u32::from_le_bytes([word[0], word[1], word[2], word[3]]) as u64;
                if looks_like_address(v, &bounds) {
                    out.insert(v);
                }
            }
            continue;
        }
        let mut i = 0;
        while i + 8 <= slice.len() {
            let v = u64::from_le_bytes(slice[i..i + 8].try_into().unwrap());
            if looks_like_address(v, &bounds) {
                out.insert(v);
            }
            i += 8;
        }
    }
    Ok(out)
}

/// Every data reference in the 386 functions of the function table, as
/// `visit(function, pc, address, kind)`, in address order. An address
/// counts only when it lands inside a section of the image: an immediate
/// is most often a plain number, and a displacement under an index
/// register can be an offset.
pub(crate) fn refs_386(
    bin: &GoBinary,
    pcln: &Pclntab<'_>,
    mut visit: impl FnMut(&Function, u64, u64, Kind),
) -> Result<()> {
    disasm::each_function_386(bin, pcln, |func, code, insns| {
        for &(pc, insn) in insns {
            let bytes = &code[(pc - func.address) as usize..][..insn.len];
            let (mem, imm) = classify_386(bytes, &insn);
            for (addr, kind) in [mem, imm].into_iter().flatten() {
                if in_image(bin, addr) {
                    visit(func, pc, addr, kind);
                }
            }
        }
    })
}

/// Whether `addr` lies in a section the loader maps. Sections at address
/// zero are file-only (`.shstrtab` and the like).
fn in_image(bin: &GoBinary, addr: u64) -> bool {
    bin.sections
        .iter()
        .any(|s| s.addr != 0 && s.contains_addr(addr))
}

/// An address and how an instruction uses it.
type AddrUse = (u64, Kind);

/// The data references of one decoded 386 instruction: its absolute memory
/// operand, and an immediate that may be an address, each with how the
/// instruction uses it. Only `MOV` (with `MOVZX`, `MOVSX` and the SSE
/// moves), `LEA`, `PUSH`, `CMP`, and `CALL` and `JMP` through memory are
/// named.
fn classify_386(bytes: &[u8], insn: &x86::Insn) -> (Option<AddrUse>, Option<AddrUse>) {
    let mut i = 0;
    let mut opsize16 = false;
    let mut rep = 0;
    while let Some(&b) = bytes.get(i) {
        match b {
            0x66 => opsize16 = true,
            0xf2 | 0xf3 => rep = b,
            0xf0 | 0x26 | 0x2e | 0x36 | 0x3e | 0x64 | 0x65 => (),
            _ => break,
        }
        i += 1;
    }
    let Some(&op) = bytes.get(i) else {
        return (None, None);
    };
    // The ModRM reg field, for the opcodes that have one.
    let reg = bytes.get(i + 1).map_or(0, |m| (m >> 3) & 7);
    let mem = |kind: Kind| insn.mem_target.map(|addr| (addr, kind));
    // A 32-bit immediate ends the instruction in every form read here.
    let imm = |kind: Kind| -> Option<AddrUse> {
        if opsize16 || bytes.len() < 4 {
            return None;
        }
        let tail = &bytes[bytes.len() - 4..];
        let addr = u32::from_le_bytes([tail[0], tail[1], tail[2], tail[3]]) as u64;
        Some((addr, kind))
    };
    match op {
        0x8d => (mem(Kind::Lea), None),
        0x8a | 0x8b | 0xa0 | 0xa1 => (mem(Kind::MovLoad), None),
        0x88 | 0x89 | 0xa2 | 0xa3 => (mem(Kind::MovStore), None),
        0xc6 if reg == 0 => (mem(Kind::MovStore), None),
        0xc7 if reg == 0 => (mem(Kind::MovStore), imm(Kind::Lea)),
        0xb8..=0xbf | 0x68 => (None, imm(Kind::Lea)),
        0x38..=0x3b => (mem(Kind::Cmp), None),
        0x3d => (None, imm(Kind::Cmp)),
        0x80 | 0x82 | 0x83 if reg == 7 => (mem(Kind::Cmp), None),
        0x81 if reg == 7 => (mem(Kind::Cmp), imm(Kind::Cmp)),
        0xff => match reg {
            2..=5 => (mem(Kind::CallIndirect), None),
            6 => (mem(Kind::MovLoad), None),
            _ => (None, None),
        },
        0x0f => {
            let kind = match bytes.get(i + 1) {
                Some(0xb6 | 0xb7 | 0xbe | 0xbf) => Kind::MovLoad,
                Some(0x10 | 0x12 | 0x16 | 0x28 | 0x6e | 0x6f) => Kind::MovLoad,
                Some(0x11 | 0x13 | 0x17 | 0x29 | 0x2b | 0x7f | 0xe7) => Kind::MovStore,
                // MOVQ xmm, m64 with F3; MOVD r/m32, xmm without.
                Some(0x7e) if rep == 0xf3 => Kind::MovLoad,
                Some(0x7e) => Kind::MovStore,
                Some(0xd6) if opsize16 => Kind::MovStore,
                _ => return (None, None),
            };
            (mem(kind), None)
        }
        _ => (None, None),
    }
}

/// Every data reference in arm64 code, as `visit(pc, address, kind)`: an
/// `ADRP` and the instruction right after it that adds the low 12 bits of
/// the address through the same register, reported at that second
/// instruction. Go's assembler emits the two back to back for every
/// `sym(SB)` operand.
///
/// Go 1.18 and earlier (1.15 to 1.18 checked) load and store a global in
/// three instructions through the assembler's scratch register: `ADRP R27;
/// ADD $lo, R27, R27; MOVD (R27), R0`. That is one access, reported at the
/// load or store.
pub(crate) fn refs_arm64(text: &[u8], text_start: u64, mut visit: impl FnMut(u64, u64, Kind)) {
    let mut page: Option<(u32, u64)> = None;
    // An address the `ADD` of a three-instruction access left in R27, with
    // the `ADD`'s PC.
    let mut scratch: Option<(u64, u64)> = None;
    for (k, word) in text.chunks_exact(4).enumerate() {
        let pc = text_start + 4 * k as u64;
        let insn = u32::from_le_bytes([word[0], word[1], word[2], word[3]]);
        if let Some((addr, add_pc)) = scratch.take() {
            match page_offset_use(insn, REGTMP) {
                Some((offset, kind)) if kind != Kind::Lea => {
                    visit(pc, addr.wrapping_add(offset), kind)
                }
                _ => visit(add_pc, addr, Kind::Lea),
            }
        }
        if let Some((base, page_addr)) = page.take() {
            if let Some((offset, kind)) = page_offset_use(insn, base) {
                let addr = page_addr.wrapping_add(offset);
                if kind == Kind::Lea && base == REGTMP && insn & 31 == REGTMP {
                    scratch = Some((addr, pc));
                } else {
                    visit(pc, addr, kind);
                }
            }
        }
        if let disasm::arm64::Kind::Addr { dst, target } = disasm::arm64::decode(insn, pc) {
            if insn & 0x8000_0000 != 0 {
                page = Some((u32::from(dst), target));
            }
        }
    }
    if let Some((addr, add_pc)) = scratch {
        visit(add_pc, addr, Kind::Lea);
    }
}

/// R27, the register Go's arm64 assembler builds addresses in.
const REGTMP: u32 = 27;

/// The low bits an instruction adds to the page in register `base`, and
/// how it uses the address: `ADD` (immediate), or a load or store with an
/// unsigned scaled offset.
fn page_offset_use(insn: u32, base: u32) -> Option<(u64, Kind)> {
    if (insn >> 5) & 31 != base {
        return None;
    }
    let imm12 = ((insn >> 10) & 0xfff) as u64;
    if insn & 0xff80_0000 == 0x9100_0000 {
        let shift = if insn & (1 << 22) != 0 { 12 } else { 0 };
        return Some((imm12 << shift, Kind::Lea));
    }
    // Load/store register (unsigned immediate): size, 111, V, 01, opc.
    if insn & 0x3b00_0000 != 0x3900_0000 {
        return None;
    }
    let size = insn >> 30;
    let vector = insn & (1 << 26) != 0;
    let (scale, kind) = match (vector, (insn >> 22) & 3) {
        (_, 0) => (size, Kind::MovStore),
        (_, 1) => (size, Kind::MovLoad),
        // Sign-extending loads. With size 3, opc 2 is a prefetch.
        (false, 2) if size < 3 => (size, Kind::MovLoad),
        (false, 3) if size < 2 => (size, Kind::MovLoad),
        // The 128-bit vector forms.
        (true, 2) if size == 0 => (4, Kind::MovStore),
        (true, 3) if size == 0 => (4, Kind::MovLoad),
        _ => return None,
    };
    Some((imm12 << scale, kind))
}

fn scan_text_amd64(text_bytes: &[u8], text_start: u64, out: &mut std::collections::HashSet<u64>) {
    let mut i = 0usize;
    while i + 7 <= text_bytes.len() {
        let b = text_bytes[i];
        if b == 0xff && i + 6 <= text_bytes.len() {
            let modrm = text_bytes[i + 1];
            if modrm & 0xC7 == 0x05 {
                let reg = (modrm >> 3) & 0x7;
                if reg == 2 || reg == 4 {
                    let disp = read_i32(&text_bytes[i + 2..i + 6]);
                    let next_pc = text_start + (i as u64) + 6;
                    out.insert(next_pc.wrapping_add(disp as i64 as u64));
                }
                i += 6;
                continue;
            }
        }
        if b == 0x48 && i + 7 <= text_bytes.len() {
            let op = text_bytes[i + 1];
            let modrm = text_bytes[i + 2];
            if modrm & 0xC7 == 0x05 && matches!(op, 0x8D | 0x8B | 0x89 | 0x39 | 0x3B) {
                let disp = read_i32(&text_bytes[i + 3..i + 7]);
                let next_pc = text_start + (i as u64) + 7;
                out.insert(next_pc.wrapping_add(disp as i64 as u64));
                i += 7;
                continue;
            }
        }
        i += 1;
    }
}

/// Cheap range check: a u64 looks like an address when it falls into
/// any known mapped section's span. Filters out lengths/caps/zeros
/// that would otherwise inflate the address set with garbage.
fn looks_like_address(v: u64, bounds: &[(u64, u64)]) -> bool {
    if v < 0x1000 {
        return false;
    }
    bounds.iter().any(|&(lo, hi)| v >= lo && v < hi)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn classify(bytes: &[u8]) -> (Option<AddrUse>, Option<AddrUse>) {
        let insn = x86::decode32(bytes, 0x1000).expect("decodes");
        assert_eq!(insn.len, bytes.len(), "length of {bytes:02x?}");
        classify_386(bytes, &insn)
    }

    #[test]
    fn classify_386_names_each_use_of_an_absolute_address() {
        let at = 0x085d_9770;
        let mem = |kind| (Some((at, kind)), None);
        let imm = |kind| (None, Some((at, kind)));
        // LEAL, MOVL load and store, MOVB store, from Go 1.26 linux/386.
        assert_eq!(
            classify(&[0x8d, 0x05, 0x70, 0x97, 0x5d, 0x08]),
            mem(Kind::Lea)
        );
        assert_eq!(
            classify(&[0x8b, 0x05, 0x70, 0x97, 0x5d, 0x08]),
            mem(Kind::MovLoad)
        );
        assert_eq!(
            classify(&[0x89, 0x05, 0x70, 0x97, 0x5d, 0x08]),
            mem(Kind::MovStore)
        );
        assert_eq!(
            classify(&[0x88, 0x05, 0x70, 0x97, 0x5d, 0x08]),
            mem(Kind::MovStore)
        );
        // CMPL x(SB), $2 and CMPL x(SB), AX.
        assert_eq!(
            classify(&[0x83, 0x3d, 0x70, 0x97, 0x5d, 0x08, 0x02]),
            mem(Kind::Cmp)
        );
        assert_eq!(
            classify(&[0x39, 0x05, 0x70, 0x97, 0x5d, 0x08]),
            mem(Kind::Cmp)
        );
        // MOVSD_XMM x(SB), X0 and back.
        let load = [0xf2, 0x0f, 0x10, 0x05, 0x70, 0x97, 0x5d, 0x08];
        let store = [0xf2, 0x0f, 0x11, 0x05, 0x70, 0x97, 0x5d, 0x08];
        assert_eq!(classify(&load), mem(Kind::MovLoad));
        assert_eq!(classify(&store), mem(Kind::MovStore));
        // CALL through x(SB).
        assert_eq!(
            classify(&[0xff, 0x15, 0x70, 0x97, 0x5d, 0x08]),
            mem(Kind::CallIndirect)
        );
        // The address as an immediate: PUSHL, MOVL to a register and to
        // the stack, CMPL.
        assert_eq!(classify(&[0x68, 0x70, 0x97, 0x5d, 0x08]), imm(Kind::Lea));
        assert_eq!(classify(&[0xb9, 0x70, 0x97, 0x5d, 0x08]), imm(Kind::Lea));
        let to_stack = [0xc7, 0x04, 0x24, 0x70, 0x97, 0x5d, 0x08];
        assert_eq!(classify(&to_stack), imm(Kind::Lea));
        assert_eq!(classify(&[0x3d, 0x70, 0x97, 0x5d, 0x08]), imm(Kind::Cmp));
        // INCL x(SB) is no MOV, LEA, PUSH, CMP, CALL or JMP.
        assert_eq!(
            classify(&[0xff, 0x05, 0x70, 0x97, 0x5d, 0x08]),
            (None, None)
        );
    }

    fn arm64(words: &[u32]) -> Vec<(u64, u64, Kind)> {
        let text: Vec<u8> = words.iter().flat_map(|w| w.to_le_bytes()).collect();
        let mut out = Vec::new();
        refs_arm64(&text, 0x10000, |pc, addr, kind| out.push((pc, addr, kind)));
        out
    }

    #[test]
    fn arm64_pairs_adrp_with_the_instruction_after_it() {
        // ADRP 3592192(PC), R27 (page 0x37d000 here); then MOVBU 3092(R27),
        // R2, MOVD R2, 3288(R27), or ADD $3296, R3, R3 after ADRP into R3.
        assert_eq!(
            arm64(&[0xb000_1b7b, 0x3970_5362]),
            vec![(0x10004, 0x37d000 + 3092, Kind::MovLoad)]
        );
        assert_eq!(
            arm64(&[0xb000_1b7b, 0xf906_6f62]),
            vec![(0x10004, 0x37d000 + 3288, Kind::MovStore)]
        );
        assert_eq!(
            arm64(&[0xb000_1b63, 0x9133_8063]),
            vec![(0x10004, 0x37d000 + 3296, Kind::Lea)]
        );
        // The page register is not the next instruction's base.
        assert_eq!(arm64(&[0xb000_1b63, 0x3970_5362]), vec![]);
    }

    #[test]
    fn arm64_three_instruction_access_is_one_load_or_store() {
        // Go 1.15: ADRP 2551808(PC), R27; ADD $1968, R27, R27; then
        // MOVD (R27), R0 or MOVD R0, (R27).
        let addr = 0x27f000 + 1968;
        assert_eq!(
            arm64(&[0xf000_137b, 0x911e_c37b, 0xf940_0360]),
            vec![(0x10008, addr, Kind::MovLoad)]
        );
        assert_eq!(
            arm64(&[0xf000_137b, 0x911e_c37b, 0xf900_0360]),
            vec![(0x10008, addr, Kind::MovStore)]
        );
        // Without an access after it, the ADD only loads the address.
        assert_eq!(
            arm64(&[0xf000_137b, 0x911e_c37b, 0xd503_201f]),
            vec![(0x10004, addr, Kind::Lea)]
        );
    }
}
