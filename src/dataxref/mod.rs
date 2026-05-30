use serde::Serialize;

use crate::error::Error;
use crate::gobin::{Arch, GoBinary, SectionKind};
use crate::pclntab::Pclntab;
use crate::Result;

/// One static reference from `.text` to a data address.
#[derive(Debug, Clone, Serialize)]
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
pub enum Kind {
    /// `LEA r64, [rip+disp32]` - address loaded, no memory read.
    Lea,
    /// `MOV r64, [rip+disp32]` - memory read.
    MovLoad,
    /// `MOV [rip+disp32], r64` - memory write.
    MovStore,
    /// `CMP r64, [rip+disp32]` or `CMP [rip+disp32], r64`. Matters at
    /// type-assertion sites that compare an itab pointer in memory
    /// against an expected itab address.
    Cmp,
    /// `CALL [rip+disp32]` or `JMP [rip+disp32]` - dispatch through a
    /// memory pointer.
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
/// amd64 only today. Other architectures return an error; the
/// scanner is a linear sweep of RIP-relative instruction encodings
/// and would need a parallel arm64 implementation to support those
/// binaries.
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
    if !matches!(bin.arch, Arch::X86_64) {
        return Err(Error::Xrefs(format!(
            "data xref scan is amd64 only today; got {:?}",
            bin.arch
        )));
    }

    let text = bin
        .sections
        .iter()
        .find(|s| s.kind == SectionKind::Text && s.name.ends_with(".text"))
        .or_else(|| {
            bin.sections
                .iter()
                .filter(|s| s.kind == SectionKind::Text)
                .max_by_key(|s| s.file_size)
        })
        .ok_or_else(|| Error::Xrefs("no text section".into()))?;

    let text_start = text.addr;
    let text_bytes = &bin.bytes[text.file_offset..text.file_offset + text.file_size];

    let mut hits = Vec::new();
    scan_amd64(text_bytes, text_start, target, direction, pcln, &mut hits);
    Ok(hits)
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
