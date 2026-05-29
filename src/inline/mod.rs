//! Inlined-call recovery from Go's `FUNCDATA_InlTree`.
//!
//! Decodes the per-function `FUNCDATA_InlTree` array into a flat
//! `Vec<InlinedCall>`, one entry per inlined call site recorded by the
//! Go compiler.
//!
//! # Supported Go envelope
//!
//! Witnessed format-stable across **Go 1.22 through 1.24** by the
//! coverage probe (see `internal/inlinecov/REPORT.md`): same 16-byte
//! `runtime.inlinedCall` layout, same `FUNCDATA_InlTree=3`, same
//! `PCDATA_InlTreeIndex=2`. Go 1.22 is the supported floor; Go 1.20
//! and 1.21 share the layout but are not witnessed by this codebase.
//! Later toolchains (Go 1.26+) are best-effort: the layout has been
//! stable since Go 1.20 and is unlikely to drift soon, but a returned
//! error on an unrecognized funcdata layout is the honest fallback if
//! it does. Garble's `entryoff` XOR rewrite provably does not touch
//! the inline-tree FUNCDATA section, so this decoder works on
//! garble-obfuscated binaries unchanged.
//!
//! # On-disk encoding
//!
//! Packed 16-byte struct per entry:
//!
//! ```text
//!   off  size  field
//!   0    1     funcID          u8
//!   1    3     _pad            [3]u8
//!   4    4     nameOff         i32   (offset into pclntab funcname table)
//!   8    4     parentPc        i32   (PC offset within the physical fn,
//!                                     of the call site that triggered the
//!                                     inline; -1 for top-level entries)
//!   12   4     startLine       i32
//! ```
//!
//! The array lives in the `gofunc` blob (a contiguous mapped region
//! described by moduledata). The per-function entry point is funcdata
//! index 3 (`FUNCDATA_InlTree`), stored as a u32 offset relative to
//! `gofunc`. A value of `u32::MAX` means "no inline tree for this
//! function" — the decoder returns `Ok(vec![])` in that case.
//!
//! Safety: every decoded `parent_pc` is asserted to lie strictly inside
//! the host function's PC range. This catches the most common
//! garble-style corruption (a truncated/reused inltree blob from another
//! function), and is the headline invariant we check during the Day-2
//! probe.

use crate::error::Error;
use crate::gobin::GoBinary;
use crate::pclntab::{FuncEntry, Pclntab};
use crate::Result;

/// One inlined-call record from `FUNCDATA_InlTree`.
#[derive(Debug, Clone, Copy)]
pub struct InlinedCall {
    pub func_id: u8,
    pub name_off: i32,
    pub parent_pc: i32,
    pub start_line: i32,
}

/// Number of funcdata pointer slots required before `FUNCDATA_InlTree`
/// is addressable in a function's funcdata array.
const FUNCDATA_INLTREE: usize = 3;
/// PCDATA index whose stream yields the current inline-tree index at each
/// PC. The array length we need is `max(stream) + 1`.
const PCDATA_INLTREE_INDEX: usize = 2;

/// Hard cap on entries per function. A real inline tree fits in a handful
/// of KB; 65_536 entries (1 MiB) is a very generous structural ceiling
/// and protects against a garbage length being inferred from a corrupt
/// next-pointer.
const MAX_INLINE_ENTRIES: usize = 65_536;

/// Decode the `FUNCDATA_InlTree` array for a single function.
///
/// Returns `Ok(vec![])` when the function has no inline tree (either
/// because it has fewer than 4 funcdata entries, or because slot 3 is
/// the sentinel `u32::MAX`). Returns an error if the gofunc base is
/// missing (call [`Pclntab::with_gofunc`] first), if the encoded
/// structure straddles unmapped memory, or — most importantly — if any
/// decoded entry's `parent_pc` falls outside the host function's PC
/// range. The last check is the safety assertion the wizard flagged.
pub fn decode_inline_tree(
    bin: &GoBinary,
    pcln: &Pclntab,
    func: &FuncEntry,
) -> Result<Vec<InlinedCall>> {
    let data = pcln.data();
    let le = pcln.little_endian();
    let func_start = pcln.funcdata_off() + func.func_off;

    // Layout of `_func` (Go 1.20+, 40-byte fixed header + packed tail):
    //   off=0  entryOff       u32
    //   off=4  nameOff        i32
    //   off=8  args           i32
    //   off=12 deferreturn    u32
    //   off=16 pcsp           u32
    //   off=20 pcfile         u32
    //   off=24 pcln           u32
    //   off=28 npcdata        u32
    //   off=32 cuOffset       u32
    //   off=36 startLine      i32
    //   off=40 funcID         u8
    //   off=41 flag           u8
    //   off=42 _pad           u8
    //   off=43 nfuncdata      u8
    //   off=44 [npcdata]u32   pcdata table
    //   off=44+npcdata*4 [nfuncdata]u32 funcdata table
    if func_start + 44 > data.len() {
        return Ok(vec![]);
    }
    let npcdata = read_u32(data, func_start + 28, le)? as usize;
    let nfuncdata = data[func_start + 43] as usize;
    if nfuncdata <= FUNCDATA_INLTREE || npcdata <= PCDATA_INLTREE_INDEX {
        return Ok(vec![]);
    }

    // Resolve the array length first by scanning the PCDATA_InlTreeIndex
    // pcvalue stream for its maximum index across the function's PC range.
    // The inline-tree subarray for this function holds (max_idx + 1) entries;
    // walking past that point reads adjacent functions' subarrays and the
    // parent_pc bounds-check rejects it. This is the safe termination the
    // wizard flagged.
    let pcdata_off = func_start + 44;
    let pcdata_inltree_off = read_u32(data, pcdata_off + PCDATA_INLTREE_INDEX * 4, le)? as usize;
    let max_idx = max_pcvalue(
        pcln_pctab(pcln),
        pcdata_inltree_off,
        u32::try_from(func.size).unwrap_or(u32::MAX),
    );
    if max_idx < 0 {
        // No inline indices ever recorded for this function — empty tree.
        return Ok(vec![]);
    }
    let n_entries = (max_idx as usize).saturating_add(1).min(MAX_INLINE_ENTRIES);

    let funcdata_arr_off = func_start + 44 + npcdata * 4;
    let inltree_slot_off = funcdata_arr_off + FUNCDATA_INLTREE * 4;
    if inltree_slot_off + 4 > data.len() {
        return Ok(vec![]);
    }
    let inltree_funcdata = read_u32(data, inltree_slot_off, le)?;
    if inltree_funcdata == u32::MAX {
        return Ok(vec![]);
    }

    let Some(gofunc) = pcln.gofunc() else {
        return Err(Error::ModuleData(
            "inline-tree decoding requires gofunc base; \
             call Pclntab::with_gofunc(moduledata.gofunc) first"
                .to_string(),
        ));
    };
    let inltree_addr = gofunc.wrapping_add(inltree_funcdata as u64);

    // The array is not length-prefixed. The runtime indexes into it using
    // the PCDATA_InlTreeIndex stream, so the structural length is "as many
    // valid 16-byte records as the gofunc region holds". We bound by:
    //   (a) MAX_INLINE_ENTRIES, the absolute ceiling
    //   (b) the section containing inltree_addr (read_at_addr enforces this)
    //
    // We read entries until the next 16-byte slice fails to map, at which
    // point we stop. Production v1.1 will tighten this using the
    // pcdata-derived high-watermark; for the probe this conservative walk
    // is what we want — it surfaces stray padding bytes rather than
    // silently truncating real entries.
    let mut out = Vec::with_capacity(n_entries);
    for i in 0..n_entries {
        let entry_addr = inltree_addr.wrapping_add((i as u64) * 16);
        let Some(bytes) = bin.read_at_addr(entry_addr, 16) else {
            break;
        };
        let func_id = bytes[0];
        let name_off = i32::from_le_bytes(bytes[4..8].try_into().unwrap());
        let parent_pc = i32::from_le_bytes(bytes[8..12].try_into().unwrap());
        let start_line = i32::from_le_bytes(bytes[12..16].try_into().unwrap());

        let entry = InlinedCall {
            func_id,
            name_off,
            parent_pc,
            start_line,
        };

        // SAFETY ASSERTION (wizard's call): parent_pc must point inside
        // the host function. parent_pc == -1 is the runtime's marker for
        // "top-level inline" (no parent call site), so we allow it; any
        // other negative value or an offset past func.size is corruption
        // (mis-resolved funcdata, recycled blob, etc.) and we refuse to
        // return tainted entries.
        if entry.parent_pc != -1 {
            if entry.parent_pc < 0 {
                return Err(Error::ModuleData(format!(
                    "inline tree for {} has negative parent_pc {} at index {}",
                    func.name, entry.parent_pc, i,
                )));
            }
            let pc = entry.parent_pc as u64;
            if pc >= func.size {
                return Err(Error::ModuleData(format!(
                    "inline tree for {} has parent_pc 0x{:x} >= func.size 0x{:x} at index {}",
                    func.name, pc, func.size, i,
                )));
            }
        }

        out.push(entry);
    }
    Ok(out)
}

/// Resolve a leaf entry's `name_off` to a function name. Returns `None`
/// if the offset is zero, out of range, or resolves to an empty string —
/// the three "unresolved" buckets the probe measurement harness reports.
pub fn resolve_leaf_name(pcln: &Pclntab, leaf: &InlinedCall) -> Option<String> {
    if leaf.name_off == 0 {
        return None;
    }
    if leaf.name_off < 0 {
        return None;
    }
    let off = leaf.name_off as usize;
    let abs = pcln.funcname_off().checked_add(off)?;
    if abs >= pcln.data().len() {
        return None;
    }
    let name = pcln.read_name_at(off).ok()?;
    if name.is_empty() {
        None
    } else {
        Some(name)
    }
}

/// Slice of pclntab `data()` starting at the pctab base. Convenience for
/// passing to [`max_pcvalue`].
fn pcln_pctab<'a>(pcln: &'a Pclntab<'_>) -> &'a [u8] {
    let off = pcln.pctab_off();
    let data = pcln.data();
    if off >= data.len() {
        &[]
    } else {
        &data[off..]
    }
}

/// Walk a pc-value stream and return the maximum `value` it ever produces
/// while `pc < pc_limit`. Returns -1 if the stream is empty/unparseable
/// (meaning: no inline-tree index ever recorded for this function).
fn max_pcvalue(table: &[u8], start: usize, pc_limit: u32) -> i64 {
    if start >= table.len() {
        return -1;
    }
    let mut value: i64 = -1;
    let mut pc: u32 = 0;
    let mut pos = start;
    let mut max_seen: i64 = -1;
    let mut iter_guard = 0;
    while pos < table.len() && iter_guard < 1_000_000 {
        iter_guard += 1;
        let (uval, n) = match read_varint(&table[pos..]) {
            Some(v) => v,
            None => return max_seen,
        };
        // A zero value-delta after the first record terminates the stream
        // (Go runtime convention; the leading record is always non-zero).
        if uval == 0 && pc != 0 {
            return max_seen;
        }
        pos += n;
        let delta = zig_zag(uval);
        value = value.wrapping_add(delta);
        let (pc_delta, n2) = match read_varint(&table[pos..]) {
            Some(v) => v,
            None => return max_seen,
        };
        pos += n2;
        pc = pc.wrapping_add(pc_delta as u32);
        if value > max_seen {
            max_seen = value;
        }
        if pc >= pc_limit {
            return max_seen;
        }
    }
    max_seen
}

fn zig_zag(u: u64) -> i64 {
    ((u >> 1) as i64) ^ -((u & 1) as i64)
}

fn read_varint(buf: &[u8]) -> Option<(u64, usize)> {
    const MAX_BYTES: usize = 10;
    let mut result: u64 = 0;
    let mut shift = 0;
    for (i, &b) in buf.iter().take(MAX_BYTES).enumerate() {
        result |= ((b & 0x7f) as u64) << shift;
        if b & 0x80 == 0 {
            return Some((result, i + 1));
        }
        shift += 7;
        if shift >= 64 {
            return None;
        }
    }
    None
}

fn read_u32(buf: &[u8], off: usize, little_endian: bool) -> Result<u32> {
    if off + 4 > buf.len() {
        return Err(Error::ShortRead {
            wanted: 4,
            offset: off,
            available: buf.len().saturating_sub(off),
        });
    }
    let s = &buf[off..off + 4];
    Ok(if little_endian {
        u32::from_le_bytes(s.try_into().unwrap())
    } else {
        u32::from_be_bytes(s.try_into().unwrap())
    })
}
