//! Per-function metadata beyond names and entry PCs: the `_func` fields, the
//! pc-value tables (lines, files, SP deltas, pcdata), funcdata pointers, and
//! the decoders for the funcdata records a decompiler wants: FUNCDATA_ArgInfo
//! (the parameter layout the runtime's traceback printer uses),
//! FUNCDATA_OpenCodedDeferInfo, and the inline tree.
//!
//! Every reader is layout-aware across the pclntab layouts [`Pclntab`] parses:
//! Go 1.16/1.17 (magic `0xfffffffa`), Go 1.18/1.19 (`0xfffffff0`), and Go 1.20+
//! (`0xfffffff1`, and garble-rewritten magics that keep that shape). The
//! references are the toolchain's own reader and writer: `runtime/runtime2.go`
//! (`_func`), `runtime/symtab.go` (`funcdata`, `pcvalue`, `step`),
//! `runtime/symtabinl.go` (`inlinedCall`), `runtime/traceback.go`
//! (`printArgs`), `runtime/panic.go` (open-coded defers),
//! `cmd/compile/internal/ssagen/ssa.go` (`EmitArgInfo`, `emitOpenDeferInfo`).
//!
//! Nothing here guesses: a field the layout does not carry is `None`, a record
//! that does not decode cleanly is `None`, never a best-effort value.

use serde::Serialize;

use super::{read_u32, read_uintptr, read_varint, FuncEntry, Layout, Pclntab, MAGIC_1_18};

/// PCDATA table whose value at a PC is the index of the innermost inlined call
/// covering it, or -1 outside inlined code. Stable since Go 1.12.
pub const PCDATA_INL_TREE_INDEX: u32 = 2;
/// FUNCDATA slot of the inline tree (`[]inlinedCall`).
pub const FUNCDATA_INL_TREE: u8 = 3;
/// FUNCDATA slot of the open-coded defer record (Go 1.14+).
pub const FUNCDATA_OPEN_CODED_DEFER_INFO: u8 = 4;
/// FUNCDATA slot of the traceback argument layout (Go 1.17+).
pub const FUNCDATA_ARG_INFO: u8 = 5;
/// FUNCDATA slot of the argument pointer bitmaps (one per stack map index).
pub const FUNCDATA_ARGS_POINTER_MAPS: u8 = 0;
/// FUNCDATA slot of the locals pointer bitmaps.
pub const FUNCDATA_LOCALS_POINTER_MAPS: u8 = 1;
/// FUNCDATA slot of the stack object records (address-taken locals with
/// pointers that stay on the stack).
pub const FUNCDATA_STACK_OBJECTS: u8 = 2;
/// FUNCDATA slot of the register-argument liveness record (Go 1.18+).
pub const FUNCDATA_ARG_LIVE_INFO: u8 = 6;
/// PCDATA table whose value at a PC is the stack map index of the pointer
/// bitmaps that hold there.
pub const PCDATA_STACK_MAP_INDEX: u32 = 1;

/// One stack object record (`runtime.stackObjectRecord`): an address-taken
/// local that holds pointers and stays in the frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StackObject {
    /// Offset in the frame: negative from varp (entry SP - 8), else from
    /// argp (entry SP + 8).
    pub off: i32,
    pub size: i32,
    /// The bytes holding pointers, from its start.
    pub ptr_bytes: i32,
    /// Where the pointer mask of the object's type is (`runtime.gcbits.*`,
    /// one bit per word over `ptr_bytes`): an offset from moduledata's
    /// `rodata` (Go 1.18+, `gcdataoff`), else (Go 1.17) its address.
    /// [`Pclntab::stack_object_mask`] reads it.
    pub gcdata: u64,
}

/// A function's pointer bitmaps (`FUNCDATA_ArgsPointerMaps` or
/// `FUNCDATA_LocalsPointerMaps`): `nbit` words each, one bitmap per stack
/// map index.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PointerMaps {
    pub nbit: u32,
    pub maps: Vec<Vec<u8>>,
}

impl PointerMaps {
    /// Whether word `w` holds a pointer in bitmap `idx`.
    pub fn bit(&self, idx: usize, w: u32) -> bool {
        w < self.nbit
            && self
                .maps
                .get(idx)
                .and_then(|m| m.get((w / 8) as usize))
                .is_some_and(|b| b & (1 << (w % 8)) != 0)
    }
}

/// `abi.TraceArgsMaxLen`: (TraceArgsMaxDepth*3+2)*TraceArgsLimit + 1. An
/// ArgInfo record longer than this is rejected by the compiler.
const TRACE_ARGS_MAX_LEN: usize = (5 * 3 + 2) * 10 + 1;
/// Nesting the compiler can emit: depth 0 plus `TraceArgsMaxDepth` aggregate
/// levels. Anything deeper is not a record the writer produced.
const TRACE_ARGS_MAX_NEST: usize = 5;
const TRACE_ARGS_END_SEQ: u8 = 0xff;
const TRACE_ARGS_START_AGG: u8 = 0xfe;
const TRACE_ARGS_END_AGG: u8 = 0xfd;
const TRACE_ARGS_DOTDOTDOT: u8 = 0xfc;
const TRACE_ARGS_OFFSET_TOO_LARGE: u8 = 0xfb;
const TRACE_ARGS_SPECIAL: u8 = 0xf0;

/// Open-coded defers per function are capped at 8 (one deferBits byte).
const MAX_OPEN_DEFERS: u32 = 8;
/// Upper bound on a decoded open-coded defer record. The longest (Go 1.14 to
/// 1.17, eight defers each with arguments) stays far below this.
const OPEN_DEFER_READ_LEN: usize = 1024;

/// Per-PC inline depth cap. Real chains are rarely deeper than 5; the cap
/// keeps a hostile parentPc cycle from looping.
const MAX_INLINE_DEPTH: usize = 32;
/// Cap on an inline-tree index, matching the decoder in `crate::inline`.
const MAX_INLTREE_INDEX: i32 = 65_536;
/// Cap on records in one pc-value table walk.
const MAX_PCVALUE_STEPS: u32 = 1_000_000;

/// The fixed fields of a function's `_func` record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct FuncFields {
    /// Entry PC from the functab. The `_func` copy is not used: garble XORs it.
    pub entry: u64,
    /// Offset of the name in the funcname table.
    pub name_off: i32,
    /// In/out argument area size in bytes (`ArgsSizeUnknown` = i32::MIN).
    pub args: i32,
    /// Offset from entry of the deferreturn call, 0 when there is none.
    pub deferreturn: u32,
    /// pctab offsets of the SP-delta, file, and line tables (0 = no table).
    pub pcsp: u32,
    pub pcfile: u32,
    pub pcln: u32,
    pub npcdata: u32,
    /// Base index of this function's compilation unit in the cutab.
    pub cu_offset: u32,
    /// Line of the `func` keyword. Go 1.20+ only; earlier layouts lack it.
    pub start_line: Option<i32>,
    /// Raw `funcID`. Its numbering differs by release; use
    /// [`Pclntab::is_wrapper`] rather than comparing it to a constant.
    pub func_id: u8,
    /// `funcFlag` bits (TopFrame 1, SPWrite 2, Asm 4 from Go 1.21). Go 1.16 has
    /// a zero pad byte here, so 0 on a 1.16/1.17-magic binary proves nothing.
    pub flag: u8,
    pub nfuncdata: u8,
}

/// A source position covering a PC range of one function. Ranges are absolute
/// PCs, half-open, increasing, and non-overlapping.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LineSpan {
    pub pc_lo: u64,
    pub pc_hi: u64,
    pub file: String,
    pub line: u32,
}

/// The innermost inlined call covering a PC.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct InlineLeaf {
    /// Name of the inlined callee; empty when the record names none (`-tiny`).
    pub func_name: String,
    /// Source position of the PC itself, inside the inlined callee.
    pub file: Option<String>,
    pub line: Option<u32>,
    /// Absolute PC of an instruction whose source position is the call site
    /// in the caller (the record's parentPc plus the function entry). Every
    /// record carries a real parentPc; there is no -1 sentinel.
    pub parent_pc: u64,
    /// Line of the callee's `func` keyword (Go 1.20+ records only).
    pub start_line: Option<u32>,
    /// The callee's raw `funcID`.
    pub func_id: u8,
}

/// One component of a function's FUNCDATA_ArgInfo, as the runtime's traceback
/// printer reads it. Words are frame offsets of the (spilled or stack)
/// argument words; aggregates (strings, slices, interfaces, structs, arrays,
/// complex numbers) nest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum ArgComp {
    /// A scalar of `size` bytes at argument-frame offset `off`.
    Word { off: u8, size: u8 },
    /// An aggregate's components in order. An empty struct or array is `Agg([])`.
    Agg(Vec<ArgComp>),
    /// The compiler stopped listing (10-component limit or nesting depth).
    Ellipsis,
    /// The component's offset did not fit the encoding (>= 0xf0).
    TooLarge,
}

/// Which compiler wrote an open-coded defer record. The format changed twice.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum OpenDeferFormat {
    /// Go 1.14 to 1.17: maxargsize, deferBits, nDefers, then per defer its arg
    /// width, closure slot, and argument copies.
    Go114,
    /// Go 1.18 to 1.21: deferBits, nDefers, then one closure slot per defer.
    Go118,
    /// Go 1.22+: deferBits and the slot of defer 0; slots are contiguous.
    Go122,
}

/// A decoded FUNCDATA_OpenCodedDeferInfo record. Offsets are positive and
/// subtracted from the frame's varp (`varp - off`), as the runtime does.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OpenDeferInfo {
    pub format: OpenDeferFormat,
    /// The deferBits byte lives at `varp - defer_bits_offset`.
    pub defer_bits_offset: u32,
    /// Number of open-coded defers. Stated by Go 1.14 to 1.21 records; Go
    /// 1.22+ records omit it (count the deferBits updates in the code).
    pub num_defers: Option<u32>,
    /// Closure slot offset of each defer, indexed by its deferBits bit (bit i
    /// is the i-th defer statement in source order). Empty for Go 1.22+.
    pub closure_slot_offsets: Vec<u32>,
    /// Closure slot of defer bit 0. On Go 1.22+ the slot of bit i is at
    /// `varp - (slots_offset - i * ptrsize)`.
    pub slots_offset: u32,
}

/// Internal view of one `inlinedCall` record, normalized across layouts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct InlRecord {
    pub func_id: u8,
    pub name_off: i32,
    pub parent_pc: i32,
    /// Go 1.20+ only.
    pub start_line: Option<i32>,
}

impl<'a> Pclntab<'a> {
    /// True when `_func` carries `startLine` and `inlinedCall` is the 16-byte
    /// 1.20+ record. Go 1.18/1.19 share the 1.18+ functab but not this.
    fn is_go120(&self) -> bool {
        self.layout == Layout::Modern && self.magic != MAGIC_1_18
    }

    /// Size of the fixed `_func` header, i.e. the offset of `pcdata[0]`.
    fn func_header_size(&self) -> usize {
        // entry, then nameOff..cuOffset (8 x 4 bytes), then [startLine], then
        // funcID, flag/pad, pad, nfuncdata.
        let base = self.fields_base() + 32;
        if self.is_go120() {
            base + 8
        } else {
            base + 4
        }
    }

    fn func_start(&self, func: &FuncEntry) -> Option<usize> {
        self.funcdata_off.checked_add(func.func_off)
    }

    /// The function containing `pc`, with its `_func` offset and size, for the
    /// per-function readers below. `O(log n)`.
    pub fn func_entry_at(&self, pc: u64) -> Option<FuncEntry> {
        let n = self.nfunc as usize;
        let (mut lo, mut hi) = (0usize, n);
        while lo < hi {
            let mid = lo + (hi - lo) / 2;
            if self.functab_addr(mid)? <= pc {
                lo = mid + 1;
            } else {
                hi = mid;
            }
        }
        let idx = lo.checked_sub(1)?;
        let next = self.functab_addr(idx + 1).unwrap_or(u64::MAX);
        if pc >= next {
            return None;
        }
        let (address, func_start) = self.functab_entry(idx)?;
        let name_off = read_u32(
            self.data,
            func_start.checked_add(self.fields_base())?,
            self.little_endian,
        )
        .ok()?;
        Some(FuncEntry {
            address,
            name: self.read_name(name_off as usize).unwrap_or_default(),
            func_off: func_start - self.funcdata_off,
            size: next.saturating_sub(address),
        })
    }

    /// Decode the fixed `_func` fields of `func` for this binary's layout.
    pub fn func_fields(&self, func: &FuncEntry) -> Option<FuncFields> {
        let start = self.func_start(func)?;
        let end = start.checked_add(self.func_header_size())?;
        if end > self.data.len() {
            return None;
        }
        let fb = start + self.fields_base();
        let le = self.little_endian;
        let u32_at = |off: usize| read_u32(self.data, fb + off, le).ok();
        let (start_line, tail) = if self.is_go120() {
            (Some(u32_at(32)? as i32), fb + 36)
        } else {
            (None, fb + 32)
        };
        Some(FuncFields {
            entry: func.address,
            name_off: u32_at(0)? as i32,
            args: u32_at(4)? as i32,
            deferreturn: u32_at(8)?,
            pcsp: u32_at(12)?,
            pcfile: u32_at(16)?,
            pcln: u32_at(20)?,
            npcdata: u32_at(24)?,
            cu_offset: u32_at(28)?,
            start_line,
            func_id: self.data[tail],
            flag: self.data[tail + 1],
            nfuncdata: self.data[tail + 3],
        })
    }

    /// The pctab offset of pcdata table `table` for `func`, or None when the
    /// function has no such table (index past npcdata, or offset 0).
    pub(crate) fn pcdata_table(
        &self,
        func: &FuncEntry,
        fields: &FuncFields,
        table: u32,
    ) -> Option<u32> {
        if table >= fields.npcdata {
            return None;
        }
        let off = self
            .func_start(func)?
            .checked_add(self.func_header_size())?
            .checked_add(table as usize * 4)?;
        let v = read_u32(self.data, off, self.little_endian).ok()?;
        (v != 0).then_some(v)
    }

    /// The value of PCDATA table `table` at absolute `pc` inside `func`.
    pub fn pcdata_value(&self, func: &FuncEntry, table: u32, pc: u64) -> Option<i32> {
        let fields = self.func_fields(func)?;
        let off = self.pc_offset(func, pc)?;
        let t = self.pcdata_table(func, &fields, table)?;
        self.pcvalue(t, off, func.size)
    }

    /// The address of funcdata slot `idx` for `func`, or None when the slot is
    /// absent or nil. On Go 1.18+ slots are offsets from gofunc, so this needs
    /// [`Pclntab::with_gofunc`]; on Go 1.16/1.17 they are absolute pointers.
    pub fn funcdata(&self, func: &FuncEntry, idx: u8) -> Option<u64> {
        let fields = self.func_fields(func)?;
        if idx >= fields.nfuncdata {
            return None;
        }
        let le = self.little_endian;
        let arr = self
            .func_start(func)?
            .checked_add(self.func_header_size())?
            .checked_add(fields.npcdata as usize * 4)?;
        match self.layout {
            Layout::Modern => {
                let off = read_u32(self.data, arr.checked_add(idx as usize * 4)?, le).ok()?;
                if off == u32::MAX {
                    return None;
                }
                Some(self.gofunc?.wrapping_add(off as u64))
            }
            Layout::Pre118 => {
                // runtime 1.16/1.17 funcdata(): the uintptr array is 8-aligned
                // on 64-bit; the _func itself is pointer-aligned, so align the
                // offset relative to its start.
                let ps = self.ptrsize as usize;
                let rel = arr - self.func_start(func)?;
                let arr = if ps == 8 && rel & 4 != 0 {
                    arr + 4
                } else {
                    arr
                };
                let p =
                    read_uintptr(self.data, arr.checked_add(idx as usize * ps)?, ps, le).ok()?;
                (p != 0).then_some(p)
            }
        }
    }

    /// True when funcdata slots are offsets from gofunc (Go 1.18+), so
    /// [`Pclntab::funcdata`] needs [`Pclntab::with_gofunc`].
    pub(crate) fn funcdata_needs_gofunc(&self) -> bool {
        self.layout == Layout::Modern
    }

    /// Function-relative offset of absolute `pc`, if `pc` is inside `func`.
    fn pc_offset(&self, func: &FuncEntry, pc: u64) -> Option<u64> {
        let off = pc.checked_sub(func.address)?;
        (off < func.size).then_some(off)
    }

    /// The value a pc-value table holds at function-relative `off`. Mirrors
    /// runtime `pcvalue`: table offset 0 means no table.
    pub(crate) fn pcvalue(&self, table_off: u32, off: u64, limit: u64) -> Option<i32> {
        self.pcvalue_runs(table_off, limit)
            .find(|&(lo, hi, _)| lo <= off && off < hi)
            .map(|(_, _, v)| v)
    }

    /// The runs of a pc-value table as `(lo, hi, value)` over function-relative
    /// offsets, clipped to `limit` (the function size).
    pub(crate) fn pcvalue_runs(&self, table_off: u32, limit: u64) -> PcValueIter<'_> {
        let table = self.data.get(self.pctab_off..).unwrap_or(&[]);
        PcValueIter::new(table, table_off, self.quantum, limit)
    }

    /// SP delta (bytes below the entry SP) at absolute `pc`, from the pcsp
    /// table. 0 at the entry instruction; the frame size inside the body.
    pub fn sp_delta_at(&self, func: &FuncEntry, pc: u64) -> Option<i32> {
        let fields = self.func_fields(func)?;
        let off = self.pc_offset(func, pc)?;
        self.pcvalue(fields.pcsp, off, func.size)
    }

    /// (file, line) at function-relative `off` from the pcfile and pcln tables.
    fn file_line_at_off(
        &self,
        fields: &FuncFields,
        off: u64,
        limit: u64,
    ) -> (Option<String>, Option<u32>) {
        let file = self
            .pcvalue(fields.pcfile, off, limit)
            .filter(|&i| i >= 0)
            .and_then(|i| self.resolve_file(fields.cu_offset as usize, i as usize));
        let line = self
            .pcvalue(fields.pcln, off, limit)
            .filter(|&l| l > 0)
            .map(|l| l as u32);
        (file, line)
    }

    /// The per-PC source positions of `func`, in increasing PC order, with
    /// adjacent ranges at the same file and line merged. PCs whose file does not
    /// resolve or whose line is not positive are left out rather than guessed.
    /// The positions are the innermost source positions: inside inlined code
    /// they name the inlined callee's file and line (see [`Self::inline_leaf`]).
    pub fn line_table(&self, func: &FuncEntry) -> Vec<LineSpan> {
        let Some(fields) = self.func_fields(func) else {
            return Vec::new();
        };
        let files: Vec<_> = self.pcvalue_runs(fields.pcfile, func.size).collect();
        let lines: Vec<_> = self.pcvalue_runs(fields.pcln, func.size).collect();
        let mut out: Vec<LineSpan> = Vec::new();
        // File index -> resolved name, in first-seen order (no hash iteration).
        let mut names: Vec<(i32, Option<String>)> = Vec::new();
        let (mut i, mut j) = (0, 0);
        while i < files.len() && j < lines.len() {
            let (flo, fhi, fidx) = files[i];
            let (llo, lhi, line) = lines[j];
            let (lo, hi) = (flo.max(llo), fhi.min(lhi));
            if lo < hi && line > 0 && fidx >= 0 {
                let name = match names.iter().find(|(k, _)| *k == fidx) {
                    Some((_, n)) => n.clone(),
                    None => {
                        let n = self.resolve_file(fields.cu_offset as usize, fidx as usize);
                        names.push((fidx, n.clone()));
                        n
                    }
                };
                if let Some(file) = name {
                    let (pc_lo, pc_hi) = (func.address + lo, func.address + hi);
                    match out.last_mut() {
                        Some(prev)
                            if prev.pc_hi == pc_lo
                                && prev.line == line as u32
                                && prev.file == file =>
                        {
                            prev.pc_hi = pc_hi;
                        }
                        _ => out.push(LineSpan {
                            pc_lo,
                            pc_hi,
                            file,
                            line: line as u32,
                        }),
                    }
                }
            }
            if fhi <= lhi {
                i += 1;
            } else {
                j += 1;
            }
        }
        out
    }

    /// The `inlinedCall` record at index `idx` of the inline tree at `tree`.
    pub(crate) fn inline_record(&self, tree: u64, idx: i32) -> Option<InlRecord> {
        if !(0..=MAX_INLTREE_INDEX).contains(&idx) {
            return None;
        }
        let size: u64 = if self.is_go120() { 16 } else { 20 };
        let addr = tree.checked_add(idx as u64 * size)?;
        let b = self.bin.read_at_addr(addr, size as usize)?;
        let i32_at = |o: usize| {
            let a: [u8; 4] = b[o..o + 4].try_into().unwrap();
            if self.little_endian {
                i32::from_le_bytes(a)
            } else {
                i32::from_be_bytes(a)
            }
        };
        Some(if self.is_go120() {
            // funcID u8, _ [3]byte, nameOff, parentPc, startLine.
            InlRecord {
                func_id: b[0],
                name_off: i32_at(4),
                parent_pc: i32_at(8),
                start_line: Some(i32_at(12)),
            }
        } else {
            // parent int16, funcID u8, _ byte, file, line (of the call site),
            // func_ (nameOff), parentPc.
            InlRecord {
                func_id: b[2],
                name_off: i32_at(12),
                parent_pc: i32_at(16),
                start_line: None,
            }
        })
    }

    /// The inlined-call chain at absolute `pc`, innermost first, excluding the
    /// physical function. Empty outside inlined code or when the inline tree
    /// is unreachable (Go 1.18+ without gofunc).
    pub(crate) fn inline_chain(&self, func: &FuncEntry, pc: u64) -> Vec<InlineLeaf> {
        let mut out = Vec::new();
        let Some(fields) = self.func_fields(func) else {
            return out;
        };
        let Some(mut off) = self.pc_offset(func, pc) else {
            return out;
        };
        let Some(idx_table) = self.pcdata_table(func, &fields, PCDATA_INL_TREE_INDEX) else {
            return out;
        };
        let Some(tree) = self.funcdata(func, FUNCDATA_INL_TREE) else {
            return out;
        };
        let mut idx = self.pcvalue(idx_table, off, func.size).unwrap_or(-1);
        while idx >= 0 && out.len() < MAX_INLINE_DEPTH {
            let Some(rec) = self.inline_record(tree, idx) else {
                break;
            };
            let (file, line) = self.file_line_at_off(&fields, off, func.size);
            let func_name = if rec.name_off > 0 {
                self.read_name(rec.name_off as usize).unwrap_or_default()
            } else {
                String::new()
            };
            out.push(InlineLeaf {
                func_name,
                file,
                line,
                parent_pc: func.address.wrapping_add(rec.parent_pc as i64 as u64),
                start_line: rec.start_line.filter(|&l| l > 0).map(|l| l as u32),
                func_id: rec.func_id,
            });
            // The record's parentPc must lie inside the physical function; a
            // value outside it is corruption, so stop rather than follow it.
            if rec.parent_pc < 0 || rec.parent_pc as u64 >= func.size {
                break;
            }
            off = rec.parent_pc as u64;
            idx = self.pcvalue(idx_table, off, func.size).unwrap_or(-1);
        }
        out
    }

    /// The innermost inlined call covering absolute `pc` in `func`: the inlined
    /// callee's name, the PC's own source position, and the call site in the
    /// caller. None when `pc` is not inside inlined code, or when the inline
    /// tree is unreachable (Go 1.18+ needs [`Pclntab::with_gofunc`]).
    pub fn inline_leaf(&self, func: &FuncEntry, pc: u64) -> Option<InlineLeaf> {
        self.inline_chain(func, pc).into_iter().next()
    }

    /// The decoded FUNCDATA_ArgInfo of `func` (Go 1.17+): one component per
    /// input parameter, after the generic dictionary, in declaration order. It
    /// covers inputs only (results are not recorded) and the compiler stops
    /// after 10 components, marking the cut with [`ArgComp::Ellipsis`].
    pub fn arg_info(&self, func: &FuncEntry) -> Option<Vec<ArgComp>> {
        let addr = self.funcdata(func, FUNCDATA_ARG_INFO)?;
        parse_arg_info(self.read_upto(addr, TRACE_ARGS_MAX_LEN)?)
    }

    /// The first byte of FUNCDATA_ArgLiveInfo (Go 1.18+): the frame offset
    /// (from argp) of the first register argument's spill slot the compiler
    /// tracks liveness for. Every register argument's slot lies at or past
    /// the first register argument's, so arguments at lower offsets that
    /// entry code does not store from a register came on the stack.
    pub fn arg_live_first(&self, func: &FuncEntry) -> Option<u8> {
        if self.layout != Layout::Modern {
            return None;
        }
        let addr = self.funcdata(func, FUNCDATA_ARG_LIVE_INFO)?;
        self.read_upto(addr, 1)?.first().copied()
    }

    /// The stack object records of `func` (Go 1.17+ layout; None for the
    /// Go 1.16 record, which names a type instead of a size).
    pub fn stack_objects(&self, func: &FuncEntry) -> Option<Vec<StackObject>> {
        let addr = self.funcdata(func, FUNCDATA_STACK_OBJECTS)?;
        let le = self.little_endian;
        let head = self.read_upto(addr, 8)?;
        let n = read_uintptr(head, 0, 8, le).ok()? as usize;
        if n > 4096 {
            return None;
        }
        let rs = match self.layout {
            Layout::Modern => 16,
            Layout::Pre118 => 24,
        };
        let body = self.read_upto(addr + 8, n * rs)?;
        if body.len() < n * rs {
            return None;
        }
        let mut out = Vec::with_capacity(n);
        for k in 0..n {
            let r = k * rs;
            let off = read_u32(body, r, le).ok()? as i32;
            let size = read_u32(body, r + 4, le).ok()? as i32;
            let ptr_bytes = read_u32(body, r + 8, le).ok()? as i32;
            let gcdata = match self.layout {
                Layout::Modern => u64::from(read_u32(body, r + 12, le).ok()?),
                Layout::Pre118 => read_uintptr(body, r + 16, 8, le).ok()?,
            };
            // Go 1.16's {off int64, typ *_type} reads as a size of -1 here.
            if size <= 0 || ptr_bytes < 0 || ptr_bytes > size {
                return None;
            }
            out.push(StackObject {
                off,
                size,
                ptr_bytes,
                gcdata,
            });
        }
        Some(out)
    }

    /// The pointer mask of stack object `o`'s type: one bit per word of its
    /// first `ptr_bytes` bytes, low bit first (the `runtime.gcbits.*` bytes a
    /// type descriptor of that type also points at). Go 1.18+ records an
    /// offset from moduledata's `rodata`, which `rodata` must give; Go 1.17
    /// records the address. None when the bytes are not in the image.
    pub fn stack_object_mask(&self, o: &StackObject, rodata: Option<u64>) -> Option<Vec<u8>> {
        let addr = match self.layout {
            Layout::Modern => rodata?.checked_add(o.gcdata)?,
            Layout::Pre118 => o.gcdata,
        };
        let words = usize::try_from(o.ptr_bytes).ok()?.div_ceil(8);
        let n = words.div_ceil(8);
        if n == 0 {
            return Some(Vec::new());
        }
        let b = self.read_upto(addr, n)?;
        (b.len() == n).then(|| b.to_vec())
    }

    /// The argument (`locals == false`) or locals pointer bitmaps of `func`.
    pub fn pointer_maps(&self, func: &FuncEntry, locals: bool) -> Option<PointerMaps> {
        let idx = if locals {
            FUNCDATA_LOCALS_POINTER_MAPS
        } else {
            FUNCDATA_ARGS_POINTER_MAPS
        };
        let addr = self.funcdata(func, idx)?;
        let le = self.little_endian;
        let head = self.read_upto(addr, 8)?;
        let n = read_u32(head, 0, le).ok()? as usize;
        let nbit = read_u32(head, 4, le).ok()?;
        if n > 1 << 16 || nbit > 1 << 20 {
            return None;
        }
        let bpm = nbit.div_ceil(8) as usize;
        let body = if n * bpm == 0 {
            &[][..]
        } else {
            self.read_upto(addr + 8, n * bpm)?
        };
        if body.len() < n * bpm {
            return None;
        }
        Some(PointerMaps {
            nbit,
            maps: (0..n)
                .map(|k| body[k * bpm..(k + 1) * bpm].to_vec())
                .collect(),
        })
    }

    /// The stack map index (into [`Self::pointer_maps`]) at absolute `pc`.
    pub fn stack_map_index(&self, func: &FuncEntry, pc: u64) -> Option<i32> {
        self.pcdata_value(func, PCDATA_STACK_MAP_INDEX, pc)
    }

    /// The decoded FUNCDATA_OpenCodedDeferInfo of `func`, or None when it has
    /// no open-coded defers or the record's format cannot be pinned (a 1.20+
    /// magic binary whose runtime names are gone and whose record reads both
    /// ways).
    pub fn open_coded_defer_info(&self, func: &FuncEntry) -> Option<OpenDeferInfo> {
        let addr = self.funcdata(func, FUNCDATA_OPEN_CODED_DEFER_INFO)?;
        let bytes = self.read_upto(addr, OPEN_DEFER_READ_LEN)?;
        let format = match self.layout {
            Layout::Pre118 => Some(OpenDeferFormat::Go114),
            Layout::Modern if !self.is_go120() => Some(OpenDeferFormat::Go118),
            // Go 1.20/1.21 and 1.22+ share the magic. FuncID_corostart (1.22)
            // moved systemstack_switch from 20 to 21 (22 from 1.25).
            Layout::Modern => match self.systemstack_switch_id() {
                Some(20) => Some(OpenDeferFormat::Go118),
                Some(id) if id > 20 => Some(OpenDeferFormat::Go122),
                Some(_) => None,
                None => None,
            },
        };
        parse_open_defer_info(bytes, format, self.ptrsize as u32)
    }

    /// Whether `func` is compiler-generated wrapper code (method value and
    /// promoted-method wrappers, hash and eq algorithms): its funcID is
    /// FuncIDWrapper. None when the binary's FuncID numbering cannot be pinned
    /// (a 1.20+ magic binary without a findable `runtime.systemstack_switch`).
    pub fn is_wrapper(&self, func: &FuncEntry) -> Option<bool> {
        let wrapper = self.wrapper_func_id()?;
        Some(self.func_fields(func)?.func_id == wrapper)
    }

    /// FuncIDWrapper for this binary. It is the last FuncID, and the enum grew:
    /// 22 in Go 1.16/1.17, 21 in 1.18 to 1.21, 22 in 1.22 to 1.24, 23 from
    /// 1.25. From 1.17 on it directly follows FuncID_systemstack_switch.
    fn wrapper_func_id(&self) -> Option<u8> {
        match self.layout {
            Layout::Pre118 => Some(22),
            Layout::Modern if !self.is_go120() => Some(21),
            Layout::Modern => self.systemstack_switch_id()?.checked_add(1),
        }
    }

    /// The funcID of `runtime.systemstack_switch`, found by one functab walk
    /// and cached.
    fn systemstack_switch_id(&self) -> Option<u8> {
        *self.systemstack_switch_id.get_or_init(|| {
            const NAME: &[u8] = b"runtime.systemstack_switch\0";
            let stride = self.functab_stride();
            let avail = self.data.len().saturating_sub(self.funcdata_off) / stride;
            let n = (self.nfunc as usize).min(avail);
            let tail = if self.is_go120() { 36 } else { 32 };
            for i in 0..n {
                let Some((_, start)) = self.functab_entry(i) else {
                    continue;
                };
                let Some(fb) = start.checked_add(self.fields_base()) else {
                    continue;
                };
                let Ok(name_off) = read_u32(self.data, fb, self.little_endian) else {
                    continue;
                };
                let at = self.funcname_off.saturating_add(name_off as usize);
                if self.data.get(at..at.saturating_add(NAME.len())) == Some(NAME) {
                    return self.data.get(fb + tail).copied();
                }
            }
            None
        })
    }

    /// Up to `max` mapped bytes starting at `addr`, clamped to the containing
    /// section's file-backed bytes.
    fn read_upto(&self, addr: u64, max: usize) -> Option<&'a [u8]> {
        let bin = self.bin;
        let s = bin.section_for_addr(addr)?;
        let start = s.file_offset_of(addr)?;
        let end = start
            .saturating_add(max)
            .min(s.file_offset.saturating_add(s.file_size))
            .min(bin.bytes.len());
        (start < end).then(|| &bin.bytes[start..end])
    }
}

/// Iterator over the runs of a pc-value table, mirroring runtime `step`: the
/// value starts at -1 and the pc at 0; each record adds a zig-zag value delta
/// and a pc delta times the quantum; a zero value delta after the first record
/// ends the table.
pub(crate) struct PcValueIter<'t> {
    table: &'t [u8],
    pos: usize,
    pc: u64,
    val: i32,
    first: bool,
    quantum: u64,
    limit: u64,
    steps: u32,
    done: bool,
}

impl<'t> PcValueIter<'t> {
    pub(crate) fn new(table: &'t [u8], off: u32, quantum: u8, limit: u64) -> Self {
        PcValueIter {
            table,
            pos: off as usize,
            pc: 0,
            val: -1,
            first: true,
            quantum: quantum.max(1) as u64,
            limit,
            steps: 0,
            // Offset 0 means "no table" (runtime pcvalue).
            done: off == 0 || off as usize >= table.len(),
        }
    }
}

impl Iterator for PcValueIter<'_> {
    /// (lo, hi, value) over function-relative offsets, hi exclusive.
    type Item = (u64, u64, i32);

    fn next(&mut self) -> Option<Self::Item> {
        while !self.done {
            self.steps += 1;
            if self.steps > MAX_PCVALUE_STEPS || self.pc >= self.limit {
                self.done = true;
                return None;
            }
            let rest = self.table.get(self.pos..).unwrap_or(&[]);
            let Some((uv, n)) = read_varint(rest) else {
                self.done = true;
                return None;
            };
            // runtime readvarint decodes into a uint32.
            let uv = uv as u32;
            if uv == 0 && !self.first {
                self.done = true;
                return None;
            }
            self.first = false;
            self.val = self
                .val
                .wrapping_add(((uv >> 1) as i32) ^ -((uv & 1) as i32));
            let Some((pcd, n2)) = read_varint(rest.get(n..).unwrap_or(&[])) else {
                self.done = true;
                return None;
            };
            self.pos += n + n2;
            let lo = self.pc;
            let hi = lo.saturating_add((pcd as u32 as u64).saturating_mul(self.quantum));
            self.pc = hi;
            if hi > lo {
                return Some((lo, hi.min(self.limit), self.val));
            }
        }
        None
    }
}

/// Decode a FUNCDATA_ArgInfo byte string exactly as runtime `printArgs` walks
/// it. None when the bytes are not a record the compiler writes (an operator
/// byte in the reserved range, unbalanced aggregates, nesting past the
/// compiler's limit, or no terminator).
pub fn parse_arg_info(bytes: &[u8]) -> Option<Vec<ArgComp>> {
    fn seq(b: &[u8], pos: &mut usize, depth: usize) -> Option<Vec<ArgComp>> {
        let mut out = Vec::new();
        loop {
            let op = *b.get(*pos)?;
            *pos += 1;
            match op {
                TRACE_ARGS_END_SEQ => return (depth == 0).then_some(out),
                TRACE_ARGS_END_AGG => return (depth > 0).then_some(out),
                TRACE_ARGS_START_AGG => {
                    if depth >= TRACE_ARGS_MAX_NEST {
                        return None;
                    }
                    out.push(ArgComp::Agg(seq(b, pos, depth + 1)?));
                }
                TRACE_ARGS_DOTDOTDOT => out.push(ArgComp::Ellipsis),
                TRACE_ARGS_OFFSET_TOO_LARGE => out.push(ArgComp::TooLarge),
                o if o < TRACE_ARGS_SPECIAL => {
                    let size = *b.get(*pos)?;
                    *pos += 1;
                    out.push(ArgComp::Word { off: o, size });
                }
                _ => return None,
            }
        }
    }
    let b = &bytes[..bytes.len().min(TRACE_ARGS_MAX_LEN)];
    seq(b, &mut 0, 0)
}

/// runtime `readvarintUnsafe`: a uint32 varint of at most 5 bytes.
fn read_varint_u32(b: &[u8], pos: &mut usize) -> Option<u32> {
    let mut r: u32 = 0;
    let mut shift = 0u32;
    loop {
        let byte = *b.get(*pos)?;
        *pos += 1;
        if byte < 0x80 {
            return Some(r | (byte as u32).checked_shl(shift)?);
        }
        r |= ((byte & 0x7f) as u32) << shift;
        shift += 7;
        if shift > 28 {
            return None;
        }
    }
}

/// Decode an open-coded defer record in `format`. When `format` is None (a
/// 1.20+ binary whose epoch could not be pinned), the record is decoded only
/// when its second value tells the formats apart: Go 1.22+ stores a pointer-
/// aligned slot offset there (>= ptrsize), Go 1.18 to 1.21 a defer count of 1
/// to 8. A value that reads as both yields None.
pub fn parse_open_defer_info(
    bytes: &[u8],
    format: Option<OpenDeferFormat>,
    ptrsize: u32,
) -> Option<OpenDeferInfo> {
    let mut pos = 0usize;
    let format = match format {
        Some(f) => f,
        None => {
            let mut p = 0usize;
            read_varint_u32(bytes, &mut p)?;
            let second = read_varint_u32(bytes, &mut p)?;
            let can_be_count = (1..=MAX_OPEN_DEFERS).contains(&second);
            let can_be_slot = ptrsize > 0 && second >= ptrsize && second % ptrsize == 0;
            match (can_be_count, can_be_slot) {
                (true, false) => OpenDeferFormat::Go118,
                (false, true) => OpenDeferFormat::Go122,
                _ => return None,
            }
        }
    };
    let mut next = || read_varint_u32(bytes, &mut pos);
    match format {
        OpenDeferFormat::Go122 => {
            let defer_bits_offset = next()?;
            let slots_offset = next()?;
            Some(OpenDeferInfo {
                format,
                defer_bits_offset,
                num_defers: None,
                closure_slot_offsets: Vec::new(),
                slots_offset,
            })
        }
        OpenDeferFormat::Go118 | OpenDeferFormat::Go114 => {
            if format == OpenDeferFormat::Go114 {
                next()?; // maxargsize
            }
            let defer_bits_offset = next()?;
            let n = next()?;
            if !(1..=MAX_OPEN_DEFERS).contains(&n) {
                return None;
            }
            // Records are written last defer first (bit n-1 down to bit 0).
            let mut slots = vec![0u32; n as usize];
            for k in 0..n {
                if format == OpenDeferFormat::Go114 {
                    next()?; // argWidth
                }
                let closure = next()?;
                if format == OpenDeferFormat::Go114 {
                    let nargs = next()?;
                    if nargs > 64 {
                        return None;
                    }
                    for _ in 0..nargs * 3 {
                        next()?; // argOffset, argLen, argCallOffset
                    }
                }
                slots[(n - 1 - k) as usize] = closure;
            }
            Some(OpenDeferInfo {
                format,
                defer_bits_offset,
                num_defers: Some(n),
                slots_offset: slots[0],
                closure_slot_offsets: slots,
            })
        }
    }
}

#[cfg(test)]
mod tests;
