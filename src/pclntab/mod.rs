use serde::Serialize;

use crate::error::Error;
use crate::gobin::GoBinary;
use crate::Result;

mod funcinfo;
pub use funcinfo::{
    parse_arg_info, parse_open_defer_info, ArgComp, FuncFields, InlineLeaf, LineSpan,
    OpenDeferFormat, OpenDeferInfo, PointerMaps, StackObject, FUNCDATA_ARGS_POINTER_MAPS,
    FUNCDATA_ARG_INFO, FUNCDATA_ARG_LIVE_INFO, FUNCDATA_INL_TREE, FUNCDATA_LOCALS_POINTER_MAPS,
    FUNCDATA_OPEN_CODED_DEFER_INFO, FUNCDATA_STACK_OBJECTS, PCDATA_INL_TREE_INDEX,
    PCDATA_STACK_MAP_INDEX,
};

pub const MAGIC_1_20: u32 = 0xfffffff1;
/// Go 1.18 and 1.19 pclntab magic. The layout is byte-compatible with
/// 1.20+ for the fields we care about, only the magic differs.
pub const MAGIC_1_18: u32 = 0xfffffff0;
/// Go 1.16 and 1.17 pclntab magic. The header has no textStart, the functab
/// entries are pointer-sized (an absolute entry PC and a funcoff), and the `_func`
/// struct leads with a uintptr entry.
pub const MAGIC_1_16: u32 = 0xfffffffa;
/// Go 1.2 to 1.15 pclntab magic. There is no offset header: the functab
/// follows `nfunc` directly, a u32 after it locates the file table, and every
/// other offset (function names, pc-value tables, `_func` records, file names)
/// is relative to the start of the table.
pub const MAGIC_1_2: u32 = 0xfffffffb;

/// The Go release family for a pclntab magic this reader does not implement.
/// Every layout since Go 1.2 is read, so this returns None for every magic. It
/// is kept so callers written against the earlier API still build.
pub fn unsupported_pre118_magic(magic: u32) -> Option<&'static str> {
    let _ = magic;
    None
}

/// Which pclntab table layout a binary uses. The header field positions, the
/// functab entry width, and the `_func` struct prefix changed in Go 1.16 and
/// again in Go 1.18.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Layout {
    /// Go 1.2 to 1.15 (magic [`MAGIC_1_2`]).
    Go12,
    /// Go 1.16 and 1.17 (magic [`MAGIC_1_16`]).
    Pre118,
    /// Go 1.18 and later, and garble-rewritten magics that keep the 1.18+ shape.
    Modern,
}

#[derive(Debug, Clone, Serialize)]
#[non_exhaustive]
pub struct Function {
    pub address: u64,
    pub name: String,
    pub file: Option<String>,
    /// Line of the function's `func` keyword. The line of a PC inside the
    /// function is [`Pclntab::pc_position`].
    pub start_line: Option<u32>,
}

/// Cloning is cheap: every field is a slice reference or a small scalar. A
/// clone lets a decoded function carry its own call-resolution handle without
/// re-parsing, which is what keeps whole-program sweeps linear.
#[derive(Clone)]
pub struct Pclntab<'a> {
    /// The binary the table was parsed from. Funcdata (the inline tree, ArgInfo,
    /// OpenCodedDeferInfo) lives outside the pclntab, so the metadata readers in
    /// [`funcinfo`] resolve it through the container's sections.
    bin: &'a GoBinary,
    data: &'a [u8],
    little_endian: bool,
    magic: u32,
    layout: Layout,
    quantum: u8,
    ptrsize: u8,
    nfunc: u64,
    text_start: u64,

    funcname_off: usize,
    cu_off: usize,
    filetab_off: usize,
    pctab_off: usize,
    /// Base the functab's `_func` offsets are relative to: the functab itself
    /// from Go 1.16, the start of the table in Go 1.2 to 1.15.
    funcoff_base: usize,
    /// Offset of the functab's first entry. Equal to `funcoff_base` from Go
    /// 1.16, right after `nfunc` in Go 1.2 to 1.15.
    functab_off: usize,

    /// Optional: gofunc base from moduledata. Required for inline-tree walking
    /// (the funcdata entries are offsets relative to gofunc). When None,
    /// inline-tree decoding falls back to returning the leaf frame only.
    gofunc: Option<u64>,

    /// The `funcID` of `runtime.systemstack_switch`, found once on demand. The
    /// FuncID enum grew between releases sharing the 1.20+ magic, and
    /// systemstack_switch always sits directly before FuncIDWrapper (Go 1.17+),
    /// so this one value pins both the wrapper ID and the toolchain epoch
    /// (1.20/1.21 vs 1.22+) that the open-coded defer format depends on.
    systemstack_switch_id: std::sync::OnceLock<Option<u8>>,

    /// Go 1.2 to 1.15 only: whether `_func` ends with the Go 1.12 tail
    /// (`funcID u8, _ [2]int8, nfuncdata u8`) rather than the older
    /// `nfuncdata int32`. The releases share the magic, so it is read from the
    /// records once, on demand.
    go112_func_tail: std::sync::OnceLock<bool>,
}

/// A richer per-function record with the raw `_func` struct offset and the
/// PC-range size, both of which are needed to decode funcdata structures
/// such as the inline tree.
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct FuncEntry {
    pub address: u64,
    pub name: String,
    /// Offset of the function's `_func` struct inside `Pclntab::data()`.
    pub func_off: usize,
    /// PC size of the function in bytes (next_text_off - text_off). On the
    /// final functab entry this is derived from the sentinel.
    pub size: u64,
}

/// One frame in a recovered inline call stack at a given PC. The innermost
/// (leaf) frame comes first; subsequent entries are the inlined call chain
/// outward to the physical function the compiler actually emitted code for.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct InlineFrame {
    pub name: String,
    pub file: Option<String>,
    pub line: Option<u32>,
    pub inlined: bool,
}

impl<'a> Pclntab<'a> {
    pub fn parse(bin: &'a GoBinary) -> Result<Self> {
        let data = bin.pclntab_slice();
        let little_endian = bin.little_endian;

        if data.len() < 8 {
            return Err(Error::BadPclntab {
                offset: bin.pclntab_offset,
                reason: format!("header truncated: only {} bytes", data.len()),
            });
        }

        let magic = read_u32(data, 0, little_endian)?;
        // Go 1.2 to 1.15, Go 1.16/1.17 and Go 1.18+ differ in the header field
        // positions, the functab entry width, and the _func prefix. Pick the
        // reader by magic. A garble-rewritten magic keeps the 1.18+ shape, so it
        // reads as Modern; the structural checks below still reject a genuinely
        // broken header.
        let layout = match magic {
            MAGIC_1_2 => Layout::Go12,
            MAGIC_1_16 => Layout::Pre118,
            _ => Layout::Modern,
        };

        if data[4] != 0 || data[5] != 0 {
            return Err(Error::BadPclntab {
                offset: bin.pclntab_offset,
                reason: format!(
                    "expected zero pad at [4..6], got {:02x} {:02x}",
                    data[4], data[5]
                ),
            });
        }

        let quantum = data[6];
        let ptrsize = data[7];
        if !matches!(quantum, 1 | 2 | 4) {
            return Err(Error::BadPclntab {
                offset: bin.pclntab_offset,
                reason: format!("invalid quantum {quantum}, expected 1, 2, or 4"),
            });
        }
        if !matches!(ptrsize, 4 | 8) {
            return Err(Error::BadPclntab {
                offset: bin.pclntab_offset,
                reason: format!("invalid ptrsize {ptrsize}, expected 4 or 8"),
            });
        }

        let ps = ptrsize as usize;
        let read_uptr = |off: usize| read_uintptr(data, off, ps, little_endian);

        let nfunc = read_uptr(8)?;
        // Go 1.18 inserted textStart into the header before the offset table, so on
        // 1.16/1.17 the offsets sit one pointer earlier and there is no textStart
        // (functab entries carry absolute PCs instead).
        let (text_start, funcname_off, cu_off, filetab_off, pctab_off, funcdata_off) = match layout
        {
            Layout::Modern => (
                read_uptr(8 + 2 * ps)?,
                read_uptr(8 + 3 * ps)? as usize,
                read_uptr(8 + 4 * ps)? as usize,
                read_uptr(8 + 5 * ps)? as usize,
                read_uptr(8 + 6 * ps)? as usize,
                read_uptr(8 + 7 * ps)? as usize,
            ),
            Layout::Pre118 => (
                0,
                read_uptr(8 + 2 * ps)? as usize,
                read_uptr(8 + 3 * ps)? as usize,
                read_uptr(8 + 4 * ps)? as usize,
                read_uptr(8 + 5 * ps)? as usize,
                read_uptr(8 + 6 * ps)? as usize,
            ),
            // No offset header. The functab follows nfunc: nfunc (entry, funcoff)
            // pointer pairs and the end PC of the last function, then a u32 that
            // locates the file table. Names, pc-value tables and _func records are
            // addressed from the start of the table, so those bases are zero.
            // There is no cutab: a pcfile value indexes the file table directly.
            Layout::Go12 => {
                let tab_end = usize::try_from(nfunc)
                    .ok()
                    .and_then(|n| n.checked_mul(2)?.checked_add(1)?.checked_mul(ps))
                    .and_then(|size| size.checked_add(8 + ps))
                    .filter(|&end| end.saturating_add(4) <= data.len());
                let Some(tab_end) = tab_end else {
                    return Err(Error::BadPclntab {
                        offset: bin.pclntab_offset,
                        reason: format!("functab of {nfunc} entries extends past pclntab end"),
                    });
                };
                let filetab_off = read_u32(data, tab_end, little_endian)? as usize;
                (0, 0, 0, filetab_off, 0, 0)
            }
        };
        let functab_off = match layout {
            Layout::Go12 => 8 + ps,
            Layout::Pre118 | Layout::Modern => funcdata_off,
        };

        for (name, off) in [
            ("funcnameOffset", funcname_off),
            ("cuOffset", cu_off),
            ("filetabOffset", filetab_off),
            ("pctabOffset", pctab_off),
            ("funcdataOffset", funcdata_off),
        ] {
            if off >= data.len() {
                return Err(Error::BadPclntab {
                    offset: bin.pclntab_offset,
                    reason: format!(
                        "{name}=0x{off:x} is past end of pclntab (0x{:x})",
                        data.len()
                    ),
                });
            }
        }

        // textStart in the header is the runtime-resolved VA. Windows builds and
        // Go 1.26+ store zero (the runtime takes the base from moduledata), so fall
        // back to the .text section address from the container. That anchor is
        // only right for the container's own table: GoBinary::parse refuses a
        // scanned table that belongs to an embedded image. Only meaningful for
        // Modern; older functab entries are absolute, so text_start stays 0 there.
        let text_start = if layout == Layout::Modern && text_start == 0 {
            bin.text_addr
        } else {
            text_start
        };

        Ok(Pclntab {
            bin,
            data,
            little_endian,
            magic,
            layout,
            quantum,
            ptrsize,
            nfunc,
            text_start,
            funcname_off,
            cu_off,
            filetab_off,
            pctab_off,
            funcoff_base: funcdata_off,
            functab_off,
            gofunc: None,
            systemstack_switch_id: std::sync::OnceLock::new(),
            go112_func_tail: std::sync::OnceLock::new(),
        })
    }

    /// Attach the gofunc base address from moduledata so subsequent inline-tree
    /// lookups can resolve funcdata pointers. Without this, `lookup_inline`
    /// degrades to returning only the leaf frame.
    pub fn with_gofunc(mut self, gofunc: u64) -> Self {
        self.gofunc = Some(gofunc);
        self
    }

    pub fn magic(&self) -> u32 {
        self.magic
    }

    pub fn magic_is_official(&self) -> bool {
        matches!(self.magic, MAGIC_1_20 | MAGIC_1_18 | MAGIC_1_16 | MAGIC_1_2)
    }

    /// Whether the table has the Go 1.18 and later shape, which a
    /// garble-rewritten magic keeps.
    pub(crate) fn is_go118_or_later(&self) -> bool {
        self.layout == Layout::Modern
    }

    /// Whether the table has the Go 1.16 and 1.17 shape.
    pub(crate) fn is_go116_or_go117(&self) -> bool {
        self.layout == Layout::Pre118
    }

    pub fn nfunc(&self) -> u64 {
        self.nfunc
    }

    /// Bytes per functab entry: a u32 pair in 1.18+, a pointer pair before.
    fn functab_stride(&self) -> usize {
        match self.layout {
            Layout::Modern => 8,
            Layout::Go12 | Layout::Pre118 => 2 * self.ptrsize as usize,
        }
    }

    /// Entry PC (absolute VA) of functab index `i`. In 1.18+ the entry is a u32
    /// offset from textStart; before 1.18 it is an absolute uintptr.
    pub(crate) fn functab_addr(&self, i: usize) -> Option<u64> {
        // Checked throughout: a hostile header can set nfunc or the offsets so that
        // functab_off + i*stride overflows usize. Overflow resolves to None (no
        // such entry), never a panic or a wrapped offset.
        let off = self
            .functab_off
            .checked_add(i.checked_mul(self.functab_stride())?)?;
        match self.layout {
            Layout::Modern => self
                .text_start
                .checked_add(read_u32(self.data, off, self.little_endian).ok()? as u64),
            Layout::Go12 | Layout::Pre118 => {
                read_uintptr(self.data, off, self.ptrsize as usize, self.little_endian).ok()
            }
        }
    }

    /// The (entry PC, `_func` struct offset within `data`) for functab index `i`.
    /// The funcoff is relative to `funcoff_base`: the functab base from Go 1.16,
    /// the start of the table in Go 1.2 to 1.15.
    fn functab_entry(&self, i: usize) -> Option<(u64, usize)> {
        let ps = self.ptrsize as usize;
        let off = self
            .functab_off
            .checked_add(i.checked_mul(self.functab_stride())?)?;
        let func_off = match self.layout {
            Layout::Modern => {
                read_u32(self.data, off.checked_add(4)?, self.little_endian).ok()? as usize
            }
            Layout::Go12 | Layout::Pre118 => {
                read_uintptr(self.data, off.checked_add(ps)?, ps, self.little_endian).ok()? as usize
            }
        };
        Some((
            self.functab_addr(i)?,
            self.funcoff_base.checked_add(func_off)?,
        ))
    }

    /// Offset from a `_func` struct start to its `nameOff` field, i.e. the width of
    /// the leading entry field: a u32 entryOff in 1.18+, a uintptr entry before.
    /// Every later `_func` field is at a fixed offset past this.
    fn fields_base(&self) -> usize {
        match self.layout {
            Layout::Modern => 4,
            Layout::Go12 | Layout::Pre118 => self.ptrsize as usize,
        }
    }

    /// Raw pclntab bytes. Exposed for sibling modules (e.g. `crate::inline`)
    /// that need to decode structures beyond what the top-level walker
    /// surfaces (the inline tree array, pcdata streams, etc.).
    pub fn data(&self) -> &[u8] {
        self.data
    }

    /// Endianness flag for any reader that needs to decode integers from
    /// `data()` directly.
    pub fn little_endian(&self) -> bool {
        self.little_endian
    }

    /// Offset of the functab inside `data()`. Each entry is `(entry, func_off)`:
    /// two u32s on Go 1.18+ (entry as an offset from textStart), two uintptrs
    /// before (absolute entry). The final sentinel entry marks the end of the
    /// last function. `func_off` is relative to this offset from Go 1.16 and to
    /// the start of `data()` in Go 1.2 to 1.15.
    pub fn funcdata_off(&self) -> usize {
        self.functab_off
    }

    /// Offset of the funcname string table inside `data()`. Add a per-function
    /// `nameOff` to this to get the absolute byte offset of the function's
    /// NUL-terminated name.
    pub fn funcname_off(&self) -> usize {
        self.funcname_off
    }

    /// Offset of the pctab (pc-value tables) inside `data()`. Per-function
    /// pcdata streams (pcsp, pcfile, pcln, and the pcdata[] array, including
    /// PCDATA_InlTreeIndex) are encoded as offsets into this region.
    pub fn pctab_off(&self) -> usize {
        self.pctab_off
    }

    /// `gofunc` base from moduledata, if it was supplied via [`with_gofunc`](Self::with_gofunc).
    /// Required for inline-tree decoding because funcdata pointers are stored
    /// as offsets relative to this address.
    pub fn gofunc(&self) -> Option<u64> {
        self.gofunc
    }

    /// Resolve a function `nameOff` into the recovered string. Returns an
    /// empty string when the offset lands on a NUL byte (which the corpus
    /// shows up as for some compiler-generated helpers).
    pub fn read_name_at(&self, name_off: usize) -> Result<String> {
        self.read_name(name_off)
    }

    /// Resolve a single PC to its containing function. Uses binary search on
    /// the functab, `O(log n)` per query, suitable for use inside debugger
    /// scripts and crash-dump tooling.
    pub fn lookup(&self, pc: u64) -> Option<Function> {
        let n = self.nfunc as usize;

        // Binary search on the functab's entry PCs. functab_addr returns an
        // absolute VA in both layouts, so the search is layout-independent. The
        // function spans [entry[idx], entry[idx+1]).
        let mut lo = 0usize;
        let mut hi = n;
        while lo < hi {
            let mid = (lo + hi) / 2;
            let mid_addr = self.functab_addr(mid)?;
            if mid_addr <= pc {
                lo = mid + 1;
            } else {
                hi = mid;
            }
        }
        if lo == 0 {
            return None;
        }
        let idx = lo - 1;

        // Verify pc is still within this function (before the next entry's start).
        let next_addr = self.functab_addr(idx + 1).unwrap_or(u64::MAX);
        if pc >= next_addr {
            return None;
        }

        let (address, func_start) = self.functab_entry(idx)?;
        self.read_function(address, func_start).ok()
    }

    /// Resolve a PC to the full inlined call stack, innermost frame first.
    /// Reads PCDATA_InlTreeIndex at `pc`, decodes that FUNCDATA_InlTree record,
    /// and follows each record's parentPc until the physical function is
    /// reached; the physical frame is always last. On Go 1.18+ the inline tree
    /// is addressed relative to gofunc, so without [`with_gofunc`] only the
    /// physical frame comes back. On Go 1.16/1.17 funcdata pointers are
    /// absolute and no gofunc is needed. Funcdata is read through the binary
    /// this table was parsed from; `_bin` is kept for API compatibility.
    ///
    /// Each frame carries the source line at its own PC, as a Go traceback
    /// prints it: the PC's line for the innermost frame and the call site for
    /// each frame outside it.
    ///
    /// [`with_gofunc`]: Self::with_gofunc
    pub fn lookup_inline(&self, _bin: &crate::gobin::GoBinary, pc: u64) -> Vec<InlineFrame> {
        let Some(leaf) = self.lookup(pc) else {
            return Vec::new();
        };
        let mut frames = Vec::new();
        // The physical frame's position is the outermost call site when the PC
        // is in inlined code, and the PC's own otherwise.
        let mut physical_pc = pc;
        if let Some(func) = self.func_entry_at(pc) {
            for (i, call) in self.inline_chain(&func, pc).into_iter().enumerate() {
                physical_pc = call.parent_pc;
                let name = if call.func_name.is_empty() {
                    format!("inlined@{i}")
                } else {
                    call.func_name
                };
                frames.push(InlineFrame {
                    name,
                    file: call.file,
                    line: call.line.or(call.start_line),
                    inlined: true,
                });
            }
        }
        let (file, line) = self.pc_position(physical_pc);
        frames.push(InlineFrame {
            name: leaf.name,
            file: file.or(leaf.file),
            line,
            inlined: false,
        });
        frames
    }

    fn resolve_file(&self, cu_offset: usize, file_idx: usize) -> Option<String> {
        if self.layout == Layout::Go12 {
            // No cutab: the pcfile value indexes the file table, whose first word
            // is its own length, so the linker numbers files from 1. Each entry is
            // the offset of a NUL-terminated name from the start of the table.
            let n = read_u32(self.data, self.filetab_off, self.little_endian).ok()? as usize;
            if file_idx == 0 || file_idx >= n {
                return None;
            }
            let entry = file_idx.checked_mul(4)?.checked_add(self.filetab_off)?;
            let name_off = read_u32(self.data, entry, self.little_endian).ok()?;
            return read_cstring(self.data, name_off as usize).ok();
        }
        // cu_offset and file_idx come from attacker-controlled pc-value tables,
        // so the cutab index arithmetic is checked: a crafted value resolves to
        // no file rather than overflowing (a panic with overflow checks on, or a
        // wrapped bad offset in a release build).
        let cutab_entry = cu_offset
            .checked_add(file_idx)?
            .checked_mul(4)?
            .checked_add(self.cu_off)?;
        if cutab_entry.checked_add(4)? > self.data.len() {
            return None;
        }
        let raw = read_u32(self.data, cutab_entry, self.little_endian).ok()?;
        if raw == u32::MAX {
            return None;
        }
        let abs = self.filetab_off.checked_add(raw as usize)?;
        read_cstring(self.data, abs).ok()
    }

    pub fn text_start(&self) -> u64 {
        self.text_start
    }

    pub fn ptrsize(&self) -> u8 {
        self.ptrsize
    }

    pub fn quantum(&self) -> u8 {
        self.quantum
    }

    /// Walks the function table and returns every recovered function.
    /// Entries with unreadable names are skipped rather than failing the whole parse -
    /// a stripped binary in the wild often has a few damaged or unusual entries
    /// near the end of the table, and returning 2840 of 2841 functions is more
    /// useful than returning none.
    pub fn functions(&self) -> Result<Vec<Function>> {
        let stride = self.functab_stride();
        const MAX_FUNCS: u64 = 5_000_000;

        // Derive the structural maximum from the bytes actually available,
        // before honoring the header's claimed nfunc. A hostile pclntab can
        // claim nfunc=2^60; we must not allocate based on that.
        let available_bytes = self.data.len().saturating_sub(self.functab_off);
        let max_possible = (available_bytes / stride).saturating_sub(1) as u64;

        let n = self.nfunc.min(MAX_FUNCS).min(max_possible) as usize;
        if (self.nfunc > MAX_FUNCS || self.nfunc > max_possible) && self.nfunc != 0 {
            // Honest about the truncation rather than silently parsing fewer
            // entries than the header claims.
            return Err(Error::BadPclntab {
                offset: 0,
                reason: format!(
                    "nfunc {} exceeds available functab capacity (max {} from byte range, cap {})",
                    self.nfunc, max_possible, MAX_FUNCS,
                ),
            });
        }

        // Required byte range for (n+1) entries: the trailing sentinel marks
        // the end of the last function, so we always read one extra.
        let table_bytes = n.saturating_add(1).saturating_mul(stride);
        if self.functab_off + table_bytes > self.data.len() {
            return Err(Error::BadPclntab {
                offset: 0,
                reason: format!("functab ({n} entries x {stride}) extends past pclntab end"),
            });
        }

        let mut out = Vec::with_capacity(n);
        for i in 0..n {
            let Some((address, func_start)) = self.functab_entry(i) else {
                continue;
            };
            match self.read_function(address, func_start) {
                Ok(f) => out.push(f),
                Err(_) => continue,
            }
        }

        Ok(out)
    }

    /// Walk the functab and yield a richer per-function record that includes
    /// the `_func` struct offset and the function's PC size. Callers that need
    /// to decode funcdata/pcdata structures want this richer view; callers
    /// that only want names and entry PCs should use [`functions`](Self::functions) instead.
    pub fn functions_with_offsets(&self) -> Result<Vec<FuncEntry>> {
        let stride = self.functab_stride();
        const MAX_FUNCS: u64 = 5_000_000;
        let available_bytes = self.data.len().saturating_sub(self.functab_off);
        let max_possible = (available_bytes / stride).saturating_sub(1) as u64;
        let n = self.nfunc.min(MAX_FUNCS).min(max_possible) as usize;
        if (self.nfunc > MAX_FUNCS || self.nfunc > max_possible) && self.nfunc != 0 {
            return Err(Error::BadPclntab {
                offset: 0,
                reason: format!(
                    "nfunc {} exceeds functab capacity (max {}, cap {})",
                    self.nfunc, max_possible, MAX_FUNCS,
                ),
            });
        }
        let table_bytes = n.saturating_add(1).saturating_mul(stride);
        if self.functab_off + table_bytes > self.data.len() {
            return Err(Error::BadPclntab {
                offset: 0,
                reason: format!("functab ({n} entries) extends past pclntab end"),
            });
        }
        let fb = self.fields_base();
        let mut out = Vec::with_capacity(n);
        for i in 0..n {
            let Some((address, func_start)) = self.functab_entry(i) else {
                continue;
            };
            // The next entry's PC is the end of this function, so its size needs
            // no further scan.
            let next_addr = self.functab_addr(i + 1).unwrap_or(u64::MAX);
            let size = next_addr.saturating_sub(address);
            if func_start + fb + 4 > self.data.len() {
                continue;
            }
            let name_off = match read_u32(self.data, func_start + fb, self.little_endian) {
                Ok(v) => v as usize,
                Err(_) => continue,
            };
            let name = self.read_name(name_off).unwrap_or_default();
            out.push(FuncEntry {
                address,
                name,
                func_off: func_start - self.funcoff_base,
                size,
            });
        }
        Ok(out)
    }

    fn read_function(&self, address: u64, func_start: usize) -> Result<Function> {
        let fb = self.fields_base();
        // func_start comes from a header-controlled funcoff, so the nameOff field
        // end can overflow usize; treat overflow as out of range, not a panic.
        let end = func_start.checked_add(fb).and_then(|x| x.checked_add(4));
        if end.is_none_or(|e| e > self.data.len()) {
            return Err(Error::ShortRead {
                wanted: fb + 4,
                offset: func_start,
                available: self.data.len().saturating_sub(func_start),
            });
        }

        let name_off = read_u32(self.data, func_start + fb, self.little_endian)? as usize;

        // The functab entry already carries the function's absolute address, so
        // there is no need to re-read the _func entry field.
        let name = self.read_name(name_off)?;

        let (file, start_line) = self.read_file_and_line(func_start).unwrap_or((None, None));

        Ok(Function {
            address,
            name,
            file,
            start_line,
        })
    }

    fn read_name(&self, off: usize) -> Result<String> {
        let abs = self.funcname_off + off;
        read_cstring(self.data, abs)
    }

    /// Best-effort file + line resolution. The _func struct fields we need:
    ///   func_start + 0  entryOff      u32
    ///   func_start + 4  nameOff       i32
    ///   func_start + 8  args          i32
    ///   func_start + 12 deferreturn   u32
    ///   func_start + 16 pcsp          u32  (offset into pctab)
    ///   func_start + 20 pcfile        u32  (offset into pctab)
    ///   func_start + 24 pcln          u32  (offset into pctab)
    ///   func_start + 28 npcdata       u32
    ///   func_start + 32 cuOffset      u32  (index base into cutab)
    ///   ...
    ///
    /// We read pcfile + pcln, decode the first pc-value table entry of each
    /// (that gives us the file index and line at function entry), then map
    /// file index through cutab -> filetab.
    fn read_file_and_line(&self, func_start: usize) -> Option<(Option<String>, Option<u32>)> {
        // The _func fields sit past the leading entry field (a u32 in 1.18+, a
        // uintptr before), so offset them from fields_base: pcfile at +16, pcln
        // at +20, cuOffset at +28. Go 1.2 to 1.15 have no cuOffset.
        let fb = self.fields_base();
        let fields_len = match self.layout {
            Layout::Go12 => 24,
            Layout::Pre118 | Layout::Modern => 32,
        };
        // Checked: a hostile funcoff can push func_start near usize::MAX.
        let end = func_start
            .checked_add(fb)
            .and_then(|x| x.checked_add(fields_len));
        if end.is_none_or(|e| e > self.data.len()) {
            return None;
        }

        let pcfile_off =
            read_u32(self.data, func_start + fb + 16, self.little_endian).ok()? as usize;
        let pcln_off = read_u32(self.data, func_start + fb + 20, self.little_endian).ok()? as usize;
        let cu_offset = match self.layout {
            Layout::Go12 => 0,
            Layout::Pre118 | Layout::Modern => {
                read_u32(self.data, func_start + fb + 28, self.little_endian).ok()? as usize
            }
        };

        let file_idx = first_pcvalue(&self.data[self.pctab_off..], pcfile_off)?;
        let line = first_pcvalue(&self.data[self.pctab_off..], pcln_off)?;

        let file = self.resolve_file(cu_offset, file_idx as usize);
        Some((file, if line > 0 { Some(line as u32) } else { None }))
    }
}

/// Decodes the first non-trivial value from a pc-value table. Used to recover
/// the function's entry-PC line and file index (the value at the first
/// instruction). For lookups at arbitrary PCs, use `Pclntab::pcvalue`.
fn first_pcvalue(table: &[u8], start: usize) -> Option<i64> {
    if start >= table.len() {
        return None;
    }
    let (uval, n) = read_varint(&table[start..])?;
    if uval == 0 {
        return None;
    }
    let delta = zig_zag(uval);
    let mut value: i64 = -1;
    value = value.wrapping_add(delta);
    let _ = n;
    Some(value)
}

fn zig_zag(u: u64) -> i64 {
    ((u >> 1) as i64) ^ -((u & 1) as i64)
}

fn read_varint(buf: &[u8]) -> Option<(u64, usize)> {
    // A varint encoding a u64 needs at most 10 bytes. Anything longer is
    // malformed input and we reject rather than overshift.
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
    let slice = &buf[off..off + 4];
    Ok(if little_endian {
        u32::from_le_bytes(slice.try_into().unwrap())
    } else {
        u32::from_be_bytes(slice.try_into().unwrap())
    })
}

fn read_u64(buf: &[u8], off: usize, little_endian: bool) -> Result<u64> {
    if off + 8 > buf.len() {
        return Err(Error::ShortRead {
            wanted: 8,
            offset: off,
            available: buf.len().saturating_sub(off),
        });
    }
    let slice = &buf[off..off + 8];
    Ok(if little_endian {
        u64::from_le_bytes(slice.try_into().unwrap())
    } else {
        u64::from_be_bytes(slice.try_into().unwrap())
    })
}

fn read_uintptr(buf: &[u8], off: usize, ptrsize: usize, little_endian: bool) -> Result<u64> {
    match ptrsize {
        4 => read_u32(buf, off, little_endian).map(|v| v as u64),
        8 => read_u64(buf, off, little_endian),
        _ => Err(Error::BadPclntab {
            offset: off,
            reason: format!("ptrsize {ptrsize} is neither 4 nor 8"),
        }),
    }
}

fn read_cstring(buf: &[u8], off: usize) -> Result<String> {
    if off >= buf.len() {
        return Err(Error::ShortRead {
            wanted: 1,
            offset: off,
            available: 0,
        });
    }
    let end = buf[off..]
        .iter()
        .position(|&b| b == 0)
        .map(|p| off + p)
        .unwrap_or(buf.len());
    std::str::from_utf8(&buf[off..end])
        .map(|s| s.to_string())
        .map_err(|_| Error::BadString { offset: off })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A GoBinary over `bytes` as one section mapped at 0x1000, read as the
    /// pclntab, for tests that build a table by hand.
    fn table_bin(bytes: Vec<u8>) -> GoBinary {
        use crate::gobin::{Arch, Container, Section, SectionKind};
        let n = bytes.len();
        GoBinary {
            bytes,
            container: Container::Elf,
            arch: Arch::X86_64,
            little_endian: true,
            ptr_size: 8,
            sections: vec![Section {
                name: ".text".to_string(),
                kind: SectionKind::Text,
                file_offset: 0,
                file_size: n,
                addr: 0x1000,
                vmsize: 0x100000,
            }],
            pclntab_offset: 0,
            pclntab_size: n,
            pclntab_addr: 0x1000,
            text_addr: 0x1000,
        }
    }

    #[test]
    fn every_magic_since_go_1_2_is_read() {
        for magic in [MAGIC_1_2, MAGIC_1_16, MAGIC_1_18, MAGIC_1_20, 0x1234_5678] {
            assert_eq!(unsupported_pre118_magic(magic), None, "{magic:#x}");
        }
    }

    #[test]
    fn parses_a_go_1_2_table() {
        // Two functions in one file, laid out as cmd/link wrote Go 1.2 to 1.15
        // tables: no offset header, a functab of (entry, funcoff) pointer
        // pairs and the end PC, the file table offset, and every other offset
        // relative to the start of the table.
        let mut b = vec![0u8; 200];
        let put64 =
            |b: &mut Vec<u8>, at: usize, v: u64| b[at..at + 8].copy_from_slice(&v.to_le_bytes());
        let put32 =
            |b: &mut Vec<u8>, at: usize, v: u32| b[at..at + 4].copy_from_slice(&v.to_le_bytes());
        b[0..4].copy_from_slice(&MAGIC_1_2.to_le_bytes());
        b[6] = 1;
        b[7] = 8;
        put64(&mut b, 8, 2);
        for (i, v) in [0x1000, 112, 0x1010, 160, 0x1020].into_iter().enumerate() {
            put64(&mut b, 16 + 8 * i, v);
        }
        put32(&mut b, 56, 64);
        // File table: its length (file 0 is never used), then name offsets.
        put32(&mut b, 64, 2);
        put32(&mut b, 68, 72);
        b[72..76].copy_from_slice(b"a.go");
        b[80..86].copy_from_slice(b"main.a");
        b[88..94].copy_from_slice(b"main.b");
        // pc-value tables over 0x10 bytes: file 1, line 10, line 20.
        b[96..98].copy_from_slice(&[4, 0x10]);
        b[100..102].copy_from_slice(&[22, 0x10]);
        b[104..106].copy_from_slice(&[42, 0x10]);
        // _func: entry, nameoff, args, frame, pcsp, pcfile, pcln, npcdata,
        // nfuncdata.
        for (at, entry, name, pcln) in [(112, 0x1000, 80, 100), (160, 0x1010, 88, 104)] {
            put64(&mut b, at, entry);
            put32(&mut b, at + 8, name);
            put32(&mut b, at + 24, 96);
            put32(&mut b, at + 28, pcln);
        }

        let bin = table_bin(b);
        let pcln = Pclntab::parse(&bin).expect("parse a Go 1.2 table");
        assert!(pcln.magic_is_official());
        let funcs = pcln.functions().expect("walk the functab");
        let got: Vec<(u64, &str, Option<&str>, Option<u32>)> = funcs
            .iter()
            .map(|f| (f.address, f.name.as_str(), f.file.as_deref(), f.start_line))
            .collect();
        assert_eq!(
            got,
            [
                (0x1000, "main.a", Some("a.go"), Some(10)),
                (0x1010, "main.b", Some("a.go"), Some(20)),
            ]
        );
        assert_eq!(pcln.lookup(0x101f).map(|f| f.name), Some("main.b".into()));
        assert_eq!(pcln.lookup(0x1020).map(|f| f.name), None, "past the end PC");
        assert_eq!(pcln.pc_position(0x1004), (Some("a.go".into()), Some(10)));
        let entry = pcln.func_entry_at(0x1010).expect("func entry");
        let fields = pcln.func_fields(&entry).expect("func fields");
        assert_eq!((fields.pcfile, fields.pcln, fields.cu_offset), (96, 104, 0));
        assert_eq!(
            pcln.funcdata(&entry, 0),
            None,
            "funcdata is not decoded here"
        );
    }

    #[test]
    fn varint_decodes_single_byte() {
        assert_eq!(read_varint(&[0x05]), Some((5, 1)));
        assert_eq!(read_varint(&[0x7f]), Some((127, 1)));
    }

    #[test]
    fn varint_decodes_multi_byte() {
        // 300 = 0b100101100 -> bytes 0xAC 0x02
        assert_eq!(read_varint(&[0xac, 0x02]), Some((300, 2)));
    }

    #[test]
    fn varint_unterminated_returns_none() {
        assert!(read_varint(&[0x80, 0x80, 0x80]).is_none());
    }

    #[test]
    fn zig_zag_round_trips() {
        assert_eq!(zig_zag(0), 0);
        assert_eq!(zig_zag(1), -1);
        assert_eq!(zig_zag(2), 1);
        assert_eq!(zig_zag(3), -2);
    }

    #[test]
    fn cstring_stops_at_nul() {
        let buf = b"hello\0world";
        assert_eq!(read_cstring(buf, 0).unwrap(), "hello");
        assert_eq!(read_cstring(buf, 6).unwrap(), "world");
    }

    #[test]
    fn u32_respects_endianness() {
        let buf = [0x01, 0x02, 0x03, 0x04];
        assert_eq!(read_u32(&buf, 0, true).unwrap(), 0x04030201);
        assert_eq!(read_u32(&buf, 0, false).unwrap(), 0x01020304);
    }

    #[test]
    fn resolve_file_rejects_overflowing_indices() {
        // A crafted pc-value table can feed resolve_file enormous cu_offset and
        // file_idx values; the cutab index arithmetic must resolve to no file
        // rather than overflow. Found by fuzzing the recovery stack.
        let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("testdata")
            .join("hello.linux-amd64.stripped");
        if !path.exists() {
            return;
        }
        let bin = GoBinary::open(&path).expect("open fixture");
        let pcln = Pclntab::parse(&bin).expect("parse pclntab");
        for (cu, idx) in [(usize::MAX, usize::MAX), (usize::MAX, 0), (0, usize::MAX)] {
            assert!(
                pcln.resolve_file(cu, idx).is_none(),
                "overflowing ({cu}, {idx}) must resolve to no file"
            );
        }
    }

    #[test]
    fn parses_go_1_17_functab() {
        // Go 1.16 and 1.17 use the pre-1.18 layout: magic 0xfffffffa, no textStart
        // in the header, pointer-sized functab entries with absolute PCs, and a
        // _func that leads with a uintptr entry. The fixture is hello.go built with
        // go1.17; the program's own functions must recover with their names and a
        // plausible absolute entry address.
        let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("testdata")
            .join("hello.go117.stripped");
        if !path.exists() {
            return;
        }
        let bin = GoBinary::open(&path).expect("open go1.17 fixture");
        let pcln = Pclntab::parse(&bin).expect("parse go1.17 pclntab");
        assert_eq!(pcln.magic(), MAGIC_1_16);
        let funcs = pcln.functions().expect("walk go1.17 functab");
        let names: Vec<&str> = funcs.iter().map(|f| f.name.as_str()).collect();
        for required in ["main.main", "main.greet", "main.parseFlags"] {
            assert!(
                names.contains(&required),
                "expected {required} among {} recovered functions",
                names.len()
            );
        }
        let main = funcs.iter().find(|f| f.name == "main.main").unwrap();
        assert!(
            main.address > 0x400000,
            "main.main entry {:#x} is not a plausible absolute PC",
            main.address
        );
    }

    #[test]
    fn parse_chain_never_panics_on_hostile_pclntab() {
        // Malware crafts pclntab fields to crash naive parsers. Feed a valid header
        // prefix for each layout (1.2, 1.16 and 1.18+) with hostile bodies plus
        // deterministic byte mutations through the whole walk. Every read is
        // bounds-checked, so the chain must return a Result, never panic.

        // A syntactically valid header prefix; the body is mutated below.
        let mut base = vec![0u8; 4096];
        base[6] = 1; // quantum
        base[7] = 8; // ptr size

        // Deterministic PRNG (SplitMix64) so the corpus is reproducible.
        let mut state: u64 = 0x9e37_79b9_7f4a_7c15;
        let mut rng = || {
            state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
            let mut z = state;
            z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
            z ^ (z >> 31)
        };

        let magics: [[u8; 4]; 4] = [
            [0xfa, 0xff, 0xff, 0xff], // 1.16/1.17
            [0xfb, 0xff, 0xff, 0xff], // 1.2-1.15
            [0xf0, 0xff, 0xff, 0xff], // 1.18/1.19
            [0xf1, 0xff, 0xff, 0xff], // 1.20+
        ];
        for magic in magics {
            for _ in 0..2000 {
                let mut b = base.clone();
                b[0..4].copy_from_slice(&magic);
                let muts = (rng() % 80) as usize;
                for _ in 0..muts {
                    let idx = (rng() as usize) % b.len();
                    b[idx] = (rng() & 0xff) as u8;
                }
                if rng() % 4 == 0 {
                    let cut = (rng() as usize) % b.len();
                    b.truncate(cut);
                }
                let bin = table_bin(b);
                let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    if let Ok(p) = Pclntab::parse(&bin) {
                        let _ = p.functions();
                        let _ = p.functions_with_offsets();
                        let _ = p.lookup(0x1234);
                        let _ = p.lookup(0xffff_ffff_ffff_ffff);
                        if let Some(e) = p.func_entry_at(0x1000) {
                            let _ = p.func_fields(&e);
                            let _ = p.line_table(&e);
                        }
                        let _ = p.pc_position(0x1000);
                    }
                }));
                assert!(res.is_ok(), "parse chain panicked on a hostile pclntab");
            }
        }
    }
}
