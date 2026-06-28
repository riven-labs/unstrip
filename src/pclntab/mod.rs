use serde::Serialize;

use crate::error::Error;
use crate::gobin::GoBinary;
use crate::Result;

pub const MAGIC_1_20: u32 = 0xfffffff1;
/// Go 1.18 and 1.19 pclntab magic. The layout is byte-compatible with
/// 1.20+ for the fields we care about, only the magic differs.
pub const MAGIC_1_18: u32 = 0xfffffff0;
/// Go 1.16 and 1.17 pclntab magic. The header has no textStart, the functab
/// entries are pointer-sized (an absolute entry PC and a funcoff), and the `_func`
/// struct leads with a uintptr entry. [`Layout::Pre118`] reads it.
pub const MAGIC_1_16: u32 = 0xfffffffa;
/// Go 1.2 to 1.15 pclntab magic. A different table shape again (a two-level
/// functab and no offset header) that this reader does not yet implement.
pub const MAGIC_1_2: u32 = 0xfffffffb;

/// The Go release family for a pclntab magic this reader does not implement.
/// Returns None for every layout we can read (1.16 through 1.20+ and a
/// garble-rewritten magic, which keeps the 1.18+ shape). Naming the version lets a
/// caller report "this is Go 1.2 to 1.15" instead of "not a Go binary".
pub fn unsupported_pre118_magic(magic: u32) -> Option<&'static str> {
    match magic {
        MAGIC_1_2 => Some("Go 1.2 to 1.15"),
        _ => None,
    }
}

/// Which pclntab table layout a binary uses. The header field positions, the
/// functab entry width, and the `_func` struct prefix all changed in Go 1.18.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Layout {
    /// Go 1.16 and 1.17 (magic [`MAGIC_1_16`]).
    Pre118,
    /// Go 1.18 and later, and garble-rewritten magics that keep the 1.18+ shape.
    Modern,
}

#[derive(Debug, Clone, Serialize)]
pub struct Function {
    pub address: u64,
    pub name: String,
    pub file: Option<String>,
    pub start_line: Option<u32>,
}

/// Cloning is cheap: every field is a slice reference or a small scalar. A
/// clone lets a decoded function carry its own call-resolution handle without
/// re-parsing, which is what keeps whole-program sweeps linear.
#[derive(Clone)]
pub struct Pclntab<'a> {
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
    funcdata_off: usize,

    /// Optional: gofunc base from moduledata. Required for inline-tree walking
    /// (the funcdata entries are offsets relative to gofunc). When None,
    /// inline-tree decoding falls back to returning the leaf frame only.
    gofunc: Option<u64>,
}

/// A richer per-function record with the raw `_func` struct offset and the
/// PC-range size, both of which are needed to decode funcdata structures
/// such as the inline tree.
#[derive(Debug, Clone)]
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
        // Go 1.2 to 1.15 used a different table shape (a two-level functab, no
        // offset header) that this reader does not implement; name the version
        // honestly rather than walk it with the wrong reader.
        if magic == MAGIC_1_2 {
            return Err(Error::UnsupportedPclntabVersion {
                magic,
                version: "Go 1.2 to 1.15",
            });
        }
        // Go 1.16/1.17 and Go 1.18+ differ in the header field positions, the
        // functab entry width, and the _func prefix. Pick the reader by magic. A
        // garble-rewritten magic keeps the 1.18+ shape, so it reads as Modern; the
        // structural checks below still reject a genuinely broken header.
        let layout = if magic == MAGIC_1_16 {
            Layout::Pre118
        } else {
            Layout::Modern
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

        // textStart in the header is the runtime-resolved VA. If the binary sets
        // it to zero (rare, but happens for some shared objects), fall back to the
        // .text section address from the container. Only meaningful for Modern;
        // Pre118 functab entries are absolute, so text_start stays 0 there.
        let text_start = if layout == Layout::Modern && text_start == 0 {
            bin.text_addr
        } else {
            text_start
        };

        Ok(Pclntab {
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
            funcdata_off,
            gofunc: None,
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
        self.magic == MAGIC_1_20 || self.magic == MAGIC_1_18 || self.magic == MAGIC_1_16
    }

    pub fn nfunc(&self) -> u64 {
        self.nfunc
    }

    /// Bytes per functab entry: a u32 pair in 1.18+, a pointer pair in 1.16/1.17.
    fn functab_stride(&self) -> usize {
        match self.layout {
            Layout::Modern => 8,
            Layout::Pre118 => 2 * self.ptrsize as usize,
        }
    }

    /// Entry PC (absolute VA) of functab index `i`. In 1.18+ the entry is a u32
    /// offset from textStart; in 1.16/1.17 it is an absolute uintptr.
    fn functab_addr(&self, i: usize) -> Option<u64> {
        let off = self.funcdata_off + i * self.functab_stride();
        match self.layout {
            Layout::Modern => {
                Some(self.text_start + read_u32(self.data, off, self.little_endian).ok()? as u64)
            }
            Layout::Pre118 => {
                read_uintptr(self.data, off, self.ptrsize as usize, self.little_endian).ok()
            }
        }
    }

    /// The (entry PC, `_func` struct offset within `data`) for functab index `i`.
    /// The funcoff is relative to the functab base in both layouts.
    fn functab_entry(&self, i: usize) -> Option<(u64, usize)> {
        let ps = self.ptrsize as usize;
        let off = self.funcdata_off + i * self.functab_stride();
        let func_off = match self.layout {
            Layout::Modern => read_u32(self.data, off + 4, self.little_endian).ok()? as usize,
            Layout::Pre118 => {
                read_uintptr(self.data, off + ps, ps, self.little_endian).ok()? as usize
            }
        };
        Some((self.functab_addr(i)?, self.funcdata_off + func_off))
    }

    /// Offset from a `_func` struct start to its `nameOff` field, i.e. the width of
    /// the leading entry field: a u32 entryOff in 1.18+, a uintptr entry in
    /// 1.16/1.17. Every later `_func` field is at a fixed offset past this.
    fn fields_base(&self) -> usize {
        match self.layout {
            Layout::Modern => 4,
            Layout::Pre118 => self.ptrsize as usize,
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

    /// Offset of the functab inside `data()`. Each entry is two u32s:
    /// `(text_off, func_off)`. The final sentinel entry has `text_off`
    /// equal to the text size, terminating the array.
    pub fn funcdata_off(&self) -> usize {
        self.funcdata_off
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

    /// `gofunc` base from moduledata, if it was supplied via [`with_gofunc`].
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
    /// Requires `with_gofunc` to have been called; otherwise returns the
    /// single physical frame from `lookup`. Walks the FUNCDATA_InlTree array
    /// for the containing function and follows parentPc links until the
    /// physical function is reached.
    pub fn lookup_inline(&self, bin: &crate::gobin::GoBinary, pc: u64) -> Vec<InlineFrame> {
        let mut frames = Vec::new();
        let Some(leaf) = self.lookup(pc) else {
            return frames;
        };
        let physical_frame = InlineFrame {
            name: leaf.name.clone(),
            file: leaf.file.clone(),
            line: leaf.start_line,
            inlined: false,
        };

        // The inline-tree walk below reads the functab and _func at their 1.18+
        // offsets. On 1.16/1.17 those positions differ, so return the physical
        // frame rather than decode the tree with the wrong layout.
        if self.layout != Layout::Modern {
            frames.push(physical_frame);
            return frames;
        }

        let Some(gofunc) = self.gofunc else {
            frames.push(physical_frame);
            return frames;
        };

        // Re-locate the function entry to access its _func struct.
        let n = self.nfunc as usize;
        let pc_off = match pc.checked_sub(self.text_start) {
            Some(v) => v as u32,
            None => {
                frames.push(physical_frame);
                return frames;
            }
        };
        let read_text_off =
            |i: usize| read_u32(self.data, self.funcdata_off + i * 8, self.little_endian).ok();
        let mut lo = 0;
        let mut hi = n;
        while lo < hi {
            let mid = (lo + hi) / 2;
            match read_text_off(mid) {
                Some(o) if o <= pc_off => lo = mid + 1,
                _ => hi = mid,
            }
        }
        if lo == 0 {
            frames.push(physical_frame);
            return frames;
        }
        let idx = lo - 1;
        let Some(func_off) = read_u32(
            self.data,
            self.funcdata_off + idx * 8 + 4,
            self.little_endian,
        )
        .ok() else {
            frames.push(physical_frame);
            return frames;
        };
        let func_start = self.funcdata_off + func_off as usize;

        // _func header layout (Go 1.20+, 40 bytes):
        //   off=0  entryOff   u32
        //   off=4  nameOff    i32
        //   off=8  args       i32
        //   off=12 deferreturn u32
        //   off=16 pcsp       u32
        //   off=20 pcfile     u32
        //   off=24 pcln       u32
        //   off=28 npcdata    u32
        //   off=32 cuOffset   u32
        //   off=36 startLine  i32  (also funcID+flag+pad+nfuncdata packed at off=40)
        // Then [npcdata]u32 then [nfuncdata]u32.
        if func_start + 44 > self.data.len() {
            frames.push(physical_frame);
            return frames;
        }
        let npcdata = match read_u32(self.data, func_start + 28, self.little_endian) {
            Ok(v) => v as usize,
            Err(_) => {
                frames.push(physical_frame);
                return frames;
            }
        };
        let nfuncdata = self.data[func_start + 43] as usize;

        // The variable arrays sit right after the 44-byte fixed header.
        let pcdata_off = func_start + 44;
        let funcdata_arr_off = pcdata_off + npcdata * 4;

        const PCDATA_INLTREE_INDEX: usize = 2;
        const FUNCDATA_INLTREE: usize = 3;
        if nfuncdata <= FUNCDATA_INLTREE || npcdata <= PCDATA_INLTREE_INDEX {
            frames.push(physical_frame);
            return frames;
        }
        let inltree_funcdata = match read_u32(
            self.data,
            funcdata_arr_off + FUNCDATA_INLTREE * 4,
            self.little_endian,
        ) {
            Ok(v) => v,
            Err(_) => {
                frames.push(physical_frame);
                return frames;
            }
        };
        if inltree_funcdata == u32::MAX {
            frames.push(physical_frame);
            return frames;
        }
        let inltree_addr = gofunc.wrapping_add(inltree_funcdata as u64);

        // PCDATA_InlTreeIndex: offset into pctab. The pc-value table is
        // decoded with the current PC offset (relative to function entry) to
        // produce the current inltree index, or -1 for "not inlined here".
        let pcdata_inltree_off = match read_u32(
            self.data,
            pcdata_off + PCDATA_INLTREE_INDEX * 4,
            self.little_endian,
        ) {
            Ok(v) => v as usize,
            Err(_) => {
                frames.push(physical_frame);
                return frames;
            }
        };
        let func_entry_pc = self.text_start + read_text_off(idx).unwrap_or(0) as u64;
        let target_off = (pc - func_entry_pc) as u32;
        let mut current_idx =
            pcvalue_at(&self.data[self.pctab_off..], pcdata_inltree_off, target_off);

        // Walk: each inlinedCall is 16 bytes (funcID+pad+nameOff+parentPc+startLine).
        // Cap the per-PC inline depth at 32. Real call chains are rarely deeper
        // than 5; 32 leaves room for pathological inlining without trusting a
        // hostile inltree index to bound the loop on its own.
        const MAX_INLINE_DEPTH: usize = 32;
        // Cap the absolute inltree index. A real inline tree fits in a handful
        // of KB; 65536 entries (1 MiB) is a very generous structural ceiling.
        const MAX_INLTREE_INDEX: i64 = 65_536;

        let mut current_pc_off = target_off;
        let mut iter_guard = 0;
        while current_idx >= 0 && iter_guard < MAX_INLINE_DEPTH {
            if current_idx > MAX_INLTREE_INDEX {
                break;
            }
            iter_guard += 1;
            let entry_addr = inltree_addr + (current_idx as u64) * 16;
            let Some(entry) = bin.read_at_addr(entry_addr, 16) else {
                break;
            };
            let name_off = i32::from_le_bytes(entry[4..8].try_into().unwrap()) as usize;
            let parent_pc = i32::from_le_bytes(entry[8..12].try_into().unwrap());
            let start_line = i32::from_le_bytes(entry[12..16].try_into().unwrap());

            let name = self
                .read_name(name_off)
                .unwrap_or_else(|_| format!("inlined@{current_idx}"));
            let file_and_line = self.file_and_line_for_pc(func_start, current_pc_off);
            frames.push(InlineFrame {
                name,
                file: file_and_line.0,
                line: file_and_line.1.or(if start_line > 0 {
                    Some(start_line as u32)
                } else {
                    None
                }),
                inlined: true,
            });

            // Advance to the parent: parentPc is an offset from function entry
            // that points at the call site whose source position is recorded.
            current_pc_off = parent_pc as u32;
            current_idx = pcvalue_at(
                &self.data[self.pctab_off..],
                pcdata_inltree_off,
                current_pc_off,
            );
        }

        frames.push(physical_frame);
        frames
    }

    /// Decode (file, line) at a specific PC offset within a function. Uses
    /// the function's pcfile and pcln pc-value tables, advanced to the
    /// target offset rather than just the first entry.
    fn file_and_line_for_pc(
        &self,
        func_start: usize,
        target_off: u32,
    ) -> (Option<String>, Option<u32>) {
        let Ok(pcfile_off) = read_u32(self.data, func_start + 20, self.little_endian) else {
            return (None, None);
        };
        let Ok(pcln_off) = read_u32(self.data, func_start + 24, self.little_endian) else {
            return (None, None);
        };
        let Ok(cu_offset) = read_u32(self.data, func_start + 32, self.little_endian) else {
            return (None, None);
        };

        let file_idx = pcvalue_at(
            &self.data[self.pctab_off..],
            pcfile_off as usize,
            target_off,
        );
        let line = pcvalue_at(&self.data[self.pctab_off..], pcln_off as usize, target_off);

        let file = if file_idx >= 0 {
            self.resolve_file(cu_offset as usize, file_idx as usize)
        } else {
            None
        };
        let line = if line > 0 { Some(line as u32) } else { None };
        (file, line)
    }

    fn resolve_file(&self, cu_offset: usize, file_idx: usize) -> Option<String> {
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
        let available_bytes = self.data.len().saturating_sub(self.funcdata_off);
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
        if self.funcdata_off + table_bytes > self.data.len() {
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
    /// that only want names and entry PCs should use [`functions`] instead.
    pub fn functions_with_offsets(&self) -> Result<Vec<FuncEntry>> {
        let stride = self.functab_stride();
        const MAX_FUNCS: u64 = 5_000_000;
        let available_bytes = self.data.len().saturating_sub(self.funcdata_off);
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
        if self.funcdata_off + table_bytes > self.data.len() {
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
                func_off: func_start - self.funcdata_off,
                size,
            });
        }
        Ok(out)
    }

    fn read_function(&self, address: u64, func_start: usize) -> Result<Function> {
        let fb = self.fields_base();
        if func_start + fb + 4 > self.data.len() {
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
        // uintptr in 1.16/1.17), so offset them from fields_base: pcfile at +16,
        // pcln at +20, cuOffset at +28.
        let fb = self.fields_base();
        if func_start + fb + 32 > self.data.len() {
            return None;
        }

        let pcfile_off = read_u32(self.data, func_start + fb + 16, self.little_endian).ok()? as usize;
        let pcln_off = read_u32(self.data, func_start + fb + 20, self.little_endian).ok()? as usize;
        let cu_offset = read_u32(self.data, func_start + fb + 28, self.little_endian).ok()? as usize;

        let file_idx = first_pcvalue(&self.data[self.pctab_off..], pcfile_off)?;
        let line = first_pcvalue(&self.data[self.pctab_off..], pcln_off)?;

        let file = self.resolve_file(cu_offset, file_idx as usize);
        Some((file, if line > 0 { Some(line as u32) } else { None }))
    }
}

/// Walk a pc-value table until `target_off` falls inside the current run.
/// Returns the value covering that offset, or -1 if exhausted / not present.
///
/// Format per `src/runtime/symtab.go`: stream of (zig-zag value delta varint,
/// pc delta varint x quantum), terminated by a zero value-delta varint.
/// Starting value is -1; each record advances both `value` (by zig-zagged
/// delta) and `pc` (by pc_delta * quantum). We return `value` as soon as
/// `target_off < pc`, meaning the current run covers the target.
fn pcvalue_at(table: &[u8], start: usize, target_off: u32) -> i64 {
    if start >= table.len() {
        return -1;
    }
    let mut value: i64 = -1;
    let mut pc: u32 = 0;
    let mut pos = start;
    // Quantum is the PC advance multiplier, 1 on amd64/arm64. We assume 1 here;
    // big-endian / non-1 quantum callers should multiply pc deltas.
    let quantum: u32 = 1;
    let mut iter_guard = 0;
    while pos < table.len() && iter_guard < 1_000_000 {
        iter_guard += 1;
        let (uval, n) = match read_varint(&table[pos..]) {
            Some(v) => v,
            None => return -1,
        };
        if uval == 0 && pc != 0 {
            return -1;
        }
        pos += n;
        let delta_val = zig_zag(uval);
        value = value.wrapping_add(delta_val);
        let (pc_delta, n2) = match read_varint(&table[pos..]) {
            Some(v) => v,
            None => return -1,
        };
        pos += n2;
        pc = pc.wrapping_add((pc_delta as u32) * quantum);
        if target_off < pc {
            return value;
        }
    }
    -1
}

/// Decodes the first non-trivial value from a pc-value table. Used to recover
/// the function's entry-PC line and file index (the value at the first
/// instruction). For lookups at arbitrary PCs, use `pcvalue_at`.
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

    #[test]
    fn only_go_1_2_to_1_15_is_an_unsupported_layout() {
        // Go 1.2 to 1.15 is the one layout this reader still does not implement, so
        // it is named and refused.
        assert_eq!(unsupported_pre118_magic(MAGIC_1_2), Some("Go 1.2 to 1.15"));
        // Every layout we read passes through: Go 1.16/1.17, Go 1.18+, and an
        // unknown (garble-rewritten) magic that keeps the 1.18+ shape.
        assert_eq!(unsupported_pre118_magic(MAGIC_1_16), None);
        assert_eq!(unsupported_pre118_magic(MAGIC_1_18), None);
        assert_eq!(unsupported_pre118_magic(MAGIC_1_20), None);
        assert_eq!(unsupported_pre118_magic(0x1234_5678), None);
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
}
