use serde::Serialize;

use crate::error::Error;
use crate::gobin::GoBinary;
use crate::Result;

pub const MAGIC_1_20: u32 = 0xfffffff1;
/// Go 1.18 and 1.19 pclntab magic. The layout is byte-compatible with
/// 1.20+ for the fields we care about, only the magic differs.
pub const MAGIC_1_18: u32 = 0xfffffff0;

#[derive(Debug, Clone, Serialize)]
pub struct Function {
    pub address: u64,
    pub name: String,
    pub file: Option<String>,
    pub start_line: Option<u32>,
}

pub struct Pclntab<'a> {
    data: &'a [u8],
    little_endian: bool,
    magic: u32,
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
        // Garble and similar obfuscators rewrite the magic to defeat naive
        // parsers. The rest of the header layout is unchanged, so we accept
        // any magic when the structural fields (zero pad, valid quantum,
        // valid ptrsize) match. The caller can read the magic to detect
        // tampering. We still reject obviously broken values via the
        // structural check below.
        let magic_unexpected = magic != MAGIC_1_20;
        let _ = magic_unexpected;

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
        let _nfiles = read_uptr(8 + ps)?;
        let text_start = read_uptr(8 + 2 * ps)?;
        let funcname_off = read_uptr(8 + 3 * ps)? as usize;
        let cu_off = read_uptr(8 + 4 * ps)? as usize;
        let filetab_off = read_uptr(8 + 5 * ps)? as usize;
        let pctab_off = read_uptr(8 + 6 * ps)? as usize;
        let funcdata_off = read_uptr(8 + 7 * ps)? as usize;

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

        // textStart in the header is the runtime-resolved VA. If the binary
        // sets it to zero (rare, but happens for some shared objects), fall
        // back to the .text section address we discovered in the container.
        let text_start = if text_start == 0 {
            bin.text_addr
        } else {
            text_start
        };

        Ok(Pclntab {
            data,
            little_endian,
            magic,
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
        self.magic == MAGIC_1_20 || self.magic == MAGIC_1_18
    }

    pub fn nfunc(&self) -> u64 {
        self.nfunc
    }

    /// Resolve a single PC to its containing function. Uses binary search on
    /// the functab, `O(log n)` per query, suitable for use inside debugger
    /// scripts and crash-dump tooling.
    pub fn lookup(&self, pc: u64) -> Option<Function> {
        let n = self.nfunc as usize;
        let entry_size = 8usize;
        if pc < self.text_start {
            return None;
        }
        let pc_off = (pc - self.text_start) as u32;

        // Binary search: each functab entry's textOffset marks the start PC
        // of that function. The function spans [text_off[i], text_off[i+1]).
        let read_off = |i: usize| -> Option<u32> {
            let entry = self.funcdata_off + i * entry_size;
            read_u32(self.data, entry, self.little_endian).ok()
        };

        let mut lo = 0usize;
        let mut hi = n;
        while lo < hi {
            let mid = (lo + hi) / 2;
            let mid_off = read_off(mid)?;
            if mid_off <= pc_off {
                lo = mid + 1;
            } else {
                hi = mid;
            }
        }
        if lo == 0 {
            return None;
        }
        let idx = lo - 1;
        let text_off = read_off(idx)?;

        // Verify pc is still within this function (before the next entry's start).
        let next_off = read_off(idx + 1).unwrap_or(u32::MAX);
        if pc_off >= next_off {
            return None;
        }

        let entry = self.funcdata_off + idx * entry_size;
        let func_off = read_u32(self.data, entry + 4, self.little_endian).ok()? as usize;
        self.read_function(text_off, func_off).ok()
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
        let cutab_entry = self.cu_off + (cu_offset + file_idx) * 4;
        if cutab_entry + 4 > self.data.len() {
            return None;
        }
        let raw = read_u32(self.data, cutab_entry, self.little_endian).ok()?;
        if raw == u32::MAX {
            return None;
        }
        let abs = self.filetab_off + raw as usize;
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
        // Functab entries are (uint32 textOffset, uint32 funcOffset) in 1.20+.
        // Located inside the funcdata region.
        const ENTRY_SIZE: usize = 8;
        const MAX_FUNCS: u64 = 5_000_000;

        // Derive the structural maximum from the bytes actually available,
        // before honoring the header's claimed nfunc. A hostile pclntab can
        // claim nfunc=2^60; we must not allocate based on that.
        let available_bytes = self.data.len().saturating_sub(self.funcdata_off);
        let max_possible = (available_bytes / ENTRY_SIZE).saturating_sub(1) as u64;

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
        let table_bytes = n.saturating_add(1).saturating_mul(ENTRY_SIZE);
        if self.funcdata_off + table_bytes > self.data.len() {
            return Err(Error::BadPclntab {
                offset: 0,
                reason: format!("functab ({n} entries x {ENTRY_SIZE}) extends past pclntab end"),
            });
        }

        let mut out = Vec::with_capacity(n);
        let entry_size = ENTRY_SIZE;

        for i in 0..n {
            let entry = self.funcdata_off + i * entry_size;
            let text_off = read_u32(self.data, entry, self.little_endian)?;
            let func_off = read_u32(self.data, entry + 4, self.little_endian)? as usize;

            match self.read_function(text_off, func_off) {
                Ok(f) => out.push(f),
                Err(_) => continue,
            }
        }

        Ok(out)
    }

    fn read_function(&self, text_off: u32, func_off: usize) -> Result<Function> {
        let func_start = self.funcdata_off + func_off;
        if func_start + 8 > self.data.len() {
            return Err(Error::ShortRead {
                wanted: 8,
                offset: func_start,
                available: self.data.len().saturating_sub(func_start),
            });
        }

        let name_off = read_u32(self.data, func_start + 4, self.little_endian)? as usize;

        // The functab's text_off and the _func struct's entryOff field hold
        // the same value in Go 1.20+. Use the functab one, it's already in
        // hand and skips a redundant 4-byte read per function.
        let address = self.text_start + text_off as u64;
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
        if func_start + 36 > self.data.len() {
            return None;
        }

        let pcfile_off = read_u32(self.data, func_start + 20, self.little_endian).ok()? as usize;
        let pcln_off = read_u32(self.data, func_start + 24, self.little_endian).ok()? as usize;
        let cu_offset = read_u32(self.data, func_start + 32, self.little_endian).ok()? as usize;

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
}
