use serde::Serialize;

use crate::error::Error;
use crate::gobin::{GoBinary, SectionKind};
use crate::Result;

/// A subset of `runtime.moduledata` recovered from a stripped binary.
///
/// We don't carry every field, only the ones that anchor further analysis.
/// The full struct has 50+ fields; what makes the difference for an RE tool
/// is types, typelinks, itablinks, and the text-region bounds. Adding more
/// fields is cheap once the anchor is known.
///
/// Field layout reference: `src/runtime/symtab.go` in the Go source tree.
/// We target the Go 1.20-1.25 layout. Field order has been stable across that
/// range; if it drifts, only the offset table here needs updating.
#[derive(Debug, Clone, Serialize)]
pub struct ModuleData {
    /// File offset where this moduledata begins.
    pub file_offset: usize,
    /// Runtime VA where this moduledata begins (= pcHeader pointer of next module's prev, but for the anchor it's just the location).
    pub addr: u64,

    /// pcHeader pointer, always equals `pclntab_addr` for a valid moduledata.
    pub pc_header_addr: u64,

    /// Slice (ptr, len, cap) of funcnametab.
    pub funcnametab: SliceHeader,
    pub cutab: SliceHeader,
    pub filetab: SliceHeader,
    pub pctab: SliceHeader,
    pub pclntable: SliceHeader,
    pub ftab: SliceHeader,

    pub findfunctab: u64,
    pub minpc: u64,
    pub maxpc: u64,

    pub text: u64,
    pub etext: u64,
    pub noptrdata: u64,
    pub enoptrdata: u64,
    pub data: u64,
    pub edata: u64,
    pub bss: u64,
    pub ebss: u64,
    pub noptrbss: u64,
    pub enoptrbss: u64,

    /// Coverage counters: present in Go 1.20+.
    pub covctrs: u64,
    pub ecovctrs: u64,

    pub end: u64,
    pub gcdata: u64,
    pub gcbss: u64,

    /// Types region. Every Go type's `_type` header lives in [types, etypes).
    pub types: u64,
    pub etypes: u64,

    pub rodata: u64,
    pub gofunc: u64,

    /// Slices of further metadata.
    pub textsectmap: SliceHeader,
    /// `typelinks` is a `[]int32` of offsets relative to `types`.
    pub typelinks: SliceHeader,
    /// `itablinks` is a `[]*itab` (one pointer per linked interface impl).
    pub itablinks: SliceHeader,
}

#[derive(Debug, Clone, Copy, Serialize)]
pub struct SliceHeader {
    pub data: u64,
    pub len: u64,
    pub cap: u64,
}

/// Which Go pclntab/moduledata layout to parse. They differ in a few
/// added/removed uintptr fields across minor versions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Layout {
    /// Go 1.18 and 1.19, no `covctrs`/`ecovctrs` fields between `enoptrbss`
    /// and `end`.
    V118,
    /// Go 1.20 through 1.25, adds the two coverage fields.
    V120,
    /// Go 1.26, adds an `epclntab` pointer after `gofunc` (before
    /// `textsectmap`). Shares the pclntab magic with V120, so the two are told
    /// apart by parsing both and keeping whichever yields valid typelinks.
    V126,
    /// Go 1.16 and 1.17 (pclntab magic 0xfffffffa): no `covctrs` (added in 1.20)
    /// and no `rodata`/`gofunc` (added in 1.18), so the offset table after
    /// `etypes` sits two pointers earlier than every later layout.
    Pre118,
}

impl ModuleData {
    /// Locate and parse `runtime.firstmoduledata` by scanning the data
    /// sections for a pointer that matches the pclntab's runtime address -
    /// that pointer is the first field of moduledata (`pcHeader *pcHeader`).
    ///
    /// We confirm a candidate by checking that the slice header three fields
    /// in (pclntable) has `data == pc_header_addr` and a sensible length. That
    /// alignment of two pclntab references with a slice-header-shaped layout
    /// between them is what distinguishes the real moduledata from random
    /// pointer matches in the data segment.
    ///
    /// Layout is chosen from the pclntab magic: 0xfffffff0 = V118,
    /// 0xfffffff1 = V120. Unknown magics default to V120.
    pub fn locate(bin: &GoBinary) -> Result<Self> {
        let ps = bin.pointer_size();
        if !matches!(ps, 4 | 8) {
            return Err(Error::BadPclntab {
                offset: 0,
                reason: format!("unsupported pointer size {ps}"),
            });
        }
        let target = bin.pclntab_addr;
        if target == 0 {
            return Err(Error::ModuleData(
                "pclntab runtime address is zero; section table may be stripped".into(),
            ));
        }

        let target_bytes = match (ps, bin.little_endian) {
            (8, true) => target.to_le_bytes().to_vec(),
            (8, false) => target.to_be_bytes().to_vec(),
            (_, true) => (target as u32).to_le_bytes().to_vec(),
            (_, false) => (target as u32).to_be_bytes().to_vec(),
        };

        let scan_kinds = [
            SectionKind::NoPtrData,
            SectionKind::Data,
            SectionKind::ReadOnlyData,
        ];

        // Each candidate layout is tried in turn; try_parse validates the
        // version-drifting tail (typelinks/itablinks) and rejects the wrong
        // one, so the layout that yields a sound moduledata wins.
        for &layout in layouts_for(bin) {
            for kind in scan_kinds {
                for section in bin.sections.iter().filter(|s| s.kind == kind) {
                    if let Some(md) = scan_section(bin, section, &target_bytes, ps, layout) {
                        return Ok(md);
                    }
                }
            }
        }

        Err(Error::ModuleData(
            "no moduledata candidate found in data sections".into(),
        ))
    }

    /// Locate every moduledata in the binary by walking the
    /// `runtime.firstmoduledata` chain. Each `moduledata` ends with a
    /// `next *moduledata` pointer; the chain terminates when `next` is
    /// zero. The order of fields between `itablinks` (where the
    /// per-version parse stops) and `next` drifts across Go releases,
    /// so we recognize `next` structurally rather than parsing the
    /// intervening tail: scan the bytes after the parsed prefix for an
    /// 8-byte value that points at another valid moduledata (i.e. its
    /// first field is a pcHeader pointer whose target begins with the
    /// pclntab magic). This handles Go 1.18 through 1.26 without a
    /// version-specific tail-field table.
    ///
    /// Most Go binaries are single-module so the returned vector almost
    /// always has length 1. Plugin binaries (`-buildmode=plugin`) and
    /// shared libraries (`-buildmode=shared`) chain additional
    /// moduledatas off the anchor; this is the path that surfaces them.
    pub fn locate_all(bin: &GoBinary) -> Result<Vec<Self>> {
        let mut out = Vec::new();
        let first = Self::locate(bin)?;

        // Scan window: 1024 bytes after the parsed prefix is generous
        // for every Go release we target. The tail today is ~200 bytes;
        // 1024 accommodates future additions.
        const WINDOW: usize = 1024;

        let mut visited = std::collections::HashSet::new();
        visited.insert(first.file_offset);
        out.push(first);

        let mut idx = 0;
        while idx < out.len() {
            let md = out[idx].clone();
            idx += 1;
            let ps = bin.pointer_size();
            let scan_start = md.file_offset + ps; // skip past pcHeader pointer
            let scan_end = (scan_start + WINDOW).min(bin.bytes.len());
            if scan_start >= bin.bytes.len() {
                continue;
            }
            let buf = &bin.bytes[scan_start..scan_end];
            // Walk pointer-aligned candidates. The first one that resolves
            // to a valid moduledata IS the next pointer; subsequent
            // pointer-shaped values further into the tail can also point
            // at moduledatas (modulehashes carry pointers too), so we
            // accept only the first hit per scan.
            for off in (0..buf.len()).step_by(ps) {
                let Some(cand) = read_ptr(buf, off, ps, bin.little_endian) else {
                    break;
                };
                if cand == 0 {
                    continue;
                }
                // Resolve cand to a file offset. If it lands in a mapped
                // section, check whether the bytes there look like a
                // moduledata (first field is a pcHeader pointer whose
                // bytes start with the pclntab magic).
                if let Some(file_off) = vaddr_to_file_offset(bin, cand) {
                    if visited.contains(&file_off) {
                        continue;
                    }
                    if !looks_like_moduledata(bin, file_off) {
                        continue;
                    }
                    if let Some(next_md) = layouts_for(bin)
                        .iter()
                        .find_map(|&layout| try_parse(bin, file_off, ps, layout).ok())
                    {
                        visited.insert(file_off);
                        out.push(next_md);
                        break; // only one next per scan
                    }
                }
            }
        }

        Ok(out)
    }
}

/// Read a `ps`-byte pointer at `off` in the binary's endianness.
fn read_ptr(bytes: &[u8], off: usize, ps: usize, le: bool) -> Option<u64> {
    let b = bytes.get(off..off + ps)?;
    Some(match (ps, le) {
        (8, true) => u64::from_le_bytes(b.try_into().ok()?),
        (8, false) => u64::from_be_bytes(b.try_into().ok()?),
        (_, true) => u32::from_le_bytes(b.try_into().ok()?) as u64,
        (_, false) => u32::from_be_bytes(b.try_into().ok()?) as u64,
    })
}

/// Read a u32 at `off` in the binary's endianness.
fn read_u32_e(bytes: &[u8], off: usize, le: bool) -> Option<u32> {
    let b: [u8; 4] = bytes.get(off..off + 4)?.try_into().ok()?;
    Some(if le {
        u32::from_le_bytes(b)
    } else {
        u32::from_be_bytes(b)
    })
}

/// Translate a runtime VA to a file offset. Returns None when the VA
/// does not fall inside any mapped section.
fn vaddr_to_file_offset(bin: &GoBinary, vaddr: u64) -> Option<usize> {
    for s in &bin.sections {
        // saturating/checked: a crafted section addr+vmsize or vaddr-relative
        // offset must not overflow into a false match or a panic.
        if vaddr >= s.addr && vaddr < s.addr.saturating_add(s.vmsize) {
            if let Some(off) = ((vaddr - s.addr) as usize).checked_add(s.file_offset) {
                if off < bin.bytes.len() {
                    return Some(off);
                }
            }
        }
    }
    None
}

/// Cheap structural check: a moduledata begins with a `pcHeader *pcHeader`
/// field. The target of that pointer should be 4-byte-aligned and start
/// with a pclntab magic (0xfffffff0 or 0xfffffff1).
fn looks_like_moduledata(bin: &GoBinary, file_off: usize) -> bool {
    let Some(pc_header_addr) =
        read_ptr(&bin.bytes, file_off, bin.pointer_size(), bin.little_endian)
    else {
        return false;
    };
    if pc_header_addr == 0 {
        return false;
    }
    let Some(pc_off) = vaddr_to_file_offset(bin, pc_header_addr) else {
        return false;
    };
    matches!(
        read_u32_e(&bin.bytes, pc_off, bin.little_endian),
        Some(0xfffffff0) | Some(0xfffffff1)
    )
}

/// Candidate moduledata layouts to try, in order, chosen from the pclntab
/// magic. Go 1.18/1.19 use 0xfffffff0; 1.20 through 1.26 share 0xfffffff1 but
/// drift in the tail (1.26 inserted `epclntab`), so both are offered and
/// try_parse keeps whichever validates. Obfuscators rewrite the magic to a
/// random value, which lands in the second arm and still gets the 1.20/1.26
/// pair.
fn layouts_for(bin: &GoBinary) -> &'static [Layout] {
    match read_u32_e(bin.pclntab_slice(), 0, bin.little_endian) {
        Some(0xfffffff0) => &[Layout::V118],
        Some(0xfffffffa) => &[Layout::Pre118],
        _ => &[Layout::V120, Layout::V126],
    }
}

fn scan_section(
    bin: &GoBinary,
    section: &crate::gobin::Section,
    target_bytes: &[u8],
    ps: usize,
    layout: Layout,
) -> Option<ModuleData> {
    let start = section.file_offset;
    // A crafted section header can carry a file_offset + file_size that overflows
    // usize; that wraps end small and the slice below panics. Bail instead.
    let end = start.checked_add(section.file_size)?;
    if end > bin.bytes.len() {
        return None;
    }
    let buf = &bin.bytes[start..end];
    let stride = ps;

    let mut pos = 0usize;
    while pos + target_bytes.len() <= buf.len() {
        if buf[pos..pos + target_bytes.len()] == *target_bytes {
            let file_off = start + pos;
            match try_parse(bin, file_off, ps, layout) {
                Ok(md) => return Some(md),
                Err(e) => {
                    if std::env::var("UNSTRIP_DEBUG").is_ok() {
                        eprintln!("  candidate at file 0x{file_off:x} rejected: {e}");
                    }
                }
            }
        }
        pos += stride;
    }

    // Fallback byte scan in case the moduledata wasn't pointer-aligned
    // (rare but possible on packed binaries).
    let mut pos = 0usize;
    while pos + target_bytes.len() <= buf.len() {
        if buf[pos..pos + target_bytes.len()] == *target_bytes && pos % stride != 0 {
            let file_off = start + pos;
            if let Ok(md) = try_parse(bin, file_off, ps, layout) {
                return Some(md);
            }
        }
        pos += 1;
    }

    None
}

fn try_parse(bin: &GoBinary, file_off: usize, ps: usize, layout: Layout) -> Result<ModuleData> {
    let bytes = &bin.bytes;
    let mut r = Reader::new(bytes, file_off, ps, bin.little_endian);

    let pc_header_addr = r.uptr()?;
    if pc_header_addr != bin.pclntab_addr {
        return Err(Error::ModuleData(format!(
            "pcHeader pointer 0x{pc_header_addr:x} != pclntab 0x{:x}",
            bin.pclntab_addr
        )));
    }

    let funcnametab = r.slice_header()?;
    let cutab = r.slice_header()?;
    let filetab = r.slice_header()?;
    let pctab = r.slice_header()?;
    let pclntable = r.slice_header()?;
    let ftab = r.slice_header()?;

    // Sanity: all five sub-region slices (funcnametab, cutab, filetab,
    // pctab, pclntable, ftab) must point inside the pclntab. In Go 1.20+
    // they're all sub-slices of the same blob the linker emitted. This is a
    // much stronger corroborating signal than checking any single offset.
    let pclntab_lo = bin.pclntab_addr;
    let pclntab_hi = bin.pclntab_addr.saturating_add(bin.pclntab_size as u64);
    let inside = |h: SliceHeader| {
        h.data >= pclntab_lo
            && h.data < pclntab_hi
            && h.len <= bin.pclntab_size as u64
            && h.data.saturating_add(h.len) <= pclntab_hi
            && h.len == h.cap
    };
    for (name, h) in [
        ("funcnametab", funcnametab),
        ("cutab", cutab),
        ("filetab", filetab),
        ("pctab", pctab),
        ("pclntable", pclntable),
    ] {
        if !inside(h) {
            return Err(Error::ModuleData(format!(
                "{name} slice [0x{:x}+{}] not within pclntab [0x{:x}, 0x{:x})",
                h.data, h.len, pclntab_lo, pclntab_hi
            )));
        }
    }
    // ftab is also a sub-slice but its element size is 8 bytes (functab),
    // not 1, check addr and that (len+1)*8 fits in the remaining pclntab.
    // The +1 is the trailing sentinel entry.
    if ftab.data < pclntab_lo || ftab.data >= pclntab_hi {
        return Err(Error::ModuleData(format!(
            "ftab slice data 0x{:x} not within pclntab [0x{:x}, 0x{:x})",
            ftab.data, pclntab_lo, pclntab_hi
        )));
    }
    const FTAB_ENTRY_SIZE: u64 = 8;
    let ftab_bytes = ftab.len.saturating_add(1).saturating_mul(FTAB_ENTRY_SIZE);
    if ftab.data.saturating_add(ftab_bytes) > pclntab_hi {
        return Err(Error::ModuleData(format!(
            "ftab ({} entries x {}B) extends past pclntab end",
            ftab.len, FTAB_ENTRY_SIZE,
        )));
    }
    if ftab.len > 5_000_000 {
        return Err(Error::ModuleData(format!(
            "ftab length {} exceeds sanity cap",
            ftab.len
        )));
    }

    let findfunctab = r.uptr()?;
    let minpc = r.uptr()?;
    let maxpc = r.uptr()?;

    let text = r.uptr()?;
    let etext = r.uptr()?;
    let noptrdata = r.uptr()?;
    let enoptrdata = r.uptr()?;
    let data = r.uptr()?;
    let edata = r.uptr()?;
    let bss = r.uptr()?;
    let ebss = r.uptr()?;
    let noptrbss = r.uptr()?;
    let enoptrbss = r.uptr()?;
    // covctrs/ecovctrs were added in Go 1.20 and are present in every layout
    // since. The pre-1.20 layout skips straight from enoptrbss to
    // end/gcdata/gcbss.
    let (covctrs, ecovctrs) = if matches!(layout, Layout::V120 | Layout::V126) {
        (r.uptr()?, r.uptr()?)
    } else {
        (0, 0)
    };
    let end = r.uptr()?;
    let gcdata = r.uptr()?;
    let gcbss = r.uptr()?;
    let types = r.uptr()?;
    let etypes = r.uptr()?;
    // Go 1.18 inserted `rodata` and `gofunc` after `etypes`; Go 1.16/1.17 do not
    // have them, so the slice headers that follow sit two pointers earlier.
    let (rodata, gofunc) = if matches!(layout, Layout::Pre118) {
        (0, 0)
    } else {
        (r.uptr()?, r.uptr()?)
    };
    // Go 1.26 inserted an `epclntab` pointer here, before textsectmap. Reading
    // it keeps the slice headers that follow aligned; older layouts skip it.
    if matches!(layout, Layout::V126) {
        let _epclntab = r.uptr()?;
    }

    let textsectmap = r.slice_header()?;
    let typelinks = r.slice_header()?;
    let itablinks = r.slice_header()?;

    // Post-decode sanity. If pclntab magic and moduledata layout disagree
    // (custom linker, hand-patched binary, sniff wrong) we'd return a
    // parsed-but-garbage struct. These checks catch it before the caller
    // walks any of the recovered fields.
    if types == 0 || etypes < types {
        return Err(Error::ModuleData(format!(
            "implausible types region: [0x{types:x}, 0x{etypes:x})"
        )));
    }
    if text == 0 || etext < text {
        return Err(Error::ModuleData(format!(
            "implausible text region: [0x{text:x}, 0x{etext:x})"
        )));
    }
    if minpc > maxpc {
        return Err(Error::ModuleData(format!(
            "implausible pc range: minpc=0x{minpc:x} > maxpc=0x{maxpc:x}"
        )));
    }
    // Sanity ceiling on region sizes. The largest legitimate Go binaries
    // we know of (kube-apiserver static-linked, ~120 MiB; some CGO-heavy
    // builds linking V8/oniguruma, 200-500 MiB) have text and types
    // regions in the hundreds of MiB. 1 GiB leaves headroom for the next
    // generation of giants while still catching the "we read garbage
    // fields and got nonsense sizes" case (which produces values like
    // 0xdeadbeef-sized regions, far above any plausible real binary).
    const MAX_REGION_BYTES: u64 = 1024 * 1024 * 1024;
    if etypes - types > MAX_REGION_BYTES {
        return Err(Error::ModuleData(format!(
            "types region size {} bytes exceeds {} MiB sanity cap",
            etypes - types,
            MAX_REGION_BYTES / (1024 * 1024)
        )));
    }
    if etext - text > MAX_REGION_BYTES {
        return Err(Error::ModuleData(format!(
            "text region size {} bytes exceeds {} MiB sanity cap",
            etext - text,
            MAX_REGION_BYTES / (1024 * 1024)
        )));
    }
    // gofunc should land in a mapped section. If it doesn't, every funcdata
    // dereference we do later will fail with cryptic "unmapped" errors;
    // better to fail clean here.
    if gofunc != 0 && bin.section_for_addr(gofunc).is_none() {
        return Err(Error::ModuleData(format!(
            "gofunc 0x{gofunc:x} does not fall in any mapped section"
        )));
    }
    // typelinks and itablinks come after the version-drifting tail, so a layout
    // mismatch leaves their slice headers shifted by a pointer. The whole array
    // must fit inside the section that holds its data: a one-pointer shift (e.g.
    // Go 1.26 inserted a field before these) reads a wildly large length whose
    // array would overrun the section, which fails this check and lets the
    // caller try the other layout. Checking only that the data pointer resolves
    // is not enough -- a shifted pointer can land in a real section by chance
    // while the length stays garbage.
    let slice_fits = |hdr: &SliceHeader, elem: u64| -> bool {
        if hdr.len == 0 {
            return true;
        }
        match bin.section_for_addr(hdr.data) {
            Some(s) => {
                let end = hdr.data.saturating_add(hdr.len.saturating_mul(elem));
                end <= s.addr.saturating_add(s.vmsize.max(s.file_size as u64))
            }
            None => false,
        }
    };
    if !slice_fits(&typelinks, 4) {
        return Err(Error::ModuleData(format!(
            "typelinks (data 0x{:x}, len {}) does not fit its section",
            typelinks.data, typelinks.len
        )));
    }
    if !slice_fits(&itablinks, ps as u64) {
        return Err(Error::ModuleData(format!(
            "itablinks (data 0x{:x}, len {}) does not fit its section",
            itablinks.data, itablinks.len
        )));
    }

    let addr = bin
        .sections
        .iter()
        .find(|s| file_off >= s.file_offset && file_off < s.file_offset + s.file_size)
        .map(|s| s.addr + (file_off - s.file_offset) as u64)
        .unwrap_or(0);

    Ok(ModuleData {
        file_offset: file_off,
        addr,
        pc_header_addr,
        funcnametab,
        cutab,
        filetab,
        pctab,
        pclntable,
        ftab,
        findfunctab,
        minpc,
        maxpc,
        text,
        etext,
        noptrdata,
        enoptrdata,
        data,
        edata,
        bss,
        ebss,
        noptrbss,
        enoptrbss,
        covctrs,
        ecovctrs,
        end,
        gcdata,
        gcbss,
        types,
        etypes,
        rodata,
        gofunc,
        textsectmap,
        typelinks,
        itablinks,
    })
}

struct Reader<'a> {
    bytes: &'a [u8],
    pos: usize,
    ps: usize,
    le: bool,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8], pos: usize, ps: usize, le: bool) -> Self {
        Self { bytes, pos, ps, le }
    }

    fn uptr(&mut self) -> Result<u64> {
        let end = self.pos + self.ps;
        if end > self.bytes.len() {
            return Err(Error::ShortRead {
                wanted: self.ps,
                offset: self.pos,
                available: self.bytes.len().saturating_sub(self.pos),
            });
        }
        let v = match self.ps {
            8 => {
                let arr: [u8; 8] = self.bytes[self.pos..end].try_into().unwrap();
                if self.le {
                    u64::from_le_bytes(arr)
                } else {
                    u64::from_be_bytes(arr)
                }
            }
            4 => {
                let arr: [u8; 4] = self.bytes[self.pos..end].try_into().unwrap();
                (if self.le {
                    u32::from_le_bytes(arr)
                } else {
                    u32::from_be_bytes(arr)
                }) as u64
            }
            _ => unreachable!(),
        };
        self.pos = end;
        Ok(v)
    }

    fn slice_header(&mut self) -> Result<SliceHeader> {
        let data = self.uptr()?;
        let len = self.uptr()?;
        let cap = self.uptr()?;
        Ok(SliceHeader { data, len, cap })
    }
}
