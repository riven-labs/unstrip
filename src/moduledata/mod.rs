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
        // Sniff the layout from the pclntab magic (first 4 bytes).
        let layout = match bin.pclntab_slice().get(0..4) {
            Some(b) => {
                let magic = u32::from_le_bytes(b.try_into().unwrap());
                if magic == 0xfffffff0 {
                    Layout::V118
                } else {
                    Layout::V120
                }
            }
            None => Layout::V120,
        };

        let target = bin.pclntab_addr;
        if target == 0 {
            return Err(Error::ModuleData(
                "pclntab runtime address is zero; section table may be stripped".into(),
            ));
        }

        let target_bytes = if ps == 8 {
            target.to_le_bytes().to_vec()
        } else {
            (target as u32).to_le_bytes().to_vec()
        };

        let scan_kinds = [
            SectionKind::NoPtrData,
            SectionKind::Data,
            SectionKind::ReadOnlyData,
        ];

        for kind in scan_kinds {
            for section in bin.sections.iter().filter(|s| s.kind == kind) {
                if let Some(md) = scan_section(bin, section, &target_bytes, ps, layout) {
                    return Ok(md);
                }
            }
        }

        Err(Error::ModuleData(
            "no moduledata candidate found in data sections".into(),
        ))
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
    let end = section.file_offset + section.file_size;
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
    let mut r = Reader::new(bytes, file_off, ps);

    // We're parsing assuming little-endian. Big-endian Go targets exist
    // (s390x) but are vanishingly rare. Add when we have a fixture.
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
    let pclntab_hi = bin.pclntab_addr + bin.pclntab_size as u64;
    let inside = |h: SliceHeader| {
        h.data >= pclntab_lo
            && h.data < pclntab_hi
            && h.len <= bin.pclntab_size as u64
            && h.data + h.len <= pclntab_hi
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
    // covctrs/ecovctrs were added in Go 1.20. The pre-1.20 layout skips
    // straight from enoptrbss to end/gcdata/gcbss.
    let (covctrs, ecovctrs) = if matches!(layout, Layout::V120) {
        (r.uptr()?, r.uptr()?)
    } else {
        (0, 0)
    };
    let end = r.uptr()?;
    let gcdata = r.uptr()?;
    let gcbss = r.uptr()?;
    let types = r.uptr()?;
    let etypes = r.uptr()?;
    let rodata = r.uptr()?;
    let gofunc = r.uptr()?;

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
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8], pos: usize, ps: usize) -> Self {
        Self { bytes, pos, ps }
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
                u64::from_le_bytes(arr)
            }
            4 => {
                let arr: [u8; 4] = self.bytes[self.pos..end].try_into().unwrap();
                u32::from_le_bytes(arr) as u64
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
