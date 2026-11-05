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
    /// Go 1.27+: the bytes of type descriptors at the start of the types
    /// region, laid out back to back (the runtime walks them, there is no
    /// `typelinks`). Zero on older layouts.
    pub typedesclen: u64,
    /// Go 1.27+: where the linked itabs sit in the types region (offset from
    /// `types`) and their total bytes, back to back (there is no
    /// `itablinks`). Zero on older layouts.
    pub itaboffset: u64,
    pub itabsize: u64,

    pub rodata: u64,
    pub gofunc: u64,

    /// Slices of further metadata.
    pub textsectmap: SliceHeader,
    /// `typelinks` is a `[]int32` of offsets relative to `types` (empty from
    /// Go 1.27, which dropped it: see [`ModuleData::type_addrs`]).
    pub typelinks: SliceHeader,
    /// `itablinks` is a `[]*itab` (one pointer per linked interface impl;
    /// empty from Go 1.27: see [`ModuleData::itab_addrs`]).
    pub itablinks: SliceHeader,

    /// How type-name lengths are encoded in this binary. `parse` cannot tell
    /// (Go 1.16 and 1.17 share the pclntab magic), so it defaults to `Varint`;
    /// `types::recover_all` and friends detect the real encoding and set it.
    pub name_enc: NameEnc,
}

/// The length encoding of a Go runtime `name` (the type/field/method name blob).
/// Go 1.2 to 1.16 used a 2-byte big-endian length; Go 1.17 switched to a varint
/// (the same encoding 1.18+ uses). The pclntab magic does not distinguish 1.16
/// from 1.17, so the encoding is detected from the data, not the magic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum NameEnc {
    /// Varint length (Go 1.17 and later).
    Varint,
    /// 2-byte big-endian length (Go 1.16 and earlier).
    TwoByteBe,
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
    /// Go 1.27: `typelinks` and `itablinks` are gone; `typedesclen` follows
    /// `types` and `itaboffset`, `itabsize` follow `etypes`. Same pclntab
    /// magic again: told apart from V126 by which parse validates.
    V127,
    /// Go 1.16 and 1.17 (pclntab magic 0xfffffffa): no `covctrs` (added in 1.20)
    /// and no `rodata`/`gofunc` (added in 1.18), so the offset table after
    /// `etypes` sits two pointers earlier than every later layout.
    Pre118,
}

/// The runtime's `textAddr` loop over a split text: `sects` is `textsectmap` as
/// `(vaddr, end, baseaddr)`, `off` a virtual text offset. The section holding
/// `off` (or the last one's end, which the functab includes) relocates it;
/// an offset in no section keeps `fallback` (`text + off`), as the runtime does.
fn text_addr_in(sects: &[(u64, u64, u64)], fallback: u64, off: u64) -> u64 {
    for (i, &(vaddr, end, base)) in sects.iter().enumerate() {
        let last = i + 1 == sects.len();
        if (off >= vaddr && off < end) || (last && off == end) {
            return base.wrapping_add(off - vaddr);
        }
    }
    fallback
}

/// Decode a Go `name` length prefix per the binary's encoding, returning the
/// length and the number of header bytes it spans. Go 1.17+ uses a varint; Go 1.16
/// and earlier a 2-byte big-endian length. `buf` points at the length (for a name,
/// the byte after the flag; for a tag, the first byte). Defined here, beside
/// `NameEnc`, so type recovery and the detector below share one decoder.
pub fn read_name_len(buf: &[u8], enc: NameEnc) -> Option<(u64, usize)> {
    match enc {
        NameEnc::Varint => {
            // uvarint, base-128 little-endian, MSB = continuation. Capped at 10
            // bytes (a u64's max), matching the reflect runtime's reader.
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
        NameEnc::TwoByteBe => {
            let hi = *buf.first()? as u64;
            let lo = *buf.get(1)? as u64;
            Some(((hi << 8) | lo, 2))
        }
    }
}

/// Detect this binary's name encoding by probing a sample of type names with both
/// forms and keeping the one that decodes more of them to plausible names. Go 1.16
/// and 1.17 share the pclntab magic, so it cannot be read from the magic. Reads raw
/// bytes only (no dependency on the type recovery), so it runs inside `locate`.
/// Defaults to `Varint` (the modern, far more common case) unless 2-byte clearly
/// wins, so a 1.18+ binary is never pushed onto the 2-byte path.
fn detect_name_encoding(bin: &GoBinary, md: &ModuleData) -> NameEnc {
    // The `str` (name offset) field sits at +40 in the 64-bit `_type` header, the
    // layout type recovery assumes; on 32-bit (size, ptrdata, equal and gcdata
    // are 4 bytes) it sits at +24 of a 32-byte header. Reading +40 there lands in
    // the next descriptor and can tip the vote to the 2-byte encoding, which then
    // garbles every name the binary's itabs and types resolve.
    let ps = bin.pointer_size();
    let str_offset = 4 * ps + 8;
    let header = 4 * ps + 16;
    const PROBES: usize = 64;
    // A Go 1.18+ magic settles it: only 1.16 and 1.17 share a magic.
    if matches!(
        read_u32_e(bin.pclntab_slice(), 0, bin.little_endian),
        Some(crate::pclntab::MAGIC_1_18 | crate::pclntab::MAGIC_1_20)
    ) {
        return NameEnc::Varint;
    }
    let Ok(addrs) = md.type_addrs(bin) else {
        return NameEnc::Varint;
    };
    let mut varint_ok = 0usize;
    let mut twobyte_ok = 0usize;
    for type_addr in addrs.into_iter().take(PROBES) {
        let Some(hdr) = bin.read_at_addr(type_addr, header) else {
            continue;
        };
        let str_off = i32::from_le_bytes(hdr[str_offset..str_offset + 4].try_into().unwrap());
        let name_addr = md.types.wrapping_add(str_off as i64 as u64);
        let Some(nbytes) = bin.read_at_addr(name_addr, 1 + 2 + 1024) else {
            continue;
        };
        if name_probe_valid(nbytes, NameEnc::Varint) {
            varint_ok += 1;
        }
        if name_probe_valid(nbytes, NameEnc::TwoByteBe) {
            twobyte_ok += 1;
        }
    }
    if twobyte_ok > varint_ok {
        NameEnc::TwoByteBe
    } else {
        NameEnc::Varint
    }
}

/// Whether a name blob (flag, length, name bytes) decodes to a plausible name under
/// `enc`: a nonempty, in-bounds run of printable ASCII. A wrong encoding reads a
/// length that overruns the buffer or a body with control/high bytes, so it fails.
fn name_probe_valid(bytes: &[u8], enc: NameEnc) -> bool {
    let Some(after_flag) = bytes.get(1..) else {
        return false;
    };
    let Some((len, len_bytes)) = read_name_len(after_flag, enc) else {
        return false;
    };
    let start = 1 + len_bytes;
    let len = len as usize;
    if len == 0 || len > bytes.len().saturating_sub(start) {
        return false;
    }
    bytes[start..start + len]
        .iter()
        .all(|&b| (0x20..=0x7e).contains(&b))
}

impl ModuleData {
    /// The address of every type descriptor the linker listed: `typelinks`
    /// resolved against `types` (Go 1.26 and older), or, from Go 1.27, which
    /// dropped `typelinks`, the descriptors walked back to back from the
    /// start of the types region for `typedesclen` bytes, as the runtime's
    /// `moduleTypelinks` does (one pointer in, each descriptor aligned to a
    /// pointer and as long as its `DescriptorSize`). A walk that meets a
    /// descriptor it cannot size stops there with what it has.
    pub fn type_addrs(&self, bin: &GoBinary) -> Result<Vec<u64>> {
        if self.typedesclen == 0 {
            const MAX_TYPELINKS: u64 = 5_000_000;
            if self.typelinks.len > MAX_TYPELINKS {
                return Err(Error::TypeRecovery(format!(
                    "typelinks length {} exceeds sanity cap {}",
                    self.typelinks.len, MAX_TYPELINKS
                )));
            }
            let bytes = bin
                .read_at_addr(self.typelinks.data, (self.typelinks.len as usize) * 4)
                .ok_or_else(|| {
                    Error::TypeRecovery(format!(
                        "typelinks at 0x{:x} (len {}) is unmapped",
                        self.typelinks.data, self.typelinks.len
                    ))
                })?;
            return Ok(bytes
                .chunks_exact(4)
                .map(|c| {
                    let off = if bin.little_endian {
                        i32::from_le_bytes(c.try_into().unwrap())
                    } else {
                        i32::from_be_bytes(c.try_into().unwrap())
                    };
                    self.types.wrapping_add(off as i64 as u64)
                })
                .collect());
        }
        let ps = bin.pointer_size() as u64;
        let end = self.types.saturating_add(self.typedesclen);
        let mut out = Vec::new();
        let mut td = self.types.saturating_add(ps);
        while td < end {
            td = td.div_ceil(ps) * ps;
            if td >= end {
                break;
            }
            let Some(size) = descriptor_size(bin, td) else {
                break;
            };
            out.push(td);
            td = td.saturating_add(size);
        }
        Ok(out)
    }

    /// The address of every itab the linker emitted: `itablinks` (Go 1.26 and
    /// older), or, from Go 1.27, which dropped it, the itabs walked back to
    /// back over `itabsize` bytes at `types + itaboffset`, as the runtime's
    /// `addModuleItabs` does (each as long as its `Size`).
    pub fn itab_addrs(&self, bin: &GoBinary) -> Result<Vec<u64>> {
        let ps = bin.pointer_size();
        if self.itabsize == 0 && self.typedesclen == 0 {
            const MAX_ITABS: u64 = 5_000_000;
            if self.itablinks.len > MAX_ITABS {
                return Err(Error::ItabRecovery(format!(
                    "itablinks length {} exceeds sanity cap {}",
                    self.itablinks.len, MAX_ITABS
                )));
            }
            let n = self.itablinks.len as usize;
            let bytes = bin
                .read_at_addr(self.itablinks.data, n * ps)
                .ok_or_else(|| {
                    Error::ItabRecovery(format!(
                        "itablinks at 0x{:x} (len {}) unmapped",
                        self.itablinks.data, self.itablinks.len
                    ))
                })?;
            return Ok(bytes
                .chunks_exact(ps)
                .filter_map(|c| read_ptr(c, 0, ps, bin.little_endian))
                .filter(|&a| a != 0)
                .collect());
        }
        let ps = ps as u64;
        let mut p = self.types.saturating_add(self.itaboffset);
        let end = p.saturating_add(self.itabsize);
        let mut out = Vec::new();
        while p < end {
            let Some(size) = itab_size(bin, p) else {
                break;
            };
            out.push(p);
            p = p.saturating_add(size.max(ps));
        }
        Ok(out)
    }

    /// Byte offset of `fun[0]` in this binary's itabs. Up to Go 1.22 the
    /// runtime's `itab` is `{inter, _type, hash uint32, _ [4]byte, fun}`; Go
    /// 1.23 moved it to `internal/abi.ITab` and dropped the pad. On 64-bit
    /// `fun` is pointer-aligned either way (24); on 32-bit it moved from 16
    /// to 12. Go 1.27 (walked itabs) is always the new layout. Before that the
    /// version is read from the itabs themselves: the old pad is always zero,
    /// while the new layout's word at 12 is the first method of a linked itab,
    /// a text address.
    pub fn itab_fun_offset(&self, bin: &GoBinary) -> u64 {
        let ps = bin.pointer_size() as u64;
        if ps == 8 {
            return 24;
        }
        if self.typedesclen != 0 {
            return 2 * ps + 4;
        }
        let Ok(addrs) = self.itab_addrs(bin) else {
            return 2 * ps + 8;
        };
        let new_layout = addrs.iter().any(|&a| {
            word_at(bin, a + 2 * ps + 4).is_some_and(|w| w >= self.text && w < self.etext)
        });
        if new_layout {
            2 * ps + 4
        } else {
            2 * ps + 8
        }
    }

    /// Whether the package-variable word at `addr` holds a pointer, from the
    /// GC pointer masks of the data and bss sections (`gcdata`, `gcbss`:
    /// GC programs the runtime expands with `progToPointerMask`, one bit
    /// per word). None outside both sections or on a malformed program.
    pub fn is_pointer_word(&self, bin: &GoBinary, addr: u64) -> Option<bool> {
        let ps = bin.pointer_size() as u64;
        let (start, end, prog) = if (self.data..self.edata).contains(&addr) {
            (self.data, self.edata, self.gcdata)
        } else if (self.bss..self.ebss).contains(&addr) {
            (self.bss, self.ebss, self.gcbss)
        } else {
            return None;
        };
        if (addr - start) % ps != 0 {
            return None;
        }
        let words = usize::try_from((end - start) / ps).ok()?;
        let mask = run_gc_prog(bin, prog, words)?;
        mask.get(usize::try_from((addr - start) / ps).ok()?)
            .copied()
    }

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
                    if let Some(mut md) = scan_section(bin, section, &target_bytes, ps, layout) {
                        // Resolve the name encoding now (the magic cannot tell 1.16
                        // from 1.17), so every later name read uses the right one.
                        md.name_enc = detect_name_encoding(bin, &md);
                        return Ok(md);
                    }
                }
            }
        }

        Err(Error::ModuleData(
            "no moduledata candidate found in data sections".into(),
        ))
    }

    /// Resolve a `TextOff` (a method table's Ifn/Tfn) to a PC, mirroring the
    /// runtime's `moduledata.textAddr`. With one text section (every internally
    /// linked binary) that is `text + off`. When the external linker split the
    /// text (ARM, PPC64, darwin/arm64 past the trampoline limit), `textsectmap`
    /// lists `{vaddr, end, baseaddr}` per section and the offset is a virtual
    /// offset into that list. `None` when the map cannot be read or the result
    /// lands past `etext`, the case the runtime throws on.
    pub fn text_addr(&self, bin: &GoBinary, off: u32) -> Option<u64> {
        let off = off as u64;
        let fallback = self.text.wrapping_add(off);
        // A few sections is normal; anything near this is a corrupt header.
        const MAX_TEXT_SECTIONS: u64 = 4096;
        let n = self.textsectmap.len;
        if n <= 1 {
            return Some(fallback);
        }
        if n > MAX_TEXT_SECTIONS {
            return None;
        }
        let ps = bin.pointer_size();
        let entry = 3 * ps;
        let raw = bin.read_at_addr(self.textsectmap.data, n as usize * entry)?;
        let word = |b: &[u8]| -> u64 {
            match (ps, bin.little_endian) {
                (8, true) => u64::from_le_bytes(b.try_into().unwrap()),
                (8, false) => u64::from_be_bytes(b.try_into().unwrap()),
                (_, true) => u32::from_le_bytes(b.try_into().unwrap()) as u64,
                (_, false) => u32::from_be_bytes(b.try_into().unwrap()) as u64,
            }
        };
        let sects: Vec<(u64, u64, u64)> = raw
            .chunks_exact(entry)
            .map(|s| (word(&s[..ps]), word(&s[ps..2 * ps]), word(&s[2 * ps..])))
            .collect();
        let pc = text_addr_in(&sects, fallback, off);
        (pc <= self.etext).then_some(pc)
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
                    if let Some(mut next_md) = layouts_for(bin)
                        .iter()
                        .find_map(|&layout| try_parse(bin, file_off, ps, layout).ok())
                    {
                        // Every module in one binary shares the name encoding the
                        // first module resolved.
                        next_md.name_enc = out[0].name_enc;
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
        _ => &[Layout::V120, Layout::V126, Layout::V127],
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
    let (covctrs, ecovctrs) = if matches!(layout, Layout::V120 | Layout::V126 | Layout::V127) {
        (r.uptr()?, r.uptr()?)
    } else {
        (0, 0)
    };
    let end = r.uptr()?;
    let gcdata = r.uptr()?;
    let gcbss = r.uptr()?;
    let types = r.uptr()?;
    let typedesclen = if matches!(layout, Layout::V127) {
        r.uptr()?
    } else {
        0
    };
    let etypes = r.uptr()?;
    let (itaboffset, itabsize) = if matches!(layout, Layout::V127) {
        (r.uptr()?, r.uptr()?)
    } else {
        (0, 0)
    };
    // Go 1.18 inserted `rodata` and `gofunc` after `etypes`; Go 1.16/1.17 do not
    // have them, so the slice headers that follow sit two pointers earlier.
    let (rodata, gofunc) = if matches!(layout, Layout::Pre118) {
        (0, 0)
    } else {
        (r.uptr()?, r.uptr()?)
    };
    // Go 1.26 inserted an `epclntab` pointer here, before textsectmap. Reading
    // it keeps the slice headers that follow aligned; older layouts skip it.
    if matches!(layout, Layout::V126 | Layout::V127) {
        let _epclntab = r.uptr()?;
    }

    let textsectmap = r.slice_header()?;
    // Go 1.27 dropped both: its types and itabs are walked in place.
    let empty = SliceHeader {
        data: 0,
        len: 0,
        cap: 0,
    };
    let (typelinks, itablinks) = if matches!(layout, Layout::V127) {
        (empty, empty)
    } else {
        (r.slice_header()?, r.slice_header()?)
    };

    // Post-decode sanity. If pclntab magic and moduledata layout disagree
    // (custom linker, hand-patched binary, sniff wrong) we'd return a
    // parsed-but-garbage struct. These checks catch it before the caller
    // walks any of the recovered fields.
    if types == 0 || etypes < types {
        return Err(Error::ModuleData(format!(
            "implausible types region: [0x{types:x}, 0x{etypes:x})"
        )));
    }
    // Go 1.27: the descriptors and the itabs lie inside the types region,
    // and the text sections map is a plausible slice. A V126 read of a 1.27
    // moduledata fails the region check above (`typedesclen` read as
    // `etypes`); a V127 read of an older one fails here.
    if matches!(layout, Layout::V127) {
        let region = etypes - types;
        if typedesclen == 0
            || typedesclen > region
            || itaboffset.saturating_add(itabsize) > region
            || (itabsize != 0 && itaboffset < typedesclen)
        {
            return Err(Error::ModuleData(format!(
                "implausible Go 1.27 type layout: typedesclen {typedesclen}, itabs {itaboffset}+{itabsize}, region {region}"
            )));
        }
        if textsectmap.len > 4096 || textsectmap.len != textsectmap.cap {
            return Err(Error::ModuleData(format!(
                "implausible textsectmap length {}",
                textsectmap.len
            )));
        }
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
        typedesclen,
        etypes,
        itaboffset,
        itabsize,
        rodata,
        gofunc,
        textsectmap,
        typelinks,
        itablinks,
        // Detected from the data by the type recovery, not knowable from the
        // pclntab magic; default to the modern varint encoding.
        name_enc: NameEnc::Varint,
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

/// Expand the GC program at `prog` (runtime `runGCProg`) into at most
/// `words` bits: literal runs (`0nnnnnnn` then the bits, LSB first) and
/// repeats (`1nnnnnnn` or `10000000 varint(n)`, then `varint(c)`: the last
/// `n` bits `c` more times), ending at a zero byte.
fn run_gc_prog(bin: &GoBinary, prog: u64, words: usize) -> Option<Vec<bool>> {
    // The program runs to the end of its section's file bytes at most.
    let s = bin.section_for_addr(prog)?;
    let in_file = usize::try_from(prog - s.addr).ok()?;
    let p = bin.read_at_addr(prog, s.file_size.checked_sub(in_file)?.min(1 << 20))?;
    expand_gc_prog(p, words)
}

/// [`run_gc_prog`] over the program bytes.
fn expand_gc_prog(p: &[u8], words: usize) -> Option<Vec<bool>> {
    let mut i = 0usize;
    let mut next = || -> Option<u8> {
        let b = *p.get(i)?;
        i += 1;
        Some(b)
    };
    let mut out: Vec<bool> = Vec::new();
    loop {
        let inst = next()?;
        let mut n = usize::from(inst & 0x7f);
        if inst & 0x80 == 0 {
            if n == 0 {
                break;
            }
            let mut bits = 0usize;
            while bits < n {
                let b = next()?;
                for k in 0..8.min(n - bits) {
                    out.push(b >> k & 1 == 1);
                }
                bits += 8;
            }
        } else {
            let varint = |next: &mut dyn FnMut() -> Option<u8>| -> Option<usize> {
                let mut x = 0usize;
                for off in (0..64).step_by(7) {
                    let b = next()?;
                    x |= usize::from(b & 0x7f).checked_shl(off)?;
                    if b & 0x80 == 0 {
                        return Some(x);
                    }
                }
                None
            };
            if n == 0 {
                n = varint(&mut next)?;
            }
            let c = varint(&mut next)?;
            if n == 0 || n > out.len() || n.checked_mul(c)? > words.saturating_sub(out.len()) + n {
                return None;
            }
            let pat: Vec<bool> = out[out.len() - n..].to_vec();
            for _ in 0..c {
                out.extend_from_slice(&pat);
            }
        }
        if out.len() > words + 64 {
            return None;
        }
    }
    out.truncate(words);
    Some(out)
}

/// A pointer-sized word at `addr`.
fn word_at(bin: &GoBinary, addr: u64) -> Option<u64> {
    let ps = bin.pointer_size();
    read_ptr(bin.read_at_addr(addr, ps)?, 0, ps, bin.little_endian)
}

/// The bytes of the Go 1.27 type descriptor at `addr`, as
/// `internal/abi.(*Type).DescriptorSize` computes them: the kind's struct,
/// its uncommon part when flagged, the data the kind keeps inline (a
/// function's parameter and result types, an interface's methods, a
/// struct's fields), then the method table. None for a kind it does not
/// know (the walk stops there).
fn descriptor_size(bin: &GoBinary, addr: u64) -> Option<u64> {
    let ps = bin.pointer_size() as u64;
    let le = bin.little_endian;
    let hdr = 4 * ps + 16;
    let head = bin.read_at_addr(addr, hdr as usize)?;
    let tflag = head[(2 * ps + 4) as usize];
    let kind = head[(2 * ps + 7) as usize] & 0x1f;
    let align = |n: u64| n.div_ceil(ps) * ps;
    let u16_at = |a: u64| -> Option<u64> {
        let b: [u8; 2] = bin.read_at_addr(a, 2)?.try_into().ok()?;
        Some(if le {
            u16::from_le_bytes(b)
        } else {
            u16::from_be_bytes(b)
        } as u64)
    };
    let (base, add) = match kind {
        // Bool through Complex128, String, UnsafePointer: the header alone.
        1..=16 | 24 | 26 => (hdr, 0),
        17 => (hdr + 3 * ps, 0), // Array: Elem, Slice, Len
        18 => (hdr + 2 * ps, 0), // Chan: Elem, Dir
        19 => {
            // Func: InCount, OutCount (top bit: variadic), then the types.
            let n_in = u16_at(addr + hdr)?;
            let n_out = u16_at(addr + hdr + 2)? & 0x7fff;
            (align(hdr + 4), (n_in + n_out) * ps)
        }
        20 => {
            // Interface: PkgPath, Methods (8-byte Imethods).
            let n = word_at(bin, addr + hdr + 2 * ps)?;
            (hdr + 4 * ps, n.checked_mul(8)?)
        }
        21 => (align(hdr + 10 * ps + 4), 0), // Map (Go 1.27 MapType)
        22 | 23 => (hdr + ps, 0),            // Pointer, Slice: Elem
        25 => {
            // Struct: PkgPath, Fields (Name, Typ, Offset each).
            let n = word_at(bin, addr + hdr + 2 * ps)?;
            (hdr + 4 * ps, n.checked_mul(3 * ps)?)
        }
        _ => return None,
    };
    let mut size = base;
    if tflag & 1 != 0 {
        // UncommonType: PkgPath, Mcount, Xcount, Moff, unused.
        let mcount = u16_at(addr + base + 4)?;
        size = size
            .checked_add(16)?
            .checked_add(add)?
            .checked_add(mcount * 16)?;
    } else {
        size = size.checked_add(add)?;
    }
    Some(size)
}

/// The bytes of the itab at `addr`, as `internal/abi.(*ITab).Size` computes
/// them: the header and one method word, plus one word per further method
/// of its interface, unless the itab is the empty "does not implement" one.
fn itab_size(bin: &GoBinary, addr: u64) -> Option<u64> {
    let ps = bin.pointer_size() as u64;
    let inter = word_at(bin, addr)?;
    let fun0 = word_at(bin, addr + 2 * ps + if ps == 8 { 8 } else { 4 })?;
    let header = 2 * ps + if ps == 8 { 8 } else { 4 };
    let size = header + ps;
    if fun0 == 0 || inter == 0 {
        return Some(size);
    }
    let hdr = 4 * ps + 16;
    let methods = word_at(bin, inter + hdr + 2 * ps)?;
    if methods == 0 || methods > 1 << 20 {
        return Some(size);
    }
    Some(size + (methods - 1) * ps)
}

#[cfg(test)]
mod tests {
    use super::{expand_gc_prog, read_name_len, text_addr_in, NameEnc};

    #[test]
    fn text_offsets_follow_split_text_sections() {
        // Two sections: virtual [0, 0x1000) loaded at 0x10000, virtual
        // [0x1000, 0x1800) loaded at 0x20000 (a trampoline gap between them).
        let sects = [(0, 0x1000, 0x10000), (0x1000, 0x1800, 0x20000)];
        let fallback = |off: u64| 0x10000 + off;
        assert_eq!(text_addr_in(&sects, fallback(0x10), 0x10), 0x10010);
        assert_eq!(text_addr_in(&sects, fallback(0x1010), 0x1010), 0x20010);
        // The last section's end is included (the functab carries etext).
        assert_eq!(text_addr_in(&sects, fallback(0x1800), 0x1800), 0x20800);
        // No section holds it: keep text + off, as the runtime does.
        assert_eq!(text_addr_in(&sects, fallback(0x2000), 0x2000), 0x12000);
        // One section (or none): plain text + off.
        assert_eq!(text_addr_in(&[], fallback(0x44), 0x44), 0x10044);
    }

    #[test]
    fn name_len_decodes_both_encodings() {
        // Varint (Go 1.17+): low 7 bits per byte, MSB continuation.
        assert_eq!(read_name_len(&[0x05, b'h'], NameEnc::Varint), Some((5, 1)));
        assert_eq!(
            read_name_len(&[0x80, 0x01], NameEnc::Varint),
            Some((128, 2))
        );
        // 2-byte big-endian (Go 1.16 and earlier).
        assert_eq!(
            read_name_len(&[0x00, 0x05], NameEnc::TwoByteBe),
            Some((5, 2))
        );
        assert_eq!(
            read_name_len(&[0x01, 0x2c], NameEnc::TwoByteBe),
            Some((300, 2))
        );
        // The same first byte means different things under each encoding: 0x05 is a
        // length of 5 as a varint but the high byte of a 1280+ length as 2-byte BE.
        // This is exactly why the encoding must be detected per binary, not guessed.
        assert_eq!(
            read_name_len(&[0x05, 0x00], NameEnc::TwoByteBe),
            Some((0x0500, 2))
        );
        // Truncated input yields None rather than panicking.
        assert_eq!(read_name_len(&[0x80], NameEnc::Varint), None);
        assert_eq!(read_name_len(&[0x00], NameEnc::TwoByteBe), None);
        assert_eq!(read_name_len(&[], NameEnc::Varint), None);
    }

    /// A literal `1 0 1` (pointer, scalar, pointer), then the last 2 bits
    /// twice more, then the end: 7 words.
    #[test]
    fn gc_programs_expand_to_pointer_masks() {
        let prog = [0x03, 0b101, 0x82, 0x02, 0x00];
        let mask = expand_gc_prog(&prog, 7).unwrap();
        assert_eq!(mask, [true, false, true, false, true, false, true]);
        // A repeat with a varint count and a long literal.
        let prog = [0x09, 0xff, 0x01, 0x80, 0x01, 0x03, 0x00];
        let mask = expand_gc_prog(&prog, 12).unwrap();
        assert_eq!(mask.iter().filter(|b| **b).count(), 12);
        // Truncated and malformed programs say nothing.
        assert_eq!(expand_gc_prog(&[0x03], 3), None);
        assert_eq!(expand_gc_prog(&[0x81, 0x05, 0x00], 5), None);
    }
}
