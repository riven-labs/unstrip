use std::fs;
use std::path::Path;

use goblin::Object;

use crate::error::Error;
use crate::Result;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Container {
    Elf,
    MachO,
    Pe,
}

impl Container {
    pub fn as_str(self) -> &'static str {
        match self {
            Container::Elf => "ELF",
            Container::MachO => "Mach-O",
            Container::Pe => "PE",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Arch {
    X86_64,
    Aarch64,
    X86,
    Arm,
    Other,
}

impl Arch {
    pub fn as_str(self) -> &'static str {
        match self {
            Arch::X86_64 => "amd64",
            Arch::Aarch64 => "arm64",
            Arch::X86 => "386",
            Arch::Arm => "arm",
            Arch::Other => "other",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SectionKind {
    Text,
    ReadOnlyData,
    Data,
    NoPtrData,
    Bss,
    Pclntab,
    Other,
}

#[derive(Debug, Clone)]
pub struct Section {
    pub name: String,
    pub kind: SectionKind,
    pub file_offset: usize,
    pub file_size: usize,
    pub addr: u64,
    pub vmsize: u64,
}

impl Section {
    pub fn contains_addr(&self, addr: u64) -> bool {
        addr >= self.addr
            && addr
                < self
                    .addr
                    .saturating_add(self.vmsize.max(self.file_size as u64))
    }

    pub fn file_offset_of(&self, addr: u64) -> Option<usize> {
        if !self.contains_addr(addr) {
            return None;
        }
        let delta = (addr - self.addr) as usize;
        if delta >= self.file_size {
            return None;
        }
        // file_offset comes straight from the container's section header, so a
        // crafted offset near usize::MAX would overflow this add; saturate and
        // let the caller's bounds check against the file length reject it.
        Some(self.file_offset.saturating_add(delta))
    }

    /// Coarse memory classification a Go RE consumer cares about, in
    /// the order they'd ask: does the GC walk this region for pointers,
    /// and is the region writable at runtime. Derived from the section
    /// name first so the distinction Go's own naming carries
    /// (`.bss` ptr vs `.noptrbss` noptr, `.data` ptr vs `.noptrdata`
    /// noptr) survives the lossier SectionKind enum collapse. Returns
    /// `None` for kinds where the distinction is meaningless (`.text`,
    /// `.pclntab`, unknown sections).
    pub fn ptr_bearing(&self) -> Option<bool> {
        // Name-driven first: Go's `.noptrdata` / `.noptrbss` /
        // `.gosymtab` / `.gopclntab` carry the intent in the name and
        // the runtime treats them accordingly.
        let n = self.name.as_str();
        if n.contains("noptr") {
            return Some(false);
        }
        match self.kind {
            SectionKind::Data | SectionKind::Bss => {
                // `.bss` / `.data` are ptr-bearing in Go's GC model.
                // The noptr-prefixed variants above already short-
                // circuited; what remains is the genuinely scanned
                // variant.
                Some(true)
            }
            SectionKind::ReadOnlyData | SectionKind::NoPtrData | SectionKind::Pclntab => {
                Some(false)
            }
            SectionKind::Text | SectionKind::Other => None,
        }
    }

    /// True when the section is read-only at runtime (rodata, pclntab,
    /// text). False when it is writable (data, bss, noptrdata,
    /// noptrbss). None for unclassified.
    pub fn writable(&self) -> Option<bool> {
        match self.kind {
            SectionKind::ReadOnlyData | SectionKind::Pclntab | SectionKind::Text => Some(false),
            SectionKind::Data | SectionKind::Bss | SectionKind::NoPtrData => Some(true),
            SectionKind::Other => None,
        }
    }
}

pub struct GoBinary {
    pub bytes: Vec<u8>,
    pub container: Container,
    pub arch: Arch,
    pub little_endian: bool,
    pub sections: Vec<Section>,
    pub pclntab_offset: usize,
    pub pclntab_size: usize,
    pub pclntab_addr: u64,
    pub text_addr: u64,
}

impl GoBinary {
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self> {
        let bytes = fs::read(path)?;
        Self::parse(bytes)
    }

    pub fn parse(bytes: Vec<u8>) -> Result<Self> {
        let parsed = describe(&bytes)?;
        finish(bytes, parsed)
    }

    pub fn pclntab_slice(&self) -> &[u8] {
        &self.bytes[self.pclntab_offset..self.pclntab_offset + self.pclntab_size]
    }

    pub fn pointer_size(&self) -> usize {
        match self.arch {
            Arch::X86_64 | Arch::Aarch64 => 8,
            Arch::X86 | Arch::Arm => 4,
            Arch::Other => 8,
        }
    }

    pub fn section_for_addr(&self, addr: u64) -> Option<&Section> {
        self.sections.iter().find(|s| s.contains_addr(addr))
    }

    pub fn file_offset_for_addr(&self, addr: u64) -> Option<usize> {
        self.section_for_addr(addr)
            .and_then(|s| s.file_offset_of(addr))
    }

    /// Read `len` bytes from the binary at the given runtime virtual address.
    /// Returns None if the address is unmapped or the range overflows the
    /// containing section's backing file bytes.
    pub fn read_at_addr(&self, addr: u64, len: usize) -> Option<&[u8]> {
        let s = self.section_for_addr(addr)?;
        let start_off = s.file_offset_of(addr)?;
        let end_off = start_off.checked_add(len)?;
        if end_off > s.file_offset + s.file_size {
            return None;
        }
        // Belt-and-suspenders: the section bookkeeping should keep us within
        // self.bytes, but on some containers (PE with virtual_size > raw_size,
        // truncated input) the section can extend past the file. Reject
        // explicitly so callers see None instead of a panic.
        if end_off > self.bytes.len() {
            return None;
        }
        Some(&self.bytes[start_off..end_off])
    }
}

#[derive(Debug, Clone)]
struct Described {
    container: Container,
    arch: Arch,
    little_endian: bool,
    sections: Vec<Section>,
    pclntab_offset: usize,
    pclntab_size: usize,
    pclntab_addr: u64,
    text_addr: u64,
}

fn describe(bytes: &[u8]) -> Result<Described> {
    let object = Object::parse(bytes)?;
    match object {
        Object::Elf(elf) => describe_elf(bytes, elf),
        Object::Mach(mach) => describe_mach(bytes, mach),
        Object::PE(pe) => describe_pe(bytes, pe),
        _ => Err(Error::UnknownContainer),
    }
}

fn describe_elf(bytes: &[u8], elf: goblin::elf::Elf<'_>) -> Result<Described> {
    let arch = match elf.header.e_machine {
        goblin::elf::header::EM_X86_64 => Arch::X86_64,
        goblin::elf::header::EM_AARCH64 => Arch::Aarch64,
        goblin::elf::header::EM_386 => Arch::X86,
        goblin::elf::header::EM_ARM => Arch::Arm,
        _ => Arch::Other,
    };
    let little_endian = elf.little_endian;

    let mut sections = Vec::new();
    let mut text_addr = 0u64;
    let mut pcln: Option<(usize, usize, u64)> = None;

    for sh in elf.section_headers.iter() {
        let name = elf.shdr_strtab.get_at(sh.sh_name).unwrap_or("").to_string();
        let kind = classify_elf_section(&name, sh);
        let section = Section {
            name: name.clone(),
            kind,
            file_offset: sh.sh_offset as usize,
            file_size: sh.sh_size as usize,
            addr: sh.sh_addr,
            vmsize: sh.sh_size,
        };
        if section.kind == SectionKind::Text && text_addr == 0 {
            text_addr = section.addr;
        }
        if matches!(name.as_str(), ".gopclntab" | "__gopclntab" | "gopclntab") {
            pcln = Some((section.file_offset, section.file_size, section.addr));
        }
        sections.push(section);
    }

    let (pclntab_offset, pclntab_size, pclntab_addr) = match pcln {
        Some(v) => v,
        None => {
            let (off, size) = locate_pclntab(bytes, &sections, text_addr, little_endian)?;
            let addr = addr_for_offset(&sections, off).unwrap_or(0);
            (off, size, addr)
        }
    };

    Ok(Described {
        container: Container::Elf,
        arch,
        little_endian,
        sections,
        pclntab_offset,
        pclntab_size,
        pclntab_addr,
        text_addr,
    })
}

fn classify_elf_section(name: &str, sh: &goblin::elf::SectionHeader) -> SectionKind {
    use goblin::elf::section_header::*;
    if matches!(name, ".gopclntab" | "__gopclntab" | "gopclntab") {
        return SectionKind::Pclntab;
    }
    match name {
        ".text" => SectionKind::Text,
        ".rodata" => SectionKind::ReadOnlyData,
        ".data" => SectionKind::Data,
        ".noptrdata" => SectionKind::NoPtrData,
        ".bss" | ".noptrbss" => SectionKind::Bss,
        _ => {
            if sh.sh_type == SHT_PROGBITS && (sh.sh_flags & SHF_EXECINSTR as u64) != 0 {
                SectionKind::Text
            } else if sh.sh_type == SHT_PROGBITS && (sh.sh_flags & SHF_WRITE as u64) != 0 {
                SectionKind::Data
            } else if sh.sh_type == SHT_PROGBITS {
                SectionKind::ReadOnlyData
            } else if sh.sh_type == SHT_NOBITS {
                SectionKind::Bss
            } else {
                SectionKind::Other
            }
        }
    }
}

fn describe_mach(bytes: &[u8], mach: goblin::mach::Mach<'_>) -> Result<Described> {
    let macho = match mach {
        goblin::mach::Mach::Binary(m) => m,
        goblin::mach::Mach::Fat(fat) => {
            // Universal (fat) binaries contain multiple architecture slices.
            // We don't yet expose a way to pick one, and silently grabbing
            // slice 0 would analyze the wrong arch on most ARM Macs. Refuse
            // until we add --arch selection.
            //
            // iter_arches() yields one item per arch count claimed in the
            // header, and a crafted fat header can claim billions; counting
            // the full sequence to fill this error would spin. A real
            // universal binary has a handful of slices, so cap the walk well
            // above any genuine count and bail.
            const MAX_FAT_ARCHES: usize = 64;
            let count = fat.iter_arches().take(MAX_FAT_ARCHES).count();
            return Err(Error::FatBinary { slice_count: count });
        }
    };

    let arch = match macho.header.cputype() {
        goblin::mach::cputype::CPU_TYPE_X86_64 => Arch::X86_64,
        goblin::mach::cputype::CPU_TYPE_ARM64 => Arch::Aarch64,
        goblin::mach::cputype::CPU_TYPE_X86 => Arch::X86,
        goblin::mach::cputype::CPU_TYPE_ARM => Arch::Arm,
        _ => Arch::Other,
    };
    let little_endian = macho.little_endian;

    let mut sections = Vec::new();
    let mut text_addr = 0u64;
    let mut pcln: Option<(usize, usize, u64)> = None;

    for segment in macho.segments.iter() {
        let segname = segment.name().unwrap_or("").to_string();
        for section in segment.sections().map_err(Error::Goblin)? {
            let (sect, _data) = section;
            let sectname = sect.name().unwrap_or("").to_string();
            let kind = classify_mach_section(&segname, &sectname);
            let s = Section {
                name: format!("{segname},{sectname}"),
                kind,
                file_offset: sect.offset as usize,
                file_size: sect.size as usize,
                addr: sect.addr,
                vmsize: sect.size,
            };
            if kind == SectionKind::Text && text_addr == 0 {
                text_addr = s.addr;
            }
            if kind == SectionKind::Pclntab {
                pcln = Some((s.file_offset, s.file_size, s.addr));
            }
            sections.push(s);
        }
    }

    let (pclntab_offset, pclntab_size, pclntab_addr) = match pcln {
        Some(v) => v,
        None => {
            let (off, size) = locate_pclntab(bytes, &sections, text_addr, little_endian)?;
            let addr = addr_for_offset(&sections, off).unwrap_or(0);
            (off, size, addr)
        }
    };

    Ok(Described {
        container: Container::MachO,
        arch,
        little_endian,
        sections,
        pclntab_offset,
        pclntab_size,
        pclntab_addr,
        text_addr,
    })
}

fn classify_mach_section(segname: &str, sectname: &str) -> SectionKind {
    if matches!(sectname, "__gopclntab" | "gopclntab") {
        return SectionKind::Pclntab;
    }
    match (segname, sectname) {
        ("__TEXT", "__text") => SectionKind::Text,
        ("__TEXT", "__rodata") | ("__DATA_CONST", "__const") | ("__TEXT", "__const") => {
            SectionKind::ReadOnlyData
        }
        ("__DATA", "__data") => SectionKind::Data,
        ("__DATA", "__noptrdata") => SectionKind::NoPtrData,
        ("__DATA", "__bss") | ("__DATA", "__noptrbss") => SectionKind::Bss,
        _ => SectionKind::Other,
    }
}

fn describe_pe(bytes: &[u8], pe: goblin::pe::PE<'_>) -> Result<Described> {
    let arch = match pe.header.coff_header.machine {
        goblin::pe::header::COFF_MACHINE_X86_64 => Arch::X86_64,
        goblin::pe::header::COFF_MACHINE_ARM64 => Arch::Aarch64,
        goblin::pe::header::COFF_MACHINE_X86 => Arch::X86,
        goblin::pe::header::COFF_MACHINE_ARM => Arch::Arm,
        _ => Arch::Other,
    };
    let little_endian = true;

    let image_base = pe
        .header
        .optional_header
        .map(|h| h.windows_fields.image_base)
        .unwrap_or(0);

    let mut sections = Vec::new();
    let mut text_addr = 0u64;
    let mut pcln: Option<(usize, usize, u64)> = None;

    for sect in &pe.sections {
        let name = sect.name().unwrap_or("").to_string();
        let kind = classify_pe_section(&name, sect.characteristics);
        // A PE section's address is image_base plus a relative virtual address,
        // both read from the file. A crafted image_base near u64::MAX overflows
        // this add; saturate so a hostile header yields an out-of-range address
        // that no real vaddr lookup matches, rather than panicking.
        let addr = image_base.saturating_add(sect.virtual_address as u64);
        let s = Section {
            name: name.clone(),
            kind,
            file_offset: sect.pointer_to_raw_data as usize,
            file_size: sect.size_of_raw_data as usize,
            addr,
            vmsize: sect.virtual_size as u64,
        };
        if kind == SectionKind::Text && text_addr == 0 {
            text_addr = s.addr;
        }
        if name == ".gopclntab" || name == "gopclntab" || name.starts_with(".gopclntab") {
            pcln = Some((s.file_offset, s.file_size, s.addr));
        }
        sections.push(s);
    }

    let (pclntab_offset, pclntab_size, pclntab_addr) = match pcln {
        Some(v) => v,
        None => {
            let (off, size) = locate_pclntab(bytes, &sections, text_addr, little_endian)?;
            let addr = addr_for_offset(&sections, off).unwrap_or(0);
            (off, size, addr)
        }
    };

    Ok(Described {
        container: Container::Pe,
        arch,
        little_endian,
        sections,
        pclntab_offset,
        pclntab_size,
        pclntab_addr,
        text_addr,
    })
}

fn classify_pe_section(name: &str, characteristics: u32) -> SectionKind {
    use goblin::pe::section_table::*;
    const EXEC: u32 = IMAGE_SCN_MEM_EXECUTE;
    const WRITE: u32 = IMAGE_SCN_MEM_WRITE;
    if name == ".gopclntab" || name == "gopclntab" || name.starts_with(".gopclntab") {
        return SectionKind::Pclntab;
    }
    match name {
        ".text" => SectionKind::Text,
        ".rdata" => SectionKind::ReadOnlyData,
        ".data" => SectionKind::Data,
        ".noptrdata" => SectionKind::NoPtrData,
        ".bss" | ".noptrbss" => SectionKind::Bss,
        _ => {
            if characteristics & EXEC != 0 {
                SectionKind::Text
            } else if characteristics & WRITE != 0 {
                SectionKind::Data
            } else {
                SectionKind::ReadOnlyData
            }
        }
    }
}

fn addr_for_offset(sections: &[Section], offset: usize) -> Option<u64> {
    for s in sections {
        // file_offset, file_size, and addr all come from the section header, so
        // a crafted header can drive either add past its type's range; saturate
        // both so a hostile section is skipped rather than overflowing.
        if offset >= s.file_offset && offset < s.file_offset.saturating_add(s.file_size) {
            let delta = (offset - s.file_offset) as u64;
            return Some(s.addr.saturating_add(delta));
        }
    }
    None
}

const PCLNTAB_MAGIC_1_20: [u8; 4] = [0xf1, 0xff, 0xff, 0xff];
const PCLNTAB_MAGIC_1_20_BE: [u8; 4] = [0xff, 0xff, 0xff, 0xf1];
const PCLNTAB_MAGIC_1_18: [u8; 4] = [0xf0, 0xff, 0xff, 0xff];
const PCLNTAB_MAGIC_1_18_BE: [u8; 4] = [0xff, 0xff, 0xff, 0xf0];

fn scan_for_magic(bytes: &[u8], little_endian: bool) -> Result<(usize, usize)> {
    let candidates: [[u8; 4]; 2] = if little_endian {
        [PCLNTAB_MAGIC_1_20, PCLNTAB_MAGIC_1_18]
    } else {
        [PCLNTAB_MAGIC_1_20_BE, PCLNTAB_MAGIC_1_18_BE]
    };

    let mut best: Option<usize> = None;
    for magic in &candidates {
        let mut search_from = 0usize;
        while let Some(found) = find_subslice(&bytes[search_from..], magic) {
            let offset = search_from + found;
            if offset + 8 > bytes.len() {
                break;
            }
            let pad_ok = bytes[offset + 4] == 0 && bytes[offset + 5] == 0;
            let quantum = bytes[offset + 6];
            let ptrsize = bytes[offset + 7];
            if pad_ok && matches!(quantum, 1 | 2 | 4) && matches!(ptrsize, 4 | 8) {
                best = Some(best.map(|b| b.min(offset)).unwrap_or(offset));
                break;
            }
            search_from = offset + 4;
        }
    }
    match best {
        Some(offset) => Ok((offset, bytes.len() - offset)),
        None => Err(Error::NoPclntab),
    }
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// Locate the pclntab when no named section points at it: try the fixed-magic
/// scan first, then a magic-independent structural scan. garble rewrites the
/// pcHeader magic to a per-build random value, so on a Windows PE (which has no
/// named pclntab section) the magic scan finds nothing; the structural scan
/// recovers the header by its shape instead. The same fallback helps any
/// container whose section table was stripped.
fn locate_pclntab(
    bytes: &[u8],
    sections: &[Section],
    text_addr: u64,
    little_endian: bool,
) -> Result<(usize, usize)> {
    match scan_for_magic(bytes, little_endian) {
        Ok(found) => Ok(found),
        Err(_) => scan_for_pcheader(bytes, sections, text_addr, little_endian),
    }
}

fn read_uint_at(bytes: &[u8], off: usize, ptr_size: usize, little_endian: bool) -> Option<u64> {
    let slice = bytes.get(off..off.checked_add(ptr_size)?)?;
    let mut v: u64 = 0;
    if little_endian {
        for (i, &b) in slice.iter().enumerate() {
            v |= (b as u64) << (8 * i);
        }
    } else {
        for &b in slice {
            v = (v << 8) | b as u64;
        }
    }
    Some(v)
}

/// Magic-independent pcHeader discovery. Slides a pointer-aligned window over
/// the data-bearing sections and accepts an offset whose bytes form a valid Go
/// 1.18+ pcHeader: zero pad bytes, a sane quantum and pointer size, the five
/// table offsets strictly increasing and inside the file, and a textStart that
/// lands in a recovered text section. The offset-ordering and textStart checks
/// are what keep this from matching arbitrary data: a bare pad/quantum/ptrsize
/// test alone would produce false positives across megabytes of `.rdata`.
fn scan_for_pcheader(
    bytes: &[u8],
    sections: &[Section],
    _text_addr: u64,
    little_endian: bool,
) -> Result<(usize, usize)> {
    for s in sections {
        // The pclntab lives in read-only or data regions (on PE it sits inside
        // .rdata). Skip code, bss, and anything without file bytes.
        match s.kind {
            SectionKind::ReadOnlyData
            | SectionKind::Data
            | SectionKind::NoPtrData
            | SectionKind::Pclntab
            | SectionKind::Other => {}
            SectionKind::Text | SectionKind::Bss => continue,
        }
        let start = s.file_offset.min(bytes.len());
        let end = s.file_offset.saturating_add(s.file_size).min(bytes.len());
        // pcHeaders are pointer-aligned; step by 8 from an aligned start.
        let mut off = start + (start % 8 == 0).then_some(0).unwrap_or(8 - start % 8);
        while off + 8 <= end {
            if let Some(size) = pcheader_at(bytes, off, sections, little_endian) {
                return Ok((off, size));
            }
            off += 8;
        }
    }
    Err(Error::NoPclntab)
}

/// Validate that the bytes at `off` look like a pcHeader and return the implied
/// pclntab size (bytes from `off` to end of file) when they do.
fn pcheader_at(
    bytes: &[u8],
    off: usize,
    sections: &[Section],
    little_endian: bool,
) -> Option<usize> {
    if bytes.get(off + 4)? != &0 || bytes.get(off + 5)? != &0 {
        return None;
    }
    let quantum = *bytes.get(off + 6)?;
    let ptr_size = *bytes.get(off + 7)?;
    if !matches!(quantum, 1 | 2 | 4) || !matches!(ptr_size, 4 | 8) {
        return None;
    }
    let ps = ptr_size as usize;
    // Need the full Go 1.18+ header: the 8-byte prefix plus eight pointer-sized
    // fields (nfunc, nfiles, textStart, then the five table offsets).
    let header_end = off.checked_add(8 + 8 * ps)?;
    if header_end > bytes.len() {
        return None;
    }
    let text_start = read_uint_at(bytes, off + 8 + 2 * ps, ps, little_endian)?;
    let funcname = read_uint_at(bytes, off + 8 + 3 * ps, ps, little_endian)?;
    let cu = read_uint_at(bytes, off + 8 + 4 * ps, ps, little_endian)?;
    let filetab = read_uint_at(bytes, off + 8 + 5 * ps, ps, little_endian)?;
    let pctab = read_uint_at(bytes, off + 8 + 6 * ps, ps, little_endian)?;
    let pcln = read_uint_at(bytes, off + 8 + 7 * ps, ps, little_endian)?;
    // The table offsets are relative to the pcHeader base and must climb in
    // order and stay inside the bytes that follow.
    if !(funcname < cu && cu < filetab && filetab < pctab && pctab < pcln) {
        return None;
    }
    let available = (bytes.len() - off) as u64;
    if pcln >= available {
        return None;
    }
    // textStart must land in a recovered text section, which separates a real
    // header from coincidental data with climbing offsets. A zero textStart is
    // accepted: every Windows PE leaves the field zero and the runtime resolves
    // the text base from moduledata instead, so rejecting it discards the real
    // header on the one platform the structural scan exists for. The parser
    // already tolerates a zero textStart the same way; the offset-ordering check
    // above is what carries the no-false-positive guarantee here.
    let text_ok = text_start == 0
        || sections.iter().any(|t| {
            t.kind == SectionKind::Text
                && text_start >= t.addr
                && text_start < t.addr.saturating_add(t.vmsize.max(t.file_size as u64))
        });
    if !text_ok {
        return None;
    }
    Some(bytes.len() - off)
}

fn finish(bytes: Vec<u8>, d: Described) -> Result<GoBinary> {
    if d.pclntab_offset >= bytes.len() || d.pclntab_offset + d.pclntab_size > bytes.len() {
        return Err(Error::BadPclntab {
            offset: d.pclntab_offset,
            reason: format!(
                "section bounds out of range (file is {} bytes)",
                bytes.len()
            ),
        });
    }
    Ok(GoBinary {
        bytes,
        container: d.container,
        arch: d.arch,
        little_endian: d.little_endian,
        sections: d.sections,
        pclntab_offset: d.pclntab_offset,
        pclntab_size: d.pclntab_size,
        pclntab_addr: d.pclntab_addr,
        text_addr: d.text_addr,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sec(name: &str, kind: SectionKind) -> Section {
        Section {
            name: name.to_string(),
            kind,
            file_offset: 0,
            file_size: 1,
            addr: 0x1000,
            vmsize: 1,
        }
    }

    #[test]
    fn ptr_bearing_classifies_go_sections_by_name_first() {
        // Name-driven: a section literally called .noptrdata or
        // .noptrbss is noptr regardless of how the kind classifier
        // collapsed it.
        assert_eq!(
            sec(".noptrdata", SectionKind::NoPtrData).ptr_bearing(),
            Some(false)
        );
        assert_eq!(
            sec(".noptrbss", SectionKind::Bss).ptr_bearing(),
            Some(false)
        );
        // The unsplit .data / .bss are ptr-bearing per Go GC model.
        assert_eq!(sec(".data", SectionKind::Data).ptr_bearing(), Some(true));
        assert_eq!(sec(".bss", SectionKind::Bss).ptr_bearing(), Some(true));
        // rodata / pclntab carry no live pointers the GC walks.
        assert_eq!(
            sec(".rodata", SectionKind::ReadOnlyData).ptr_bearing(),
            Some(false)
        );
        assert_eq!(
            sec(".gopclntab", SectionKind::Pclntab).ptr_bearing(),
            Some(false)
        );
        // Text and Other have no meaningful ptr classification.
        assert_eq!(sec(".text", SectionKind::Text).ptr_bearing(), None);
        assert_eq!(sec(".shstrtab", SectionKind::Other).ptr_bearing(), None);
    }

    #[test]
    fn writable_matches_runtime_protection_bits() {
        assert_eq!(
            sec(".rodata", SectionKind::ReadOnlyData).writable(),
            Some(false)
        );
        assert_eq!(sec(".text", SectionKind::Text).writable(), Some(false));
        assert_eq!(
            sec(".gopclntab", SectionKind::Pclntab).writable(),
            Some(false)
        );
        assert_eq!(sec(".data", SectionKind::Data).writable(), Some(true));
        assert_eq!(sec(".bss", SectionKind::Bss).writable(), Some(true));
        assert_eq!(
            sec(".noptrdata", SectionKind::NoPtrData).writable(),
            Some(true)
        );
        assert_eq!(sec(".shstrtab", SectionKind::Other).writable(), None);
    }
}
