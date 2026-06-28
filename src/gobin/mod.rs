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
    /// Pointer width in bytes, read from the container header (ELF class, PE
    /// magic, Mach-O ABI64 bit) rather than inferred from `arch`. This is correct
    /// even for an arch we don't otherwise name, so 32-bit targets get 4.
    pub ptr_size: usize,
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
        // A Mach-O universal (fat) binary holds several arch slices. Select one
        // and parse it as a standalone Mach-O so every offset is consistent.
        if let Some(slice) = fat_slice(&bytes) {
            return Self::parse(slice);
        }
        let parsed = describe(&bytes)?;
        finish(bytes, parsed)
    }

    pub fn pclntab_slice(&self) -> &[u8] {
        &self.bytes[self.pclntab_offset..self.pclntab_offset + self.pclntab_size]
    }

    pub fn pointer_size(&self) -> usize {
        self.ptr_size
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
        // saturating_add: a crafted section can carry a file_offset/file_size
        // whose sum overflows usize; saturate so the bound stays meaningful
        // instead of wrapping (which would let the range slip through) or
        // panicking on overflow.
        if end_off > s.file_offset.saturating_add(s.file_size) {
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
    ptr_size: usize,
    sections: Vec<Section>,
    pclntab_offset: usize,
    pclntab_size: usize,
    pclntab_addr: u64,
    text_addr: u64,
    /// The section table was stripped and the section map was rebuilt from ELF
    /// program headers. The executable segment's base is only a coarse text
    /// address (it can sit a page below the real `.text`), so `finish` refines it
    /// from `moduledata.text` when that recovers.
    stripped_sections: bool,
}

/// If `bytes` is a Mach-O universal (fat) binary, return the bytes of one arch
/// slice to parse on its own. Prefer amd64 (the arch relift can also
/// decompile), then arm64, then the first slice. Returns None for non-fat
/// input, so the common path pays only a 4-byte magic check.
fn fat_slice(bytes: &[u8]) -> Option<Vec<u8>> {
    // FAT_MAGIC / FAT_MAGIC_64, stored big-endian. (Java class files share
    // 0xcafebabe, so confirm with a real parse below.)
    let fat_magic = matches!(
        bytes.get(0..4),
        Some([0xca, 0xfe, 0xba, 0xbe]) | Some([0xca, 0xfe, 0xba, 0xbf])
    );
    if !fat_magic {
        return None;
    }
    let Ok(Object::Mach(goblin::mach::Mach::Fat(fat))) = Object::parse(bytes) else {
        return None;
    };
    use goblin::mach::cputype::{CPU_TYPE_ARM64, CPU_TYPE_X86_64};
    const MAX_FAT_ARCHES: usize = 64;
    let mut best: Option<(usize, usize, u8)> = None; // (offset, size, rank)
    for arch in fat.iter_arches().take(MAX_FAT_ARCHES).flatten() {
        let rank = match arch.cputype() {
            CPU_TYPE_X86_64 => 0,
            CPU_TYPE_ARM64 => 1,
            _ => 2,
        };
        if best.is_none_or(|(_, _, r)| rank < r) {
            best = Some((arch.offset as usize, arch.size as usize, rank));
        }
    }
    let (off, size, _) = best?;
    let end = off.checked_add(size).filter(|&e| e <= bytes.len())?;
    Some(bytes[off..end].to_vec())
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
    let ptr_size = if elf.is_64 { 8 } else { 4 };

    let mut sections = Vec::new();
    let mut text_addr = 0u64;
    let mut stripped_sections = false;
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

    // A stripped section table (a real anti-analysis move on ELF) leaves
    // `section_headers` empty: with no `.text` the text address stays zero and
    // `addr_for_offset` has nothing to map, so every recovered address comes out
    // relative to zero instead of its load VA -- wrong, and silently so. Rebuild a
    // coarse map from the PT_LOAD program headers, which the loader needs and which
    // malware therefore leaves intact. Each loadable segment maps a file offset to
    // its `p_vaddr` exactly (it is the kernel's own mapping), so `addr_for_offset`
    // becomes correct; the executable segment's base is the text address the
    // pclntab's `textStart` is taken relative to when the header stores zero.
    if sections.is_empty() {
        use goblin::elf::program_header::{PF_W, PF_X, PT_LOAD};
        stripped_sections = true;
        for ph in elf.program_headers.iter() {
            if ph.p_type != PT_LOAD {
                continue;
            }
            let (name, kind) = if ph.p_flags & PF_X != 0 {
                (".text", SectionKind::Text)
            } else if ph.p_flags & PF_W != 0 {
                (".data", SectionKind::Data)
            } else {
                (".rodata", SectionKind::ReadOnlyData)
            };
            if kind == SectionKind::Text && text_addr == 0 {
                text_addr = ph.p_vaddr;
            }
            sections.push(Section {
                name: name.to_string(),
                kind,
                file_offset: ph.p_offset as usize,
                file_size: ph.p_filesz as usize,
                addr: ph.p_vaddr,
                vmsize: ph.p_memsz,
            });
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
        container: Container::Elf,
        arch,
        little_endian,
        ptr_size,
        sections,
        pclntab_offset,
        pclntab_size,
        pclntab_addr,
        text_addr,
        stripped_sections,
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
    let ptr_size = if macho.is_64 { 8 } else { 4 };

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
        ptr_size,
        sections,
        pclntab_offset,
        pclntab_size,
        pclntab_addr,
        text_addr,
        // Mach-O already maps via segments/load commands, which survive a stripped
        // section table, so there is no program-header refinement step here.
        stripped_sections: false,
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
        // Go's Darwin linker places runtime.firstmoduledata in its own
        // __go_module section rather than in __noptrdata as on ELF. Classify it
        // like noptrdata so the moduledata scan looks there; without this,
        // moduledata location (and every itab/type/buildinfo feature that needs
        // it) fails on every Mach-O binary, garbled or not.
        ("__DATA", "__noptrdata") | ("__DATA", "__go_module") => SectionKind::NoPtrData,
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
    let ptr_size = if pe.is_64 { 8 } else { 4 };

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
        ptr_size,
        sections,
        pclntab_offset,
        pclntab_size,
        pclntab_addr,
        text_addr,
        // PE recovers the pclntab structurally and resolves addresses through the
        // section table / image base; no program-header refinement applies.
        stripped_sections: false,
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

fn scan_for_magic(
    bytes: &[u8],
    sections: &[Section],
    little_endian: bool,
) -> Result<(usize, usize)> {
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
            // Validate the whole pcHeader, not just the 8-byte prefix: the magic
            // is only four bytes and turns up in string and rodata by chance. A
            // bare pad/quantum/ptrsize check accepts those false positives, and
            // the functab walk later fails with a confusing internal offset
            // error (a candidate whose funcdata offset is ASCII text). Requiring
            // the full structural check -- climbing table offsets inside the
            // file, textStart in a text section -- rejects the stray match so the
            // scan continues to the real header, or reports none found.
            if pcheader_at(bytes, offset, sections, little_endian).is_some() {
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
    if let Ok(found) = scan_for_magic(bytes, sections, little_endian) {
        return Ok(found);
    }
    if let Ok(found) = scan_for_pcheader(bytes, sections, text_addr, little_endian) {
        return Ok(found);
    }
    // Both scans look for the Go 1.18+ pcHeader shape. Before reporting "no
    // pclntab" -- which an analyst reads as "not a Go binary" -- check for a
    // pre-1.18 pclntab we recognize but do not parse. Naming the version turns a
    // misleading container fallback into the honest "this is Go 1.16/1.17, which
    // relift does not yet read". Consulted last, so it never downgrades a binary
    // the real scans could parse, and a garble-rewritten (random) magic never
    // reaches it.
    if let Some(magic) = detect_pre118_magic(bytes, sections, little_endian) {
        if let Some(version) = crate::pclntab::unsupported_pre118_magic(magic) {
            return Err(Error::UnsupportedPclntabVersion { magic, version });
        }
    }
    Err(Error::NoPclntab)
}

/// Pre-1.18 pclntab magics (little-endian on disk; the high byte differs from the
/// 1.18/1.20 magics). 0xfffffffa is Go 1.16/1.17; 0xfffffffb is Go 1.2-1.15.
const PCLNTAB_MAGIC_1_16: [u8; 4] = [0xfa, 0xff, 0xff, 0xff];
const PCLNTAB_MAGIC_1_16_BE: [u8; 4] = [0xff, 0xff, 0xff, 0xfa];
const PCLNTAB_MAGIC_1_2: [u8; 4] = [0xfb, 0xff, 0xff, 0xff];
const PCLNTAB_MAGIC_1_2_BE: [u8; 4] = [0xff, 0xff, 0xff, 0xfb];

/// Recognize (do not parse) a pre-1.18 pclntab and return its magic. Deliberately
/// shallow: the pre-1.18 on-disk layout differs from 1.18+ (1.16/1.17 drop the
/// `textStart` field; 1.2-1.15 have no climbing offset table at all), so
/// `pcheader_at` -- which encodes the 1.18+ shape -- cannot validate them. We only
/// need to recognize the format to choose an honest error message, so validate just
/// the version-independent prefix every pclntab since Go 1.2 shares: the 4-byte
/// magic, two zero pad bytes, a quantum in {1,2,4}, and a pointer size in {4,8}.
/// The match must sit in a data-bearing section. False positives are bounded and
/// far less harmful than the alternative: a real Go binary mislabeled "not Go".
fn detect_pre118_magic(bytes: &[u8], sections: &[Section], little_endian: bool) -> Option<u32> {
    let candidates: [([u8; 4], u32); 2] = if little_endian {
        [
            (PCLNTAB_MAGIC_1_16, 0xfffffffa),
            (PCLNTAB_MAGIC_1_2, 0xfffffffb),
        ]
    } else {
        [
            (PCLNTAB_MAGIC_1_16_BE, 0xfffffffa),
            (PCLNTAB_MAGIC_1_2_BE, 0xfffffffb),
        ]
    };
    for s in sections {
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
        for (magic_bytes, magic) in &candidates {
            let mut from = start;
            while from < end {
                let Some(found) = find_subslice(&bytes[from..end], magic_bytes) else {
                    break;
                };
                let off = from + found;
                // Version-independent pcHeader prefix shared by every pclntab since
                // Go 1.2: magic(4), two zero pad bytes, quantum, pointer size.
                if off + 8 <= bytes.len()
                    && bytes[off + 4] == 0
                    && bytes[off + 5] == 0
                    && matches!(bytes[off + 6], 1 | 2 | 4)
                    && matches!(bytes[off + 7], 4 | 8)
                {
                    return Some(*magic);
                }
                from = off + 4;
            }
        }
    }
    None
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
        let mut off = start + if start % 8 == 0 { 0 } else { 8 - start % 8 };
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
    // Clamp every section's file range to the bytes we actually hold. A crafted
    // header can declare a file_offset/file_size past the end of the input (or
    // one whose sum overflows usize); without this, any consumer that slices
    // `bytes[file_offset..file_offset + file_size]` panics. Clamp once here so
    // every reader downstream is safe. vmsize (the in-memory size) is left as
    // declared -- only the on-disk range is bounded by the file.
    let len = bytes.len();
    let mut sections = d.sections;
    for s in &mut sections {
        s.file_offset = s.file_offset.min(len);
        s.file_size = s.file_size.min(len - s.file_offset);
    }
    let mut bin = GoBinary {
        bytes,
        container: d.container,
        arch: d.arch,
        little_endian: d.little_endian,
        ptr_size: d.ptr_size,
        sections,
        pclntab_offset: d.pclntab_offset,
        pclntab_size: d.pclntab_size,
        pclntab_addr: d.pclntab_addr,
        text_addr: d.text_addr,
    };

    // When the section table was stripped, `text_addr` is only the executable
    // segment's base, which can sit a page below the real `.text` -- and the
    // pclntab's `textStart` is the value function addresses are taken relative to
    // when it stores zero, so a coarse base shifts every recovered address by that
    // gap. `moduledata.text` is the authoritative text start (`runtime.text`),
    // recovered without the section table by scanning the data for the pclntab
    // pointer. Refine from it when it parses to a plausible value; otherwise keep
    // the segment base, which is still far closer than zero. Best-effort: a failure
    // here never breaks parsing.
    if d.stripped_sections {
        if let Ok(md) = crate::moduledata::ModuleData::locate(&bin) {
            if md.text != 0 {
                bin.text_addr = md.text;
            }
        }
    }

    Ok(bin)
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

    fn data_sec(len: usize) -> Vec<Section> {
        vec![Section {
            name: ".rdata".to_string(),
            kind: SectionKind::ReadOnlyData,
            file_offset: 0,
            file_size: len,
            addr: 0x1000,
            vmsize: len as u64,
        }]
    }

    #[test]
    fn pre118_magic_recognized_for_honest_message() {
        // A pre-1.18 pclntab prefix (magic, two zero pad bytes, quantum, ptr size)
        // in a data section must be recognized so the loader reports the honest
        // "Go 1.16/1.17 unsupported" instead of "no pclntab" (which reads as not-Go).
        let mut bytes = vec![0u8; 256];
        let off = 32;
        bytes[off..off + 4].copy_from_slice(&[0xfa, 0xff, 0xff, 0xff]);
        bytes[off + 6] = 1; // quantum (pad bytes at +4,+5 already zero)
        bytes[off + 7] = 8; // ptr size
        let sections = data_sec(bytes.len());
        assert_eq!(detect_pre118_magic(&bytes, &sections, true), Some(0xfffffffa));
        // The 1.2-1.15 magic is recognized the same way.
        bytes[off] = 0xfb;
        assert_eq!(detect_pre118_magic(&bytes, &sections, true), Some(0xfffffffb));
    }

    #[test]
    fn pre118_detector_avoids_false_positives() {
        let mut bytes = vec![0u8; 256];
        let off = 32;
        bytes[off..off + 4].copy_from_slice(&[0xfa, 0xff, 0xff, 0xff]);
        bytes[off + 7] = 8;
        // A nonzero pad byte means it is not a pcHeader prefix: reject.
        bytes[off + 4] = 0x41;
        assert_eq!(detect_pre118_magic(&bytes, &data_sec(bytes.len()), true), None);
        // A valid prefix sitting in a .text section is skipped (a pclntab never
        // lives in code), so a stray match in executable bytes is not a header.
        bytes[off + 4] = 0;
        bytes[off + 6] = 1;
        let text = vec![Section {
            name: ".text".to_string(),
            kind: SectionKind::Text,
            file_offset: 0,
            file_size: bytes.len(),
            addr: 0x1000,
            vmsize: bytes.len() as u64,
        }];
        assert_eq!(detect_pre118_magic(&bytes, &text, true), None);
        // The 1.18+ magic is not a pre-1.18 magic: this detector ignores it (the
        // real scans handle it), so it never shadows a parseable binary.
        bytes[off..off + 4].copy_from_slice(&[0xf1, 0xff, 0xff, 0xff]);
        assert_eq!(detect_pre118_magic(&bytes, &data_sec(bytes.len()), true), None);
    }

    #[test]
    fn read_at_addr_rejects_overflowing_section_range() {
        // A fuzz-found crash: a crafted section carried a file_offset/file_size
        // whose sum overflows usize, so the bound check `end_off > file_offset +
        // file_size` panicked on the addition before it could reject the read.
        // read_at_addr must return None for any address in such a section, not
        // panic. (Build the GoBinary directly so the bad section bypasses the
        // finish() clamp and exercises read_at_addr's own guard.)
        let bin = GoBinary {
            bytes: vec![0u8; 64],
            container: Container::Elf,
            arch: Arch::X86_64,
            little_endian: true,
            ptr_size: 8,
            sections: vec![Section {
                name: ".text".to_string(),
                kind: SectionKind::Text,
                file_offset: usize::MAX - 16,
                file_size: usize::MAX,
                addr: 0x1000,
                vmsize: usize::MAX as u64,
            }],
            pclntab_offset: 0,
            pclntab_size: 0,
            pclntab_addr: 0,
            text_addr: 0x1000,
        };
        assert_eq!(bin.read_at_addr(0x1000, 16), None);
        assert_eq!(bin.read_at_addr(0x1008, 8), None);
    }

    #[test]
    fn finish_clamps_section_file_range_to_input_length() {
        // finish() must clamp every section's on-disk range to the bytes it
        // holds so downstream `bytes[file_offset..file_offset + file_size]`
        // slices can never run past the end or overflow.
        let d = Described {
            container: Container::Elf,
            arch: Arch::X86_64,
            little_endian: true,
            ptr_size: 8,
            sections: vec![Section {
                name: ".text".to_string(),
                kind: SectionKind::Text,
                file_offset: usize::MAX - 8,
                file_size: usize::MAX,
                addr: 0x1000,
                vmsize: 1,
            }],
            pclntab_offset: 0,
            pclntab_size: 0,
            pclntab_addr: 0,
            text_addr: 0x1000,
            stripped_sections: false,
        };
        let bin = finish(vec![0u8; 100], d).expect("finish");
        let s = &bin.sections[0];
        assert!(s.file_offset <= 100);
        assert!(s.file_offset + s.file_size <= 100);
        // The slice every consumer takes must now be in bounds.
        let _ = &bin.bytes[s.file_offset..s.file_offset + s.file_size];
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
