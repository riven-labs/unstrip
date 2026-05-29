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
        Some(self.file_offset + delta)
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
            let (off, size) = scan_for_magic(bytes, little_endian)?;
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
            let count = fat.iter_arches().count();
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
            let (off, size) = scan_for_magic(bytes, little_endian)?;
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
        let addr = image_base + sect.virtual_address as u64;
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
            let (off, size) = scan_for_magic(bytes, little_endian)?;
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
        if offset >= s.file_offset && offset < s.file_offset + s.file_size {
            let delta = (offset - s.file_offset) as u64;
            return Some(s.addr + delta);
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
