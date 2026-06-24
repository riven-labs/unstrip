//! Container probe: what can be said about a binary even when Go metadata
//! recovery fails. Container, architecture, the section table, per-section and
//! whole-file entropy, trailing overlay, and a packer/obfuscation verdict.
//!
//! This is the honest fallback for a packed, encrypted, or non-Go binary. When
//! the pclntab cannot be found, returning a bare "no pclntab" error tells the
//! analyst nothing; a probe tells them what the file *is* and why Go recovery
//! lost -- the Detect-It-Easy move. The probe never depends on Go structures,
//! so it succeeds on any input goblin recognizes as a container.

use crate::error::Error;
use crate::Result;
use goblin::Object;

/// One section/segment as seen in the container header, with the Shannon
/// entropy of its on-disk bytes. High entropy in an executable section is the
/// classic packed/encrypted signal.
#[derive(Debug, Clone)]
pub struct SectionInfo {
    pub name: String,
    pub vaddr: u64,
    pub vsize: u64,
    pub file_size: usize,
    /// Shannon entropy of the section's file bytes, 0.0..=8.0 bits per byte.
    pub entropy: f64,
    pub executable: bool,
}

/// A container-level summary that does not depend on any Go metadata.
#[derive(Debug, Clone)]
pub struct ContainerProbe {
    pub container: &'static str,
    pub arch: String,
    pub bits: u32,
    pub little_endian: bool,
    pub file_size: usize,
    /// Shannon entropy of the whole file, 0.0..=8.0 bits per byte.
    pub file_entropy: f64,
    pub sections: Vec<SectionInfo>,
    /// Bytes after the end of the last section's file range (a PE overlay, an
    /// appended archive, a second-stage payload).
    pub overlay_size: usize,
    /// Whether a Go pclntab section is present by name (it may still be findable
    /// by magic scan even when this is false).
    pub has_go_pclntab: bool,
    /// A short verdict when the layout looks packed/obfuscated, else None.
    pub packer: Option<String>,
}

/// Shannon entropy in bits per byte over a byte slice.
pub fn entropy(bytes: &[u8]) -> f64 {
    if bytes.is_empty() {
        return 0.0;
    }
    let mut counts = [0u64; 256];
    for &b in bytes {
        counts[b as usize] += 1;
    }
    let len = bytes.len() as f64;
    let mut h = 0.0;
    for &c in counts.iter() {
        if c > 0 {
            let p = c as f64 / len;
            h -= p * p.log2();
        }
    }
    h
}

/// Known packer/protector section or segment names. The match is the verdict.
fn packer_by_section_name(name: &str) -> Option<&'static str> {
    let n = name.to_ascii_lowercase();
    let table: &[(&str, &str)] = &[
        ("upx", "UPX"),
        (".aspack", "ASPack"),
        (".adata", "ASPack"),
        (".petite", "Petite"),
        (".vmp", "VMProtect"),
        ("themida", "Themida/WinLicense"),
        (".winlice", "Themida/WinLicense"),
        (".enigma", "Enigma Protector"),
        (".mpress", "MPRESS"),
        (".nsp", "NsPack"),
        (".pelock", "PELock"),
        (".y0da", "yoda"),
        (".taz", "PESpin"),
    ];
    for (needle, label) in table {
        if n.contains(needle) {
            return Some(label);
        }
    }
    None
}

/// Decide a packer/obfuscation verdict from the section table and entropy.
fn packer_verdict(
    sections: &[SectionInfo],
    has_go_pclntab: bool,
    file_entropy: f64,
) -> Option<String> {
    for s in sections {
        if let Some(label) = packer_by_section_name(&s.name) {
            return Some(format!("{label} (section `{}`)", s.name));
        }
    }
    // A high-entropy executable section is the textbook packed/encrypted signal.
    let exec_hi = sections
        .iter()
        .filter(|s| s.executable && s.file_size >= 1024)
        .max_by(|a, b| {
            a.entropy
                .partial_cmp(&b.entropy)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
    if let Some(s) = exec_hi {
        if s.entropy >= 7.2 {
            return Some(format!(
                "high-entropy executable section `{}` ({:.2} bits/byte); likely packed or encrypted",
                s.name, s.entropy
            ));
        }
    }
    // No Go pclntab section and a high-entropy file as a whole: still worth
    // flagging, since a clean Go binary is mostly low-entropy code and tables.
    if !has_go_pclntab && file_entropy >= 7.2 {
        return Some(format!(
            "no Go pclntab section and high whole-file entropy ({file_entropy:.2} bits/byte); likely packed or encrypted"
        ));
    }
    None
}

fn slice(bytes: &[u8], off: usize, size: usize) -> &[u8] {
    let start = off.min(bytes.len());
    let end = off.saturating_add(size).min(bytes.len());
    &bytes[start..end]
}

fn is_go_pclntab_name(name: &str) -> bool {
    matches!(name, ".gopclntab" | "__gopclntab" | "gopclntab")
}

fn finish(
    container: &'static str,
    arch: String,
    bits: u32,
    little_endian: bool,
    bytes: &[u8],
    sections: Vec<SectionInfo>,
    max_file_end: usize,
) -> ContainerProbe {
    let file_entropy = entropy(bytes);
    let has_go_pclntab = sections.iter().any(|s| is_go_pclntab_name(&s.name));
    let overlay_size = bytes.len().saturating_sub(max_file_end);
    let packer = packer_verdict(&sections, has_go_pclntab, file_entropy);
    ContainerProbe {
        container,
        arch,
        bits,
        little_endian,
        file_size: bytes.len(),
        file_entropy,
        sections,
        overlay_size,
        has_go_pclntab,
        packer,
    }
}

/// Probe a binary's container without touching any Go metadata. Errors only if
/// the bytes are not a recognized single-arch container.
pub fn probe(bytes: &[u8]) -> Result<ContainerProbe> {
    match Object::parse(bytes)? {
        Object::Elf(elf) => Ok(probe_elf(bytes, elf)),
        Object::Mach(goblin::mach::Mach::Binary(m)) => Ok(probe_mach(bytes, m)),
        Object::Mach(goblin::mach::Mach::Fat(_)) => {
            // The fat wrapper itself carries no sections; the caller parses a
            // slice. A probe of the raw fat bytes would be meaningless.
            Err(Error::UnknownContainer)
        }
        Object::PE(pe) => Ok(probe_pe(bytes, pe)),
        _ => Err(Error::UnknownContainer),
    }
}

fn probe_elf(bytes: &[u8], elf: goblin::elf::Elf<'_>) -> ContainerProbe {
    use goblin::elf::header::*;
    use goblin::elf::section_header::SHF_EXECINSTR;
    let arch = match elf.header.e_machine {
        EM_X86_64 => "x86-64",
        EM_AARCH64 => "aarch64",
        EM_386 => "i386",
        EM_ARM => "arm",
        EM_S390 => "s390x",
        EM_PPC64 => "ppc64",
        EM_MIPS => "mips",
        EM_RISCV => "riscv",
        0x102 => "loongarch", // EM_LOONGARCH, not in this goblin's constants
        _ => "unknown",
    }
    .to_string();
    let bits = if elf.is_64 { 64 } else { 32 };
    let mut sections = Vec::new();
    let mut max_file_end = 0usize;
    for sh in elf.section_headers.iter() {
        let name = elf.shdr_strtab.get_at(sh.sh_name).unwrap_or("").to_string();
        // NOBITS (.bss) occupies no file bytes; skip its file range/entropy.
        let occupies_file = sh.sh_type != goblin::elf::section_header::SHT_NOBITS;
        let fsize = if occupies_file {
            sh.sh_size as usize
        } else {
            0
        };
        let data = slice(bytes, sh.sh_offset as usize, fsize);
        if occupies_file {
            max_file_end = max_file_end.max((sh.sh_offset as usize).saturating_add(fsize));
        }
        sections.push(SectionInfo {
            name,
            vaddr: sh.sh_addr,
            vsize: sh.sh_size,
            file_size: data.len(),
            entropy: entropy(data),
            executable: (sh.sh_flags & SHF_EXECINSTR as u64) != 0,
        });
    }
    finish(
        "ELF",
        arch,
        bits,
        elf.little_endian,
        bytes,
        sections,
        max_file_end,
    )
}

fn probe_mach(bytes: &[u8], macho: goblin::mach::MachO<'_>) -> ContainerProbe {
    use goblin::mach::constants::cputype::*;
    let arch = match macho.header.cputype {
        CPU_TYPE_X86_64 => "x86-64",
        CPU_TYPE_ARM64 => "arm64",
        CPU_TYPE_X86 => "i386",
        CPU_TYPE_ARM => "arm",
        _ => "unknown",
    }
    .to_string();
    let bits = if macho.is_64 { 64 } else { 32 };
    let mut sections = Vec::new();
    let mut max_file_end = 0usize;
    for seg in macho.segments.iter() {
        let seg_exec = seg.name().map(|n| n == "__TEXT").unwrap_or(false);
        if let Ok(sects) = seg.sections() {
            for (sect, _data) in sects {
                let name = sect.name().unwrap_or("").to_string();
                let off = sect.offset as usize;
                let size = sect.size as usize;
                let data = slice(bytes, off, size);
                max_file_end = max_file_end.max(off.saturating_add(size));
                let executable =
                    seg_exec || sect.flags & goblin::mach::constants::S_ATTR_PURE_INSTRUCTIONS != 0;
                sections.push(SectionInfo {
                    name,
                    vaddr: sect.addr,
                    vsize: sect.size,
                    file_size: data.len(),
                    entropy: entropy(data),
                    executable,
                });
            }
        }
    }
    finish(
        "Mach-O",
        arch,
        bits,
        macho.little_endian,
        bytes,
        sections,
        max_file_end,
    )
}

fn probe_pe(bytes: &[u8], pe: goblin::pe::PE<'_>) -> ContainerProbe {
    use goblin::pe::section_table::IMAGE_SCN_MEM_EXECUTE;
    let arch = match pe.header.coff_header.machine {
        0x8664 => "x86-64",
        0x14c => "i386",
        0xaa64 => "arm64",
        0x1c0 | 0x1c4 => "arm",
        _ => "unknown",
    }
    .to_string();
    let bits = if pe.is_64 { 64 } else { 32 };
    let mut sections = Vec::new();
    let mut max_file_end = 0usize;
    for s in pe.sections.iter() {
        let name = s.name().unwrap_or("").trim_end_matches('\0').to_string();
        let off = s.pointer_to_raw_data as usize;
        let size = s.size_of_raw_data as usize;
        let data = slice(bytes, off, size);
        max_file_end = max_file_end.max(off.saturating_add(size));
        sections.push(SectionInfo {
            name,
            vaddr: s.virtual_address as u64,
            vsize: s.virtual_size as u64,
            file_size: data.len(),
            entropy: entropy(data),
            executable: s.characteristics & IMAGE_SCN_MEM_EXECUTE != 0,
        });
    }
    finish("PE", arch, bits, true, bytes, sections, max_file_end)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entropy_bounds() {
        assert_eq!(entropy(&[]), 0.0);
        assert_eq!(entropy(&[7, 7, 7, 7]), 0.0); // single symbol -> 0 bits
                                                 // A uniform 0..=255 ramp uses every symbol once -> 8 bits/byte.
        let ramp: Vec<u8> = (0..=255).collect();
        assert!((entropy(&ramp) - 8.0).abs() < 1e-9);
    }

    #[test]
    fn packer_name_table_matches_upx() {
        assert_eq!(packer_by_section_name("UPX0"), Some("UPX"));
        assert_eq!(packer_by_section_name(".vmp0"), Some("VMProtect"));
        assert_eq!(packer_by_section_name(".text"), None);
    }

    #[test]
    fn high_entropy_exec_section_flags_packed() {
        let s = vec![SectionInfo {
            name: ".text".to_string(),
            vaddr: 0x1000,
            vsize: 4096,
            file_size: 4096,
            entropy: 7.9,
            executable: true,
        }];
        assert!(packer_verdict(&s, false, 6.0).is_some());
        // A normal low-entropy text section is not flagged.
        let s2 = vec![SectionInfo {
            entropy: 6.0,
            ..s[0].clone()
        }];
        assert!(packer_verdict(&s2, true, 6.0).is_none());
    }
}
