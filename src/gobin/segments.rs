//! An ELF read through its file header and program headers alone: the view the
//! kernel loader takes. goblin's full parse also walks the section header table
//! (and the dynamic segment), so a file whose section table points outside the
//! file (damaged on purpose as an anti-analysis move, or cut short by a
//! truncated download) fails to parse at all, although the loader would map it.
//! Go's own tools and `readelf -l` read such a file from its segments; this does
//! the same, so the pclntab can still be searched for in the loadable bytes and
//! the probe can still name the architecture and the segments.

use goblin::elf::program_header::{ProgramHeader, PF_W, PF_X, PT_LOAD};
use goblin::elf::Elf;

use super::{Section, SectionKind};

/// An ELF's loadable segments, with the header facts the loader and the probe
/// need.
pub(crate) struct Segments {
    pub e_machine: u16,
    pub is_64: bool,
    pub little_endian: bool,
    /// The PT_LOAD program headers, in file order.
    pub loads: Vec<ProgramHeader>,
    /// Where the section header table ends according to the file header, when it
    /// names one (`e_shoff + e_shnum * e_shentsize`).
    pub section_table_end: Option<u64>,
    /// The end of the furthest PT_LOAD segment's file bytes. Larger than the
    /// file length when the file is truncated: the loader could not map it.
    pub load_end: u64,
}

/// Read an ELF's file header and program headers, or None when the bytes are not
/// an ELF or the program header table itself does not fit in the file (without
/// it there is nothing the loader could map either).
pub(crate) fn read(bytes: &[u8]) -> Option<Segments> {
    if !bytes.starts_with(&[0x7f, b'E', b'L', b'F']) {
        return None;
    }
    let header = Elf::parse_header(bytes).ok()?;
    let ctx = goblin::container::Ctx::new(header.container().ok()?, header.endianness().ok()?);
    let phoff = usize::try_from(header.e_phoff).ok()?;
    let phnum = header.e_phnum as usize;
    let phdrs = ProgramHeader::parse(bytes, phoff, phnum, ctx).ok()?;
    let ph_end = header
        .e_phoff
        .saturating_add(header.e_phnum as u64 * header.e_phentsize as u64);
    let section_table_end = (header.e_shnum > 0 && header.e_shoff > 0).then(|| {
        header
            .e_shoff
            .saturating_add(header.e_shnum as u64 * header.e_shentsize as u64)
    });
    let loads: Vec<ProgramHeader> = phdrs.into_iter().filter(|p| p.p_type == PT_LOAD).collect();
    let load_end = loads
        .iter()
        .map(|p| p.p_offset.saturating_add(p.p_filesz))
        .max()
        .unwrap_or(0);
    Some(Segments {
        e_machine: header.e_machine,
        is_64: ctx.container.is_big(),
        little_endian: ctx.le.is_little(),
        loads,
        section_table_end,
        load_end: load_end.max(ph_end),
    })
}

/// The coarse section map a set of PT_LOAD segments gives: each loadable
/// segment becomes one section named for what it holds (`.text` for the
/// executable one, `.data` for writable, `.rodata` otherwise), mapping its file
/// offset to its `p_vaddr` exactly as the kernel does. Returns the sections and
/// the executable segment's base address (0 when none is executable).
pub(crate) fn sections_from_loads<'a>(
    loads: impl IntoIterator<Item = &'a ProgramHeader>,
) -> (Vec<Section>, u64) {
    let mut sections = Vec::new();
    let mut text_addr = 0u64;
    for ph in loads {
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
    (sections, text_addr)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// A minimal little-endian ELF64 x86-64 executable: the file header, one
    /// PT_LOAD program header mapping the whole file read+execute at 0x400000,
    /// and a section header table offset that points far outside the file (the
    /// damage this reader exists for). `len` is the total file length.
    pub(crate) fn elf64_bogus_shoff(len: usize) -> Vec<u8> {
        let mut b = vec![0u8; len];
        b[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
        b[4] = 2; // ELFCLASS64
        b[5] = 1; // little endian
        b[6] = 1; // EV_CURRENT
        b[16..18].copy_from_slice(&2u16.to_le_bytes()); // ET_EXEC
        b[18..20].copy_from_slice(&62u16.to_le_bytes()); // EM_X86_64
        b[20..24].copy_from_slice(&1u32.to_le_bytes());
        b[24..32].copy_from_slice(&0x400000u64.to_le_bytes()); // entry
        b[32..40].copy_from_slice(&64u64.to_le_bytes()); // e_phoff
        b[40..48].copy_from_slice(&30_302_232u64.to_le_bytes()); // e_shoff: bogus
        b[52..54].copy_from_slice(&64u16.to_le_bytes()); // e_ehsize
        b[54..56].copy_from_slice(&56u16.to_le_bytes()); // e_phentsize
        b[56..58].copy_from_slice(&1u16.to_le_bytes()); // e_phnum
        b[58..60].copy_from_slice(&64u16.to_le_bytes()); // e_shentsize
        b[60..62].copy_from_slice(&35u16.to_le_bytes()); // e_shnum
        b[62..64].copy_from_slice(&34u16.to_le_bytes()); // e_shstrndx
        let ph = 64;
        b[ph..ph + 4].copy_from_slice(&PT_LOAD.to_le_bytes());
        b[ph + 4..ph + 8].copy_from_slice(&(PF_X | 4).to_le_bytes()); // r-x
        b[ph + 8..ph + 16].copy_from_slice(&0u64.to_le_bytes()); // p_offset
        b[ph + 16..ph + 24].copy_from_slice(&0x400000u64.to_le_bytes()); // p_vaddr
        b[ph + 24..ph + 32].copy_from_slice(&0x400000u64.to_le_bytes()); // p_paddr
        b[ph + 32..ph + 40].copy_from_slice(&(len as u64).to_le_bytes()); // p_filesz
        b[ph + 40..ph + 48].copy_from_slice(&(len as u64).to_le_bytes()); // p_memsz
        b[ph + 48..ph + 56].copy_from_slice(&0x1000u64.to_le_bytes()); // p_align
        b
    }

    #[test]
    fn goblin_rejects_the_bogus_section_table_but_the_segments_read() {
        let b = elf64_bogus_shoff(4096);
        assert!(
            Elf::parse(&b).is_err(),
            "the fixture must reproduce the damage"
        );
        let s = read(&b).expect("program headers are intact");
        assert_eq!(s.e_machine, 62);
        assert!(s.is_64 && s.little_endian);
        assert_eq!(s.loads.len(), 1);
        assert_eq!(s.section_table_end, Some(30_302_232 + 35 * 64));
        assert_eq!(s.load_end, 4096);
        let (sections, text) = sections_from_loads(&s.loads);
        assert_eq!(text, 0x400000);
        assert_eq!(sections.len(), 1);
        assert_eq!(sections[0].kind, SectionKind::Text);
        assert_eq!(sections[0].file_size, 4096);
    }

    #[test]
    fn a_program_header_table_past_the_end_reads_as_nothing() {
        let mut b = elf64_bogus_shoff(4096);
        b[32..40].copy_from_slice(&0x10_0000u64.to_le_bytes()); // e_phoff past EOF
        assert!(read(&b).is_none());
        assert!(read(b"MZ\x90\x00").is_none());
    }
}
