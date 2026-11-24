//! Telling a container's own pclntab from one that belongs to a Go program
//! carried inside the file as data.
//!
//! A container that names no pclntab section (every PE, any ELF or Mach-O
//! without a Go section) is searched by scanning, and the scan accepts the first
//! well-formed pcHeader it meets. When the file carries a Go binary as data, that
//! header can be the embedded program's. Windows and Go 1.26+ builds store a zero
//! `textStart`, so the parser then anchors the embedded function table at the
//! container's own text, and every recovered name lands on unrelated code.
//!
//! A false "embedded" verdict would refuse a real Go binary, so the verdict needs
//! two things. First, no moduledata in the container references the table: the
//! Go runtime finds its pclntab through `runtime.firstmoduledata`, whose first
//! field holds the table's address, so every Go program carries that pointer and
//! a table carried as data has nothing pointing at it from the container's
//! address space. Second, positive evidence that the table describes another
//! image (see [`verdict`]). A table with no reference and no such evidence keeps
//! today's reading.

use goblin::Object;

use super::{parse_container, Arch, GoBinary};
use crate::error::Error;

/// How many scanned pclntab candidates one parse examines before it gives up.
/// Each is a full rescan of the file, and a real file carries a handful of Go
/// images at most, so the cap only bounds hostile inputs.
pub(super) const MAX_CANDIDATES: usize = 8;

/// Functions sampled from the table for the code check.
const CODE_SAMPLES: usize = 64;
/// Fewer sampled functions than this and the code check gives no verdict.
const MIN_CODE_SAMPLES: usize = 16;

/// Container headers tried (parsed with goblin) while looking for the image that
/// encloses an embedded pclntab, nearest first.
const MAX_HEADER_PARSES: usize = 32;

pub(super) enum Verdict {
    /// A moduledata in the container references the table.
    Own,
    /// Nothing references the table, and nothing ties it to another image.
    Unproven,
    /// The table belongs to a Go program carried as data.
    Embedded(Error),
}

/// Judge a pclntab that `bin` found by scanning.
///
/// Embedded only when no moduledata references the table and at least one of
/// these holds, each of which a real Go binary cannot produce:
///
/// - An ELF, PE, or Mach-O header earlier in the file starts an image that
///   covers the table, and that image, parsed on its own, finds its pclntab at
///   exactly this offset. The container's own header sits at offset 0, so it is
///   never the candidate.
/// - The pcHeader disagrees with the container: its pointer size differs from
///   the container's, or its PC quantum does not fit the container's
///   architecture (1 on x86, 4 on ARM). Go's linker writes both from the
///   target it links for.
/// - The code the table maps onto is not Go. See [`code_is_foreign`].
pub(super) fn verdict(bin: &GoBinary) -> Verdict {
    if crate::moduledata::ModuleData::locate(bin).is_ok() {
        return Verdict::Own;
    }
    if let Some(image) = enclosing_image(&bin.bytes, bin.pclntab_offset) {
        return Verdict::Embedded(Error::EmbeddedGoImage {
            offset: image.offset,
            len: Some(image.len),
            pclntab_offset: bin.pclntab_offset,
            goos: image.goos,
            goarch: image.goarch,
        });
    }
    let Some((quantum, ptrsize)) = header_shape(bin) else {
        return Verdict::Unproven;
    };
    if header_disagrees(bin, quantum, ptrsize) || code_is_foreign(bin) {
        return Verdict::Embedded(Error::EmbeddedGoImage {
            offset: bin.pclntab_offset,
            len: None,
            pclntab_offset: bin.pclntab_offset,
            goos: None,
            goarch: goarch_from_header(quantum, ptrsize).map(str::to_string),
        });
    }
    Verdict::Unproven
}

/// The pcHeader's PC quantum and pointer size.
fn header_shape(bin: &GoBinary) -> Option<(u8, u8)> {
    let at = bin.pclntab_offset;
    Some((*bin.bytes.get(at + 6)?, *bin.bytes.get(at + 7)?))
}

fn header_disagrees(bin: &GoBinary, quantum: u8, ptrsize: u8) -> bool {
    if ptrsize as usize != bin.ptr_size {
        return true;
    }
    match bin.arch {
        Arch::X86_64 | Arch::X86 => quantum != 1,
        Arch::Aarch64 | Arch::Arm => quantum != 4,
        // Other architectures use 1, 2, or 4; no single value to hold them to.
        Arch::Other => false,
    }
}

/// The GOARCH the pcHeader alone pins down. Only x86 is unambiguous: quantum 1
/// is x86's alone, while quantum 4 is shared by arm64, ppc64, mips64, riscv64,
/// and loong64.
fn goarch_from_header(quantum: u8, ptrsize: u8) -> Option<&'static str> {
    match (quantum, ptrsize) {
        (1, 8) => Some("amd64"),
        (1, 4) => Some("386"),
        _ => None,
    }
}

/// Whether the code the function table maps onto is not Go.
///
/// Every Go function that may grow its stack opens with the stack-bound check
/// against the goroutine's `stackguard0`, and the compiler emits it in a few
/// fixed shapes per architecture (see [`go_prologue`]). Across the Go 1.16 to
/// 1.27 test binaries (amd64, 386, arm64; ELF, PE, Mach-O; garbled or not) at
/// least 62% of sampled entries start with one; the rest are small leaf
/// functions that skip the check. An entry that lands on unrelated code matches
/// essentially never: the shapes are 4 to 12 specific bytes built around the
/// goroutine register (r14, x28) or Go's TLS slot, which other compilers do not
/// address that way.
///
/// The verdict is "foreign" when fewer than one sampled entry in eight looks like
/// Go (an entry outside every text section counts as not Go). The threshold sits
/// five times below the lowest share seen on real binaries and far above the
/// near-zero share on foreign code, and a table with fewer than
/// [`MIN_CODE_SAMPLES`] functions gives no verdict. Architectures without a known
/// prologue shape fall back to whether the entries land in text at all, which
/// still catches a Go 1.16/1.17 table, whose entries are absolute addresses in
/// the embedded image's own address space.
fn code_is_foreign(bin: &GoBinary) -> bool {
    let Ok(tab) = crate::pclntab::Pclntab::parse(bin) else {
        return false;
    };
    let Ok(n) = usize::try_from(tab.nfunc()) else {
        return false;
    };
    if n < MIN_CODE_SAMPLES {
        return false;
    }
    let samples = n.min(CODE_SAMPLES);
    let mut go_like = 0usize;
    for k in 0..samples {
        // Spread the samples evenly across the table, so one cluster of
        // assembly or leaf functions cannot decide the verdict alone.
        let i = k * n / samples;
        let Some(pc) = tab.functab_addr(i) else {
            continue;
        };
        let Some(code) = bin.text_slice_at(pc, 16) else {
            continue;
        };
        if go_prologue(bin.arch, code).unwrap_or(true) {
            go_like += 1;
        }
    }
    go_like * 8 < samples
}

/// Whether `code` opens with one of the Go compiler's stack-check prologues for
/// `arch`. None for an architecture without a known shape.
fn go_prologue(arch: Arch, code: &[u8]) -> Option<bool> {
    let at = |i: usize, want: &[u8]| code.get(i..i + want.len()) == Some(want);
    Some(match arch {
        Arch::X86_64 => {
            // Go 1.17+ register ABI: cmp rsp, [r14+0x10]; large frames compute
            // the bound first, lea r12, [rsp-N] (disp8 or disp32), then cmp r12,
            // [r14+0x10].
            at(0, &[0x49, 0x3b, 0x66, 0x10])
                || (at(0, &[0x4c, 0x8d, 0x64, 0x24]) && at(5, &[0x4d, 0x3b, 0x66, 0x10]))
                || (at(0, &[0x4c, 0x8d, 0xa4, 0x24]) && at(8, &[0x4d, 0x3b, 0x66, 0x10]))
                // Go 1.16 loads g from TLS first: mov rcx, fs:[x] or gs:[x],
                // or through a TLS offset in memory in position-independent code.
                || at(0, &[0x64, 0x48, 0x8b, 0x0c, 0x25])
                || at(0, &[0x65, 0x48, 0x8b, 0x0c, 0x25])
                || (at(0, &[0x48, 0x8b, 0x0d]) && at(7, &[0x64, 0x48, 0x8b, 0x09]))
        }
        Arch::X86 => {
            // 386 loads g from TLS: mov ecx, gs:[0] (Linux), mov ecx, fs:[0x14]
            // (Windows up to Go 1.21), or mov ecx, [tls index] then mov ecx,
            // fs:[ecx] / gs:[ecx] (Windows from Go 1.22, and PIE).
            at(0, &[0x65, 0x8b, 0x0d])
                || at(0, &[0x64, 0x8b, 0x0d])
                || (at(0, &[0x8b, 0x0d])
                    && (at(6, &[0x64, 0x8b, 0x09]) || at(6, &[0x65, 0x8b, 0x09])))
        }
        Arch::Aarch64 => {
            // ldr xN, [x28, #16] (stackguard0) or [x28, #24]: x28 holds g.
            code.len() >= 4
                && code[0] & 0xe0 == 0x80
                && matches!(code[1], 0x0b | 0x0f)
                && code[2] == 0x40
                && code[3] == 0xf9
        }
        Arch::Arm | Arch::Other => return None,
    })
}

struct Image {
    offset: usize,
    len: usize,
    goos: Option<String>,
    goarch: Option<String>,
}

/// Find an ELF, PE, or Mach-O image inside `bytes` (not at offset 0, which is the
/// container itself) that covers `pclntab_offset` and that, parsed on its own,
/// finds its pclntab exactly there.
fn enclosing_image(bytes: &[u8], pclntab_offset: usize) -> Option<Image> {
    let mut parses = 0usize;
    for start in (1..pclntab_offset.min(bytes.len())).rev() {
        if !looks_like_header(bytes, start) {
            continue;
        }
        parses += 1;
        if parses > MAX_HEADER_PARSES {
            return None;
        }
        let Some(len) = image_len(&bytes[start..]) else {
            continue;
        };
        if start + len <= pclntab_offset {
            continue;
        }
        let Ok(inner) = parse_container(bytes[start..start + len].to_vec(), false) else {
            continue;
        };
        if start + inner.pclntab_offset != pclntab_offset {
            continue;
        }
        let (goos, goarch) = platform_of(&inner);
        return Some(Image {
            offset: start,
            len,
            goos,
            goarch,
        });
    }
    None
}

/// A cheap check before handing `bytes[start..]` to goblin: the format's magic
/// plus the fields that make it a header rather than chance bytes.
fn looks_like_header(bytes: &[u8], start: usize) -> bool {
    let b = &bytes[start..];
    match b {
        // ELF: magic, class 1 or 2, data encoding 1 or 2, version 1.
        [0x7f, b'E', b'L', b'F', 1 | 2, 1 | 2, 1, ..] => true,
        // PE: an MZ stub whose e_lfanew points at the PE signature.
        [b'M', b'Z', ..] => {
            let Some(lfanew) = b.get(0x3c..0x40) else {
                return false;
            };
            let lfanew = u32::from_le_bytes([lfanew[0], lfanew[1], lfanew[2], lfanew[3]]);
            let lfanew = lfanew as usize;
            (0x40..0x1000).contains(&lfanew) && b.get(lfanew..lfanew + 4) == Some(b"PE\0\0")
        }
        // Thin Mach-O, 32 or 64 bit, either byte order.
        [0xce | 0xcf, 0xfa, 0xed, 0xfe, ..] | [0xfe, 0xed, 0xfa, 0xce | 0xcf, ..] => true,
        _ => false,
    }
}

/// The byte extent of the image whose header starts `b`, from its own tables:
/// the furthest file byte any header, segment, or section claims. Clamped to the
/// bytes present, so a truncated image still carves to what is there.
fn image_len(b: &[u8]) -> Option<usize> {
    let end: u64 = match Object::parse(b).ok()? {
        Object::Elf(elf) => {
            let h = &elf.header;
            let mut end = (h.e_ehsize as u64)
                .max(
                    h.e_phoff
                        .saturating_add(h.e_phnum as u64 * h.e_phentsize as u64),
                )
                .max(
                    h.e_shoff
                        .saturating_add(h.e_shnum as u64 * h.e_shentsize as u64),
                );
            for ph in &elf.program_headers {
                end = end.max(ph.p_offset.saturating_add(ph.p_filesz));
            }
            for sh in &elf.section_headers {
                if sh.sh_type != goblin::elf::section_header::SHT_NOBITS {
                    end = end.max(sh.sh_offset.saturating_add(sh.sh_size));
                }
            }
            end
        }
        Object::PE(pe) => {
            let opt = pe.header.optional_header?;
            let mut end = opt.windows_fields.size_of_headers as u64;
            for s in &pe.sections {
                end = end
                    .max((s.pointer_to_raw_data as u64).saturating_add(s.size_of_raw_data as u64));
            }
            // The certificate table's address is a file offset, past the sections.
            if let Some(cert) = opt.data_directories.get_certificate_table() {
                end = end.max((cert.virtual_address as u64).saturating_add(cert.size as u64));
            }
            end
        }
        Object::Mach(goblin::mach::Mach::Binary(m)) => {
            let header = if m.is_64 { 32u64 } else { 28 };
            let mut end = header.saturating_add(m.header.sizeofcmds as u64);
            for seg in m.segments.iter() {
                end = end.max(seg.fileoff.saturating_add(seg.filesize));
            }
            end
        }
        _ => return None,
    };
    let len = usize::try_from(end).ok()?.min(b.len());
    (len > 0).then_some(len)
}

/// GOOS and GOARCH of an embedded image: its buildinfo settings when present,
/// otherwise what its container format and machine say.
fn platform_of(bin: &GoBinary) -> (Option<String>, Option<String>) {
    let settings = crate::buildinfo::BuildInfo::parse(bin)
        .map(|bi| bi.settings)
        .unwrap_or_default();
    let setting = |key: &str| {
        settings
            .iter()
            .find(|s| s.key == key && !s.value.is_empty())
            .map(|s| s.value.clone())
    };
    let goos = setting("GOOS").or_else(|| {
        match bin.container {
            super::Container::Pe => Some("windows"),
            super::Container::MachO => Some("darwin"),
            // ELF serves Linux, the BSDs, Android, and more.
            super::Container::Elf => None,
        }
        .map(str::to_string)
    });
    let goarch = setting("GOARCH").or_else(|| match bin.arch {
        Arch::Other => None,
        arch => Some(arch.as_str().to_string()),
    });
    (goos, goarch)
}

#[cfg(test)]
mod tests {
    use super::super::segments;
    use super::*;

    /// Write a Go 1.20 pcHeader at `off` with a zero textStart (as Windows and Go
    /// 1.26+ builds store it) and `nfunc` functab entries, the first function at
    /// the start of the text and each next one `0x40` further.
    fn put_pcheader(b: &mut [u8], off: usize, ptrsize: u8, nfunc: usize) {
        b[off..off + 4].copy_from_slice(&[0xf1, 0xff, 0xff, 0xff]);
        b[off + 6] = 1; // quantum
        b[off + 7] = ptrsize;
        // nfunc, nfiles, textStart, then the five table offsets, strictly
        // climbing and inside the file.
        let fields: [u64; 8] = [nfunc as u64, 1, 0, 0x60, 0x80, 0xa0, 0xc0, 0xe0];
        let ps = ptrsize as usize;
        for (i, v) in fields.iter().enumerate() {
            let at = off + 8 + i * ps;
            b[at..at + ps].copy_from_slice(&v.to_le_bytes()[..ps]);
        }
        let functab = off + 0xe0;
        for i in 0..nfunc {
            let at = functab + i * 8;
            b[at..at + 4].copy_from_slice(&(0x40 * i as u32).to_le_bytes());
        }
    }

    /// A minimal ELF64 x86-64 image that goblin parses (no section table, one
    /// PT_LOAD over the whole file) with a pcHeader at `at`: a Go image in the
    /// shape this module has to recognize when another file carries it.
    fn go_elf(len: usize, at: usize) -> Vec<u8> {
        let mut b = segments::tests::elf64_bogus_shoff(len);
        b[40..48].copy_from_slice(&0u64.to_le_bytes()); // e_shoff
        b[60..62].copy_from_slice(&0u16.to_le_bytes()); // e_shnum
        b[62..64].copy_from_slice(&0u16.to_le_bytes()); // e_shstrndx
        put_pcheader(&mut b, at, 8, 1);
        b
    }

    fn embedded(r: crate::Result<GoBinary>) -> (usize, Option<usize>, usize, Option<String>) {
        match r {
            Err(Error::EmbeddedGoImage {
                offset,
                len,
                pclntab_offset,
                goarch,
                ..
            }) => (offset, len, pclntab_offset, goarch),
            Err(e) => panic!("expected EmbeddedGoImage, got {e}"),
            Ok(bin) => panic!(
                "expected EmbeddedGoImage, parsed with the pclntab at 0x{:x}",
                bin.pclntab_offset
            ),
        }
    }

    #[test]
    fn a_go_image_carried_as_data_is_reported_with_its_extent() {
        let inner = go_elf(0x800, 0x200);
        assert!(
            GoBinary::parse(inner.clone()).is_ok(),
            "the image parses alone"
        );
        let mut outer = segments::tests::elf64_bogus_shoff(0x4000);
        outer[0x1000..0x1800].copy_from_slice(&inner);
        let (offset, len, pclntab_offset, goarch) = embedded(GoBinary::parse(outer.clone()));
        assert_eq!(offset, 0x1000);
        assert_eq!(len, Some(0x800));
        assert_eq!(pclntab_offset, 0x1200);
        assert_eq!(goarch.as_deref(), Some("amd64"));
        // The reported extent carves the image back out, and it parses.
        let carved = outer[offset..offset + 0x800].to_vec();
        assert_eq!(GoBinary::parse(carved).unwrap().pclntab_offset, 0x200);
    }

    #[test]
    fn a_table_over_foreign_code_is_reported_and_one_over_go_code_is_not() {
        // No image header anywhere: only the code the table maps onto can tell.
        // The container's one segment maps the file at 0x400000 and its text
        // starts past the 0x1000-byte header reserve, so function i sits at file
        // offset 0x1000 + 0x40 * i.
        let mut b = segments::tests::elf64_bogus_shoff(0x4000);
        put_pcheader(&mut b, 0x200, 8, 64);
        for i in 0..64 {
            let at = 0x1000 + 0x40 * i;
            b[at..at + 4].copy_from_slice(&[0x55, 0x48, 0x89, 0xe5]); // push rbp; mov rbp, rsp
        }
        let (offset, len, _, goarch) = embedded(GoBinary::parse(b.clone()));
        assert_eq!((offset, len), (0x200, None));
        assert_eq!(goarch.as_deref(), Some("amd64"));

        // The same table over Go's stack check: the container's own, and kept.
        for i in 0..64 {
            let at = 0x1000 + 0x40 * i;
            b[at..at + 4].copy_from_slice(&[0x49, 0x3b, 0x66, 0x10]); // cmp rsp, [r14+0x10]
        }
        assert_eq!(GoBinary::parse(b.clone()).unwrap().pclntab_offset, 0x200);

        // Half Go, half not (leaf functions skip the check): still the container's.
        for i in (0..64).step_by(2) {
            let at = 0x1000 + 0x40 * i;
            b[at..at + 4].copy_from_slice(&[0x55, 0x48, 0x89, 0xe5]);
        }
        assert_eq!(GoBinary::parse(b).unwrap().pclntab_offset, 0x200);
    }

    #[test]
    fn a_table_too_small_to_judge_keeps_todays_reading() {
        let mut b = segments::tests::elf64_bogus_shoff(0x4000);
        put_pcheader(&mut b, 0x200, 8, MIN_CODE_SAMPLES - 1);
        assert_eq!(GoBinary::parse(b).unwrap().pclntab_offset, 0x200);
    }

    #[test]
    fn a_pointer_size_the_container_does_not_use_is_reported() {
        // A 386 table (4-byte pointers) inside a 64-bit container.
        let mut b = segments::tests::elf64_bogus_shoff(0x4000);
        put_pcheader(&mut b, 0x200, 4, 1);
        let (offset, len, _, goarch) = embedded(GoBinary::parse(b));
        assert_eq!((offset, len), (0x200, None));
        assert_eq!(goarch.as_deref(), Some("386"));
    }

    #[test]
    fn after_an_embedded_table_an_unreferenced_one_is_not_taken() {
        // The scan meets the embedded image first, then a header nothing
        // references and nothing ties to an image. Alone, that second header
        // keeps today's reading; after an embedded one it is not taken as the
        // container's own, and the embedded image is what gets reported.
        let mut b = segments::tests::elf64_bogus_shoff(0x4000);
        b[0x1000..0x1800].copy_from_slice(&go_elf(0x800, 0x200));
        put_pcheader(&mut b, 0x3000, 8, 1);
        let (offset, ..) = embedded(GoBinary::parse(b));
        assert_eq!(offset, 0x1000);
    }

    #[test]
    fn prologue_shapes_match_go_and_not_common_foreign_entries() {
        assert_eq!(
            go_prologue(Arch::X86_64, &[0x49, 0x3b, 0x66, 0x10]),
            Some(true)
        );
        assert_eq!(
            go_prologue(
                Arch::X86_64,
                &[0x4c, 0x8d, 0x64, 0x24, 0xf8, 0x4d, 0x3b, 0x66, 0x10]
            ),
            Some(true)
        );
        assert_eq!(
            go_prologue(
                Arch::X86_64,
                &[0x4c, 0x8d, 0xa4, 0x24, 0x00, 0xfe, 0xff, 0xff, 0x4d, 0x3b, 0x66, 0x10]
            ),
            Some(true)
        );
        assert_eq!(
            go_prologue(Arch::X86, &[0x65, 0x8b, 0x0d, 0, 0, 0, 0, 0x8b, 0x89]),
            Some(true)
        );
        assert_eq!(
            go_prologue(
                Arch::X86,
                &[0x8b, 0x0d, 0x10, 0x20, 0x30, 0x00, 0x64, 0x8b, 0x09]
            ),
            Some(true)
        );
        assert_eq!(
            go_prologue(Arch::Aarch64, &[0x90, 0x0b, 0x40, 0xf9]),
            Some(true)
        );
        // MSVC/LLVM entries: push rbp; sub rsp; push ebp; mov ebp, esp; stp x29, x30.
        assert_eq!(
            go_prologue(Arch::X86_64, &[0x55, 0x48, 0x89, 0xe5]),
            Some(false)
        );
        assert_eq!(
            go_prologue(Arch::X86_64, &[0x48, 0x83, 0xec, 0x28]),
            Some(false)
        );
        assert_eq!(
            go_prologue(Arch::X86, &[0x55, 0x8b, 0xec, 0x83]),
            Some(false)
        );
        assert_eq!(
            go_prologue(Arch::Aarch64, &[0xfd, 0x7b, 0xbf, 0xa9]),
            Some(false)
        );
        assert_eq!(go_prologue(Arch::Other, &[0x49, 0x3b, 0x66, 0x10]), None);
    }
}
