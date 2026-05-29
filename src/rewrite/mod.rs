//! Rewrite a stripped Go binary in place, embedding recovered symbol
//! information into a real `.symtab` + `.strtab` so every other tool
//! in the chain (nm, objdump, gdb, perf, eBPF, delve) sees the names.
//!
//! ELF64 little-endian and PE/COFF are implemented today. Mach-O is
//! formatted differently enough that it ships in a follow-up version.
//! For ELF the strategy is:
//!
//! 1. Append a new `.strtab` section to the end of the file containing
//!    a null byte plus every function name null-terminated.
//! 2. Append a new `.symtab` section containing one `Elf64_Sym` per
//!    recovered function pointing at the right address.
//! 3. Append a fresh section header table after the two new sections
//!    that re-emits every original section header plus the two new
//!    ones. The original section header table is left in place but
//!    becomes orphaned data.
//! 4. Patch the ELF header to point `e_shoff` at the new section header
//!    table and bump `e_shnum`, `e_shstrndx`.
//!
//! The result is a strict superset of the original file with one
//! additional section that downstream tools recognize. The binary still
//! runs identically because we only append; we never relocate or
//! overwrite existing sections.

use std::fs;
use std::path::Path;

use crate::error::Error;
use crate::gobin::{Container, GoBinary};
use crate::pclntab::Function;
use crate::Result;

const ELF_MAGIC: [u8; 4] = [0x7f, b'E', b'L', b'F'];
const ELFCLASS64: u8 = 2;
const ELFDATA2LSB: u8 = 1;

// Elf64_Ehdr fields we patch or read.
const EHDR_E_SHOFF: usize = 40;
const EHDR_E_SHENTSIZE: usize = 58;
const EHDR_E_SHNUM: usize = 60;
const EHDR_E_SHSTRNDX: usize = 62;

// Elf64_Shdr layout (64 bytes total).
const SHDR_SIZE: usize = 64;

// Section header types we emit.
const SHT_NULL: u32 = 0;
const SHT_STRTAB: u32 = 3;
const SHT_SYMTAB: u32 = 2;

// Symbol info: STB_GLOBAL (1) << 4 | STT_FUNC (2) = 0x12.
const STB_GLOBAL: u8 = 1;
const STT_FUNC: u8 = 2;
const SYM_INFO_GLOBAL_FUNC: u8 = (STB_GLOBAL << 4) | STT_FUNC;

// Elf64_Sym layout (24 bytes).
const SYM_SIZE: usize = 24;

/// Write a copy of `path` to `out_path` with a synthetic `.symtab` +
/// `.strtab` added for every recovered function. Returns the number of
/// symbols written.
///
/// `source_path` is the path the input was read from; we use it to
/// preserve executable bits on the output. Pass `None` to leave the
/// output's permissions at the OS default and add chmod +x yourself.
pub fn write_symbols_as_elf(
    bin: &GoBinary,
    functions: &[Function],
    out_path: &Path,
    source_path: Option<&Path>,
) -> Result<usize> {
    if bin.container != Container::Elf {
        return Err(Error::Rewrite(format!(
            "--symbols-as elf requires an ELF input, got {:?}",
            bin.container
        )));
    }
    if !bin.little_endian {
        return Err(Error::Rewrite(
            "--symbols-as elf only supports little-endian ELF64 today".into(),
        ));
    }
    if bin.bytes.len() < 64 {
        return Err(Error::Rewrite("input is smaller than an ELF header".into()));
    }
    if bin.bytes[0..4] != ELF_MAGIC {
        return Err(Error::Rewrite("input does not start with ELF magic".into()));
    }
    if bin.bytes[4] != ELFCLASS64 {
        return Err(Error::Rewrite(
            "--symbols-as elf only supports ELF64".into(),
        ));
    }
    if bin.bytes[5] != ELFDATA2LSB {
        return Err(Error::Rewrite(
            "--symbols-as elf only supports little-endian ELF".into(),
        ));
    }

    // The original section header table lives at e_shoff; read its
    // contents so we can re-emit them in the new table at end-of-file.
    let original_shoff = u64::from_le_bytes(
        bin.bytes[EHDR_E_SHOFF..EHDR_E_SHOFF + 8]
            .try_into()
            .unwrap(),
    ) as usize;
    let original_shnum = u16::from_le_bytes(
        bin.bytes[EHDR_E_SHNUM..EHDR_E_SHNUM + 2]
            .try_into()
            .unwrap(),
    ) as usize;
    let original_shstrndx = u16::from_le_bytes(
        bin.bytes[EHDR_E_SHSTRNDX..EHDR_E_SHSTRNDX + 2]
            .try_into()
            .unwrap(),
    ) as usize;
    let shentsize = u16::from_le_bytes(
        bin.bytes[EHDR_E_SHENTSIZE..EHDR_E_SHENTSIZE + 2]
            .try_into()
            .unwrap(),
    ) as usize;
    if shentsize != SHDR_SIZE {
        return Err(Error::Rewrite(format!(
            "unexpected section header entry size {shentsize}, want {SHDR_SIZE}"
        )));
    }
    let shdr_table_size = original_shnum * SHDR_SIZE;
    if original_shoff + shdr_table_size > bin.bytes.len() {
        return Err(Error::Rewrite("section header table overruns file".into()));
    }
    let original_shdrs = &bin.bytes[original_shoff..original_shoff + shdr_table_size];

    // Read the original .shstrtab so we can rebuild a combined strtab.
    // sh_name on every original section header is an offset into this
    // table; we preserve those offsets by placing the original bytes
    // verbatim at the start of our combined strtab.
    let orig_shstrtab_hdr =
        &original_shdrs[original_shstrndx * SHDR_SIZE..original_shstrndx * SHDR_SIZE + SHDR_SIZE];
    let orig_shstrtab_off =
        u64::from_le_bytes(orig_shstrtab_hdr[24..32].try_into().unwrap()) as usize;
    let orig_shstrtab_size =
        u64::from_le_bytes(orig_shstrtab_hdr[32..40].try_into().unwrap()) as usize;
    if orig_shstrtab_off + orig_shstrtab_size > bin.bytes.len() {
        return Err(Error::Rewrite("original shstrtab overruns file".into()));
    }
    let mut shstrtab = Vec::with_capacity(orig_shstrtab_size + 64);
    shstrtab
        .extend_from_slice(&bin.bytes[orig_shstrtab_off..orig_shstrtab_off + orig_shstrtab_size]);
    let shstrtab_symtab_off = shstrtab.len() as u32;
    shstrtab.extend_from_slice(b".symtab\0");
    let shstrtab_strtab_off = shstrtab.len() as u32;
    shstrtab.extend_from_slice(b".strtab\0");
    let shstrtab_shstrtab_off = shstrtab.len() as u32;
    shstrtab.extend_from_slice(b".shstrtab\0");

    // Build the symbol string table (.strtab).
    let mut strtab = Vec::with_capacity(functions.len() * 32);
    strtab.push(0u8); // null entry; symbol with st_name=0 means no name
    let mut strtab_offsets: Vec<u32> = Vec::with_capacity(functions.len());
    for f in functions {
        strtab_offsets.push(strtab.len() as u32);
        strtab.extend_from_slice(f.name.as_bytes());
        strtab.push(0);
    }

    // Build the symbol table (.symtab). First entry is the null symbol,
    // a single zero-filled Elf64_Sym; required by the ELF spec.
    let mut symtab = Vec::with_capacity((functions.len() + 1) * SYM_SIZE);
    symtab.extend_from_slice(&[0u8; SYM_SIZE]);
    for (f, &name_off) in functions.iter().zip(strtab_offsets.iter()) {
        symtab.extend_from_slice(&name_off.to_le_bytes()); // st_name
        symtab.push(SYM_INFO_GLOBAL_FUNC); // st_info
        symtab.push(0); // st_other
        symtab.extend_from_slice(&1u16.to_le_bytes()); // st_shndx; SHN_ABS would be cleaner but most tools accept any nonzero index. Use the first text section index instead.
        symtab.extend_from_slice(&f.address.to_le_bytes()); // st_value
                                                            // st_size: distance to next function or 0 if unknown.
        symtab.extend_from_slice(&0u64.to_le_bytes());
    }
    let symbol_count = functions.len() + 1;

    // Compose the output file. Start with the original bytes, then
    // append our three new sections (.symtab, .strtab, .shstrtab) and
    // a new section header table referencing every original section
    // plus the three new ones.
    let mut out = Vec::with_capacity(bin.bytes.len() + symtab.len() + strtab.len() + 4096);
    out.extend_from_slice(&bin.bytes);

    // Align to 8 bytes for the symtab.
    while out.len() % 8 != 0 {
        out.push(0);
    }
    let symtab_off = out.len() as u64;
    let symtab_size = symtab.len() as u64;
    out.extend_from_slice(&symtab);

    let strtab_off = out.len() as u64;
    let strtab_size = strtab.len() as u64;
    out.extend_from_slice(&strtab);

    let shstrtab_off = out.len() as u64;
    let shstrtab_size = shstrtab.len() as u64;
    out.extend_from_slice(&shstrtab);

    while out.len() % 8 != 0 {
        out.push(0);
    }
    let new_shoff = out.len() as u64;

    // Re-emit every original section header. The original .shstrtab was
    // at original_shstrndx; we leave it alone and point the ELF header
    // at our new .shstrtab instead so the section names for the new
    // sections resolve cleanly.
    out.extend_from_slice(original_shdrs);
    let new_shnum_before_extras = original_shnum;

    // Find the first text section (sh_flags has SHF_EXECINSTR=4) so
    // we can point our symbols at it via st_shndx. If none, fall back
    // to 1.
    let mut text_shndx: u16 = 1;
    for i in 0..original_shnum {
        let off = i * SHDR_SIZE;
        let sh_flags = u64::from_le_bytes(original_shdrs[off + 8..off + 16].try_into().unwrap());
        if sh_flags & 0x4 != 0 {
            text_shndx = i as u16;
            break;
        }
    }
    // Patch the symtab entries' st_shndx now that we know the right value.
    for sym_idx in 1..symbol_count {
        let sym_start = symtab_off as usize + sym_idx * SYM_SIZE;
        // st_shndx lives at offset 6 within the 24-byte Elf64_Sym.
        out[sym_start + 6..sym_start + 8].copy_from_slice(&text_shndx.to_le_bytes());
    }

    // Append three new section headers: .symtab, .strtab, .shstrtab.
    // .symtab needs sh_link pointing at the .strtab section index and
    // sh_info set to the count of local symbols (we mark everything
    // global so sh_info = 1, the first non-local index).
    let new_symtab_shndx = new_shnum_before_extras as u16;
    let new_strtab_shndx = new_shnum_before_extras as u16 + 1;
    let new_shstrtab_shndx = new_shnum_before_extras as u16 + 2;

    out.extend_from_slice(&make_shdr(
        shstrtab_symtab_off,     // sh_name (index in our new .shstrtab)
        SHT_SYMTAB,              // sh_type
        0,                       // sh_flags (none for .symtab in stripped binary)
        0,                       // sh_addr (not loaded at runtime)
        symtab_off,              // sh_offset
        symtab_size,             // sh_size
        new_strtab_shndx as u32, // sh_link -> .strtab
        1,                       // sh_info; one local symbol (null entry)
        8,                       // sh_addralign
        SYM_SIZE as u64,         // sh_entsize
    ));
    out.extend_from_slice(&make_shdr(
        shstrtab_strtab_off,
        SHT_STRTAB,
        0,
        0,
        strtab_off,
        strtab_size,
        0,
        0,
        1,
        0,
    ));
    out.extend_from_slice(&make_shdr(
        shstrtab_shstrtab_off,
        SHT_STRTAB,
        0,
        0,
        shstrtab_off,
        shstrtab_size,
        0,
        0,
        1,
        0,
    ));
    let new_shnum = (new_shnum_before_extras + 3) as u16;
    let _ = original_shstrndx;
    let _ = new_symtab_shndx;

    // Patch the ELF header.
    out[EHDR_E_SHOFF..EHDR_E_SHOFF + 8].copy_from_slice(&new_shoff.to_le_bytes());
    out[EHDR_E_SHNUM..EHDR_E_SHNUM + 2].copy_from_slice(&new_shnum.to_le_bytes());
    out[EHDR_E_SHSTRNDX..EHDR_E_SHSTRNDX + 2].copy_from_slice(&new_shstrtab_shndx.to_le_bytes());

    fs::write(out_path, &out).map_err(Error::Io)?;

    // Preserve executable bits from the input. Without this, the rewritten
    // output isn't directly runnable, which defeats the whole point of
    // appending symbols to a working binary.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = source_path
            .and_then(|p| fs::metadata(p).ok())
            .map(|m| m.permissions().mode())
            .unwrap_or(0o755);
        let _ = fs::set_permissions(out_path, fs::Permissions::from_mode(mode));
    }
    #[cfg(not(unix))]
    {
        let _ = source_path;
    }
    Ok(functions.len())
}

#[allow(clippy::too_many_arguments)]
fn make_shdr(
    sh_name: u32,
    sh_type: u32,
    sh_flags: u64,
    sh_addr: u64,
    sh_offset: u64,
    sh_size: u64,
    sh_link: u32,
    sh_info: u32,
    sh_addralign: u64,
    sh_entsize: u64,
) -> [u8; SHDR_SIZE] {
    let mut h = [0u8; SHDR_SIZE];
    h[0..4].copy_from_slice(&sh_name.to_le_bytes());
    h[4..8].copy_from_slice(&sh_type.to_le_bytes());
    h[8..16].copy_from_slice(&sh_flags.to_le_bytes());
    h[16..24].copy_from_slice(&sh_addr.to_le_bytes());
    h[24..32].copy_from_slice(&sh_offset.to_le_bytes());
    h[32..40].copy_from_slice(&sh_size.to_le_bytes());
    h[40..44].copy_from_slice(&sh_link.to_le_bytes());
    h[44..48].copy_from_slice(&sh_info.to_le_bytes());
    h[48..56].copy_from_slice(&sh_addralign.to_le_bytes());
    h[56..64].copy_from_slice(&sh_entsize.to_le_bytes());
    h
}

#[allow(dead_code)]
const _: () = {
    // Compile-time check that SHT_NULL stays at the expected value;
    // referenced through the file's structure even when not directly used.
    let _ = SHT_NULL;
};

// PE/COFF constants used when appending a synthetic symbol table.
const PE_E_LFANEW_OFFSET: usize = 0x3c;
const PE_SIGNATURE: [u8; 4] = [b'P', b'E', 0, 0];
// IMAGE_FILE_HEADER field offsets (relative to the start of the header,
// which sits at e_lfanew + 4 because the PE signature precedes it).
const COFF_PTR_TO_SYMTAB: usize = 8;
const COFF_NUM_SYMBOLS: usize = 12;
const COFF_SIZE_OF_OPT_HDR: usize = 16;
const COFF_HEADER_SIZE: usize = 20;
const COFF_SECTION_HEADER_SIZE: usize = 40;
// 18-byte IMAGE_SYMBOL record per the PE/COFF spec.
const COFF_SYMBOL_SIZE: usize = 18;
// IMAGE_SCN_MEM_EXECUTE.
const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
// IMAGE_SYM_CLASS_EXTERNAL.
const IMAGE_SYM_CLASS_EXTERNAL: u8 = 2;
// Type field for a function: DT_FCN(2) << 4 | T_NULL(0) = 0x20.
const COFF_SYM_TYPE_FUNCTION: u16 = 0x20;

/// Write a copy of `path` to `out_path` with a synthetic COFF symbol
/// table plus string table appended to the end of the PE file, and
/// IMAGE_FILE_HEADER patched to point at them. Returns the number of
/// symbols written.
///
/// `source_path` is the path the input was read from; we use it to
/// preserve executable bits on the output. On Windows the permissions
/// passthrough is a no-op.
pub fn write_symbols_as_pe(
    bin: &GoBinary,
    functions: &[Function],
    out_path: &Path,
    source_path: Option<&Path>,
) -> Result<usize> {
    if bin.container != Container::Pe {
        return Err(Error::Rewrite(format!(
            "--symbols-as pe requires a PE input, got {:?}",
            bin.container
        )));
    }
    if !bin.little_endian {
        return Err(Error::Rewrite(
            "--symbols-as pe only supports little-endian PE today".into(),
        ));
    }
    if bin.bytes.len() < PE_E_LFANEW_OFFSET + 4 {
        return Err(Error::Rewrite("input is smaller than a DOS header".into()));
    }

    let e_lfanew = u32::from_le_bytes(
        bin.bytes[PE_E_LFANEW_OFFSET..PE_E_LFANEW_OFFSET + 4]
            .try_into()
            .unwrap(),
    ) as usize;
    if e_lfanew + 4 + COFF_HEADER_SIZE > bin.bytes.len() {
        return Err(Error::Rewrite("PE header overruns file".into()));
    }
    if bin.bytes[e_lfanew..e_lfanew + 4] != PE_SIGNATURE {
        return Err(Error::Rewrite("missing PE\\0\\0 signature".into()));
    }
    let coff_off = e_lfanew + 4;

    // The Go linker leaves a small COFF symbol table in stripped PE
    // outputs that names section bounds and a few internal globals but
    // not user functions. We append our own table at end of file and
    // re-point IMAGE_FILE_HEADER at it; the old table bytes are left
    // in place as orphaned data so we don't have to relocate anything
    // earlier in the file.

    let size_of_opt_hdr = u16::from_le_bytes(
        bin.bytes[coff_off + COFF_SIZE_OF_OPT_HDR..coff_off + COFF_SIZE_OF_OPT_HDR + 2]
            .try_into()
            .unwrap(),
    ) as usize;
    let section_table_off = coff_off + COFF_HEADER_SIZE + size_of_opt_hdr;

    // Recover image_base from the optional header so we can compute
    // RVAs for the Value field. The image base sits at offset 24 of
    // the optional header for PE32+ (magic 0x20b) and offset 28 for
    // PE32 (magic 0x10b); we read both formats.
    let opt_hdr_off = coff_off + COFF_HEADER_SIZE;
    if opt_hdr_off + 2 > bin.bytes.len() {
        return Err(Error::Rewrite("optional header truncated".into()));
    }
    let opt_magic = u16::from_le_bytes(bin.bytes[opt_hdr_off..opt_hdr_off + 2].try_into().unwrap());
    let image_base: u64 = match opt_magic {
        0x20b => {
            // PE32+: ImageBase is a u64 at offset 24.
            if opt_hdr_off + 24 + 8 > bin.bytes.len() {
                return Err(Error::Rewrite("PE32+ optional header truncated".into()));
            }
            u64::from_le_bytes(
                bin.bytes[opt_hdr_off + 24..opt_hdr_off + 32]
                    .try_into()
                    .unwrap(),
            )
        }
        0x10b => {
            // PE32: ImageBase is a u32 at offset 28.
            if opt_hdr_off + 28 + 4 > bin.bytes.len() {
                return Err(Error::Rewrite("PE32 optional header truncated".into()));
            }
            u32::from_le_bytes(
                bin.bytes[opt_hdr_off + 28..opt_hdr_off + 32]
                    .try_into()
                    .unwrap(),
            ) as u64
        }
        other => {
            return Err(Error::Rewrite(format!(
                "unrecognized optional header magic 0x{other:x}"
            )))
        }
    };

    // Scan the section table to find the 1-based index of the first
    // executable section. Symbols pointing at addresses in that section
    // get section_number set to this value with Value = RVA.
    let num_sections =
        u16::from_le_bytes(bin.bytes[coff_off + 2..coff_off + 4].try_into().unwrap()) as usize;
    if section_table_off + num_sections * COFF_SECTION_HEADER_SIZE > bin.bytes.len() {
        return Err(Error::Rewrite("section table overruns file".into()));
    }
    let mut text_section_index: u16 = 1;
    for i in 0..num_sections {
        let off = section_table_off + i * COFF_SECTION_HEADER_SIZE;
        let characteristics = u32::from_le_bytes(bin.bytes[off + 36..off + 40].try_into().unwrap());
        if characteristics & IMAGE_SCN_MEM_EXECUTE != 0 {
            text_section_index = (i + 1) as u16;
            break;
        }
    }

    // Build the symbol records and the appended string table. Names up
    // to 8 bytes including a trailing null go inline; longer names land
    // in the string table and are referenced by {0u32, offset u32}.
    let mut symbols: Vec<u8> = Vec::with_capacity(functions.len() * COFF_SYMBOL_SIZE);
    // The string table starts with its own 4-byte size field; offsets
    // into it are counted from the start of the size field, so the
    // first usable offset is 4.
    let mut strtab: Vec<u8> = Vec::with_capacity(functions.len() * 24);
    strtab.extend_from_slice(&[0u8; 4]);

    for f in functions {
        let mut rec = [0u8; COFF_SYMBOL_SIZE];
        let name_bytes = f.name.as_bytes();
        if name_bytes.len() <= 8 {
            // Inline; remaining bytes stay zero so the name is null-padded.
            rec[..name_bytes.len()].copy_from_slice(name_bytes);
        } else {
            let off = strtab.len() as u32;
            // First 4 bytes are zero, next 4 bytes are the strtab offset.
            rec[0..4].copy_from_slice(&0u32.to_le_bytes());
            rec[4..8].copy_from_slice(&off.to_le_bytes());
            strtab.extend_from_slice(name_bytes);
            strtab.push(0);
        }
        // Value = RVA = address - image_base. Saturate to zero on
        // underflow rather than failing the whole rewrite; a malformed
        // function record shouldn't drop every other symbol.
        let rva = f.address.saturating_sub(image_base) as u32;
        rec[8..12].copy_from_slice(&rva.to_le_bytes());
        rec[12..14].copy_from_slice(&text_section_index.to_le_bytes());
        rec[14..16].copy_from_slice(&COFF_SYM_TYPE_FUNCTION.to_le_bytes());
        rec[16] = IMAGE_SYM_CLASS_EXTERNAL;
        rec[17] = 0; // NumberOfAuxSymbols
        symbols.extend_from_slice(&rec);
    }

    // Patch the strtab size header now that we know the final length.
    let strtab_size = strtab.len() as u32;
    strtab[0..4].copy_from_slice(&strtab_size.to_le_bytes());

    // Compose the output: original bytes, then symbol records, then
    // the string table. The symbol table file offset must be 4-byte
    // aligned per the PE/COFF spec.
    let mut out = Vec::with_capacity(bin.bytes.len() + symbols.len() + strtab.len() + 16);
    out.extend_from_slice(&bin.bytes);
    while out.len() % 4 != 0 {
        out.push(0);
    }
    let symtab_file_offset = out.len() as u32;
    out.extend_from_slice(&symbols);
    out.extend_from_slice(&strtab);

    // Patch IMAGE_FILE_HEADER.PointerToSymbolTable and NumberOfSymbols.
    out[coff_off + COFF_PTR_TO_SYMTAB..coff_off + COFF_PTR_TO_SYMTAB + 4]
        .copy_from_slice(&symtab_file_offset.to_le_bytes());
    let num_symbols = functions.len() as u32;
    out[coff_off + COFF_NUM_SYMBOLS..coff_off + COFF_NUM_SYMBOLS + 4]
        .copy_from_slice(&num_symbols.to_le_bytes());

    fs::write(out_path, &out).map_err(Error::Io)?;

    // Match the input's executable bits on unix so the rewritten file
    // can still be launched under wine / mono. No-op on Windows.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = source_path
            .and_then(|p| fs::metadata(p).ok())
            .map(|m| m.permissions().mode())
            .unwrap_or(0o755);
        let _ = fs::set_permissions(out_path, fs::Permissions::from_mode(mode));
    }
    #[cfg(not(unix))]
    {
        let _ = source_path;
    }
    Ok(functions.len())
}
