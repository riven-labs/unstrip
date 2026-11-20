//! A Go program carried inside another file as data is reported, not mapped onto
//! the carrier's code, and real Go binaries are never mistaken for one.

use std::path::PathBuf;

use unstrip::gobin::GoBinary;
use unstrip::pclntab::Pclntab;
use unstrip::Error;

fn testdata() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("testdata")
}

fn fixture(name: &str) -> Option<Vec<u8>> {
    let path = testdata().join(name);
    match std::fs::read(&path) {
        Ok(bytes) => Some(bytes),
        Err(_) => {
            eprintln!("skipping: fixture {name} not built (run testdata/build-fixtures.sh)");
            None
        }
    }
}

fn function_table(bin: &GoBinary) -> Vec<(u64, String)> {
    Pclntab::parse(bin)
        .expect("parse pclntab")
        .functions()
        .expect("walk functab")
        .into_iter()
        .map(|f| (f.address, f.name))
        .collect()
}

fn put_u16(b: &mut [u8], at: usize, v: u16) {
    b[at..at + 2].copy_from_slice(&v.to_le_bytes());
}

fn put_u32(b: &mut [u8], at: usize, v: u32) {
    b[at..at + 4].copy_from_slice(&v.to_le_bytes());
}

fn put_u64(b: &mut [u8], at: usize, v: u64) {
    b[at..at + 8].copy_from_slice(&v.to_le_bytes());
}

const PE_TEXT_RAW: usize = 0x400;
const PE_TEXT_SIZE: usize = 0x1000;
const PE_RDATA_RAW: usize = PE_TEXT_RAW + PE_TEXT_SIZE;

/// A small non-Go PE32+ executable for amd64: a `.text` of ordinary
/// frame-pointer prologues and an `.rdata` that holds `payload` 0x10 bytes in,
/// the way a dropper or a test executable carries a file in its data. Returns
/// the file and the payload's file offset.
fn pe_carrying(payload: &[u8]) -> (Vec<u8>, usize) {
    let rdata_size = (0x10 + payload.len()).div_ceil(0x200) * 0x200;
    let mut b = vec![0u8; PE_RDATA_RAW + rdata_size];

    b[0..2].copy_from_slice(b"MZ");
    put_u32(&mut b, 0x3c, 0x80); // e_lfanew
    b[0x80..0x84].copy_from_slice(b"PE\0\0");
    let coff = 0x84;
    put_u16(&mut b, coff, 0x8664); // AMD64
    put_u16(&mut b, coff + 2, 2); // sections
    put_u16(&mut b, coff + 16, 240); // optional header size
    put_u16(&mut b, coff + 18, 0x22); // executable, large address aware
    let opt = coff + 20;
    put_u16(&mut b, opt, 0x20b); // PE32+
    put_u32(&mut b, opt + 4, PE_TEXT_SIZE as u32); // SizeOfCode
    put_u32(&mut b, opt + 8, rdata_size as u32); // SizeOfInitializedData
    put_u32(&mut b, opt + 16, 0x1000); // entry point
    put_u32(&mut b, opt + 20, 0x1000); // BaseOfCode
    put_u64(&mut b, opt + 24, 0x1_4000_0000); // ImageBase
    put_u32(&mut b, opt + 32, 0x1000); // SectionAlignment
    put_u32(&mut b, opt + 36, 0x200); // FileAlignment
    put_u16(&mut b, opt + 40, 6); // OS version
    put_u16(&mut b, opt + 48, 6); // subsystem version
    let image_size = 0x2000 + rdata_size.div_ceil(0x1000) * 0x1000;
    put_u32(&mut b, opt + 56, image_size as u32); // SizeOfImage
    put_u32(&mut b, opt + 60, PE_TEXT_RAW as u32); // SizeOfHeaders
    put_u16(&mut b, opt + 68, 3); // console
    put_u32(&mut b, opt + 108, 16); // data directories (all empty)

    let sections = opt + 240;
    let mut section = |i: usize, name: &[u8], va: u32, raw: usize, size: usize, flags: u32| {
        let s = sections + i * 40;
        b[s..s + name.len()].copy_from_slice(name);
        put_u32(&mut b, s + 8, size as u32); // VirtualSize
        put_u32(&mut b, s + 12, va);
        put_u32(&mut b, s + 16, size as u32); // SizeOfRawData
        put_u32(&mut b, s + 20, raw as u32);
        put_u32(&mut b, s + 36, flags);
    };
    section(0, b".text", 0x1000, PE_TEXT_RAW, PE_TEXT_SIZE, 0x6000_0020); // code, r-x
    section(1, b".rdata", 0x2000, PE_RDATA_RAW, rdata_size, 0x4000_0040); // data, r--

    // push rbp; mov rbp, rsp; sub rsp, 0x20; ...; ret -- the shape of MSVC and
    // LLVM code, not Go's.
    let body = [
        0x55, 0x48, 0x89, 0xe5, 0x48, 0x83, 0xec, 0x20, 0x90, 0x90, 0x5d, 0xc3,
    ];
    for (i, byte) in b[PE_TEXT_RAW..PE_RDATA_RAW].iter_mut().enumerate() {
        *byte = body[i % body.len()];
    }
    let at = PE_RDATA_RAW + 0x10;
    b[at..at + payload.len()].copy_from_slice(payload);
    (b, at)
}

/// A 0x800-byte ELF64 amd64 image: one PT_LOAD over the file, no section table,
/// and a Go 1.20 pcHeader at 0x200 describing one function. It parses on its own
/// with its table at 0x200.
fn small_go_elf() -> Vec<u8> {
    let len = 0x800;
    let mut b = vec![0u8; len];
    b[0..4].copy_from_slice(b"\x7fELF");
    b[4] = 2; // 64-bit
    b[5] = 1; // little endian
    b[6] = 1; // version
    put_u16(&mut b, 16, 2); // ET_EXEC
    put_u16(&mut b, 18, 62); // EM_X86_64
    put_u32(&mut b, 20, 1);
    put_u64(&mut b, 24, 0x400000); // entry
    put_u64(&mut b, 32, 64); // e_phoff
    put_u16(&mut b, 52, 64); // e_ehsize
    put_u16(&mut b, 54, 56); // e_phentsize
    put_u16(&mut b, 56, 1); // e_phnum
    put_u16(&mut b, 58, 64); // e_shentsize
    let ph = 64;
    put_u32(&mut b, ph, 1); // PT_LOAD
    put_u32(&mut b, ph + 4, 5); // r-x
    put_u64(&mut b, ph + 16, 0x400000); // p_vaddr
    put_u64(&mut b, ph + 24, 0x400000); // p_paddr
    put_u64(&mut b, ph + 32, len as u64); // p_filesz
    put_u64(&mut b, ph + 40, len as u64); // p_memsz
    put_u64(&mut b, ph + 48, 0x1000); // p_align
    let off = 0x200;
    b[off..off + 4].copy_from_slice(&[0xf1, 0xff, 0xff, 0xff]);
    b[off + 6] = 1; // quantum
    b[off + 7] = 8; // pointer size
                    // nfunc, nfiles, textStart (zero), then the five table offsets.
    for (i, v) in [1u64, 1, 0, 0x60, 0x80, 0xa0, 0xc0, 0xe0]
        .iter()
        .enumerate()
    {
        put_u64(&mut b, off + 8 + i * 8, *v);
    }
    b
}

/// The Linux hello fixture with its pcHeader textStart zeroed, as Go 1.26+ and
/// every Windows build store it. That is the shape that used to slip through:
/// a nonzero textStart has to land in the carrier's text to be accepted at all.
fn hello_with_zero_text_start() -> Option<Vec<u8>> {
    let mut elf = fixture("hello.linux-amd64.stripped")?;
    let off = GoBinary::parse(elf.clone())
        .expect("fixture parses")
        .pclntab_offset;
    put_u64(&mut elf, off + 8 + 2 * 8, 0);
    Some(elf)
}

#[test]
fn a_go_elf_inside_a_non_go_pe_is_reported_with_its_platform_and_extent() {
    let Some(elf) = hello_with_zero_text_start() else {
        return;
    };
    let expected = function_table(&GoBinary::parse(elf.clone()).unwrap());
    let (pe, at) = pe_carrying(&elf);

    let err = match GoBinary::parse(pe.clone()) {
        Err(e) => e,
        Ok(bin) => panic!(
            "the carrier's code was read as Go: pclntab at 0x{:x}, text at 0x{:x}",
            bin.pclntab_offset, bin.text_addr
        ),
    };
    let msg = err.to_string();
    let Error::EmbeddedGoImage {
        offset,
        len,
        goos,
        goarch,
        ..
    } = err
    else {
        panic!("expected EmbeddedGoImage, got {msg}");
    };
    assert_eq!(offset, at);
    assert_eq!(len, Some(elf.len()));
    assert_eq!(goos.as_deref(), Some("linux"));
    assert_eq!(goarch.as_deref(), Some("amd64"));
    assert!(
        msg.starts_with(&format!(
            "embedded Go program at file offset 0x{at:x} (linux/amd64)"
        )),
        "{msg}"
    );

    // The carved image is the original program, function for function.
    let carved = GoBinary::parse(pe[offset..offset + len.unwrap()].to_vec()).unwrap();
    assert_eq!(function_table(&carved), expected);
}

#[test]
fn a_go_pe_whose_data_carries_a_go_image_still_opens_as_itself() {
    // Plant a small Go image (an ELF with its own pcHeader) in the .rdata of a
    // real Go PE, ahead of the PE's own pclntab, so the scan meets it first. The
    // PE must still open with its own table.
    let Some(pe) = fixture("hello.windows-amd64.stripped.exe") else {
        return;
    };
    let own = GoBinary::parse(pe.clone()).unwrap();
    let expected = function_table(&own);

    let img = small_go_elf();
    let inner = GoBinary::parse(img.clone()).expect("the planted image parses alone");
    assert_eq!(inner.pclntab_offset, 0x200);

    let mut carrier = pe.clone();
    let rdata = own.sections.iter().find(|s| s.name == ".rdata").unwrap();
    let at = rdata.file_offset + 0x1000;
    assert!(at + img.len() < own.pclntab_offset);
    carrier[at..at + img.len()].copy_from_slice(&img);
    let bin = GoBinary::parse(carrier).expect("the PE still opens");
    assert_eq!(bin.pclntab_offset, own.pclntab_offset);
    assert_eq!(function_table(&bin), expected);
}

#[test]
fn no_go_fixture_is_reported_as_embedded() {
    let Ok(dir) = std::fs::read_dir(testdata()) else {
        return;
    };
    let mut seen = 0;
    for entry in dir.flatten() {
        let path = entry.path();
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        if !(name.contains(".stripped") || name.contains(".unstripped") || name.ends_with(".exe")) {
            continue;
        }
        let Ok(bytes) = std::fs::read(&path) else {
            continue;
        };
        seen += 1;
        if let Err(e @ Error::EmbeddedGoImage { .. }) = GoBinary::parse(bytes) {
            panic!("{name}: a real Go binary was reported as embedded: {e}");
        }
    }
    eprintln!("checked {seen} fixtures");
}
