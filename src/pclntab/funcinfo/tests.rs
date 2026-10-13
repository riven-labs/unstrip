//! Unit tests for the per-function metadata readers. The synthetic tables are
//! laid out the way cmd/link/internal/ld/pcln.go writes them (header, funcname
//! table, cutab, filetab, pctab, functab followed by the `_func` records), for
//! each layout, so the readers are checked byte for byte against the writer
//! rather than against themselves.

use super::*;
use crate::gobin::{Arch, Container, GoBinary, Section, SectionKind};
use crate::pclntab::{MAGIC_1_16, MAGIC_1_20};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Ver {
    /// 0xfffffffa: Go 1.16/1.17.
    Go116,
    /// 0xfffffff0: Go 1.18/1.19.
    Go118,
    /// 0xfffffff1: Go 1.20+.
    Go120,
}

const PCLN_ADDR: u64 = 0x50_0000;
const GOFUNC_ADDR: u64 = 0x60_0000;
const TEXT_START: u64 = 0x40_1000;

/// A pc-value table as the linker sees it: `(end_pc, value)` runs in order.
type Runs = Vec<(u64, i32)>;

#[derive(Clone, Default)]
struct SFunc {
    name: &'static str,
    size: u64,
    args: i32,
    deferreturn: u32,
    start_line: i32,
    func_id: u8,
    flag: u8,
    pcsp: Runs,
    pcfile: Runs,
    pcln: Runs,
    /// pcdata tables by index; None = offset 0 (no table).
    pcdata: Vec<Option<Runs>>,
    /// funcdata blobs by index; None = nil slot.
    funcdata: Vec<Option<Vec<u8>>>,
}

fn uvarint(out: &mut Vec<u8>, mut v: u64) {
    while v >= 0x80 {
        out.push((v as u8) | 0x80);
        v >>= 7;
    }
    out.push(v as u8);
}

/// cmd/internal/obj pctable writer: zig-zag value delta, pc delta / quantum,
/// then a 0 terminator.
fn encode_pcvalue(runs: &Runs, quantum: u64) -> Vec<u8> {
    let mut out = Vec::new();
    let (mut val, mut pc) = (-1i64, 0u64);
    for &(end, v) in runs {
        let d = v as i64 - val;
        uvarint(&mut out, ((d << 1) ^ (d >> 63)) as u64);
        uvarint(&mut out, (end - pc) / quantum);
        val = v as i64;
        pc = end;
    }
    out.push(0);
    out
}

fn put_u32(b: &mut Vec<u8>, v: u32) {
    b.extend_from_slice(&v.to_le_bytes());
}
fn put_u64(b: &mut Vec<u8>, v: u64) {
    b.extend_from_slice(&v.to_le_bytes());
}
fn align(b: &mut Vec<u8>, n: usize) {
    while b.len() % n != 0 {
        b.push(0);
    }
}

/// Build a GoBinary whose pclntab holds `funcs` (laid out back to back from
/// the text start) in the `ver` layout, with the funcdata blobs in a separate
/// gofunc section.
fn build(ver: Ver, funcs: &[SFunc]) -> GoBinary {
    let files = ["main.go", "inl.go"];
    let pre118 = ver == Ver::Go116;
    let header_len = if pre118 { 64 } else { 72 };

    let mut funcnames = vec![0u8];
    let mut name_offs = Vec::new();
    for f in funcs {
        name_offs.push(funcnames.len() as u32);
        funcnames.extend_from_slice(f.name.as_bytes());
        funcnames.push(0);
    }
    let mut filetab = vec![0u8];
    let mut cutab = Vec::new();
    for f in files {
        put_u32(&mut cutab, filetab.len() as u32);
        filetab.extend_from_slice(f.as_bytes());
        filetab.push(0);
    }
    // A third per-CU file index naming main.go again, as two CU file slots
    // can; the line table must merge across it.
    let main_go = u32::from_le_bytes(cutab[0..4].try_into().unwrap());
    put_u32(&mut cutab, main_go);

    // pctab: offset 0 is reserved for "no table".
    let mut pctab = vec![0u8];
    let mut add_table = |runs: &Runs| -> u32 {
        let off = pctab.len() as u32;
        pctab.extend(encode_pcvalue(runs, 1));
        off
    };
    struct Offs {
        pcsp: u32,
        pcfile: u32,
        pcln: u32,
        pcdata: Vec<u32>,
    }
    let offs: Vec<Offs> = funcs
        .iter()
        .map(|f| Offs {
            pcsp: add_table(&f.pcsp),
            pcfile: add_table(&f.pcfile),
            pcln: add_table(&f.pcln),
            pcdata: f
                .pcdata
                .iter()
                .map(|t| t.as_ref().map_or(0, &mut add_table))
                .collect(),
        })
        .collect();

    // gofunc blob: every funcdata record, 8-aligned.
    let mut gofunc = Vec::new();
    let fd_offs: Vec<Vec<Option<u32>>> = funcs
        .iter()
        .map(|f| {
            f.funcdata
                .iter()
                .map(|d| {
                    d.as_ref().map(|bytes| {
                        align(&mut gofunc, 8);
                        let off = gofunc.len() as u32;
                        gofunc.extend_from_slice(bytes);
                        off
                    })
                })
                .collect()
        })
        .collect();
    gofunc.extend_from_slice(&[0u8; 64]);

    let mut data = vec![0u8; header_len];
    let funcname_off = data.len();
    data.extend(&funcnames);
    let cu_off = data.len();
    data.extend(&cutab);
    let filetab_off = data.len();
    data.extend(&filetab);
    let pctab_off = data.len();
    data.extend(&pctab);
    align(&mut data, 8);
    let functab_off = data.len();

    let n = funcs.len();
    let stride = if pre118 { 16 } else { 8 };
    let mut funcrecs = Vec::new();
    let mut func_offs = Vec::new();
    let funcs_base = (n + 1) * stride;
    let mut pc = 0u64;
    let mut entries = Vec::new();
    for (i, f) in funcs.iter().enumerate() {
        align(&mut funcrecs, 8);
        func_offs.push(funcs_base + funcrecs.len());
        entries.push(pc);
        let mut r = Vec::new();
        if pre118 {
            put_u64(&mut r, TEXT_START + pc);
        } else {
            put_u32(&mut r, pc as u32);
        }
        put_u32(&mut r, name_offs[i]);
        put_u32(&mut r, f.args as u32);
        put_u32(&mut r, f.deferreturn);
        put_u32(&mut r, offs[i].pcsp);
        put_u32(&mut r, offs[i].pcfile);
        put_u32(&mut r, offs[i].pcln);
        put_u32(&mut r, f.pcdata.len() as u32);
        put_u32(&mut r, 0); // cuOffset
        if ver == Ver::Go120 {
            put_u32(&mut r, f.start_line as u32);
        }
        r.extend_from_slice(&[f.func_id, f.flag, 0, f.funcdata.len() as u8]);
        for &o in &offs[i].pcdata {
            put_u32(&mut r, o);
        }
        if pre118 {
            align(&mut r, 8);
            for o in &fd_offs[i] {
                put_u64(&mut r, o.map_or(0, |o| GOFUNC_ADDR + o as u64));
            }
        } else {
            for o in &fd_offs[i] {
                put_u32(&mut r, o.unwrap_or(u32::MAX));
            }
        }
        funcrecs.extend(r);
        pc += f.size;
    }
    entries.push(pc);
    for (i, &e) in entries.iter().enumerate() {
        let foff = func_offs.get(i).copied().unwrap_or(0) as u64;
        if pre118 {
            put_u64(&mut data, TEXT_START + e);
            put_u64(&mut data, foff);
        } else {
            put_u32(&mut data, e as u32);
            put_u32(&mut data, foff as u32);
        }
    }
    data.extend(&funcrecs);
    data.extend_from_slice(&[0u8; 16]);

    let magic = match ver {
        Ver::Go116 => MAGIC_1_16,
        Ver::Go118 => MAGIC_1_18,
        Ver::Go120 => MAGIC_1_20,
    };
    data[0..4].copy_from_slice(&magic.to_le_bytes());
    data[6] = 1;
    data[7] = 8;
    let mut h = 8;
    let mut hdr = |v: u64| {
        data[h..h + 8].copy_from_slice(&v.to_le_bytes());
        h += 8;
    };
    hdr(n as u64);
    hdr(files.len() as u64);
    if !pre118 {
        hdr(TEXT_START);
    }
    for v in [funcname_off, cu_off, filetab_off, pctab_off, functab_off] {
        hdr(v as u64);
    }

    let pcln_len = data.len();
    let mut bytes = data;
    bytes.extend(&gofunc);
    GoBinary {
        container: Container::Elf,
        arch: Arch::X86_64,
        little_endian: true,
        ptr_size: 8,
        sections: vec![
            Section {
                name: ".gopclntab".into(),
                kind: SectionKind::Pclntab,
                file_offset: 0,
                file_size: pcln_len,
                addr: PCLN_ADDR,
                vmsize: pcln_len as u64,
            },
            Section {
                name: ".rodata".into(),
                kind: SectionKind::ReadOnlyData,
                file_offset: pcln_len,
                file_size: gofunc.len(),
                addr: GOFUNC_ADDR,
                vmsize: gofunc.len() as u64,
            },
        ],
        pclntab_offset: 0,
        pclntab_size: pcln_len,
        pclntab_addr: PCLN_ADDR,
        text_addr: TEXT_START,
        bytes,
    }
}

/// One `inlinedCall` record in the layout of `ver`.
fn inl_record(ver: Ver, func_id: u8, name_off: i32, parent_pc: i32, start_line: i32) -> Vec<u8> {
    let mut r = Vec::new();
    if ver == Ver::Go120 {
        r.extend_from_slice(&[func_id, 0, 0, 0]);
        r.extend_from_slice(&name_off.to_le_bytes());
        r.extend_from_slice(&parent_pc.to_le_bytes());
        r.extend_from_slice(&start_line.to_le_bytes());
    } else {
        r.extend_from_slice(&(-1i16).to_le_bytes());
        r.extend_from_slice(&[func_id, 0]);
        r.extend_from_slice(&1i32.to_le_bytes()); // file
        r.extend_from_slice(&7i32.to_le_bytes()); // call-site line
        r.extend_from_slice(&name_off.to_le_bytes());
        r.extend_from_slice(&parent_pc.to_le_bytes());
    }
    r
}

/// `main.f(a int, s string)` as EmitArgInfo writes it.
const ARGINFO_INT_STRING: [u8; 9] = [0x00, 0x08, 0xfe, 0x08, 0x08, 0x10, 0x08, 0xfd, 0xff];

/// A function with lines 10/11/11/12 (and a line-0 gap), an SP delta of 0 then
/// 0x28, an inlined call of `main.inl` (name offset of the second name) over
/// [0x10, 0x18), whose call site is pc 0x0c, and ArgInfo.
fn sample(ver: Ver) -> Vec<SFunc> {
    let f = SFunc {
        name: "main.f",
        size: 0x30,
        args: 24,
        deferreturn: 0x2a,
        start_line: 9,
        func_id: 0,
        flag: 0,
        pcsp: vec![(0x4, 0), (0x2c, 0x28), (0x30, 0)],
        // main.go (index 0, then index 2 naming it again), the inlined body
        // in inl.go (index 1), then main.go.
        pcfile: vec![(0x8, 0), (0x10, 2), (0x18, 1), (0x30, 0)],
        // 0x00-0x04 line 10, 0x04-0x0c line 11 (split by the file index change
        // at 0x08), 0x0c-0x10 line 12, inlined body line 3, then a line-0 run,
        // then line 13.
        pcln: vec![
            (0x4, 10),
            (0xc, 11),
            (0x10, 12),
            (0x18, 3),
            (0x20, 0),
            (0x30, 13),
        ],
        pcdata: vec![
            Some(vec![(0x30, -1)]),
            None,
            Some(vec![(0x10, -1), (0x18, 0), (0x30, -1)]),
        ],
        funcdata: vec![
            None,
            None,
            None,
            // name offset of "main.inl" = 1 + len("main.f\0")
            Some(inl_record(ver, 0, 8, 0x0c, 2)),
            None,
            Some(ARGINFO_INT_STRING.to_vec()),
        ],
    };
    let g = SFunc {
        name: "main.inl",
        size: 0x10,
        pcsp: vec![(0x10, 0)],
        pcfile: vec![(0x10, 1)],
        pcln: vec![(0x10, 3)],
        ..Default::default()
    };
    vec![f, g]
}

fn pcln_for(bin: &GoBinary) -> Pclntab<'_> {
    Pclntab::parse(bin)
        .expect("synthetic pclntab parses")
        .with_gofunc(GOFUNC_ADDR)
}

fn entry(p: &Pclntab<'_>, name: &str) -> FuncEntry {
    p.functions_with_offsets()
        .unwrap()
        .into_iter()
        .find(|f| f.name == name)
        .unwrap_or_else(|| panic!("{name} not in synthetic table"))
}

const ALL: [Ver; 3] = [Ver::Go116, Ver::Go118, Ver::Go120];

#[test]
fn pcvalue_iter_mirrors_runtime_step() {
    let runs = vec![(0x4, 0), (0x2c, 0x28), (0x30, 0)];
    let mut table = vec![0u8];
    table.extend(encode_pcvalue(&runs, 1));
    let got: Vec<_> = PcValueIter::new(&table, 1, 1, 0x30).collect();
    assert_eq!(got, vec![(0, 4, 0), (4, 0x2c, 0x28), (0x2c, 0x30, 0)]);
    // Clipped to the function size.
    let got: Vec<_> = PcValueIter::new(&table, 1, 1, 0x10).collect();
    assert_eq!(got, vec![(0, 4, 0), (4, 0x10, 0x28)]);
    // Offset 0 is "no table".
    assert_eq!(PcValueIter::new(&table, 0, 1, 0x30).count(), 0);
}

#[test]
fn pcvalue_iter_applies_the_quantum() {
    // arm64-style quantum 4: pc deltas are stored divided by 4.
    let runs = vec![(0x8, 5), (0x20, 7)];
    let mut table = vec![0u8];
    table.extend(encode_pcvalue(&runs, 4));
    let got: Vec<_> = PcValueIter::new(&table, 1, 4, 0x20).collect();
    assert_eq!(got, vec![(0, 8, 5), (8, 0x20, 7)]);
}

#[test]
fn pcvalue_iter_allows_a_zero_first_delta() {
    // A table whose first value is -1 starts with a 0 value delta, which only
    // the first record may carry (runtime step's `first`).
    let runs = vec![(0x10, -1), (0x18, 0), (0x30, -1)];
    let mut table = vec![0u8];
    table.extend(encode_pcvalue(&runs, 1));
    assert_eq!(table[1], 0);
    let got: Vec<_> = PcValueIter::new(&table, 1, 1, 0x30).collect();
    assert_eq!(got, vec![(0, 0x10, -1), (0x10, 0x18, 0), (0x18, 0x30, -1)]);
}

#[test]
fn func_fields_follow_each_layout() {
    for ver in ALL {
        let bin = build(ver, &sample(ver));
        let p = pcln_for(&bin);
        let f = entry(&p, "main.f");
        let ff = p.func_fields(&f).expect("fields");
        assert_eq!(ff.entry, TEXT_START, "{ver:?}");
        assert_eq!(ff.name_off, 1, "{ver:?}");
        assert_eq!(ff.args, 24, "{ver:?}");
        assert_eq!(ff.deferreturn, 0x2a, "{ver:?}");
        assert_eq!(ff.npcdata, 3, "{ver:?}");
        assert_eq!(ff.nfuncdata, 6, "{ver:?}");
        assert_eq!(ff.cu_offset, 0, "{ver:?}");
        let want_start = (ver == Ver::Go120).then_some(9);
        assert_eq!(ff.start_line, want_start, "{ver:?}");
    }
}

#[test]
fn line_table_merges_runs_and_skips_unknown_lines() {
    for ver in ALL {
        let bin = build(ver, &sample(ver));
        let p = pcln_for(&bin);
        let f = entry(&p, "main.f");
        let t = p.line_table(&f);
        let got: Vec<_> = t
            .iter()
            .map(|s| {
                (
                    s.pc_lo - TEXT_START,
                    s.pc_hi - TEXT_START,
                    s.file.as_str(),
                    s.line,
                )
            })
            .collect();
        assert_eq!(
            got,
            vec![
                (0x00, 0x04, "main.go", 10),
                (0x04, 0x0c, "main.go", 11),
                (0x0c, 0x10, "main.go", 12),
                (0x10, 0x18, "inl.go", 3),
                (0x20, 0x30, "main.go", 13),
            ],
            "{ver:?}"
        );
    }
}

#[test]
fn sp_delta_reads_pcsp() {
    for ver in ALL {
        let bin = build(ver, &sample(ver));
        let p = pcln_for(&bin);
        let f = entry(&p, "main.f");
        assert_eq!(p.sp_delta_at(&f, TEXT_START), Some(0));
        assert_eq!(p.sp_delta_at(&f, TEXT_START + 0x10), Some(0x28));
        assert_eq!(p.sp_delta_at(&f, TEXT_START + 0x2c), Some(0));
        assert_eq!(
            p.sp_delta_at(&f, TEXT_START + 0x30),
            None,
            "outside the function"
        );
    }
}

#[test]
fn funcdata_addressing_per_layout() {
    for ver in ALL {
        let bin = build(ver, &sample(ver));
        let p = pcln_for(&bin);
        let f = entry(&p, "main.f");
        assert_eq!(p.funcdata(&f, 0), None, "nil slot");
        assert_eq!(p.funcdata(&f, 6), None, "past nfuncdata");
        let tree = p.funcdata(&f, FUNCDATA_INL_TREE).expect("inline tree");
        assert_eq!(tree, GOFUNC_ADDR, "{ver:?}");
        let arg = p.funcdata(&f, FUNCDATA_ARG_INFO).expect("arginfo");
        assert_eq!(arg % 8, 0);
        assert!(arg > GOFUNC_ADDR);
        // Without gofunc only the pre-1.18 absolute pointers resolve.
        let bare = Pclntab::parse(&bin).unwrap();
        assert_eq!(
            bare.funcdata(&f, FUNCDATA_ARG_INFO).is_some(),
            ver == Ver::Go116,
            "{ver:?}"
        );
    }
}

#[test]
fn pre118_funcdata_alignment_follows_npcdata_parity() {
    // runtime 1.16/1.17 funcdata(): with an odd npcdata the uintptr array is
    // padded to 8. Check both parities resolve the same blob.
    for npcdata in [2usize, 3] {
        let mut funcs = sample(Ver::Go116);
        funcs[0].pcdata.truncate(npcdata);
        let bin = build(Ver::Go116, &funcs);
        let p = Pclntab::parse(&bin).unwrap();
        let f = entry(&p, "main.f");
        assert_eq!(
            p.arg_info(&f),
            Some(vec![
                ArgComp::Word { off: 0, size: 8 },
                ArgComp::Agg(vec![
                    ArgComp::Word { off: 8, size: 8 },
                    ArgComp::Word { off: 16, size: 8 }
                ]),
            ]),
            "npcdata={npcdata}"
        );
    }
}

#[test]
fn arg_info_through_the_table() {
    for ver in ALL {
        let bin = build(ver, &sample(ver));
        let p = pcln_for(&bin);
        let f = entry(&p, "main.f");
        let a = p.arg_info(&f).expect("arginfo");
        assert_eq!(a.len(), 2, "{ver:?}");
        assert!(matches!(&a[1], ArgComp::Agg(w) if w.len() == 2));
        let g = entry(&p, "main.inl");
        assert_eq!(p.arg_info(&g), None, "no funcdata at all");
    }
}

#[test]
fn inline_leaf_and_chain_per_layout() {
    for ver in ALL {
        let bin = build(ver, &sample(ver));
        let p = pcln_for(&bin);
        let f = entry(&p, "main.f");
        assert_eq!(p.inline_leaf(&f, TEXT_START + 0x08), None, "not inlined");
        let leaf = p.inline_leaf(&f, TEXT_START + 0x12).expect("inlined pc");
        assert_eq!(leaf.func_name, "main.inl", "{ver:?}");
        assert_eq!(leaf.file.as_deref(), Some("inl.go"));
        assert_eq!(leaf.line, Some(3));
        assert_eq!(leaf.parent_pc, TEXT_START + 0x0c);
        let want_start = (ver == Ver::Go120).then_some(2);
        assert_eq!(leaf.start_line, want_start, "{ver:?}");
    }
}

#[test]
fn lookup_inline_reads_pre118_positions() {
    // Regression: file_and_line_for_pc read pcfile/pcln/cuOffset at the 1.18+
    // offsets (func_start+20/24/32), which on the Go 1.16/1.17 layout (8-byte
    // entry) land on pcsp/pcfile/npcdata. The inline frame's position must
    // come from the real pcfile/pcln on every layout.
    for ver in ALL {
        let bin = build(ver, &sample(ver));
        let p = pcln_for(&bin);
        let frames = p.lookup_inline(&bin, TEXT_START + 0x14);
        assert_eq!(frames.len(), 2, "{ver:?}: inlined frame + physical frame");
        assert_eq!(frames[0].name, "main.inl");
        assert!(frames[0].inlined);
        assert_eq!(frames[0].file.as_deref(), Some("inl.go"), "{ver:?}");
        assert_eq!(frames[0].line, Some(3), "{ver:?}");
        assert_eq!(frames[1].name, "main.f");
        assert!(!frames[1].inlined);
    }
}

#[test]
fn inline_tree_decoder_reads_both_record_sizes() {
    for ver in ALL {
        let bin = build(ver, &sample(ver));
        let p = pcln_for(&bin);
        let f = entry(&p, "main.f");
        let tree = crate::inline::decode_inline_tree(&bin, &p, &f).expect("tree");
        assert_eq!(tree.len(), 1, "{ver:?}");
        assert_eq!(tree[0].name_off, 8);
        assert_eq!(tree[0].parent_pc, 0x0c);
        assert_eq!(tree[0].start_line, if ver == Ver::Go120 { 2 } else { 0 });
    }
}

#[test]
fn func_entry_at_bounds() {
    let bin = build(Ver::Go120, &sample(Ver::Go120));
    let p = pcln_for(&bin);
    assert_eq!(p.func_entry_at(TEXT_START).unwrap().name, "main.f");
    assert_eq!(p.func_entry_at(TEXT_START + 0x2f).unwrap().size, 0x30);
    assert_eq!(p.func_entry_at(TEXT_START + 0x30).unwrap().name, "main.inl");
    assert!(p.func_entry_at(TEXT_START - 1).is_none());
    assert!(p.func_entry_at(TEXT_START + 0x40).is_none());
}

#[test]
fn wrapper_id_per_release() {
    // 1.16/1.17 magic: FuncIDWrapper = 22. 1.18/1.19: 21.
    for (ver, id) in [(Ver::Go116, 22u8), (Ver::Go118, 21)] {
        let mut funcs = sample(ver);
        funcs[1].func_id = id;
        let bin = build(ver, &funcs);
        let p = pcln_for(&bin);
        assert_eq!(p.is_wrapper(&entry(&p, "main.inl")), Some(true), "{ver:?}");
        assert_eq!(p.is_wrapper(&entry(&p, "main.f")), Some(false), "{ver:?}");
    }
    // 1.20+ magic: pinned by runtime.systemstack_switch, else unknown.
    let bin = build(Ver::Go120, &sample(Ver::Go120));
    let p = pcln_for(&bin);
    assert_eq!(p.is_wrapper(&entry(&p, "main.f")), None);
    for (ss, wrapper) in [(20u8, 21u8), (21, 22), (22, 23)] {
        let mut funcs = sample(Ver::Go120);
        funcs[1].func_id = wrapper;
        funcs.push(SFunc {
            name: "runtime.systemstack_switch",
            size: 0x10,
            func_id: ss,
            ..Default::default()
        });
        let bin = build(Ver::Go120, &funcs);
        let p = pcln_for(&bin);
        assert_eq!(p.is_wrapper(&entry(&p, "main.inl")), Some(true), "ss={ss}");
        assert_eq!(p.is_wrapper(&entry(&p, "main.f")), Some(false), "ss={ss}");
    }
}

#[test]
fn open_defer_format_follows_the_epoch() {
    // On the 1.20+ magic the format comes from runtime.systemstack_switch's
    // funcID: 20 on Go 1.20/1.21, 21 on 1.22 to 1.24, 22 from 1.25.
    let rec_118 = vec![0x19, 0x02, 0x28, 0x20];
    let rec_122 = vec![0x19, 0x28];
    for (ss, rec, want) in [
        (20u8, rec_118.clone(), OpenDeferFormat::Go118),
        (21, rec_122.clone(), OpenDeferFormat::Go122),
        (22, rec_122.clone(), OpenDeferFormat::Go122),
    ] {
        let mut funcs = sample(Ver::Go120);
        funcs[0].funcdata[4] = Some(rec);
        funcs.push(SFunc {
            name: "runtime.systemstack_switch",
            size: 0x10,
            func_id: ss,
            ..Default::default()
        });
        let bin = build(Ver::Go120, &funcs);
        let p = pcln_for(&bin);
        let info = p
            .open_coded_defer_info(&entry(&p, "main.f"))
            .expect("record");
        assert_eq!(info.format, want, "ss={ss}");
        assert_eq!(info.defer_bits_offset, 0x19);
    }
    // 1.18/1.19 magic needs no epoch.
    let mut funcs = sample(Ver::Go118);
    funcs[0].funcdata[4] = Some(rec_118);
    let bin = build(Ver::Go118, &funcs);
    let p = pcln_for(&bin);
    let info = p.open_coded_defer_info(&entry(&p, "main.f")).unwrap();
    assert_eq!(info.closure_slot_offsets, vec![0x20, 0x28]);
}

#[test]
fn parse_arg_info_matches_emit_arg_info() {
    // func(a int, s string)
    assert_eq!(
        parse_arg_info(&ARGINFO_INT_STRING),
        Some(vec![
            ArgComp::Word { off: 0, size: 8 },
            ArgComp::Agg(vec![
                ArgComp::Word { off: 8, size: 8 },
                ArgComp::Word { off: 16, size: 8 }
            ]),
        ])
    );
    // func(a, b int32): two words.
    assert_eq!(
        parse_arg_info(&[0x00, 0x04, 0x04, 0x04, 0xff]).map(|v| v.len()),
        Some(2)
    );
    // Eleven ints: ten words then the TraceArgsLimit "...".
    let mut b = Vec::new();
    for i in 0..10u8 {
        b.extend([i * 8, 8]);
    }
    b.extend([0xfc, 0xff]);
    let v = parse_arg_info(&b).unwrap();
    assert_eq!(v.len(), 11);
    assert_eq!(v[10], ArgComp::Ellipsis);
    // struct{} and an offset past 0xf0.
    assert_eq!(
        parse_arg_info(&[0xfe, 0xfd, 0xfb, 0xff]),
        Some(vec![ArgComp::Agg(vec![]), ArgComp::TooLarge])
    );
    // Five nesting levels end in "..." (TraceArgsMaxDepth).
    let deep = [
        0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfc, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xff,
    ];
    let mut v = parse_arg_info(&deep).unwrap();
    for _ in 0..5 {
        match v.pop() {
            Some(ArgComp::Agg(inner)) => v = inner,
            other => panic!("expected aggregate, got {other:?}"),
        }
    }
    assert_eq!(v, vec![ArgComp::Ellipsis]);
    // Empty parameter list.
    assert_eq!(parse_arg_info(&[0xff]), Some(vec![]));
}

#[test]
fn parse_arg_info_rejects_what_the_writer_never_emits() {
    assert_eq!(parse_arg_info(&[]), None, "no terminator");
    assert_eq!(parse_arg_info(&[0x00, 0x08]), None, "no terminator");
    assert_eq!(parse_arg_info(&[0x00]), None, "word without size");
    assert_eq!(parse_arg_info(&[0xf5, 0xff]), None, "reserved operator");
    assert_eq!(
        parse_arg_info(&[0xfd, 0xff]),
        None,
        "end of an unopened aggregate"
    );
    assert_eq!(
        parse_arg_info(&[0xfe, 0xff]),
        None,
        "terminator inside an aggregate"
    );
    let too_deep = [
        0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xff,
    ];
    assert_eq!(
        parse_arg_info(&too_deep),
        None,
        "deeper than the compiler nests"
    );
}

#[test]
fn parse_open_defer_info_reads_each_format() {
    // Go 1.22+ (emitOpenDeferInfo): -deferBits.FrameOffset, -firstSlot.
    let v = parse_open_defer_info(&[0x19, 0x30], Some(OpenDeferFormat::Go122), 8).unwrap();
    assert_eq!(v.defer_bits_offset, 0x19);
    assert_eq!(v.slots_offset, 0x30);
    assert_eq!(v.num_defers, None);
    assert!(v.closure_slot_offsets.is_empty());

    // Go 1.18-1.21: deferBits, n, closures written last defer first.
    let v = parse_open_defer_info(
        &[0x19, 0x03, 0x38, 0x30, 0x28],
        Some(OpenDeferFormat::Go118),
        8,
    )
    .unwrap();
    assert_eq!(v.num_defers, Some(3));
    assert_eq!(v.closure_slot_offsets, vec![0x28, 0x30, 0x38]);
    assert_eq!(v.slots_offset, 0x28);

    // Go 1.14-1.17: maxargsize, deferBits, n, then per defer (last first):
    // argWidth, closure, nArgs, nArgs x (argOffset, argLen, argCallOffset).
    // Defer 1 has one 8-byte arg; defer 0 has none. A two-byte varint (0x98 0x01
    // = 152) checks multi-byte reads.
    let rec = [
        0x08, 0x19, 0x02, // maxargsize, deferBits, n
        0x08, 0x98, 0x01, 0x01, 0x40, 0x08, 0x00, // defer 1
        0x00, 0x20, 0x00, // defer 0
    ];
    let v = parse_open_defer_info(&rec, Some(OpenDeferFormat::Go114), 8).unwrap();
    assert_eq!(v.num_defers, Some(2));
    assert_eq!(v.closure_slot_offsets, vec![0x20, 152]);

    // Truncated and out-of-range counts are refused.
    assert!(parse_open_defer_info(&[0x19, 0x02, 0x28], Some(OpenDeferFormat::Go118), 8).is_none());
    assert!(parse_open_defer_info(&[0x19, 0x09], Some(OpenDeferFormat::Go118), 8).is_none());
    assert!(parse_open_defer_info(&[0x19, 0x00], Some(OpenDeferFormat::Go118), 8).is_none());
}

#[test]
fn open_defer_format_is_inferred_only_when_unambiguous() {
    let v = parse_open_defer_info(&[0x19, 0x30], None, 8).unwrap();
    assert_eq!(v.format, OpenDeferFormat::Go122);
    let v = parse_open_defer_info(&[0x19, 0x02, 0x28, 0x20], None, 8).unwrap();
    assert_eq!(v.format, OpenDeferFormat::Go118);
    // 8 is both a full defer count and a pointer-aligned slot offset.
    assert!(parse_open_defer_info(&[0x19, 0x08, 0, 0, 0, 0, 0, 0, 0, 0], None, 8).is_none());
}

#[test]
fn readers_never_panic_on_hostile_tables() {
    // Mutate a valid synthetic table of each layout and run every reader. All
    // reads are bounds-checked, so nothing may panic.
    let mut state: u64 = 0x1234_5678_9abc_def0;
    let mut rng = || {
        state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = state;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    };
    for ver in ALL {
        for _ in 0..400 {
            let mut bin = build(ver, &sample(ver));
            let len = bin.bytes.len();
            for _ in 0..(rng() % 24) {
                let i = (rng() as usize) % len;
                bin.bytes[i] = rng() as u8;
            }
            let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let Ok(p) = Pclntab::parse(&bin) else {
                    return;
                };
                let p = p.with_gofunc(GOFUNC_ADDR);
                let Ok(funcs) = p.functions_with_offsets() else {
                    return;
                };
                for f in &funcs {
                    let _ = p.func_fields(f);
                    let _ = p.line_table(f);
                    let _ = p.arg_info(f);
                    let _ = p.open_coded_defer_info(f);
                    let _ = p.is_wrapper(f);
                    for off in [0u64, 0x10, 0x12, 0x2f] {
                        let _ = p.sp_delta_at(f, f.address + off);
                        let _ = p.inline_leaf(f, f.address + off);
                        let _ = p.lookup_inline(&bin, f.address + off);
                    }
                    let _ = crate::inline::decode_inline_tree(&bin, &p, f);
                }
            }));
            assert!(res.is_ok(), "{ver:?}: a reader panicked on a mutated table");
        }
    }
}
