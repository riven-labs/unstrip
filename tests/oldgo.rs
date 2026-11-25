//! Go 1.2 to 1.15 binaries: typeset.go built with each release for Linux and
//! Windows, amd64 and 386 (see `build_typeset_old` in
//! testdata/build-fixtures.sh). Those releases share the pclntab magic
//! 0xfffffffb but not the `_func` tail, the moduledata or the itab, so every
//! release is its own case. A fixture that was not built is skipped.

use std::path::PathBuf;

use unstrip::gobin::GoBinary;
use unstrip::itabs;
use unstrip::moduledata::ModuleData;
use unstrip::pclntab::{Inlining, Pclntab, MAGIC_1_2};
use unstrip::types::{self, KindData};

const RELEASES: [(&str, u32); 14] = [
    ("go12", 2),
    ("go13", 3),
    ("go14", 4),
    ("go15", 5),
    ("go16", 6),
    ("go17", 7),
    ("go18", 8),
    ("go19", 9),
    ("go110", 10),
    ("go111", 11),
    ("go112", 12),
    ("go113", 13),
    ("go114", 14),
    ("go115", 15),
];

const TARGETS: [&str; 4] = [
    "linux-amd64.stripped",
    "linux-386.stripped",
    "windows-amd64.stripped.exe",
    "windows-386.stripped.exe",
];

/// Every built fixture as (file name, Go minor version).
fn fixtures() -> Vec<(String, u32)> {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("testdata");
    let mut out = Vec::new();
    for (tag, minor) in RELEASES {
        for target in TARGETS {
            let name = format!("typeset.{tag}.{target}");
            if dir.join(&name).exists() {
                out.push((name, minor));
            }
        }
    }
    if out.is_empty() {
        eprintln!("skipping: no Go 1.2 to 1.15 fixture built (run testdata/build-fixtures.sh)");
    }
    out
}

fn open(name: &str) -> GoBinary {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("testdata")
        .join(name);
    GoBinary::open(&path).unwrap_or_else(|e| panic!("{name}: open: {e}"))
}

#[test]
fn reads_functions_files_and_lines_from_go_1_2_to_1_15() {
    for (name, _) in fixtures() {
        let bin = open(&name);
        let pcln = Pclntab::parse(&bin).unwrap_or_else(|e| panic!("{name}: pclntab: {e}"));
        assert_eq!(pcln.magic(), MAGIC_1_2, "{name}: Go 1.2 magic");
        let funcs = pcln.functions().expect("walk functab");
        assert!(
            funcs.len() as u64 == pcln.nfunc(),
            "{name}: every functab entry reads ({} of {})",
            funcs.len(),
            pcln.nfunc()
        );
        // The line of each function's entry is its `func` line in typeset.go.
        for (func, line) in [
            ("main.xorCodec.Apply", 17),
            ("main.addCodec.Name", 37),
            ("main.run", 39),
            ("main.main", 43),
        ] {
            let f = funcs
                .iter()
                .find(|f| f.name == func)
                .unwrap_or_else(|| panic!("{name}: {func} not recovered"));
            let file = f.file.as_deref().unwrap_or_default();
            assert!(
                file.ends_with("typeset.go"),
                "{name}: {func} file is {file:?}"
            );
            assert_eq!(f.start_line, Some(line), "{name}: {func} line");
            assert_eq!(
                pcln.lookup(f.address + 1).map(|g| g.name),
                Some(func.to_string()),
                "{name}: a PC inside {func} resolves to it"
            );
        }
        // The _func tail is nfuncdata int32 up to Go 1.11 and funcID, pad,
        // nfuncdata u8 from 1.12, under one magic. main.main always carries
        // its argument and locals pointer maps, so a tail read the wrong way
        // shows as fewer than two funcdata slots or no fields at all.
        let main = pcln
            .func_entry_at(
                funcs
                    .iter()
                    .find(|f| f.name == "main.main")
                    .unwrap()
                    .address,
            )
            .expect("func entry of main.main");
        let fields = pcln
            .func_fields(&main)
            .unwrap_or_else(|| panic!("{name}: main.main _func fields"));
        assert!(
            (2..=8).contains(&fields.nfuncdata),
            "{name}: main.main nfuncdata {}",
            fields.nfuncdata
        );

        // run's body spans lines 39 to 41. From Go 1.12 fmt.Println is inlined
        // into it, and those PCs carry fmt's own positions.
        let run = pcln
            .func_entry_at(funcs.iter().find(|f| f.name == "main.run").unwrap().address)
            .expect("func entry of main.run");
        let own: Vec<u32> = pcln
            .line_table(&run)
            .into_iter()
            .filter(|s| s.file.ends_with("typeset.go"))
            .map(|s| s.line)
            .collect();
        assert!(!own.is_empty(), "{name}: main.run has typeset.go lines");
        assert!(
            own.iter().all(|l| (39..=41).contains(l)),
            "{name}: main.run lines {own:?}"
        );
    }
}

#[test]
fn reads_types_and_itabs_from_go_1_7_to_1_15() {
    for (name, minor) in fixtures() {
        let bin = open(&name);
        if minor < 7 {
            // Go 1.2 to 1.6 have no types region in moduledata (Go 1.5 and
            // 1.6 list type pointers), so there is nothing to read types from.
            assert!(
                ModuleData::locate(&bin).is_err(),
                "{name}: no Go 1.7+ moduledata expected"
            );
            continue;
        }
        let md = ModuleData::locate(&bin).unwrap_or_else(|e| panic!("{name}: moduledata: {e}"));
        let ps = bin.pointer_size() as u64;

        let catalog = types::recover_all(&bin, &md).expect("recover types");
        let xor = catalog
            .iter()
            .find(|t| t.name == "main.xorCodec")
            .unwrap_or_else(|| panic!("{name}: main.xorCodec not recovered"));
        let KindData::Struct { fields } = &xor.kind_data else {
            panic!("{name}: main.xorCodec is not a struct");
        };
        let layout: Vec<(&str, u64)> = fields.iter().map(|f| (f.name.as_str(), f.offset)).collect();
        assert_eq!(layout, [("Key", 0), ("Tag", ps)], "{name}: xorCodec fields");
        assert_eq!(xor.size, 3 * ps, "{name}: xorCodec size");
        let codec = catalog
            .iter()
            .find(|t| t.name == "main.Codec")
            .unwrap_or_else(|| panic!("{name}: main.Codec not recovered"));
        let KindData::Interface { methods } = &codec.kind_data else {
            panic!("{name}: main.Codec is not an interface");
        };
        let names: Vec<&str> = methods.iter().map(|m| m.name.as_str()).collect();
        assert_eq!(names, ["Apply", "Name"], "{name}: Codec methods");

        // Each itab slot is the pointer-receiver wrapper of the value method,
        // read from the file from Go 1.10 and resolved the way the runtime
        // fills it before that.
        let pcln = Pclntab::parse(&bin).expect("parse pclntab");
        let pairs = itabs::recover_all(&bin, &md).expect("recover itabs");
        for concrete in ["xorCodec", "addCodec"] {
            let itab = pairs
                .iter()
                .find(|p| {
                    p.interface_name == "main.Codec"
                        && p.concrete_name == format!("main.{concrete}")
                })
                .unwrap_or_else(|| panic!("{name}: no main.Codec itab for {concrete}"));
            assert!(!itab.incomplete, "{name}: {concrete} itab is complete");
            assert_eq!(
                itab.hash,
                catalog
                    .iter()
                    .find(|t| t.name == format!("main.{concrete}"))
                    .unwrap()
                    .hash,
                "{name}: itab hash is the type's"
            );
            for (slot, method) in itab.methods.iter().zip(["Apply", "Name"]) {
                assert_eq!(slot.interface_method, method);
                let target = pcln.lookup(slot.concrete_fn).map(|f| (f.address, f.name));
                assert_eq!(
                    target,
                    Some((slot.concrete_fn, format!("main.(*{concrete}).{method}"))),
                    "{name}: {concrete}.{method} slot"
                );
            }
        }
    }
}

#[test]
fn pc_location_lists_only_the_physical_frame_before_go_1_16() {
    // The inline tree is not decoded on these releases, so every PC is unread:
    // one frame, the physical function, at the PC's own position. Inside the
    // fmt.Println inlined into main.run (Go 1.12+) that position is fmt's.
    for (name, _) in fixtures() {
        let bin = open(&name);
        let pcln = Pclntab::parse(&bin).unwrap_or_else(|e| panic!("{name}: pclntab: {e}"));
        let funcs = pcln.functions_with_offsets().expect("walk functab");
        let run = funcs.iter().find(|f| f.name == "main.run").unwrap();
        for span in pcln.line_table(run) {
            let location = pcln.pc_location(span.pc_lo).expect("main.run covers it");
            assert_eq!(location.inlining, Inlining::Unread, "{name}");
            assert_eq!(location.entry, run.address, "{name}");
            assert_eq!(location.frames.len(), 1, "{name}");
            let frame = &location.frames[0];
            assert_eq!(frame.function.as_deref(), Some("main.run"), "{name}");
            assert!(!frame.inlined, "{name}");
            assert_eq!(frame.file.as_deref(), Some(span.file.as_str()), "{name}");
            assert_eq!(frame.line, Some(span.line), "{name}");
        }
    }
}
