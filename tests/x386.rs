//! GOARCH=386 (32-bit pointers) across Go 1.17 to 1.27, on the 386 builds of
//! relift's test programs (linux ELF and windows PE). They live outside this
//! repository: `UNSTRIP_FIXTURES` names relift's `testdata` directory,
//! defaulting to `../relift/testdata` beside this checkout. A missing fixture
//! is skipped, like the ones `testdata/build-fixtures.sh` builds.
//!
//! The expectations are what `go version -m`, `go tool nm` and the Go
//! sources say for those programs, not snapshots of our own output.

use std::path::PathBuf;

use unstrip::buildinfo::BuildInfo;
use unstrip::gobin::GoBinary;
use unstrip::itabs;
use unstrip::moduledata::ModuleData;
use unstrip::pclntab::Pclntab;

fn fixtures_root() -> PathBuf {
    match std::env::var_os("UNSTRIP_FIXTURES") {
        Some(dir) => PathBuf::from(dir),
        None => PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../relift/testdata"),
    }
}

fn fixture(rel: &str) -> Option<PathBuf> {
    let path = fixtures_root().join(rel);
    if path.exists() {
        Some(path)
    } else {
        eprintln!(
            "skipping: fixture {} not found (set UNSTRIP_FIXTURES to relift's testdata)",
            path.display()
        );
        None
    }
}

/// Go minor versions the 386 fixtures are built with.
const LINUX_MINORS: [u32; 6] = [17, 20, 22, 24, 26, 27];
const WINDOWS_MINORS: [u32; 5] = [17, 20, 22, 24, 27];

/// Every 386 build of the AES-GCM/CBC/RC4 program (linux) and of the
/// int64/method programs (windows), with the Go minor it was built with.
fn builds() -> Vec<(u32, PathBuf)> {
    let mut out = Vec::new();
    for m in LINUX_MINORS {
        if let Some(p) = fixture(&format!("cipher/decrypt/bin386-go1.{m}")) {
            out.push((m, p));
        }
    }
    for m in WINDOWS_MINORS {
        for prog in ["int64math", "method"] {
            if let Some(p) = fixture(&format!("win386/{prog}/bin386-go1.{m}.exe")) {
                out.push((m, p));
            }
        }
    }
    out
}

#[test]
fn buildinfo_reads_every_386_release() {
    for (minor, path) in builds() {
        let bin = GoBinary::open(&path).expect("open");
        assert_eq!(bin.pointer_size(), 4);
        let info =
            BuildInfo::parse(&bin).unwrap_or_else(|e| panic!("{}: buildinfo: {e}", path.display()));
        assert!(
            info.go_version.starts_with(&format!("go1.{minor}.")),
            "{}: go version {:?}",
            path.display(),
            info.go_version
        );
        // `go version -m` on the Go 1.17 builds (pre-1.18 pointer format).
        if minor == 17 {
            let main = info.main.as_ref().map(|m| m.path.as_str());
            let want = if path.to_string_lossy().contains("win386") {
                if path.to_string_lossy().contains("int64math") {
                    "relift-win386-int64math"
                } else {
                    "relift-win386-method"
                }
            } else {
                "decrypt-fixture"
            };
            assert_eq!(main, Some(want), "{}", path.display());
            assert_eq!(info.path.as_deref(), Some("command-line-arguments"));
        }
    }
}

#[test]
fn itabs_resolve_names_and_methods_on_386() {
    for (minor, path) in builds() {
        let bin = GoBinary::open(&path).expect("open");
        let md = ModuleData::locate(&bin).expect("moduledata");
        let pcln = Pclntab::parse(&bin).expect("pclntab");
        // Go 1.23 dropped the itab's 4-byte pad: fun[0] at 12, not 16.
        assert_eq!(
            md.itab_fun_offset(&bin),
            if minor >= 23 { 12 } else { 16 },
            "{}",
            path.display()
        );
        let pairs = itabs::recover_all(&bin, &md).expect("itabs");
        assert!(pairs.len() > 5, "{}: {} itabs", path.display(), pairs.len());
        for it in &pairs {
            for name in [&it.interface_name, &it.concrete_name] {
                assert!(
                    !name.starts_with("iface@")
                        && !name.starts_with("type@")
                        && name.len() < 200
                        && name.bytes().all(|b| (0x20..0x7f).contains(&b)),
                    "{}: itab at 0x{:x} has an unresolved name {name:?}",
                    path.display(),
                    it.addr
                );
            }
            assert!(
                !it.methods.is_empty(),
                "{}: {} => {} has no methods",
                path.display(),
                it.interface_name,
                it.concrete_name
            );
            // Each slot is the concrete method of that name, or the
            // linker's stub for a method dead-code elimination removed.
            for m in &it.methods {
                let f = pcln.lookup(m.concrete_fn).unwrap_or_else(|| {
                    panic!("{}: slot 0x{:x} not code", path.display(), m.concrete_fn)
                });
                assert_eq!(
                    f.address,
                    m.concrete_fn,
                    "{}: slot not at an entry",
                    path.display()
                );
                assert!(
                    f.name.ends_with(&format!(".{}", m.interface_method))
                        || f.name == "runtime.unreachableMethod",
                    "{}: {} => {} slot {} is {}",
                    path.display(),
                    it.interface_name,
                    it.concrete_name,
                    m.interface_method,
                    f.name
                );
            }
        }
        assert!(
            pairs
                .iter()
                .any(|p| p.interface_name == "io.Writer" && p.concrete_name == "*os.File"),
            "{}: io.Writer => *os.File",
            path.display()
        );
        // The AEAD the GCM decrypt calls Open through.
        if path.to_string_lossy().contains("decrypt") {
            let gcm = if minor >= 24 {
                "*gcm.GCM"
            } else {
                "*cipher.gcm"
            };
            let it = pairs
                .iter()
                .find(|p| p.interface_name == "cipher.AEAD" && p.concrete_name == gcm)
                .unwrap_or_else(|| panic!("{}: cipher.AEAD => {gcm}", path.display()));
            let open = it
                .methods
                .iter()
                .find(|m| m.interface_method == "Open")
                .unwrap();
            let f = pcln.lookup(open.concrete_fn).unwrap();
            assert!(
                f.name.ends_with(".Open"),
                "{}: Open slot is {}",
                path.display(),
                f.name
            );
        }
    }
}

#[test]
fn stack_objects_use_4_byte_words_on_386() {
    // runtime.concatstringN keeps `a := [...]string{a0, ...}` on the stack:
    // N strings of two 4-byte words, pointers in the even words, so ptrBytes
    // stops after the last data pointer. runtime.convTslice's `v []byte`
    // argument (at argp + 0) holds one pointer in a 12-byte slice header.
    let want: [(&str, i32, i32, &[u8]); 4] = [
        ("runtime.concatstring2", 16, 12, &[0b101]),
        ("runtime.concatstring3", 24, 20, &[0b10101]),
        ("runtime.concatstring5", 40, 36, &[0b0101_0101, 0b1]),
        ("runtime.convTslice", 12, 4, &[0b1]),
    ];
    let mut checked = 0;
    for (_, path) in builds() {
        let bin = GoBinary::open(&path).expect("open");
        let md = ModuleData::locate(&bin).expect("moduledata");
        let pcln = Pclntab::parse(&bin)
            .expect("pclntab")
            .with_gofunc(md.gofunc);
        let rodata = (md.rodata != 0).then_some(md.rodata);
        let funcs = pcln.functions_with_offsets().expect("functab");
        for (name, size, ptr_bytes, mask) in want {
            let Some(f) = funcs.iter().find(|f| f.name == name) else {
                continue;
            };
            let objs = pcln
                .stack_objects(f)
                .unwrap_or_else(|| panic!("{}: {name}: no stack objects", path.display()));
            assert_eq!(objs.len(), 1, "{}: {name}", path.display());
            let o = objs[0];
            assert_eq!(
                (o.size, o.ptr_bytes),
                (size, ptr_bytes),
                "{}: {name}",
                path.display()
            );
            assert_eq!(
                o.off < 0,
                name != "runtime.convTslice",
                "{}: {name} off {}",
                path.display(),
                o.off
            );
            assert_eq!(
                pcln.stack_object_mask(&o, rodata).as_deref(),
                Some(mask),
                "{}: {name}",
                path.display()
            );
            checked += 1;
        }
        // Every record decodes, and its mask ends on a pointer word.
        for f in &funcs {
            if pcln.funcdata(f, 2).is_none() {
                continue;
            }
            let objs = pcln
                .stack_objects(f)
                .unwrap_or_else(|| panic!("{}: {}: records do not decode", path.display(), f.name));
            for o in objs {
                assert_eq!(o.ptr_bytes % 4, 0, "{}: {}", path.display(), f.name);
                let mask = pcln.stack_object_mask(&o, rodata).expect("mask");
                let last = (o.ptr_bytes / 4 - 1) as usize;
                assert!(
                    mask[last / 8] & (1 << (last % 8)) != 0,
                    "{}: {}: last word of ptrBytes {} not a pointer in {mask:?}",
                    path.display(),
                    f.name,
                    o.ptr_bytes
                );
            }
        }
    }
    if checked == 0 {
        eprintln!("skipping: no 386 fixture found");
    }
}

#[test]
fn garble_reflected_names_on_386() {
    // garble v0.16 keeps a sorted [obf, orig, ...] []string table; on 386
    // each string header is two 4-byte words.
    for prog in ["secrets", "ifaces"] {
        let Some(path) = fixture(&format!("garble/{prog}/bin386")) else {
            continue;
        };
        let bin = GoBinary::open(&path).expect("open");
        let names = unstrip::garble::recover_reflect_names(&bin)
            .unwrap_or_else(|| panic!("{}: no reflected-name table", path.display()));
        let originals: Vec<&str> = names.iter().map(|(_, orig)| orig).collect();
        for want in ["SelectCase", "rtype", "structType"] {
            assert!(
                originals.contains(&want),
                "{}: {want} in {originals:?}",
                path.display()
            );
        }
        if prog == "secrets" {
            assert!(
                originals.contains(&"Account"),
                "{}: {originals:?}",
                path.display()
            );
        }
    }
}

#[test]
fn types_and_methods_on_386() {
    use std::collections::HashMap;
    use unstrip::types::{KindData, KindName, Type};
    // io/fs.PathError{Op, Path string; Err error} is 24 bytes on 386, its
    // pointer carries Error, Timeout and Unwrap, and `error` is an
    // interface whose one method is a func() string.
    for (minor, path) in builds() {
        let bin = GoBinary::open(&path).expect("open");
        let md = ModuleData::locate(&bin).expect("moduledata");
        let pcln = Pclntab::parse(&bin).expect("pclntab");
        let ts = unstrip::types::recover_all(&bin, &md)
            .unwrap_or_else(|e| panic!("{}: types: {e}", path.display()));
        let by_addr: HashMap<u64, &Type> = ts.iter().map(|t| (t.addr, t)).collect();
        let name_of = |a: &u64| by_addr.get(a).map_or("?".to_string(), |t| t.name.clone());
        let find = |n: &str| {
            ts.iter()
                .find(|t| t.name == n)
                .unwrap_or_else(|| panic!("{}: go1.{minor}: no {n}", path.display()))
        };

        let pe = find("fs.PathError");
        assert_eq!((pe.kind, pe.size, pe.ptr_bytes), (KindName::Struct, 24, 24));
        let KindData::Struct { fields } = &pe.kind_data else {
            panic!("{}: fs.PathError not decoded", path.display());
        };
        let got: Vec<(&str, u64, String)> = fields
            .iter()
            .map(|f| (f.name.as_str(), f.offset, name_of(&f.typ)))
            .collect();
        let want = [
            ("Op", 0, "string"),
            ("Path", 8, "string"),
            ("Err", 16, "error"),
        ];
        assert_eq!(
            got,
            want.map(|(n, o, t)| (n, o, t.to_string())),
            "{}",
            path.display()
        );

        let err = find("error");
        let KindData::Interface { methods } = &err.kind_data else {
            panic!("{}: error not an interface", path.display());
        };
        assert_eq!(methods.len(), 1);
        assert_eq!(methods[0].name, "Error");
        let sig = by_addr.get(&methods[0].typ).expect("Error's func type");
        let KindData::Func {
            in_types,
            out_types,
            variadic,
            ..
        } = &sig.kind_data
        else {
            panic!("{}: {} not a func", path.display(), sig.name);
        };
        assert!(in_types.is_empty() && !variadic);
        assert_eq!(
            out_types.iter().map(name_of).collect::<Vec<_>>(),
            ["string"]
        );

        // The uncommon method table of *fs.PathError (Timeout's body may be
        // dead-code eliminated: tfn 0).
        let methods = unstrip::funcsig::recover_methods_from_types(&bin, &md, &ts);
        let mut names: Vec<&str> = methods
            .iter()
            .filter(|m| m.receiver == "*fs.PathError")
            .map(|m| m.name.as_str())
            .collect();
        names.sort();
        assert_eq!(names, ["Error", "Timeout", "Unwrap"], "{}", path.display());
        for m in methods
            .iter()
            .filter(|m| m.receiver == "*fs.PathError" && m.tfn_pc != 0)
        {
            let f = pcln.lookup(m.tfn_pc).expect("method body in text");
            assert_eq!(
                f.name,
                format!("io/fs.(*PathError).{}", m.name),
                "{}",
                path.display()
            );
        }
    }
}

#[test]
fn data_views_read_4_byte_words_on_386() {
    use unstrip::dataview::{inspect, As};
    for (_, path) in builds() {
        let bin = GoBinary::open(&path).expect("open");
        let md = ModuleData::locate(&bin).expect("moduledata");
        let pcln = Pclntab::parse(&bin).expect("pclntab");
        let functions = pcln.functions().expect("functions");
        let pairs = itabs::recover_all(&bin, &md).expect("itabs");
        let it = pairs
            .iter()
            .find(|p| p.interface_name == "io.Writer" && p.concrete_name == "*os.File")
            .expect("io.Writer => *os.File");
        // An itab read as pointers: inter, _type, then (past hash and any
        // pad) the Write slot, one 4-byte word per row.
        let fun = md.itab_fun_offset(&bin);
        let rows = inspect(
            &bin,
            &pcln,
            &pairs,
            &functions,
            it.addr,
            fun as usize + 4,
            As::Ptrs,
        )
        .expect("inspect");
        assert_eq!(rows.len() as u64, fun / 4 + 1, "{}", path.display());
        assert_eq!(rows[1].addr, it.addr + 4);
        let last = rows.last().unwrap();
        assert!(
            last.rendering.contains(".(*File).Write"),
            "{}: {}",
            path.display(),
            last.rendering
        );
        // Read as an interface header: (itab, data) is two words.
        let rows =
            inspect(&bin, &pcln, &pairs, &functions, it.addr, 16, As::Ifaces).expect("inspect");
        assert_eq!(rows.len(), 2, "{}", path.display());
        assert_eq!(rows[0].bytes.len(), 8);
    }
}
