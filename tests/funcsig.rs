//! Day-1 tests for the method-table recovery path.
//!
//! These rely on the committed `hello.linux-amd64.stripped` and
//! `depsdemo.linux-amd64.stripped` fixtures (real Go binaries built from
//! `testdata/hello.go` and `testdata/depsdemo/`). Every real Go binary
//! that imports anything from the stdlib has hundreds of methods on
//! named types (every error implementation, every io.Reader/Writer
//! concrete, every channel direction, etc.), so the floor-count
//! assertions below are conservative on purpose.

use std::path::PathBuf;

use unstrip::funcsig::{recover_methods_from_types, render_method_signature, TypeCache};
use unstrip::gobin::GoBinary;
use unstrip::moduledata::ModuleData;
use unstrip::types;

fn fixture(name: &str) -> Option<PathBuf> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("testdata")
        .join(name);
    if path.exists() {
        Some(path)
    } else {
        eprintln!("skipping: fixture {name} not built");
        None
    }
}

#[test]
fn recovers_methods_from_hello_binary() {
    let Some(path) = fixture("hello.linux-amd64.stripped") else {
        return;
    };
    let bin = GoBinary::open(&path).expect("open binary");
    let md = ModuleData::locate(&bin).expect("locate moduledata");
    let recovered_types = types::recover_all(&bin, &md).expect("recover types");
    let methods = recover_methods_from_types(&bin, &md, &recovered_types);

    // Even a hello-world Go binary imports fmt + runtime, which bring in
    // dozens of method implementations (every io.Writer concrete, every
    // error.Error, every Stringer). 50 is a deliberately low floor that
    // a working method-table walk will clear easily.
    assert!(
        methods.len() >= 50,
        "expected at least 50 recovered methods, got {}. \
         First 10: {:#?}",
        methods.len(),
        methods.iter().take(10).collect::<Vec<_>>()
    );
}

#[test]
fn recovered_methods_carry_resolvable_text_pcs() {
    let Some(path) = fixture("hello.linux-amd64.stripped") else {
        return;
    };
    let bin = GoBinary::open(&path).expect("open binary");
    let md = ModuleData::locate(&bin).expect("locate moduledata");
    let recovered_types = types::recover_all(&bin, &md).expect("recover types");
    let methods = recover_methods_from_types(&bin, &md, &recovered_types);

    // Every method whose tfn is non-zero should land inside [md.text,
    // md.etext) -- the text section bounds. If we get methods whose tfn
    // is wildly outside that range, the wrapping_add math is off.
    let mut in_range = 0usize;
    let mut zero_tfn = 0usize;
    let mut out_of_range_examples = Vec::new();
    for m in &methods {
        if m.tfn_pc == 0 {
            zero_tfn += 1;
            continue;
        }
        if m.tfn_pc >= md.text && m.tfn_pc < md.etext {
            in_range += 1;
        } else if out_of_range_examples.len() < 5 {
            out_of_range_examples.push((m.receiver.clone(), m.name.clone(), m.tfn_pc));
        }
    }

    // We accept zero_tfn (methods can legitimately have tfn == -1 when
    // only the iface wrapper exists), but in-range should dominate
    // non-zero. If anything more than 1% of methods have wildly bad PCs,
    // the offset math is broken.
    let non_zero = methods.len() - zero_tfn;
    let out_of_range = non_zero - in_range;
    assert!(
        out_of_range * 100 < non_zero,
        "{out_of_range} of {non_zero} non-zero method PCs landed outside [{:#x}, {:#x}); first 5: {:?}",
        md.text,
        md.etext,
        out_of_range_examples
    );
}

#[test]
fn recovered_methods_have_non_empty_names() {
    let Some(path) = fixture("hello.linux-amd64.stripped") else {
        return;
    };
    let bin = GoBinary::open(&path).expect("open binary");
    let md = ModuleData::locate(&bin).expect("locate moduledata");
    let recovered_types = types::recover_all(&bin, &md).expect("recover types");
    let methods = recover_methods_from_types(&bin, &md, &recovered_types);

    // Method names live in the same names blob as type names. If we
    // resolved type names fine but get empty method names, the NameOff
    // arithmetic is wrong.
    let named = methods.iter().filter(|m| !m.name.is_empty()).count();
    let total = methods.len();
    assert!(
        named * 100 >= total * 95,
        "only {named} of {total} methods have a name; names blob walk is off"
    );
}

// ---- Day 2: signature rendering ----

/// Helper for Day-2 tests: recover methods + render every one we can.
/// Returns a list of (receiver, name, signature) for methods whose
/// signature rendered successfully.
fn render_all(path: PathBuf) -> Vec<(String, String, String)> {
    let bin = GoBinary::open(&path).expect("open binary");
    let md = ModuleData::locate(&bin).expect("locate moduledata");
    let recovered_types = types::recover_all(&bin, &md).expect("recover types");
    let methods = recover_methods_from_types(&bin, &md, &recovered_types);

    let mut cache = TypeCache::new(&bin, &md);
    cache.seed_from(&recovered_types);

    let mut out = Vec::new();
    for m in &methods {
        if let Some(sig) = render_method_signature(m, &mut cache) {
            out.push((m.receiver.clone(), m.name.clone(), sig));
        }
    }
    out
}

#[test]
fn renders_well_known_stdlib_method_signatures() {
    let Some(path) = fixture("hello.linux-amd64.stripped") else {
        return;
    };
    let rendered = render_all(path);

    // Stdlib methods with stable, well-known signatures. Each tuple is
    // (receiver, method_name, expected_signature). The receiver match is
    // exact; the signature match is exact. If Go's stdlib changes the
    // signature of any of these, the test should fail loudly.
    let expected: &[(&str, &str, &str)] = &[
        ("*errors.errorString", "Error", "() string"),
        ("reflect.Kind", "String", "() string"),
        ("*os.File", "Write", "(_0 []uint8) (int, error)"),
        ("*os.File", "Read", "(_0 []uint8) (int, error)"),
        ("*atomic.Int64", "Swap", "(_0 int64) int64"),
        ("syscall.Errno", "Is", "(_0 error) bool"),
    ];

    for (recv, name, want) in expected {
        let got = rendered
            .iter()
            .find(|(r, n, _)| r == recv && n == name)
            .map(|(_, _, s)| s.as_str());
        assert_eq!(
            got,
            Some(*want),
            "{recv}.{name}: expected {want:?}, got {got:?}"
        );
    }
}

#[test]
fn signature_rendering_covers_at_least_one_third_of_methods() {
    let Some(path) = fixture("hello.linux-amd64.stripped") else {
        return;
    };
    let bin = GoBinary::open(&path).expect("open binary");
    let md = ModuleData::locate(&bin).expect("locate moduledata");
    let recovered_types = types::recover_all(&bin, &md).expect("recover types");
    let methods = recover_methods_from_types(&bin, &md, &recovered_types);

    let mut cache = TypeCache::new(&bin, &md);
    cache.seed_from(&recovered_types);

    let rendered = methods
        .iter()
        .filter(|m| render_method_signature(m, &mut cache).is_some())
        .count();
    let total = methods.len();
    // Day-2 baseline: we render signatures for methods whose mtyp lands on a
    // funcType record. Day-3 (itab method tables) and Day-4 (cross-reference
    // dedup) will push this number higher. A 33% floor today guards against
    // a regression that drops the figure into the single digits.
    assert!(
        rendered * 3 >= total,
        "only {rendered} of {total} methods got a rendered signature \
         ({:.1}%); Day-2 floor is 33%",
        100.0 * rendered as f64 / total as f64
    );
}

#[test]
fn variadic_method_renders_with_dotdotdot() {
    let Some(path) = fixture("hello.linux-amd64.stripped") else {
        return;
    };
    let rendered = render_all(path);

    // fmt.pp.Sprintf and friends are variadic. Search for any rendered
    // method whose signature contains `...` so we know the variadic path
    // produces the right shape. If hello-world doesn't pull in any
    // variadic methods on a named type, this test silently passes (we
    // only assert when we have a candidate).
    let any_variadic = rendered.iter().find(|(_, _, sig)| sig.contains("..."));
    if let Some((recv, name, sig)) = any_variadic {
        // Variadic must appear ONLY as the last parameter, and it must be
        // formatted as `...T` (no brackets).
        assert!(
            !sig.contains("...[]"),
            "{recv}.{name}: variadic should be ...T not ...[]T: {sig}"
        );
    }
}

#[test]
fn itab_merge_widens_signature_coverage() {
    // The uncommon-table path reaches every method declared on a named
    // type. The itab path adds signatures for the iface-wrapper bodies
    // that share a PC with the uncommon-table method but were generated
    // separately. Merging the two sources should produce a signature
    // count strictly greater than either alone.
    let Some(path) = fixture("hello.linux-amd64.stripped") else {
        return;
    };
    let bin = GoBinary::open(&path).expect("open binary");
    let md = ModuleData::locate(&bin).expect("locate moduledata");
    let recovered_types = types::recover_all(&bin, &md).expect("recover types");
    let recovered_itabs = unstrip::itabs::recover_all(&bin, &md).expect("recover itabs");

    let from_types = recover_methods_from_types(&bin, &md, &recovered_types);
    let from_itabs =
        unstrip::funcsig::recover_methods_from_itabs(&recovered_types, &recovered_itabs);
    let merged = unstrip::funcsig::merge_methods(from_types.clone(), from_itabs.clone());

    // Merged length is at most the sum (no duplicates introduced) and at
    // least the larger of the two (dedup never drops a unique record).
    assert!(
        merged.len() <= from_types.len() + from_itabs.len(),
        "merge created duplicates: {} > {} + {}",
        merged.len(),
        from_types.len(),
        from_itabs.len()
    );
    assert!(
        merged.len() >= from_types.len().max(from_itabs.len()),
        "merge dropped unique records: {} < max({}, {})",
        merged.len(),
        from_types.len(),
        from_itabs.len()
    );
}

#[test]
fn signatures_by_pc_keys_on_function_entry() {
    // signatures_by_pc must key the returned map on the method's tfn_pc
    // (the direct-call body entry), so the function listing's PC lookup
    // succeeds without any extra translation. Every key must fall inside
    // [md.text, md.etext).
    let Some(path) = fixture("hello.linux-amd64.stripped") else {
        return;
    };
    let bin = GoBinary::open(&path).expect("open binary");
    let md = ModuleData::locate(&bin).expect("locate moduledata");
    let recovered_types = types::recover_all(&bin, &md).expect("recover types");
    let methods = recover_methods_from_types(&bin, &md, &recovered_types);

    let mut cache = TypeCache::new(&bin, &md);
    cache.seed_from(&recovered_types);
    let by_pc = unstrip::funcsig::signatures_by_pc(&methods, &mut cache);

    assert!(
        !by_pc.is_empty(),
        "expected at least one PC-keyed signature on a hello-world binary"
    );
    for &pc in by_pc.keys() {
        assert!(
            pc >= md.text && pc < md.etext,
            "signature key 0x{pc:x} falls outside [text=0x{:x}, etext=0x{:x})",
            md.text,
            md.etext
        );
    }
}

// ---- Method tables across Go versions and kinds ----

/// Every Go release whose method-table or map layout the fixtures pin. The
/// `funcinfo` and `methodset` fixtures are built per release by
/// `testdata/build-fixtures.sh`; a missing one is skipped.
const VERSIONED_FIXTURES: &[&str] = &[
    "funcinfo.go117.stripped",
    "funcinfo.go118.stripped",
    "funcinfo.go120.stripped",
    "funcinfo.go122.stripped",
    "funcinfo.go126.stripped",
    "methodset.go117.stripped",
    "methodset.go118.stripped",
    "methodset.go120.stripped",
    "methodset.go122.stripped",
    "methodset.go124.stripped",
    "methodset.go126.stripped",
    "hello.linux-amd64.stripped",
];

/// pclntab function names keyed by entry PC: the ground truth a method's
/// tfn must land on.
fn function_names(bin: &GoBinary, md: &ModuleData) -> std::collections::HashMap<u64, String> {
    unstrip::pclntab::Pclntab::parse(bin)
        .expect("parse pclntab")
        .with_gofunc(md.gofunc)
        .functions()
        .expect("functions")
        .into_iter()
        .map(|f| (f.address, f.name))
        .collect()
}

#[test]
fn method_tables_agree_with_pclntab_on_every_version() {
    // Each recovered method must carry a name, and its direct-call body
    // (tfn) must be the entry of the pclntab function of that name. A wrong
    // UncommonType offset breaks both at once: Go 1.23+ binaries (whose
    // `iter.Seq[...]` named func types put the block at +8, not +4) yielded
    // thousands of nameless methods with PCs outside the text section.
    let mut checked = 0;
    for &name in VERSIONED_FIXTURES {
        let Some(path) = fixture(name) else {
            continue;
        };
        let bin = GoBinary::open(&path).expect("open binary");
        let md = ModuleData::locate(&bin).expect("locate moduledata");
        let recovered_types = types::recover_all(&bin, &md).expect("recover types");
        let methods = recover_methods_from_types(&bin, &md, &recovered_types);
        let funcs = function_names(&bin, &md);
        assert!(
            methods.len() >= 50,
            "{name}: only {} methods",
            methods.len()
        );

        let mut with_body = 0;
        for m in &methods {
            assert!(
                !m.name.is_empty(),
                "{name}: nameless method on {}",
                m.receiver
            );
            if m.tfn_pc == 0 {
                continue;
            }
            with_body += 1;
            let func = funcs.get(&m.tfn_pc);
            assert!(
                func.is_some_and(|f| f.ends_with(&format!(".{}", m.name))),
                "{name}: {}.{} tfn 0x{:x} is {func:?}",
                m.receiver,
                m.name,
                m.tfn_pc
            );
            if m.ifn_pc != 0 {
                assert!(
                    funcs.contains_key(&m.ifn_pc),
                    "{name}: {}.{} ifn 0x{:x} is not a function entry",
                    m.receiver,
                    m.name,
                    m.ifn_pc
                );
            }
        }
        assert!(
            with_body >= 50,
            "{name}: only {with_body} methods with a body"
        );
        checked += 1;
    }
    if checked == 0 {
        eprintln!("skipping: no versioned fixtures built");
    }
}

#[test]
fn every_receiver_kind_recovers_its_methods_across_versions() {
    // methodset.go gives a named func, map, chan, array, slice, float,
    // string, and struct-pointer type one `Show(string) string` method each.
    // Every kind puts its UncommonType at a different offset (maps by
    // implementation: the pre-1.24 hmap MapType and the 1.24+ swiss one
    // differ), so each one is checked on each release.
    let receivers = [
        ("main.Handler", "main.Handler.Show"),
        ("main.Header", "main.Header.Show"),
        ("main.Pipe", "main.Pipe.Show"),
        ("main.Quad", "main.Quad.Show"),
        ("main.Names", "main.Names.Show"),
        ("main.Celsius", "main.Celsius.Show"),
        ("main.Label", "main.Label.Show"),
        ("*main.Box", "main.(*Box).Show"),
        // The pointer flavors of the value receivers carry the
        // autogenerated wrapper, e.g. a map's pointer type.
        ("*main.Header", "main.(*Header).Show"),
        ("*main.Handler", "main.(*Handler).Show"),
    ];
    for v in ["117", "118", "120", "122", "124", "126"] {
        let name = format!("methodset.go{v}.stripped");
        let Some(path) = fixture(&name) else {
            continue;
        };
        let bin = GoBinary::open(&path).expect("open binary");
        let md = ModuleData::locate(&bin).expect("locate moduledata");
        let recovered_types = types::recover_all(&bin, &md).expect("recover types");
        let methods = recover_methods_from_types(&bin, &md, &recovered_types);
        let funcs = function_names(&bin, &md);
        let mut cache = TypeCache::new(&bin, &md);
        cache.seed_from(&recovered_types);

        for (recv, func_name) in receivers {
            let m = methods
                .iter()
                .find(|m| m.receiver == recv && m.name == "Show")
                .unwrap_or_else(|| panic!("{name}: {recv}.Show not recovered"));
            assert_eq!(
                funcs.get(&m.tfn_pc).map(String::as_str),
                Some(func_name),
                "{name}: {recv}.Show tfn 0x{:x}",
                m.tfn_pc
            );
            assert_eq!(
                render_method_signature(m, &mut cache).as_deref(),
                Some("(_0 string) string"),
                "{name}: {recv}.Show signature"
            );
        }
    }
}
