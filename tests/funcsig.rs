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
