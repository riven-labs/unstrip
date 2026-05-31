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

use unstrip::funcsig::recover_methods_from_types;
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
