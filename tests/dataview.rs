//! Tests for the data-view renderer's honesty about what it is looking at.
//! Uses the committed `depsdemo.linux-amd64.stripped` fixture (a real stripped
//! Go binary); skips when it is not built.

use std::path::PathBuf;

use unstrip::dataview::{inspect, As};
use unstrip::gobin::GoBinary;
use unstrip::pclntab::Pclntab;

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
fn data_as_string_on_code_reports_not_a_header() {
    let Some(path) = fixture("depsdemo.linux-amd64.stripped") else {
        return;
    };
    let bin = GoBinary::open(&path).expect("open fixture");
    let pcln = Pclntab::parse(&bin).expect("parse pclntab");
    // The .text entry is machine code, not a Go string header. Read as a string,
    // its first eight bytes are an instruction stream, so the "pointer" is wild
    // and the "length" is nonsense. The renderer must say it is not a header and
    // point at --data-as bytes, not present the garbage as data.
    let rows =
        inspect(&bin, &pcln, &[], &[], bin.text_addr, 16, As::String).expect("inspect succeeds");
    assert_eq!(rows.len(), 1);
    assert!(
        rows[0].rendering.contains("not a string header"),
        "expected a not-a-header message, got: {}",
        rows[0].rendering
    );
    assert!(
        rows[0].rendering.contains("--data-as bytes"),
        "expected a pointer to --data-as bytes, got: {}",
        rows[0].rendering
    );
}
