//! String literal recovery on `testdata/strlits.go`, built for the targets
//! `testdata/build-fixtures.sh` lists. A fixture that was not built is
//! skipped.
//!
//! The expectations come from the Go source: which function uses which
//! literal, and which literals sit in initialized globals. They hold for
//! any Go release the fixture is built with, so they name functions and
//! headers, not the instruction shape (registers before Go 1.17, stack
//! stores after).

use std::path::PathBuf;

use unstrip::gobin::GoBinary;
use unstrip::pclntab::Pclntab;
use unstrip::strings::{literals, Literals};

fn fixture(name: &str) -> Option<GoBinary> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("testdata")
        .join(name);
    if !path.exists() {
        eprintln!("skipping: fixture {name} not built (run testdata/build-fixtures.sh)");
        return None;
    }
    Some(GoBinary::open(&path).expect("fixture parses"))
}

fn recover(bin: &GoBinary) -> Literals {
    let pcln = Pclntab::parse(bin).expect("pclntab parses");
    literals(bin, &pcln).expect("literal recovery runs")
}

/// The functions that use the literal `text`, by name.
fn users(report: &Literals, text: &str) -> Vec<String> {
    let mut out: Vec<String> = report
        .literals
        .iter()
        .filter(|l| l.text.as_deref() == Some(text))
        .flat_map(|l| l.uses.iter().filter_map(|u| u.function.clone()))
        .collect();
    out.sort();
    out.dedup();
    out
}

fn static_headers(report: &Literals, text: &str) -> usize {
    report
        .literals
        .iter()
        .filter(|l| l.text.as_deref() == Some(text))
        .map(|l| l.headers.len())
        .sum()
}

/// What every report must satisfy, whatever the target: the bytes are the
/// binary's own, and no two literals overlap.
fn check_invariants(bin: &GoBinary, report: &Literals) {
    let mut end = 0u64;
    for l in &report.literals {
        let bytes = bin
            .read_at_addr(l.addr, l.len as usize)
            .expect("a literal's bytes are mapped");
        assert_eq!(bytes, l.bytes.as_slice(), "literal at 0x{:x}", l.addr);
        assert_eq!(l.len as usize, l.bytes.len());
        assert!(
            l.addr >= end,
            "literal at 0x{:x} overlaps the one before it",
            l.addr
        );
        end = l.addr + l.len;
    }
}

/// Literals of strlits.go and the function that uses each, as the source
/// says.
const USED_BY: [(&str, &str); 8] = [
    ("dynamic-host.strlits.example", "main.build"),
    ("strlits-agent/2.0 (", "main.build"),
    ("/strlits/first", "main.build"),
    ("strlits-pick-a", "main.main"),
    ("strlits-pick-suffix", "main.main"),
    ("strlits kind unknown", "main.describe"),
    ("strlits: empty host given to connect", "main.connect"),
    ("strlits-map-value-one", "main.init"),
];

/// `classify` compares its argument with these through
/// `runtime.memequal`. Before the register ABI the length reaches the call
/// from a register only the preceding branch pins, so this holds from Go
/// 1.17 on.
const COMPARED_IN_CLASSIFY: [&str; 3] = [
    "strlits-case-alpha",
    "strlits-case-charlie-longer-value",
    "strlits comparison value that is long enough",
];

/// Literals held by initialized globals: `endpoints`, `defaultConfig`,
/// `banner`.
const IN_GLOBALS: [&str; 4] = [
    "https://alpha.strlits.example/api/v1",
    "https://charlie.strlits.example/upload",
    "static-host.strlits.example",
    "strlits global banner value",
];

fn check_strlits(name: &str) -> Option<Literals> {
    let bin = fixture(name)?;
    let report = recover(&bin);
    assert!(report.code_scanned, "{name}: amd64 and arm64 are scanned");
    check_invariants(&bin, &report);
    for (text, function) in USED_BY {
        assert!(
            users(&report, text).iter().any(|f| f == function),
            "{name}: {text:?} is used by {function}, got {:?}",
            users(&report, text)
        );
    }
    for text in IN_GLOBALS {
        assert!(
            static_headers(&report, text) >= 1,
            "{name}: {text:?} sits in an initialized global"
        );
    }
    if report.register_abi {
        for text in COMPARED_IN_CLASSIFY {
            assert!(
                users(&report, text).iter().any(|f| f == "main.classify"),
                "{name}: classify compares with {text:?}"
            );
        }
    }
    // `defaultConfig.Host` is read straight from the global's header.
    assert!(
        users(&report, "static-host.strlits.example")
            .iter()
            .any(|f| f == "main.main"),
        "{name}: main reads defaultConfig.Host through its header"
    );
    Some(report)
}

#[test]
fn linux_amd64_literals_match_the_source() {
    if let Some(report) = check_strlits("strlits.linux-amd64.stripped") {
        assert!(
            report.register_abi,
            "a current Go build passes arguments in registers"
        );
    }
}

#[test]
fn linux_arm64_literals_match_the_source() {
    check_strlits("strlits.linux-arm64.stripped");
}

#[test]
fn windows_amd64_literals_match_the_source() {
    check_strlits("strlits.windows-amd64.stripped.exe");
}

#[test]
fn darwin_arm64_literals_match_the_source() {
    check_strlits("strlits.darwin-arm64.stripped");
}

#[test]
fn go115_literals_pair_through_stack_stores() {
    if let Some(report) = check_strlits("strlits.go115.linux-amd64.stripped") {
        assert!(
            !report.register_abi,
            "Go 1.15 passes arguments on the stack"
        );
    }
}

#[test]
fn literals_with_odd_bytes_keep_them() {
    let Some(bin) = fixture("strlits.linux-amd64.stripped") else {
        return;
    };
    let report = recover(&bin);
    assert!(
        report
            .literals
            .iter()
            .any(|l| l.text.as_deref() == Some("strlits non-ascii: h\u{e9}llo w\u{f6}rld")),
        "UTF-8 text comes back as text"
    );
    let binary = report
        .literals
        .iter()
        .find(|l| l.bytes == b"strlits\x00binary\xff")
        .expect("the literal with a NUL and a 0xff byte is found");
    assert_eq!(binary.text, None, "it is not UTF-8");
    assert_eq!(
        binary.hex.as_deref(),
        Some("7374726c6974730062696e617279ff")
    );
}

#[test]
fn x386_has_no_scanner_and_reports_nothing() {
    let Some(bin) = fixture("strlits.linux-386.stripped") else {
        return;
    };
    let report = recover(&bin);
    assert!(!report.code_scanned);
    assert!(
        report.literals.is_empty(),
        "nothing locates the table on 386"
    );
}
