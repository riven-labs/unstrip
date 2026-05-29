//! Probe-grade tests for the inline-tree decoder.
//!
//! These rely on the committed `hello.linux-amd64.stripped` fixture, which
//! is a real Go binary built from `testdata/hello.go`. Every real Go
//! binary has at least one function with a non-empty inline tree
//! (runtime.* is aggressively inlined), so we assert that property
//! directly and additionally verify the `parent_pc < func.size`
//! safety invariant for every decoded entry across the whole binary.

use std::path::PathBuf;

use unstrip::gobin::GoBinary;
use unstrip::inline::{decode_inline_tree, resolve_leaf_name};
use unstrip::moduledata::ModuleData;
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
fn decodes_at_least_one_non_empty_inline_tree() {
    let Some(path) = fixture("hello.linux-amd64.stripped") else {
        return;
    };
    let bin = GoBinary::open(&path).expect("open binary");
    let md = ModuleData::locate(&bin).expect("locate moduledata");
    let pcln = Pclntab::parse(&bin)
        .expect("parse pclntab")
        .with_gofunc(md.gofunc);

    let funcs = pcln
        .functions_with_offsets()
        .expect("walk functions_with_offsets");

    let mut non_empty = 0usize;
    let mut total_entries = 0usize;
    for f in &funcs {
        match decode_inline_tree(&bin, &pcln, f) {
            Ok(entries) => {
                if !entries.is_empty() {
                    non_empty += 1;
                    total_entries += entries.len();
                }
            }
            Err(e) => panic!("decode failed for {} (size=0x{:x}): {e}", f.name, f.size),
        }
    }
    assert!(
        non_empty > 0,
        "expected at least one function with a non-empty inline tree, got 0 \
         across {} functions",
        funcs.len(),
    );
    eprintln!(
        "non-empty inline trees: {non_empty} / {} funcs, {total_entries} total entries",
        funcs.len()
    );
}

#[test]
fn parent_pc_invariant_holds_for_every_entry() {
    let Some(path) = fixture("hello.linux-amd64.stripped") else {
        return;
    };
    let bin = GoBinary::open(&path).expect("open binary");
    let md = ModuleData::locate(&bin).expect("locate moduledata");
    let pcln = Pclntab::parse(&bin)
        .expect("parse pclntab")
        .with_gofunc(md.gofunc);

    let funcs = pcln.functions_with_offsets().expect("functions");
    for f in &funcs {
        // decode_inline_tree itself enforces parent_pc < func.size; if any
        // entry violates that invariant it returns an error rather than a
        // tainted Vec, so successful decoding across the whole binary is
        // proof the invariant held.
        let entries =
            decode_inline_tree(&bin, &pcln, f).unwrap_or_else(|e| panic!("{}: {e}", f.name));
        for (i, e) in entries.iter().enumerate() {
            if e.parent_pc != -1 {
                assert!(
                    (e.parent_pc as u64) < f.size,
                    "{} entry {}: parent_pc=0x{:x} >= size 0x{:x}",
                    f.name,
                    i,
                    e.parent_pc,
                    f.size,
                );
            }
        }
    }
}

#[test]
fn resolve_leaf_name_returns_some_for_real_leaves() {
    let Some(path) = fixture("hello.linux-amd64.stripped") else {
        return;
    };
    let bin = GoBinary::open(&path).expect("open");
    let md = ModuleData::locate(&bin).expect("md");
    let pcln = Pclntab::parse(&bin).expect("pcln").with_gofunc(md.gofunc);

    let funcs = pcln.functions_with_offsets().expect("functions");
    let mut resolved = 0usize;
    for f in &funcs {
        let Ok(entries) = decode_inline_tree(&bin, &pcln, f) else {
            continue;
        };
        for e in &entries {
            if resolve_leaf_name(&pcln, e).is_some() {
                resolved += 1;
            }
        }
    }
    assert!(
        resolved > 0,
        "expected at least one resolvable inline leaf name in the corpus",
    );
}
