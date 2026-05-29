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
use unstrip::inline::{
    decode_inline_tree, inline_callgraph, resolve_leaf_name, EdgeKind, Node, NodeKind,
};
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

#[test]
fn inline_callgraph_emits_one_node_per_physical_function() {
    let Some(path) = fixture("hello.linux-amd64.stripped") else {
        return;
    };
    let bin = GoBinary::open(&path).expect("open");
    let md = ModuleData::locate(&bin).expect("md");
    let pcln = Pclntab::parse(&bin).expect("pcln").with_gofunc(md.gofunc);

    let g = inline_callgraph(&bin, &pcln).expect("build callgraph");
    let funcs = pcln.functions_with_offsets().expect("funcs");

    let physical_count = g
        .nodes
        .iter()
        .filter(|n| matches!(n.kind, NodeKind::Physical))
        .count();
    assert_eq!(
        physical_count,
        funcs.len(),
        "one Physical node per pclntab function"
    );

    let names: std::collections::HashSet<&str> = g.nodes.iter().map(|n| n.name.as_str()).collect();
    assert!(names.contains("main.main"), "main.main must appear");
}

#[test]
fn inline_callgraph_inlined_edges_anchor_real_callers_and_call_sites() {
    let Some(path) = fixture("hello.linux-amd64.stripped") else {
        return;
    };
    let bin = GoBinary::open(&path).expect("open");
    let md = ModuleData::locate(&bin).expect("md");
    let pcln = Pclntab::parse(&bin).expect("pcln").with_gofunc(md.gofunc);

    let g = inline_callgraph(&bin, &pcln).expect("build callgraph");
    let funcs = pcln.functions_with_offsets().expect("funcs");

    assert!(
        !g.edges.is_empty(),
        "any real Go binary inlines runtime.* calls; expected at least one Inlined edge"
    );

    for e in &g.edges {
        assert!(matches!(e.kind, EdgeKind::Inlined));
        let caller = funcs
            .iter()
            .find(|f| f.address == e.from)
            .unwrap_or_else(|| panic!("edge.from 0x{:x} must match a physical function", e.from));
        assert!(
            e.call_site >= caller.address && e.call_site < caller.address + caller.size,
            "call_site 0x{:x} must lie inside caller {} (0x{:x}..0x{:x})",
            e.call_site,
            caller.name,
            caller.address,
            caller.address + caller.size,
        );
    }
}

#[test]
fn inline_callgraph_dedupes_inlined_edges_and_named_callees() {
    let Some(path) = fixture("hello.linux-amd64.stripped") else {
        return;
    };
    let bin = GoBinary::open(&path).expect("open");
    let md = ModuleData::locate(&bin).expect("md");
    let pcln = Pclntab::parse(&bin).expect("pcln").with_gofunc(md.gofunc);

    let g = inline_callgraph(&bin, &pcln).expect("build callgraph");

    let mut edge_keys: std::collections::HashSet<(u64, u64, u64)> =
        std::collections::HashSet::new();
    for e in &g.edges {
        let was_new = edge_keys.insert((e.from, e.to, e.call_site));
        assert!(
            was_new,
            "duplicate edge: from=0x{:x} to=0x{:x} site=0x{:x}",
            e.from, e.to, e.call_site
        );
    }

    // Inlined-only callees (NodeKind::AnonymousInline with a non-empty
    // name) must dedupe by name: when many physical functions inline
    // the same callee, the inlined edges all point at one node, not N.
    // Physical nodes with duplicate names are NOT duplicates — the Go
    // linker legitimately emits multiple physical functions sharing a
    // name in a stripped binary (e.g. `runtime.debugCallWrap` is
    // instantiated per stack-arg-size), and collapsing them would lose
    // real call sites.
    let mut by_name: std::collections::HashMap<&str, usize> = std::collections::HashMap::new();
    for n in &g.nodes {
        if matches!(n.kind, NodeKind::AnonymousInline { .. }) && !n.name.is_empty() {
            *by_name.entry(n.name.as_str()).or_insert(0) += 1;
        }
    }
    for (name, count) in &by_name {
        assert_eq!(
            *count, 1,
            "named inlined-only node {name} appears {count} times; expected 1"
        );
    }
}

#[test]
fn inline_callgraph_anonymous_addrs_use_high_bit_tag() {
    let Some(path) = fixture("hello.linux-amd64.stripped") else {
        return;
    };
    let bin = GoBinary::open(&path).expect("open");
    let md = ModuleData::locate(&bin).expect("md");
    let pcln = Pclntab::parse(&bin).expect("pcln").with_gofunc(md.gofunc);

    let g = inline_callgraph(&bin, &pcln).expect("build callgraph");
    for n in &g.nodes {
        match n.kind {
            NodeKind::Physical => assert!(
                !Node::is_anonymous_addr(n.addr),
                "physical node addr 0x{:x} must not have the anonymous tag",
                n.addr,
            ),
            NodeKind::AnonymousInline { .. } => assert!(
                Node::is_anonymous_addr(n.addr),
                "anonymous-inline node addr 0x{:x} must have the anonymous tag",
                n.addr,
            ),
        }
    }
}
