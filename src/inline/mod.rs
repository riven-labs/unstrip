//! Inlined-call recovery from Go's `FUNCDATA_InlTree`.
//!
//! Decodes the per-function `FUNCDATA_InlTree` array into a flat
//! `Vec<InlinedCall>`, one entry per inlined call site recorded by the
//! Go compiler.
//!
//! # Supported Go envelope
//!
//! Every pclntab layout the reader parses: Go 1.16 through 1.26.
//! `FUNCDATA_InlTree=3` and `PCDATA_InlTreeIndex=2` are unchanged across
//! that range; the record itself changed once, in Go 1.20 (see below). The
//! `_func` header and funcdata addressing are read through
//! [`Pclntab::func_fields`] and [`Pclntab::funcdata`], which know each
//! layout. Garble's `entryoff` XOR rewrite does not touch the inline-tree
//! FUNCDATA section, so this decoder works on garble-obfuscated binaries
//! unchanged.
//!
//! # On-disk encoding
//!
//! Go 1.20+ packs a 16-byte `runtime.inlinedCall` per entry:
//!
//! ```text
//!   off  size  field
//!   0    1     funcID          u8
//!   1    3     _pad            [3]u8
//!   4    4     nameOff         i32   (offset into pclntab funcname table)
//!   8    4     parentPc        i32   (PC offset within the physical fn of
//!                                     an instruction whose source position
//!                                     is the call site; every entry has one)
//!   12   4     startLine       i32
//! ```
//!
//! Go 1.16 to 1.19 use a 20-byte record: `parent int16, funcID u8, _ u8,
//! file i32, line i32, func_ i32 (nameOff), parentPc i32`. There the
//! `parent` index (not `parentPc`) is -1 for a top-level inline; the record
//! has no `startLine`, so [`InlinedCall::start_line`] is 0 for those
//! releases.
//!
//! The array lives in the `gofunc` blob (Go 1.18+, slot 3 is a u32 offset
//! from `gofunc`, `u32::MAX` = none) or at an absolute pointer (Go
//! 1.16/1.17, 0 = none). The decoder returns `Ok(vec![])` when there is no
//! tree.
//!
//! Safety: every decoded `parent_pc` is asserted to lie strictly inside
//! the host function's PC range. This catches the most common
//! garble-style corruption (a truncated/reused inltree blob from another
//! function), and is the headline invariant we check during the Day-2
//! probe.

use crate::error::Error;
use crate::gobin::GoBinary;
use crate::pclntab::{FuncEntry, Pclntab, FUNCDATA_INL_TREE, PCDATA_INL_TREE_INDEX};
use crate::Result;

/// One inlined-call record from `FUNCDATA_InlTree`.
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub struct InlinedCall {
    pub func_id: u8,
    pub name_off: i32,
    pub parent_pc: i32,
    /// Line of the callee's `func` keyword. Go 1.20+ only; 0 on Go 1.16 to
    /// 1.19, whose records do not carry it.
    pub start_line: i32,
}

/// Hard cap on entries per function. A real inline tree fits in a handful
/// of KB; 65_536 entries (1 MiB) is a very generous structural ceiling
/// and protects against a garbage length being inferred from a corrupt
/// next-pointer.
const MAX_INLINE_ENTRIES: usize = 65_536;

/// Decode the `FUNCDATA_InlTree` array for a single function.
///
/// Returns `Ok(vec![])` when the function has no inline tree (no
/// PCDATA_InlTreeIndex table, no inline index ever recorded, or a nil
/// slot 3). Returns an error if the tree is gofunc-relative and the gofunc
/// base is missing (call [`Pclntab::with_gofunc`] first), or (most
/// importantly) if any decoded entry's `parent_pc` falls outside the host
/// function's PC range. The last check rejects corrupted or recycled
/// funcdata. `bin` is kept for API compatibility; the records are read
/// through the binary `pcln` was parsed from.
pub fn decode_inline_tree(
    bin: &GoBinary,
    pcln: &Pclntab,
    func: &FuncEntry,
) -> Result<Vec<InlinedCall>> {
    let _ = bin;
    let Some(fields) = pcln.func_fields(func) else {
        return Ok(vec![]);
    };
    if fields.nfuncdata <= FUNCDATA_INL_TREE {
        return Ok(vec![]);
    }
    let Some(idx_table) = pcln.pcdata_table(func, &fields, PCDATA_INL_TREE_INDEX) else {
        return Ok(vec![]);
    };

    // The array is not length-prefixed. The runtime indexes into it using the
    // PCDATA_InlTreeIndex stream, so the function's subarray holds
    // (max index + 1) entries; walking past that reads adjacent functions'
    // subarrays.
    let max_idx = pcln
        .pcvalue_runs(idx_table, func.size)
        .map(|(_, _, v)| v)
        .max()
        .unwrap_or(-1);
    if max_idx < 0 {
        // No inline indices ever recorded for this function: empty tree.
        return Ok(vec![]);
    }
    let n_entries = (max_idx as usize).saturating_add(1).min(MAX_INLINE_ENTRIES);

    let Some(tree) = pcln.funcdata(func, FUNCDATA_INL_TREE) else {
        if pcln.funcdata_needs_gofunc() && pcln.gofunc().is_none() {
            return Err(Error::ModuleData(
                "inline-tree decoding requires gofunc base; \
                 call Pclntab::with_gofunc(moduledata.gofunc) first"
                    .to_string(),
            ));
        }
        return Ok(vec![]);
    };

    let mut out = Vec::with_capacity(n_entries);
    for i in 0..n_entries {
        let Some(rec) = pcln.inline_record(tree, i as i32) else {
            break;
        };
        let entry = InlinedCall {
            func_id: rec.func_id,
            name_off: rec.name_off,
            parent_pc: rec.parent_pc,
            start_line: rec.start_line.unwrap_or(0),
        };

        // Safety: parent_pc must point inside the host function. The
        // toolchain never writes a negative parentPc (top-level inlines carry
        // a real call-site offset too); -1 is tolerated defensively because
        // older probe output treated it as a root marker. Any other negative
        // value or an offset past func.size is corruption (mis-resolved
        // funcdata, recycled blob, etc.) and we refuse to return tainted
        // entries.
        if entry.parent_pc != -1 {
            if entry.parent_pc < 0 {
                return Err(Error::ModuleData(format!(
                    "inline tree for {} has negative parent_pc {} at index {}",
                    func.name, entry.parent_pc, i,
                )));
            }
            let pc = entry.parent_pc as u64;
            if pc >= func.size {
                return Err(Error::ModuleData(format!(
                    "inline tree for {} has parent_pc 0x{:x} >= func.size 0x{:x} at index {}",
                    func.name, pc, func.size, i,
                )));
            }
        }

        out.push(entry);
    }
    Ok(out)
}

/// Resolve a leaf entry's `name_off` to a function name. Returns `None`
/// if the offset is zero, out of range, or resolves to an empty string.
/// Those are the three "unresolved" buckets the probe measurement tool reports.
pub fn resolve_leaf_name(pcln: &Pclntab, leaf: &InlinedCall) -> Option<String> {
    if leaf.name_off == 0 {
        return None;
    }
    if leaf.name_off < 0 {
        return None;
    }
    let off = leaf.name_off as usize;
    let abs = pcln.funcname_off().checked_add(off)?;
    if abs >= pcln.data().len() {
        return None;
    }
    let name = pcln.read_name_at(off).ok()?;
    if name.is_empty() {
        None
    } else {
        Some(name)
    }
}

// ---------------------------------------------------------------------------
//
// Inlined call graph.
//
// `inline_callgraph` walks every physical function's `FUNCDATA_InlTree` and
// stitches the inlined-call records into a directed graph. v1.1 ships
// inlined edges only; pcdata-derived direct-call edges land in v1.2 (the
// `EdgeKind::Direct` variant is reserved now so its addition does not
// break callers).
//
// Edge semantics: `Edge { from, to, call_site, kind: Inlined }` means
// "the physical function at `from` inlined a call at `call_site` whose
// callee is the node at `to`". `call_site` is the link-time VA of the
// inlined call within the physical caller's text.
//
// Node identity:
//   - `NodeKind::Physical` nodes use the function's real entry PC as
//     their `addr`. Every function in pclntab is emitted exactly once.
//   - `NodeKind::AnonymousInline` nodes have no name (the compiler
//     emitted `name_off == 0`, typically because `-tiny` zeroed it).
//     They carry their parent's PC and their inline-tree start line,
//     and their `addr` is a synthetic, deterministic ID drawn from the
//     anonymous-ID space (high bit set) so they never collide with a
//     real text VA. Two anonymous-inline records with the same
//     `(parent_addr, parent_pc, start_line)` collapse to one node.
//
// Cycles: inline trees themselves are acyclic by Go compiler invariant
// (the compiler will not inline a function into itself). Across
// functions, an A->B inlined edge and a B->A inlined edge can both
// exist when both directions inlined a peer call site; the graph
// allows that. No cycle-breaking is performed; consumers walking the
// graph are responsible for their own visit tracking if they need it.

/// A node in the inlined call graph: either a physical function from
/// pclntab or a synthetic anonymous-inline placeholder for an inlined
/// call site whose callee name was stripped (`name_off == 0`).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Node {
    /// Real text VA for `Physical` nodes; a synthetic high-bit-tagged
    /// ID for `AnonymousInline` nodes (see [`Self::is_anonymous_addr`]).
    pub addr: u64,
    /// Function name. Empty string for anonymous-inline nodes.
    pub name: String,
    pub kind: NodeKind,
}

impl Node {
    /// Synthetic anonymous-inline addresses have the top bit set so they
    /// cannot collide with a 63-bit text VA produced by any real Go
    /// binary on a 64-bit target.
    const ANONYMOUS_ADDR_BIT: u64 = 1 << 63;

    /// True if `addr` was synthesized by the anonymous-inline ID
    /// generator rather than read out of pclntab.
    pub fn is_anonymous_addr(addr: u64) -> bool {
        addr & Self::ANONYMOUS_ADDR_BIT != 0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum NodeKind {
    /// Real function from pclntab. `addr` is its link-time entry PC.
    Physical,
    /// Inlined callee whose name was stripped from the inline tree.
    /// Topology is fully recovered; only the name is gone.
    AnonymousInline {
        /// Entry PC of the physical function the inlined record was
        /// found in. Anchors the anonymous node to a real call site.
        parent: u64,
        /// `startLine` field from the inlined-call record.
        start_line: i32,
    },
}

/// An edge in the inlined call graph.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Edge {
    /// `addr` of the caller node.
    pub from: u64,
    /// `addr` of the callee node.
    pub to: u64,
    /// Link-time VA of the call site within the caller's text.
    pub call_site: u64,
    pub kind: EdgeKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum EdgeKind {
    /// The caller inlined the callee at `call_site`.
    Inlined,
    /// Reserved for v1.2 pcdata-derived direct-call edges. Not
    /// emitted by [`inline_callgraph`] today.
    Direct,
}

/// The inlined call graph for a Go binary.
///
/// Built by [`inline_callgraph`]; see the function's docs for the
/// Go envelope this is witnessed on.
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct CallGraph {
    pub nodes: Vec<Node>,
    pub edges: Vec<Edge>,
}

impl CallGraph {
    /// Look up a node by `addr`. O(n); for callers walking the graph
    /// in bulk, build a `HashMap<u64, &Node>` once.
    pub fn node(&self, addr: u64) -> Option<&Node> {
        self.nodes.iter().find(|n| n.addr == addr)
    }

    /// All outgoing edges from `from`. O(n).
    pub fn edges_from(&self, from: u64) -> impl Iterator<Item = &Edge> {
        self.edges.iter().filter(move |e| e.from == from)
    }

    /// All incoming edges to `to`. O(n).
    pub fn edges_to(&self, to: u64) -> impl Iterator<Item = &Edge> {
        self.edges.iter().filter(move |e| e.to == to)
    }
}

/// Build the inlined call graph for `bin`.
///
/// For every physical function recovered from `pcln`, decodes its
/// `FUNCDATA_InlTree` and emits one `Edge` per inlined call record
/// (every record is a real inlined call; the toolchain writes no root
/// entry, and a defensive `parent_pc == -1` is skipped). Inlined
/// callees with a resolvable name dedupe across the binary (one
/// `Node` per distinct name); anonymous-inline records dedupe within
/// their parent function by `(parent, parent_pc, start_line)`.
///
/// Reads both `runtime.inlinedCall` layouts (Go 1.16 to 1.19 and Go 1.20+)
/// and runs unchanged through Go 1.26. Garble-obfuscated binaries
/// produce a graph with obfuscated callee names; structure is
/// unchanged.
pub fn inline_callgraph(bin: &GoBinary, pcln: &Pclntab) -> Result<CallGraph> {
    use std::collections::HashMap;

    let funcs = pcln.functions_with_offsets()?;

    let mut graph = CallGraph::default();
    // Track named-callee nodes by name so we emit one per distinct
    // inlined callee, not one per call site.
    let mut named_nodes: HashMap<String, u64> = HashMap::new();
    // Track anonymous-inline nodes by their identity tuple within
    // their parent function so the same inlined record across
    // multiple PCs collapses to one node.
    let mut anon_nodes: HashMap<(u64, i32, i32), u64> = HashMap::new();
    // Dedupe edges by full identity so a parent function recorded
    // twice in the corpus does not produce duplicate edges.
    let mut edge_keys: std::collections::HashSet<(u64, u64, u64)> =
        std::collections::HashSet::new();
    // Counter for synthesizing anonymous-inline addresses.
    let mut next_anon: u64 = 1;

    // Emit a Physical node for every real function. Some of these
    // will have no inline tree at all (the ~50% of Go functions
    // that inline nothing); they remain in the graph as isolated
    // nodes so consumers can iterate every function uniformly.
    for f in &funcs {
        graph.nodes.push(Node {
            addr: f.address,
            name: f.name.clone(),
            kind: NodeKind::Physical,
        });
        named_nodes.insert(f.name.clone(), f.address);
    }

    for f in &funcs {
        let entries = match decode_inline_tree(bin, pcln, f) {
            Ok(v) => v,
            // A single function with a corrupt inline tree must not
            // poison the whole graph. Skip it; its physical node is
            // already in the graph.
            Err(_) => continue,
        };

        for entry in &entries {
            // The toolchain never writes parent_pc == -1 (every record has a
            // real call-site offset); skip it defensively, as there is no
            // call site to anchor an edge to.
            if entry.parent_pc == -1 {
                continue;
            }

            let call_site = f.address.wrapping_add(entry.parent_pc as u64);
            let resolved = resolve_leaf_name(pcln, entry);

            let callee_addr = match resolved {
                Some(name) => *named_nodes.entry(name.clone()).or_insert_with(|| {
                    // Inlined callee whose name we know but which has
                    // no physical body in this binary (the compiler
                    // fully inlined it away). Allocate a synthetic
                    // address in the anonymous space and emit a node
                    // labelled with the recovered name. The node's
                    // kind stays AnonymousInline because we have no
                    // physical entry PC to back it; the name is the
                    // identity, the addr is just a handle.
                    let addr = Node::ANONYMOUS_ADDR_BIT | next_anon;
                    next_anon += 1;
                    graph.nodes.push(Node {
                        addr,
                        name,
                        kind: NodeKind::AnonymousInline {
                            parent: f.address,
                            start_line: entry.start_line,
                        },
                    });
                    addr
                }),
                None => {
                    // True anonymous-inline (name_off == 0). Dedupe
                    // within the parent by (parent, parent_pc,
                    // start_line); different parent_pcs within the
                    // same function are distinct inlined call sites
                    // and get distinct nodes.
                    let key = (f.address, entry.parent_pc, entry.start_line);
                    *anon_nodes.entry(key).or_insert_with(|| {
                        let addr = Node::ANONYMOUS_ADDR_BIT | next_anon;
                        next_anon += 1;
                        graph.nodes.push(Node {
                            addr,
                            name: String::new(),
                            kind: NodeKind::AnonymousInline {
                                parent: f.address,
                                start_line: entry.start_line,
                            },
                        });
                        addr
                    })
                }
            };

            let ek = (f.address, callee_addr, call_site);
            if edge_keys.insert(ek) {
                graph.edges.push(Edge {
                    from: f.address,
                    to: callee_addr,
                    call_site,
                    kind: EdgeKind::Inlined,
                });
            }
        }
    }

    Ok(graph)
}
