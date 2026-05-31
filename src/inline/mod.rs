//! Inlined-call recovery from Go's `FUNCDATA_InlTree`.
//!
//! Decodes the per-function `FUNCDATA_InlTree` array into a flat
//! `Vec<InlinedCall>`, one entry per inlined call site recorded by the
//! Go compiler.
//!
//! # Supported Go envelope
//!
//! The 16-byte `runtime.inlinedCall` record has been format-stable
//! since Go 1.20 (the version that added `startLine`). Same layout,
//! same `FUNCDATA_InlTree=3`, same `PCDATA_InlTreeIndex=2` through
//! Go 1.26. A returned error on an unrecognized funcdata layout is
//! the honest fallback if a future Go release drifts. Garble's
//! `entryoff` XOR rewrite does not touch the inline-tree FUNCDATA
//! section, so this decoder works on garble-obfuscated binaries
//! unchanged.
//!
//! # On-disk encoding
//!
//! Packed 16-byte struct per entry:
//!
//! ```text
//!   off  size  field
//!   0    1     funcID          u8
//!   1    3     _pad            [3]u8
//!   4    4     nameOff         i32   (offset into pclntab funcname table)
//!   8    4     parentPc        i32   (PC offset within the physical fn,
//!                                     of the call site that triggered the
//!                                     inline; -1 for top-level entries)
//!   12   4     startLine       i32
//! ```
//!
//! The array lives in the `gofunc` blob (a contiguous mapped region
//! described by moduledata). The per-function entry point is funcdata
//! index 3 (`FUNCDATA_InlTree`), stored as a u32 offset relative to
//! `gofunc`. A value of `u32::MAX` means "no inline tree for this
//! function". The decoder returns `Ok(vec![])` in that case.
//!
//! Safety: every decoded `parent_pc` is asserted to lie strictly inside
//! the host function's PC range. This catches the most common
//! garble-style corruption (a truncated/reused inltree blob from another
//! function), and is the headline invariant we check during the Day-2
//! probe.

use crate::error::Error;
use crate::gobin::GoBinary;
use crate::pclntab::{FuncEntry, Pclntab};
use crate::Result;

/// One inlined-call record from `FUNCDATA_InlTree`.
#[derive(Debug, Clone, Copy)]
pub struct InlinedCall {
    pub func_id: u8,
    pub name_off: i32,
    pub parent_pc: i32,
    pub start_line: i32,
}

/// Number of funcdata pointer slots required before `FUNCDATA_InlTree`
/// is addressable in a function's funcdata array.
const FUNCDATA_INLTREE: usize = 3;
/// PCDATA index whose stream yields the current inline-tree index at each
/// PC. The array length we need is `max(stream) + 1`.
const PCDATA_INLTREE_INDEX: usize = 2;

/// Hard cap on entries per function. A real inline tree fits in a handful
/// of KB; 65_536 entries (1 MiB) is a very generous structural ceiling
/// and protects against a garbage length being inferred from a corrupt
/// next-pointer.
const MAX_INLINE_ENTRIES: usize = 65_536;

/// Decode the `FUNCDATA_InlTree` array for a single function.
///
/// Returns `Ok(vec![])` when the function has no inline tree (either
/// because it has fewer than 4 funcdata entries, or because slot 3 is
/// the sentinel `u32::MAX`). Returns an error if the gofunc base is
/// missing (call [`Pclntab::with_gofunc`] first), if the encoded
/// structure straddles unmapped memory, or (most importantly) if any
/// decoded entry's `parent_pc` falls outside the host function's PC
/// range. The last check is the safety assertion the wizard flagged.
pub fn decode_inline_tree(
    bin: &GoBinary,
    pcln: &Pclntab,
    func: &FuncEntry,
) -> Result<Vec<InlinedCall>> {
    let data = pcln.data();
    let le = pcln.little_endian();
    let func_start = pcln.funcdata_off() + func.func_off;

    // Layout of `_func` (Go 1.20+, 40-byte fixed header + packed tail):
    //   off=0  entryOff       u32
    //   off=4  nameOff        i32
    //   off=8  args           i32
    //   off=12 deferreturn    u32
    //   off=16 pcsp           u32
    //   off=20 pcfile         u32
    //   off=24 pcln           u32
    //   off=28 npcdata        u32
    //   off=32 cuOffset       u32
    //   off=36 startLine      i32
    //   off=40 funcID         u8
    //   off=41 flag           u8
    //   off=42 _pad           u8
    //   off=43 nfuncdata      u8
    //   off=44 [npcdata]u32   pcdata table
    //   off=44+npcdata*4 [nfuncdata]u32 funcdata table
    if func_start + 44 > data.len() {
        return Ok(vec![]);
    }
    let npcdata = read_u32(data, func_start + 28, le)? as usize;
    let nfuncdata = data[func_start + 43] as usize;
    if nfuncdata <= FUNCDATA_INLTREE || npcdata <= PCDATA_INLTREE_INDEX {
        return Ok(vec![]);
    }

    // Resolve the array length first by scanning the PCDATA_InlTreeIndex
    // pcvalue stream for its maximum index across the function's PC range.
    // The inline-tree subarray for this function holds (max_idx + 1) entries;
    // walking past that point reads adjacent functions' subarrays and the
    // parent_pc bounds-check rejects it. This is the safe termination the
    // wizard flagged.
    let pcdata_off = func_start + 44;
    let pcdata_inltree_off = read_u32(data, pcdata_off + PCDATA_INLTREE_INDEX * 4, le)? as usize;
    let max_idx = max_pcvalue(
        pcln_pctab(pcln),
        pcdata_inltree_off,
        u32::try_from(func.size).unwrap_or(u32::MAX),
    );
    if max_idx < 0 {
        // No inline indices ever recorded for this function: empty tree.
        return Ok(vec![]);
    }
    let n_entries = (max_idx as usize).saturating_add(1).min(MAX_INLINE_ENTRIES);

    let funcdata_arr_off = func_start + 44 + npcdata * 4;
    let inltree_slot_off = funcdata_arr_off + FUNCDATA_INLTREE * 4;
    if inltree_slot_off + 4 > data.len() {
        return Ok(vec![]);
    }
    let inltree_funcdata = read_u32(data, inltree_slot_off, le)?;
    if inltree_funcdata == u32::MAX {
        return Ok(vec![]);
    }

    let Some(gofunc) = pcln.gofunc() else {
        return Err(Error::ModuleData(
            "inline-tree decoding requires gofunc base; \
             call Pclntab::with_gofunc(moduledata.gofunc) first"
                .to_string(),
        ));
    };
    let inltree_addr = gofunc.wrapping_add(inltree_funcdata as u64);

    // The array is not length-prefixed. The runtime indexes into it using
    // the PCDATA_InlTreeIndex stream, so the structural length is "as many
    // valid 16-byte records as the gofunc region holds". We bound by:
    //   (a) MAX_INLINE_ENTRIES, the absolute ceiling
    //   (b) the section containing inltree_addr (read_at_addr enforces this)
    //
    // We read entries until the next 16-byte slice fails to map, at which
    // point we stop. Production v1.1 will tighten this using the
    // pcdata-derived high-watermark; for the probe this conservative walk
    // is what we want; it surfaces stray padding bytes rather than
    // silently truncating real entries.
    let mut out = Vec::with_capacity(n_entries);
    for i in 0..n_entries {
        let entry_addr = inltree_addr.wrapping_add((i as u64) * 16);
        let Some(bytes) = bin.read_at_addr(entry_addr, 16) else {
            break;
        };
        let func_id = bytes[0];
        let name_off = i32::from_le_bytes(bytes[4..8].try_into().unwrap());
        let parent_pc = i32::from_le_bytes(bytes[8..12].try_into().unwrap());
        let start_line = i32::from_le_bytes(bytes[12..16].try_into().unwrap());

        let entry = InlinedCall {
            func_id,
            name_off,
            parent_pc,
            start_line,
        };

        // SAFETY ASSERTION (wizard's call): parent_pc must point inside
        // the host function. parent_pc == -1 is the runtime's marker for
        // "top-level inline" (no parent call site), so we allow it; any
        // other negative value or an offset past func.size is corruption
        // (mis-resolved funcdata, recycled blob, etc.) and we refuse to
        // return tainted entries.
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

/// Slice of pclntab `data()` starting at the pctab base. Convenience for
/// passing to [`max_pcvalue`].
fn pcln_pctab<'a>(pcln: &'a Pclntab<'_>) -> &'a [u8] {
    let off = pcln.pctab_off();
    let data = pcln.data();
    if off >= data.len() {
        &[]
    } else {
        &data[off..]
    }
}

/// Walk a pc-value stream and return the maximum `value` it ever produces
/// while `pc < pc_limit`. Returns -1 if the stream is empty/unparseable
/// (meaning: no inline-tree index ever recorded for this function).
fn max_pcvalue(table: &[u8], start: usize, pc_limit: u32) -> i64 {
    if start >= table.len() {
        return -1;
    }
    let mut value: i64 = -1;
    let mut pc: u32 = 0;
    let mut pos = start;
    let mut max_seen: i64 = -1;
    let mut iter_guard = 0;
    while pos < table.len() && iter_guard < 1_000_000 {
        iter_guard += 1;
        let (uval, n) = match read_varint(&table[pos..]) {
            Some(v) => v,
            None => return max_seen,
        };
        // A zero value-delta after the first record terminates the stream
        // (Go runtime convention; the leading record is always non-zero).
        if uval == 0 && pc != 0 {
            return max_seen;
        }
        pos += n;
        let delta = zig_zag(uval);
        value = value.wrapping_add(delta);
        let (pc_delta, n2) = match read_varint(&table[pos..]) {
            Some(v) => v,
            None => return max_seen,
        };
        pos += n2;
        pc = pc.wrapping_add(pc_delta as u32);
        if value > max_seen {
            max_seen = value;
        }
        if pc >= pc_limit {
            return max_seen;
        }
    }
    max_seen
}

fn zig_zag(u: u64) -> i64 {
    ((u >> 1) as i64) ^ -((u & 1) as i64)
}

fn read_varint(buf: &[u8]) -> Option<(u64, usize)> {
    const MAX_BYTES: usize = 10;
    let mut result: u64 = 0;
    let mut shift = 0;
    for (i, &b) in buf.iter().take(MAX_BYTES).enumerate() {
        result |= ((b & 0x7f) as u64) << shift;
        if b & 0x80 == 0 {
            return Some((result, i + 1));
        }
        shift += 7;
        if shift >= 64 {
            return None;
        }
    }
    None
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
/// (those with `parent_pc != -1`; the `-1` root entry represents
/// the physical function itself and produces no edge). Inlined
/// callees with a resolvable name dedupe across the binary (one
/// `Node` per distinct name); anonymous-inline records dedupe within
/// their parent function by `(parent, parent_pc, start_line)`.
///
/// The `runtime.inlinedCall` layout has been stable since Go 1.20
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
            // parent_pc == -1 marks the synthetic root entry that
            // represents the physical function itself, not an
            // inlined call. No edge to emit.
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

fn read_u32(buf: &[u8], off: usize, little_endian: bool) -> Result<u32> {
    if off + 4 > buf.len() {
        return Err(Error::ShortRead {
            wanted: 4,
            offset: off,
            available: buf.len().saturating_sub(off),
        });
    }
    let s = &buf[off..off + 4];
    Ok(if little_endian {
        u32::from_le_bytes(s.try_into().unwrap())
    } else {
        u32::from_be_bytes(s.try_into().unwrap())
    })
}
