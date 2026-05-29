//! Build a call graph from a stripped Go binary by scanning `.text`
//! for CALL/BL instructions and resolving each target against the
//! recovered function table.
//!
//! This is a fast static analysis: linear sweep, no decoding of
//! intervening instructions, no taint or alias analysis. CALLs through
//! a register (virtual dispatch, dynamically loaded function pointers)
//! don't show up here; their destinations are in the itab table for
//! interface calls and only at runtime for everything else. Direct
//! CALLs to a fixed PC are what the static pass catches, and on a
//! typical Go binary that's 80-90% of the call sites.
//!
//! For interface dispatch resolution see `--itabs`.

use serde::Serialize;

use crate::error::Error;
use crate::gobin::{Arch, GoBinary, SectionKind};
use crate::pclntab::{Function, Pclntab};
use crate::Result;

/// One edge in the call graph: caller calls callee at this site.
#[derive(Debug, Clone, Serialize)]
pub struct CallEdge {
    pub call_site: u64,
    pub caller_addr: u64,
    pub caller_name: String,
    pub callee_addr: u64,
    pub callee_name: String,
}

pub fn find_calls(bin: &GoBinary, pcln: &Pclntab<'_>) -> Result<Vec<CallEdge>> {
    if !bin.little_endian {
        return Err(Error::Xrefs(
            "only little-endian binaries supported today".into(),
        ));
    }
    if !matches!(bin.arch, Arch::X86_64 | Arch::Aarch64) {
        return Err(Error::Xrefs(format!(
            "unsupported arch {:?}; only amd64 and arm64 today",
            bin.arch
        )));
    }

    let functions = pcln.functions()?;
    let by_addr: std::collections::HashMap<u64, &Function> =
        functions.iter().map(|f| (f.address, f)).collect();

    // Pick the actual .text section, not just the first executable one.
    // On Linux ELF helm-class binaries .init and .plt appear before .text
    // in the section header table and would shadow it under a naive
    // first-match search.
    let text = bin
        .sections
        .iter()
        .find(|s| s.kind == SectionKind::Text && s.name.ends_with(".text"))
        .or_else(|| {
            bin.sections
                .iter()
                .filter(|s| s.kind == SectionKind::Text)
                .max_by_key(|s| s.file_size)
        })
        .ok_or_else(|| Error::Xrefs("no text section".into()))?;
    let text_start_va = text.addr;
    let text_bytes = &bin.bytes[text.file_offset..text.file_offset + text.file_size];

    let mut edges = Vec::new();
    match bin.arch {
        Arch::X86_64 => scan_amd64(text_bytes, text_start_va, pcln, &by_addr, &mut edges),
        Arch::Aarch64 => scan_arm64(text_bytes, text_start_va, pcln, &by_addr, &mut edges),
        _ => unreachable!(),
    }
    Ok(edges)
}

fn scan_amd64(
    text_bytes: &[u8],
    text_start_va: u64,
    pcln: &Pclntab<'_>,
    by_addr: &std::collections::HashMap<u64, &Function>,
    out: &mut Vec<CallEdge>,
) {
    let mut i = 0;
    while i + 5 <= text_bytes.len() {
        if text_bytes[i] == 0xE8 {
            let rel = i32::from_le_bytes(text_bytes[i + 1..i + 5].try_into().unwrap());
            let call_site_va = text_start_va + i as u64;
            let call_next_va = call_site_va + 5;
            let target_va = call_next_va.wrapping_add(rel as i64 as u64);

            // Resolve caller by looking up which function contains the
            // call site. Resolve callee by direct address lookup.
            if let Some(callee) = by_addr.get(&target_va) {
                if let Some(caller) = pcln.lookup(call_site_va) {
                    out.push(CallEdge {
                        call_site: call_site_va,
                        caller_addr: caller.address,
                        caller_name: caller.name,
                        callee_addr: target_va,
                        callee_name: callee.name.clone(),
                    });
                }
            }
        }
        i += 1;
    }
}

fn scan_arm64(
    text_bytes: &[u8],
    text_start_va: u64,
    pcln: &Pclntab<'_>,
    by_addr: &std::collections::HashMap<u64, &Function>,
    out: &mut Vec<CallEdge>,
) {
    let mut i = 0;
    while i + 4 <= text_bytes.len() {
        let insn = u32::from_le_bytes(text_bytes[i..i + 4].try_into().unwrap());
        if (insn >> 26) == 0x25 {
            let imm26 = insn & 0x03ff_ffff;
            let signed = if imm26 & 0x0200_0000 != 0 {
                (imm26 as i64) | !0x03ff_ffff
            } else {
                imm26 as i64
            };
            let call_site_va = text_start_va + i as u64;
            let target_va = call_site_va.wrapping_add((signed << 2) as u64);

            if let Some(callee) = by_addr.get(&target_va) {
                if let Some(caller) = pcln.lookup(call_site_va) {
                    out.push(CallEdge {
                        call_site: call_site_va,
                        caller_addr: caller.address,
                        caller_name: caller.name,
                        callee_addr: target_va,
                        callee_name: callee.name.clone(),
                    });
                }
            }
        }
        i += 4;
    }
}

/// Forward callgraph: caller -> callees. One row per (caller, callee)
/// pair, deduplicated (a function calling another function 5 times
/// from 5 different sites still emits one edge).
pub fn forward_graph(edges: &[CallEdge]) -> Vec<(String, String)> {
    let mut seen = std::collections::BTreeSet::new();
    let mut out = Vec::new();
    for e in edges {
        if seen.insert((e.caller_name.clone(), e.callee_name.clone())) {
            out.push((e.caller_name.clone(), e.callee_name.clone()));
        }
    }
    out
}

/// Callers of `target_name`: every function that calls into it,
/// transitively up to `depth` levels.
pub fn callers_of(edges: &[CallEdge], target: &str, depth: usize) -> Vec<String> {
    let mut by_callee: std::collections::HashMap<&str, Vec<&str>> =
        std::collections::HashMap::new();
    for e in edges {
        by_callee
            .entry(e.callee_name.as_str())
            .or_default()
            .push(e.caller_name.as_str());
    }
    let mut seen = std::collections::BTreeSet::new();
    let mut frontier: Vec<&str> = vec![target];
    for _ in 0..depth {
        let mut next = Vec::new();
        for f in &frontier {
            if let Some(callers) = by_callee.get(f) {
                for c in callers {
                    if seen.insert(c.to_string()) {
                        next.push(*c);
                    }
                }
            }
        }
        if next.is_empty() {
            break;
        }
        frontier = next;
    }
    seen.into_iter().collect()
}

/// Callees from `caller_name`, transitively up to `depth`.
pub fn callees_from(edges: &[CallEdge], from: &str, depth: usize) -> Vec<String> {
    let mut by_caller: std::collections::HashMap<&str, Vec<&str>> =
        std::collections::HashMap::new();
    for e in edges {
        by_caller
            .entry(e.caller_name.as_str())
            .or_default()
            .push(e.callee_name.as_str());
    }
    let mut seen = std::collections::BTreeSet::new();
    let mut frontier: Vec<&str> = vec![from];
    for _ in 0..depth {
        let mut next = Vec::new();
        for f in &frontier {
            if let Some(callees) = by_caller.get(f) {
                for c in callees {
                    if seen.insert(c.to_string()) {
                        next.push(*c);
                    }
                }
            }
        }
        if next.is_empty() {
            break;
        }
        frontier = next;
    }
    seen.into_iter().collect()
}

/// Emit the call graph in Graphviz dot format. Pass through the dot
/// formatter for `dot -Tsvg -o callgraph.svg` rendering.
pub fn to_dot(edges: &[CallEdge]) -> String {
    let mut s = String::from(
        "digraph callgraph {\n  rankdir=LR;\n  node [shape=box, fontname=\"monospace\"];\n",
    );
    let pairs = forward_graph(edges);
    for (caller, callee) in pairs {
        s.push_str(&format!("  {} -> {};\n", quote(&caller), quote(&callee)));
    }
    s.push_str("}\n");
    s
}

fn quote(s: &str) -> String {
    let escaped = s.replace('\\', "\\\\").replace('"', "\\\"");
    format!("\"{escaped}\"")
}
