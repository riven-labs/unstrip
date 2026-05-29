//! Compare two stripped Go binaries by recovered function set and emit
//! a diff suitable for porting annotations across malware-family
//! rebuilds.
//!
//! The matching strategy is two-pass:
//!
//! 1. **By address.** Functions at the same `address` in old and new are
//!    paired directly. On a minor-version bump this catches most of the
//!    binary because the linker typically rebuilds at the same offsets.
//! 2. **By name (only when both also disagree on address).** Functions
//!    with the same recovered Go name in both binaries but different
//!    addresses are paired with a `moved` flag. The analyst can carry
//!    over their renames at the new address.
//!
//! Everything left over is either `added` (in new, not in old) or
//! `removed` (in old, not in new). That's the worklist the analyst opens
//! when triaging the rebuild.

use std::collections::HashMap;

use serde::Serialize;

use crate::pclntab::Function;

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub enum MatchKind {
    /// Same address, same name. Nothing changed; existing annotations
    /// port directly.
    Identical,
    /// Same address, different recovered name. Rare; usually a Go
    /// version bump that renamed an internal symbol.
    AddressMoved,
    /// Same name in both binaries but at a different address. Existing
    /// annotations can be ported to the new address.
    Renamed,
    /// In new, no counterpart in old.
    Added,
    /// In old, no counterpart in new.
    Removed,
}

#[derive(Debug, Clone, Serialize)]
pub struct Pairing {
    pub kind: MatchKind,
    pub old_addr: Option<u64>,
    pub new_addr: Option<u64>,
    pub old_name: Option<String>,
    pub new_name: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DiffReport {
    pub old_total: usize,
    pub new_total: usize,
    pub identical: usize,
    pub renamed: usize,
    pub added: usize,
    pub removed: usize,
    pub address_moved: usize,
    pub pairings: Vec<Pairing>,
}

pub fn compute(old: &[Function], new: &[Function]) -> DiffReport {
    let _old_by_addr: HashMap<u64, &Function> = old.iter().map(|f| (f.address, f)).collect();
    let new_by_addr: HashMap<u64, &Function> = new.iter().map(|f| (f.address, f)).collect();
    let new_by_name: HashMap<&str, &Function> = new.iter().map(|f| (f.name.as_str(), f)).collect();

    let mut pairings = Vec::with_capacity(old.len().max(new.len()));
    let mut matched_old: std::collections::HashSet<u64> = std::collections::HashSet::new();
    let mut matched_new: std::collections::HashSet<u64> = std::collections::HashSet::new();
    let mut identical = 0usize;
    let mut renamed = 0usize;
    let mut added = 0usize;
    let mut removed = 0usize;
    let mut address_moved = 0usize;

    // Pass 1: address-keyed matches.
    for f in old {
        if let Some(g) = new_by_addr.get(&f.address) {
            matched_old.insert(f.address);
            matched_new.insert(g.address);
            if f.name == g.name {
                identical += 1;
                pairings.push(Pairing {
                    kind: MatchKind::Identical,
                    old_addr: Some(f.address),
                    new_addr: Some(g.address),
                    old_name: Some(f.name.clone()),
                    new_name: Some(g.name.clone()),
                });
            } else {
                address_moved += 1;
                pairings.push(Pairing {
                    kind: MatchKind::AddressMoved,
                    old_addr: Some(f.address),
                    new_addr: Some(g.address),
                    old_name: Some(f.name.clone()),
                    new_name: Some(g.name.clone()),
                });
            }
        }
    }

    // Pass 2: name-keyed matches on whatever's left.
    for f in old {
        if matched_old.contains(&f.address) {
            continue;
        }
        if let Some(g) = new_by_name.get(f.name.as_str()) {
            if matched_new.contains(&g.address) {
                continue;
            }
            matched_old.insert(f.address);
            matched_new.insert(g.address);
            renamed += 1;
            pairings.push(Pairing {
                kind: MatchKind::Renamed,
                old_addr: Some(f.address),
                new_addr: Some(g.address),
                old_name: Some(f.name.clone()),
                new_name: Some(g.name.clone()),
            });
        }
    }

    // Pass 3: leftovers.
    for f in old {
        if matched_old.contains(&f.address) {
            continue;
        }
        removed += 1;
        pairings.push(Pairing {
            kind: MatchKind::Removed,
            old_addr: Some(f.address),
            new_addr: None,
            old_name: Some(f.name.clone()),
            new_name: None,
        });
    }
    for f in new {
        if matched_new.contains(&f.address) {
            continue;
        }
        added += 1;
        pairings.push(Pairing {
            kind: MatchKind::Added,
            old_addr: None,
            new_addr: Some(f.address),
            old_name: None,
            new_name: Some(f.name.clone()),
        });
    }

    DiffReport {
        old_total: old.len(),
        new_total: new.len(),
        identical,
        renamed,
        added,
        removed,
        address_moved,
        pairings,
    }
}

/// Emit a port-symbols script for the given target. The script, run
/// inside the target tool, renames every Identical and Renamed pairing's
/// new-side address with whatever name the analyst had on the old-side
/// address.
///
/// Today the script names the *old recovered name* at the new address.
/// In a real workflow the analyst supplies a (old_addr -> custom_name)
/// table, but writing those out of unstrip would require the analyst
/// to export their renames first. For now we ship the structural diff
/// and let the user post-process.
pub fn write_port_script(target: crate::export::Target, report: &DiffReport) -> String {
    let mut s = String::new();
    let header = match target {
        crate::export::Target::Ida => concat!(
            "# unstrip diff: port symbols from old binary to new.\n",
            "import ida_funcs, ida_name\n\n",
            "def _rename(addr, name):\n",
            "    ida_funcs.add_func(addr)\n",
            "    ida_name.set_name(addr, name, ida_name.SN_FORCE | ida_name.SN_NOCHECK)\n\n",
        ),
        crate::export::Target::Ghidra => concat!(
            "# unstrip diff: port symbols from old binary to new.\n",
            "# @category unstrip\n",
            "from ghidra.program.model.symbol.SourceType import USER_DEFINED\n",
            "fm = currentProgram.getFunctionManager()\n",
            "af = currentProgram.getAddressFactory()\n\n",
            "def _rename(addr, name):\n",
            "    a = af.getDefaultAddressSpace().getAddress(addr)\n",
            "    f = fm.getFunctionAt(a)\n",
            "    if f is None:\n",
            "        try: f = fm.createFunction(name, a, None, USER_DEFINED)\n",
            "        except: return\n",
            "    else:\n",
            "        try: f.setName(name, USER_DEFINED)\n",
            "        except: pass\n\n",
        ),
        crate::export::Target::BinaryNinja => concat!(
            "# unstrip diff: port symbols from old binary to new.\n",
            "from binaryninja import Symbol, SymbolType\n\n",
            "def _rename(addr, name):\n",
            "    bv.add_function(addr)\n",
            "    bv.define_user_symbol(Symbol(SymbolType.FunctionSymbol, addr, name))\n\n",
        ),
    };
    s.push_str(header);

    for p in &report.pairings {
        match p.kind {
            MatchKind::Identical | MatchKind::Renamed => {
                if let (Some(addr), Some(name)) = (p.new_addr, &p.old_name) {
                    s.push_str(&format!("_rename(0x{addr:x}, {})\n", quote_py(name)));
                }
            }
            _ => {}
        }
    }

    s.push_str(&format!(
        "\nprint('unstrip: ported {} symbols ({} unchanged, {} renamed, {} added in new, {} removed from old)')\n",
        report.identical + report.renamed,
        report.identical,
        report.renamed,
        report.added,
        report.removed,
    ));
    s
}

fn quote_py(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('\'');
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '\'' => out.push_str("\\'"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\x{:02x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('\'');
    out
}
