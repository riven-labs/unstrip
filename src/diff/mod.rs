//! Compare two stripped Go binaries by recovered function set and emit
//! a diff suitable for porting annotations across malware-family
//! rebuilds.
//!
//! The matching strategy keys on identity, not address, because a rebuild
//! relinks everything at new offsets -- address-first matching reports the
//! whole binary as "moved" and is noise:
//!
//! 1. **By recovered name.** The stable identity across a rebuild. Same name
//!    is the same function; if the address also matches it is `Identical`,
//!    otherwise it `Moved` (the common case -- the function is unchanged, the
//!    linker just placed it elsewhere).
//! 2. **By masked-code signature**, for what name-matching left over. Same code
//!    under a different name is a real `Renamed`, and on a `garble` build --
//!    where every name is a per-build hash, so step 1 matches almost nothing --
//!    this is what pairs the two builds at all. Only signatures that are unique
//!    on both sides are paired, so an ambiguous hash is never matched by guess.
//!    Signatures are supplied by the caller (the matcher itself does not decode
//!    instructions); pass `None` to match by name alone.
//!
//! Everything left over is either `added` (in new, not in old) or
//! `removed` (in old, not in new). That's the worklist the analyst opens
//! when triaging the rebuild.

use std::collections::{HashMap, HashSet};

use serde::Serialize;

use crate::pclntab::Function;

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub enum MatchKind {
    /// Same recovered name, same address. Nothing changed; existing
    /// annotations port directly.
    Identical,
    /// Same recovered name, different address. The function is unchanged; the
    /// rebuild relinked it elsewhere. Annotations port to the new address.
    Moved,
    /// Different (or hashed) name, but the masked code matches. A genuine
    /// rename, or the same library function under garble's per-build hash.
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
    pub moved: usize,
    pub renamed: usize,
    pub added: usize,
    pub removed: usize,
    pub pairings: Vec<Pairing>,
}

/// Diff two function sets. `old_sigs`/`new_sigs` map a function's address to its
/// masked-code signature (see the module docs); pass `None` to match by name only.
pub fn compute(
    old: &[Function],
    new: &[Function],
    old_sigs: Option<&HashMap<u64, u64>>,
    new_sigs: Option<&HashMap<u64, u64>>,
) -> DiffReport {
    let mut pairings = Vec::with_capacity(old.len().max(new.len()));
    let mut matched_old: HashSet<u64> = HashSet::new();
    let mut matched_new: HashSet<u64> = HashSet::new();
    let mut identical = 0usize;
    let mut moved = 0usize;
    let mut renamed = 0usize;
    let mut added = 0usize;
    let mut removed = 0usize;

    // Pass 1: exact (name, address) -- a function that did not move at all. Keying
    // on the pair (not name alone) is also what makes a duplicate name correct: Go
    // emits several functions sharing a name (type-equality and hash thunks), and
    // each is distinguished by its address, so a same-build diff pairs them all here
    // rather than orphaning the duplicates.
    let new_by_name_addr: HashMap<(&str, u64), &Function> = new
        .iter()
        .map(|g| ((g.name.as_str(), g.address), g))
        .collect();
    for f in old {
        if let Some(g) = new_by_name_addr.get(&(f.name.as_str(), f.address)) {
            if matched_new.insert(g.address) {
                matched_old.insert(f.address);
                identical += 1;
                pairings.push(Pairing {
                    kind: MatchKind::Identical,
                    old_addr: Some(f.address),
                    new_addr: Some(g.address),
                    old_name: Some(f.name.clone()),
                    new_name: Some(g.name.clone()),
                });
            }
        }
    }

    // Pass 2: by recovered name, for names that are unambiguous among what is still
    // unmatched on both sides -- the function kept its name and was relinked
    // elsewhere. An ambiguous name (the same name on two unmatched functions) is
    // left for the signature pass rather than paired by guess.
    let old_by_name = unique_name_index(old, &matched_old);
    let new_by_name = unique_name_index(new, &matched_new);
    for (name, f) in &old_by_name {
        let Some(g) = new_by_name.get(name) else {
            continue;
        };
        matched_old.insert(f.address);
        matched_new.insert(g.address);
        moved += 1;
        pairings.push(Pairing {
            kind: MatchKind::Moved,
            old_addr: Some(f.address),
            new_addr: Some(g.address),
            old_name: Some(f.name.clone()),
            new_name: Some(g.name.clone()),
        });
    }

    // Pass 3: by masked-code signature, over what name-matching left unmatched.
    // Only signatures unique on both sides are paired, so a hash shared by several
    // unmatched functions is never matched by guess (those fall to added/removed).
    if let (Some(os), Some(ns)) = (old_sigs, new_sigs) {
        let old_uni = unique_sig_index(old, &matched_old, os);
        let new_uni = unique_sig_index(new, &matched_new, ns);
        for (sig, of) in &old_uni {
            let Some(gf) = new_uni.get(sig) else {
                continue;
            };
            matched_old.insert(of.address);
            matched_new.insert(gf.address);
            renamed += 1;
            pairings.push(Pairing {
                kind: MatchKind::Renamed,
                old_addr: Some(of.address),
                new_addr: Some(gf.address),
                old_name: Some(of.name.clone()),
                new_name: Some(gf.name.clone()),
            });
        }
    }

    // Pass 4: leftovers.
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
        moved,
        renamed,
        added,
        removed,
        pairings,
    }
}

/// Index the still-unmatched functions by name, keeping only names that belong to
/// exactly one such function -- a name shared by two unmatched functions cannot be
/// paired without guessing which is which, so it is dropped (the signature pass may
/// still pair them by code).
fn unique_name_index<'a>(
    funcs: &'a [Function],
    matched: &HashSet<u64>,
) -> HashMap<&'a str, &'a Function> {
    let mut count: HashMap<&str, usize> = HashMap::new();
    let mut first: HashMap<&str, &Function> = HashMap::new();
    for f in funcs {
        if matched.contains(&f.address) {
            continue;
        }
        *count.entry(f.name.as_str()).or_insert(0) += 1;
        first.entry(f.name.as_str()).or_insert(f);
    }
    first
        .into_iter()
        .filter(|(name, _)| count.get(name) == Some(&1))
        .collect()
}

/// Index the still-unmatched functions by signature, keeping only signatures that
/// belong to exactly one such function -- an ambiguous hash cannot be paired
/// without guessing, so it is dropped.
fn unique_sig_index<'a>(
    funcs: &'a [Function],
    matched: &HashSet<u64>,
    sigs: &HashMap<u64, u64>,
) -> HashMap<u64, &'a Function> {
    let mut count: HashMap<u64, usize> = HashMap::new();
    let mut first: HashMap<u64, &Function> = HashMap::new();
    for f in funcs {
        if matched.contains(&f.address) {
            continue;
        }
        let Some(&sig) = sigs.get(&f.address) else {
            continue;
        };
        *count.entry(sig).or_insert(0) += 1;
        first.entry(sig).or_insert(f);
    }
    first
        .into_iter()
        .filter(|(sig, _)| count.get(sig) == Some(&1))
        .collect()
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
            // Every matched pairing carries the old name to wherever the function
            // now lives, whether it stayed put, moved, or was renamed.
            MatchKind::Identical | MatchKind::Moved | MatchKind::Renamed => {
                if let (Some(addr), Some(name)) = (p.new_addr, &p.old_name) {
                    s.push_str(&format!("_rename(0x{addr:x}, {})\n", quote_py(name)));
                }
            }
            _ => {}
        }
    }

    s.push_str(&format!(
        "\nprint('unstrip: ported {} symbols ({} unchanged, {} moved, {} renamed, {} added in new, {} removed from old)')\n",
        report.identical + report.moved + report.renamed,
        report.identical,
        report.moved,
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

#[cfg(test)]
mod tests {
    use super::*;

    fn f(addr: u64, name: &str) -> Function {
        Function {
            address: addr,
            name: name.to_string(),
            file: None,
            start_line: None,
        }
    }

    #[test]
    fn self_diff_is_all_identical_even_with_duplicate_names() {
        // Two functions share a name (Go does this for type-equality thunks);
        // address disambiguates, so a same-build diff must pair every one as
        // identical -- never orphan a duplicate into added/removed.
        let fns = vec![
            f(0x1000, "main.main"),
            f(0x1100, "type..eq.T"),
            f(0x1200, "type..eq.T"),
        ];
        let r = compute(&fns, &fns, None, None);
        assert_eq!(r.identical, 3);
        assert_eq!(r.moved, 0);
        assert_eq!(r.renamed, 0);
        assert_eq!(r.added, 0);
        assert_eq!(r.removed, 0);
    }

    #[test]
    fn a_rebuild_relocates_functions_as_moved_not_renamed() {
        // Same names, every address shifted: the bulk of a version bump. These are
        // moves (the function is unchanged), not renames.
        let old = vec![f(0x1000, "main.a"), f(0x1100, "main.b")];
        let new = vec![f(0x2000, "main.a"), f(0x2100, "main.b")];
        let r = compute(&old, &new, None, None);
        assert_eq!(r.moved, 2);
        assert_eq!(r.identical, 0);
        assert_eq!(r.renamed, 0);
    }

    #[test]
    fn a_real_rename_is_found_by_signature_not_name() {
        // The function moved AND was renamed; only its code signature pairs it. With
        // signatures it reads as one rename; without them it falls to add/remove.
        let old = vec![f(0x1000, "main.old")];
        let new = vec![f(0x2000, "main.new")];
        let old_sigs: HashMap<u64, u64> = [(0x1000, 0xABCD)].into_iter().collect();
        let new_sigs: HashMap<u64, u64> = [(0x2000, 0xABCD)].into_iter().collect();

        let r = compute(&old, &new, Some(&old_sigs), Some(&new_sigs));
        assert_eq!(r.renamed, 1);
        assert_eq!(r.added, 0);
        assert_eq!(r.removed, 0);

        let r = compute(&old, &new, None, None);
        assert_eq!(r.renamed, 0);
        assert_eq!(r.added, 1);
        assert_eq!(r.removed, 1);
    }

    #[test]
    fn an_ambiguous_signature_is_not_paired_by_guess() {
        // Two unmatched functions per side share one signature: pairing either way
        // would be a guess, so none are paired -- they fall to add/remove.
        let old = vec![f(0x1000, "old.a"), f(0x1100, "old.b")];
        let new = vec![f(0x2000, "new.a"), f(0x2100, "new.b")];
        let sig: u64 = 0x1111;
        let old_sigs: HashMap<u64, u64> = [(0x1000, sig), (0x1100, sig)].into_iter().collect();
        let new_sigs: HashMap<u64, u64> = [(0x2000, sig), (0x2100, sig)].into_iter().collect();
        let r = compute(&old, &new, Some(&old_sigs), Some(&new_sigs));
        assert_eq!(r.renamed, 0);
        assert_eq!(r.added, 2);
        assert_eq!(r.removed, 2);
    }

    #[test]
    fn added_and_removed_are_reported() {
        let old = vec![f(0x1000, "shared"), f(0x1100, "gone")];
        let new = vec![f(0x1000, "shared"), f(0x1200, "fresh")];
        let r = compute(&old, &new, None, None);
        assert_eq!(r.identical, 1);
        assert_eq!(r.removed, 1);
        assert_eq!(r.added, 1);
    }
}
