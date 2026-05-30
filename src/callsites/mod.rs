//! Find every call site that targets a given symbol.
//!
//! `--xrefs` builds the whole call graph and lets you BFS over it;
//! `callsites::find` answers the narrower question an operator asks
//! at 2am: "who calls this thing." The two layers share an
//! instruction scanner but answer different questions.
//!
//! Today this module ships Scanner 1 only: direct amd64 `CALL rel32`
//! sites whose resolved target matches the requested symbol. Scanner
//! 2 (indirect calls through itab method slots) lands in the next
//! commit. The split exists so callers depending on the direct
//! scanner can ship without waiting for the itab work.

use serde::Serialize;

use crate::error::Error;
use crate::gobin::{Arch, GoBinary, SectionKind};
use crate::pclntab::{Function, Pclntab};
use crate::Result;

/// What the operator is looking for. Three variants because each
/// resolves to a different scan: a name needs a pclntab lookup to
/// recover the address, an address can scan directly, and an
/// indirect-itab method (deferred to Scanner 2) needs the itab
/// table to know which method slot a call goes through.
#[derive(Debug, Clone)]
pub enum Target {
    /// Function recovered from pclntab, named.
    Function(String),
    /// Resolved by link-time VA. Useful when pclntab can't name the
    /// target but the operator already has its address.
    Address(u64),
    /// An interface-method dispatch slot. Reserved for Scanner 2;
    /// included now so the public enum is stable when that ships.
    ItabMethod { itab_addr: u64, method_index: usize },
}

/// One call site that targets the requested symbol.
#[derive(Debug, Clone, Serialize)]
pub struct CallSite {
    /// Link-time VA of the call instruction itself.
    pub call_site: u64,
    /// Containing function from pclntab. `None` when the call site
    /// falls outside any recovered function (asm stubs, generated
    /// thunks, padding the scanner happened to match).
    pub caller_name: Option<String>,
    pub caller_addr: Option<u64>,
    pub kind: CallKind,
}

/// How the call site reaches its target.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum CallKind {
    /// Direct amd64 `CALL rel32` (opcode 0xE8). The most common shape
    /// on Go binaries; covers 80-90% of call sites on a typical build
    /// because the compiler prefers PC-relative direct calls when
    /// the callee is statically known.
    Direct,
    /// Direct indirect call through a known itab method slot:
    /// `CALL [rip + itab + (5 + method_index) * 8]`. Rare in real
    /// Go output (the compiler usually goes through a register, which
    /// requires basic-block tracking we deliberately don't do), but
    /// it's free to detect because the opcode shape is fixed.
    /// Populated by Scanner 2.
    IndirectItab {
        itab_addr: u64,
        method_index: usize,
        method_name: Option<String>,
    },
}

/// Find every call site that targets `target`. amd64 only; other
/// architectures return an error (the encodings are arch-specific
/// and we don't ship a fake answer).
pub fn find(bin: &GoBinary, pcln: &Pclntab<'_>, target: &Target) -> Result<Vec<CallSite>> {
    if !bin.little_endian {
        return Err(Error::Xrefs(
            "callsites scan is little-endian only today".into(),
        ));
    }
    if !matches!(bin.arch, Arch::X86_64) {
        return Err(Error::Xrefs(format!(
            "callsites scan is amd64 only today; got {:?}",
            bin.arch
        )));
    }

    let functions = pcln.functions()?;
    let target_addr = resolve_target_addr(target, &functions)?;

    let text = pick_text(bin)?;
    let text_start = text.addr;
    let text_bytes = &bin.bytes[text.file_offset..text.file_offset + text.file_size];

    let mut out = Vec::new();
    scan_direct_amd64(text_bytes, text_start, target_addr, pcln, &mut out);
    Ok(out)
}

/// Resolve a `Target` to a single u64 address the scanner can match
/// against. `Function` looks up the name in pclntab; `Address` passes
/// through; `ItabMethod` is not yet supported by Scanner 1 and
/// returns an error so callers see the gap honestly.
fn resolve_target_addr(target: &Target, functions: &[Function]) -> Result<u64> {
    match target {
        Target::Address(a) => Ok(*a),
        Target::Function(name) => functions
            .iter()
            .find(|f| f.name == *name)
            .map(|f| f.address)
            .ok_or_else(|| Error::Xrefs(format!("no function named {name:?} in pclntab"))),
        Target::ItabMethod { .. } => Err(Error::Xrefs(
            "Target::ItabMethod requires Scanner 2 which lands in a follow-up commit".into(),
        )),
    }
}

/// Same .text selection logic xrefs::find_calls uses: prefer the
/// section literally named ".text" (because helm-class binaries have
/// .init / .plt before .text and a naive first-match would pick the
/// wrong one), fall back to the largest executable section.
fn pick_text(bin: &GoBinary) -> Result<&crate::gobin::Section> {
    bin.sections
        .iter()
        .find(|s| s.kind == SectionKind::Text && s.name.ends_with(".text"))
        .or_else(|| {
            bin.sections
                .iter()
                .filter(|s| s.kind == SectionKind::Text)
                .max_by_key(|s| s.file_size)
        })
        .ok_or_else(|| Error::Xrefs("no text section".into()))
}

/// Linear sweep over .text for amd64 `CALL rel32` (opcode 0xE8). Same
/// shape as xrefs::find_calls but filtered to a single target; this
/// avoids materializing the whole call graph when the operator only
/// asked about one symbol.
fn scan_direct_amd64(
    text_bytes: &[u8],
    text_start: u64,
    target_addr: u64,
    pcln: &Pclntab<'_>,
    out: &mut Vec<CallSite>,
) {
    let mut i = 0usize;
    while i + 5 <= text_bytes.len() {
        if text_bytes[i] == 0xE8 {
            let rel = i32::from_le_bytes(text_bytes[i + 1..i + 5].try_into().unwrap());
            let call_site_va = text_start + i as u64;
            let call_next_va = call_site_va + 5;
            let resolved = call_next_va.wrapping_add(rel as i64 as u64);
            if resolved == target_addr {
                let caller = pcln.lookup(call_site_va);
                out.push(CallSite {
                    call_site: call_site_va,
                    caller_name: caller.as_ref().map(|f| f.name.clone()),
                    caller_addr: caller.as_ref().map(|f| f.address),
                    kind: CallKind::Direct,
                });
            }
        }
        i += 1;
    }
}
