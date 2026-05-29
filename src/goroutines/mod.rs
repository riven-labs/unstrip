//! Find every `runtime.newproc` and `runtime.deferproc` call site in
//! `.text` and resolve the function value passed as the first argument.
//!
//! Go's compiler emits a narrow set of code shapes here. On amd64 the
//! typical sequence is:
//!
//! ```text
//!   48 8d 0d xx xx xx xx       LEA rcx, [rip + disp32]    ; load *funcval
//!   ...                                                   ; possibly stack store
//!   e8 xx xx xx xx             CALL runtime.newproc        ; relative call
//! ```
//!
//! The `*funcval` loaded into rcx points at a `funcval` struct whose
//! first uintptr is the actual function entry PC. We resolve the funcval
//! address from the LEA's RIP-relative displacement, dereference the
//! first uintptr, and that's the goroutine entry point.
//!
//! On arm64 the equivalent is `ADRP x0, ...` + `ADD x0, x0, ...`
//! followed by `BL runtime.newproc`.
//!
//! When pattern matching fails (the LEA isn't where we expect it, the
//! funcval isn't in a section we can read, etc.) we still emit the call
//! site with `target: None` so the analyst sees how many goroutines the
//! binary spawns even if we can't always name them.

use serde::Serialize;

use crate::error::Error;
use crate::gobin::{Arch, GoBinary, SectionKind};
use crate::pclntab::{Function, Pclntab};
use crate::Result;

#[derive(Debug, Clone, Serialize)]
pub struct GoroutineSpawn {
    /// PC of the CALL instruction in `.text`.
    pub call_site: u64,
    /// The runtime function being called (`runtime.newproc`,
    /// `runtime.deferproc`, ...).
    pub spawner: String,
    /// Address of the resolved target function, if we could decode the
    /// preceding instructions and read the funcval. None when the
    /// pattern didn't match or the funcval address was unmapped.
    pub target_addr: Option<u64>,
    /// Name of the target function from our recovered set. None when
    /// `target_addr` resolved but didn't match any known function.
    pub target_name: Option<String>,
    /// File and line of the call site itself, if the pcln pc-value
    /// table covers it (it usually does).
    pub file: Option<String>,
    pub line: Option<u32>,
    /// Why resolution succeeded or failed. Lets callers separate "we
    /// never found the LEA/ADRP load" from "we found it but the funcval
    /// pointer is outside any mapped section" without re-deriving the
    /// distinction from the Option fields.
    pub resolution: Resolution,
}

/// Outcome of attempting to resolve a goroutine spawn's funcval target.
/// Serialized as a kebab-case tag so JSON consumers can filter on it
/// without parsing free-form strings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Resolution {
    /// Funcval pointer decoded and its entry PC read successfully.
    /// `target_name` may still be `None` if the entry PC doesn't match
    /// any recovered function (rare but possible).
    Resolved,
    /// No LEA (amd64) or ADRP/ADD (arm64) load was found in the window
    /// preceding the CALL. Either Go used a codegen shape we don't
    /// recognise or the funcval came from a register set further back.
    NoLeaPattern,
    /// The load pattern decoded cleanly but the resulting funcval
    /// pointer is outside any mapped section, so we couldn't read the
    /// entry PC. Usually points at a relocation we didn't apply.
    FuncvalUnmapped,
}

impl GoroutineSpawn {
    /// True when the funcval entry PC was decoded successfully. Does
    /// not require `target_name` to be present; an entry PC outside the
    /// recovered function set still counts as resolved.
    pub fn is_resolved(&self) -> bool {
        matches!(self.resolution, Resolution::Resolved)
    }
}

/// The Go runtime functions we care about, in priority order.
/// `runtime.newproc` spawns a goroutine; `runtime.deferproc` registers
/// a deferred call; `runtime.go` is older. Add others as they show up.
const SPAWNER_NAMES: &[&str] = &[
    "runtime.newproc",
    "runtime.deferproc",
    "runtime.deferprocStack",
];

pub fn find_spawns(bin: &GoBinary, pcln: &Pclntab<'_>) -> Result<Vec<GoroutineSpawn>> {
    if !bin.little_endian {
        return Err(Error::Goroutines(
            "only little-endian binaries supported today".into(),
        ));
    }
    if !matches!(bin.arch, Arch::X86_64 | Arch::Aarch64) {
        return Err(Error::Goroutines(format!(
            "unsupported arch {:?}; only amd64 and arm64 today",
            bin.arch
        )));
    }

    let functions = pcln.functions()?;
    let by_addr: std::collections::HashMap<u64, &Function> =
        functions.iter().map(|f| (f.address, f)).collect();

    // Build the spawner address table from our recovered function set.
    // If a spawner isn't recovered (e.g., this binary doesn't link
    // runtime.deferproc), skip it; that's normal.
    let mut spawners: Vec<(u64, &'static str)> = Vec::new();
    for name in SPAWNER_NAMES {
        if let Some(f) = functions.iter().find(|f| &f.name == name) {
            spawners.push((f.address, name));
        }
    }
    if spawners.is_empty() {
        return Ok(Vec::new());
    }
    let spawner_set: std::collections::HashMap<u64, &'static str> =
        spawners.iter().copied().collect();

    // Pick the actual .text section, not the first executable one.
    // .init and .plt appear before .text in the header table on most
    // ELFs and would shadow it under a naive first-match.
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
        .ok_or_else(|| Error::Goroutines("no text section".into()))?;
    let text_start_va = text.addr;
    let text_bytes = &bin.bytes[text.file_offset..text.file_offset + text.file_size];

    let mut out = Vec::new();
    match bin.arch {
        Arch::X86_64 => scan_amd64(
            bin,
            text_bytes,
            text_start_va,
            &spawner_set,
            &by_addr,
            pcln,
            &mut out,
        )?,
        Arch::Aarch64 => scan_arm64(
            bin,
            text_bytes,
            text_start_va,
            &spawner_set,
            &by_addr,
            pcln,
            &mut out,
        )?,
        _ => unreachable!(),
    }
    Ok(out)
}

/// amd64 scan: look for `E8 xx xx xx xx` (CALL rel32) where the target
/// is one of our spawner addresses. For each hit, back-track 7 bytes
/// to look for `48 8d 0d xx xx xx xx` (LEA rcx, [rip+disp32]) loading
/// the funcval.
fn scan_amd64(
    bin: &GoBinary,
    text_bytes: &[u8],
    text_start_va: u64,
    spawners: &std::collections::HashMap<u64, &'static str>,
    by_addr: &std::collections::HashMap<u64, &Function>,
    pcln: &Pclntab<'_>,
    out: &mut Vec<GoroutineSpawn>,
) -> Result<()> {
    // Linear scan. Could be smarter (skip non-executable runs, follow
    // function boundaries via the functab) but at sub-100ms on helm the
    // dumb version is fast enough.
    let mut i = 0;
    while i + 5 <= text_bytes.len() {
        if text_bytes[i] == 0xE8 {
            let rel = i32::from_le_bytes(text_bytes[i + 1..i + 5].try_into().unwrap());
            let call_site_va = text_start_va + i as u64;
            let call_next_va = call_site_va + 5;
            let target_va = call_next_va.wrapping_add(rel as i64 as u64);
            if let Some(&spawner_name) = spawners.get(&target_va) {
                let (target_addr, target_name, resolution) =
                    resolve_amd64_target(bin, text_bytes, text_start_va, i, by_addr);
                let (file, line) = pcln
                    .lookup(call_site_va)
                    .map(|f| (f.file, f.start_line))
                    .unwrap_or((None, None));
                out.push(GoroutineSpawn {
                    call_site: call_site_va,
                    spawner: spawner_name.to_string(),
                    target_addr,
                    target_name,
                    file,
                    line,
                    resolution,
                });
            }
        }
        i += 1;
    }
    Ok(())
}

/// Look at the bytes immediately before a CALL site for a Go-codegen
/// LEA loading a funcval pointer. We check the common pattern
/// `48 8d 0d xx xx xx xx` (REX.W LEA rcx, [rip+disp32]) at offsets
/// 7, 9, 11, 13 bytes before the CALL (Go often emits a few setup
/// instructions between the LEA and the CALL).
fn resolve_amd64_target(
    bin: &GoBinary,
    text_bytes: &[u8],
    text_start_va: u64,
    call_offset: usize,
    by_addr: &std::collections::HashMap<u64, &Function>,
) -> (Option<u64>, Option<String>, Resolution) {
    // Track whether we saw the LEA pattern at all so we can distinguish
    // "no pattern" from "pattern present but funcval pointer unmapped".
    let mut saw_pattern = false;
    for back in [7usize, 9, 11, 13, 16, 19, 22, 25] {
        if call_offset < back {
            continue;
        }
        let pos = call_offset - back;
        if text_bytes.len() < pos + 7 {
            continue;
        }
        // REX.W + LEA r64, [rip+disp32] = 48 8d /r modrm
        // For LEA rcx, [rip+...] the modrm byte is 0x0d (rcx, [rip+disp32])
        // For LEA rax, [rip+...] the modrm byte is 0x05 (rax, ...)
        // Go's newproc takes the funcval in rax (Go's internal calling
        // convention for ABIInternal); older versions used rcx.
        if text_bytes[pos] != 0x48 || text_bytes[pos + 1] != 0x8d {
            continue;
        }
        let modrm = text_bytes[pos + 2];
        if !matches!(modrm, 0x05 | 0x0d | 0x15 | 0x1d | 0x35 | 0x3d) {
            continue;
        }
        saw_pattern = true;
        let disp = i32::from_le_bytes(text_bytes[pos + 3..pos + 7].try_into().unwrap());
        let lea_next_va = text_start_va + (pos + 7) as u64;
        let funcval_va = lea_next_va.wrapping_add(disp as i64 as u64);

        // funcval struct: first uintptr is the function entry PC.
        if let Some(buf) = bin.read_at_addr(funcval_va, 8) {
            let entry_pc = u64::from_le_bytes(buf.try_into().unwrap());
            let name = by_addr.get(&entry_pc).map(|f| f.name.clone());
            return (Some(entry_pc), name, Resolution::Resolved);
        }
    }
    let reason = if saw_pattern {
        Resolution::FuncvalUnmapped
    } else {
        Resolution::NoLeaPattern
    };
    (None, None, reason)
}

/// arm64 scan: look for `BL` instructions (top byte 0x94 in little-endian
/// after the rel26 displacement). Encoding: `100101 imm26` where imm26 is
/// a signed 26-bit displacement in 4-byte units.
fn scan_arm64(
    bin: &GoBinary,
    text_bytes: &[u8],
    text_start_va: u64,
    spawners: &std::collections::HashMap<u64, &'static str>,
    by_addr: &std::collections::HashMap<u64, &Function>,
    pcln: &Pclntab<'_>,
    out: &mut Vec<GoroutineSpawn>,
) -> Result<()> {
    // arm64 instructions are 4-byte aligned. Iterate every 4 bytes.
    let mut i = 0;
    while i + 4 <= text_bytes.len() {
        let insn = u32::from_le_bytes(text_bytes[i..i + 4].try_into().unwrap());
        // BL: top 6 bits == 100101 (0x25), 26-bit signed displacement.
        if (insn >> 26) == 0x25 {
            let imm26 = insn & 0x03ff_ffff;
            // Sign-extend imm26 from 26 bits, shift left 2 (instruction units).
            let signed = if imm26 & 0x0200_0000 != 0 {
                (imm26 as i64) | !0x03ff_ffff
            } else {
                imm26 as i64
            };
            let call_site_va = text_start_va + i as u64;
            let target_va = call_site_va.wrapping_add((signed << 2) as u64);
            if let Some(&spawner_name) = spawners.get(&target_va) {
                let (target_addr, target_name, resolution) =
                    resolve_arm64_target(bin, text_bytes, text_start_va, i, by_addr);
                let (file, line) = pcln
                    .lookup(call_site_va)
                    .map(|f| (f.file, f.start_line))
                    .unwrap_or((None, None));
                out.push(GoroutineSpawn {
                    call_site: call_site_va,
                    spawner: spawner_name.to_string(),
                    target_addr,
                    target_name,
                    file,
                    line,
                    resolution,
                });
            }
        }
        i += 4;
    }
    Ok(())
}

/// Resolve the funcval target for an arm64 BL. The typical Go codegen
/// shape is:
///
/// ```text
///   ADRP x0, page             ; bits [31:12] of page address
///   ADD  x0, x0, #lo12         ; bits [11:0] of address
///   ...
///   BL   runtime.newproc
/// ```
///
/// We scan back 1-8 instructions for an ADRP/ADD pair targeting x0, x1,
/// or x2 (Go's calling convention puts the funcval pointer in one of
/// the first few argument registers).
fn resolve_arm64_target(
    bin: &GoBinary,
    text_bytes: &[u8],
    text_start_va: u64,
    call_offset: usize,
    by_addr: &std::collections::HashMap<u64, &Function>,
) -> (Option<u64>, Option<String>, Resolution) {
    let mut saw_pattern = false;
    // Look backward up to 8 instructions (32 bytes).
    let mut pos = call_offset;
    for _ in 0..8 {
        if pos < 8 {
            break;
        }
        pos -= 4;
        let candidate_adrp = pos;
        if candidate_adrp + 8 > text_bytes.len() {
            continue;
        }
        let adrp = u32::from_le_bytes(
            text_bytes[candidate_adrp..candidate_adrp + 4]
                .try_into()
                .unwrap(),
        );
        let add = u32::from_le_bytes(
            text_bytes[candidate_adrp + 4..candidate_adrp + 8]
                .try_into()
                .unwrap(),
        );

        // ADRP encoding: top byte 0x90 OR 0xb0 (the immlo bits steal
        // the high two bits). Easiest check: bits [31:24] roughly 0x90 to 0xb0.
        if (adrp >> 31) & 1 != 1 {
            continue;
        }
        if ((adrp >> 24) & 0x1f) != 0x10 {
            continue;
        }
        let rd_adrp = adrp & 0x1f;
        if rd_adrp > 2 {
            continue; // not x0/x1/x2; not the function argument
        }
        let immlo = (adrp >> 29) & 0x3;
        let immhi = (adrp >> 5) & 0x7ffff;
        let imm = ((immhi << 2) | immlo) as i64;
        let imm_signed = if imm & (1 << 20) != 0 {
            imm | !0x001f_ffff
        } else {
            imm
        };
        let adrp_va = text_start_va + candidate_adrp as u64;
        let page = (adrp_va & !0xfff).wrapping_add((imm_signed << 12) as u64);

        // ADD (immediate) 64-bit: 100100010 sf imm12 rn rd, where sf bit is set.
        // Pattern bits [31:22] = 1001000100 = 0x244.
        if (add >> 22) & 0x3ff != 0x244 {
            continue;
        }
        let rd_add = add & 0x1f;
        let rn_add = (add >> 5) & 0x1f;
        if rd_add != rd_adrp || rn_add != rd_adrp {
            continue;
        }
        let imm12 = (add >> 10) & 0xfff;
        let funcval_va = page.wrapping_add(imm12 as u64);
        saw_pattern = true;

        if let Some(buf) = bin.read_at_addr(funcval_va, 8) {
            let entry_pc = u64::from_le_bytes(buf.try_into().unwrap());
            let name = by_addr.get(&entry_pc).map(|f| f.name.clone());
            return (Some(entry_pc), name, Resolution::Resolved);
        }
    }
    let reason = if saw_pattern {
        Resolution::FuncvalUnmapped
    } else {
        Resolution::NoLeaPattern
    };
    (None, None, reason)
}
