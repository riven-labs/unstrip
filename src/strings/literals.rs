//! Exact Go string literals: the `(address, length)` pairs the program
//! itself uses, each with the functions that use it.
//!
//! A Go string is a `{pointer, length}` header, and the linker packs the
//! bytes of every literal end to end with no terminator, so the bytes alone
//! do not say where one literal stops. The program says it. A literal is
//! reported only where the binary pairs a pointer with a length:
//!
//! - In code, a pointer and a length set in the same basic block in two
//!   consecutive integer registers of the Go register ABI and then passed
//!   to a call or returned: `LEA AX, lit; MOV EBX, len; CALL f` on amd64,
//!   `ADRP/ADD X0, lit; MOV X1, #len; BL f` on arm64. A comparison with a
//!   literal calls `runtime.memequal(a, b, size)` with the literal as `a`
//!   or `b`; there `size` is its length.
//! - In code, a pointer and a length stored to two adjacent words off the
//!   same base: `MOV [base+d], ptr; MOV [base+d+8], len`, or one `STP` on
//!   arm64. This is how a string reaches a struct field, a slice element, a
//!   map slot, or a stack argument before the register ABI, and on 386,
//!   which has no register ABI, a stack argument always.
//! - In data, a header in an initialized global or a read-only composite
//!   literal: a pointer word into the string table and the length word
//!   after it. Code that loads the header's address uses the literal too.
//!
//! The code is read one function at a time with a forward data flow over
//! its branches, so a store pair split by a write-barrier check still
//! pairs. Assembly functions are skipped: they move words around with no
//! string meaning.
//!
//! Every candidate is then checked against the linker's string table,
//! which the code-proven pairs locate: the table is sorted by length and
//! packed, so a literal in it must keep that order with its neighbours and
//! fit between them. A pair is dropped,
//! and counted in [`Dropped`], when its pointer is a type descriptor or an
//! itab or its bytes start with an address, when its bytes leave read-only
//! data, when it lies outside the table, or when it breaks the table's
//! length order or overlaps another literal. Nothing is guessed: a literal
//! the code never pairs, such as a lookup table indexed byte by byte, is
//! not reported.

use std::collections::{BTreeMap, HashMap, HashSet};

use serde::Serialize;

use crate::gobin::{Arch, GoBinary, Section, SectionKind};
use crate::pclntab::Pclntab;
use crate::Result;

use crate::disasm::{arm64, function_code, x86};

/// One string literal, its bytes, and everything in the binary proven to
/// use it.
#[derive(Debug, Clone, Serialize)]
#[non_exhaustive]
pub struct Literal {
    /// Link-time address of the first byte.
    pub addr: u64,
    pub len: u64,
    /// The literal's bytes.
    #[serde(skip)]
    pub bytes: Vec<u8>,
    /// The bytes as text, when they are valid UTF-8.
    pub text: Option<String>,
    /// The bytes in hex, when they are not valid UTF-8.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hex: Option<String>,
    pub origin: Origin,
    /// Instructions that pair this literal's pointer with its length, in
    /// address order.
    pub uses: Vec<Use>,
    /// Static string headers in data that point at this literal.
    pub headers: Vec<Header>,
}

/// What the literal is, beyond a string the program uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum Origin {
    /// A string literal of the program or a package it links.
    Literal,
    /// The toolchain version or the module info the linker records for
    /// `runtime/debug.ReadBuildInfo` (`runtime.buildVersion`,
    /// `runtime.modinfo`). `--buildinfo` decodes these.
    BuildInfo,
}

/// One instruction that uses a literal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct Use {
    /// The instruction that loads the literal's address (or the header's).
    pub pc: u64,
    /// Entry PC of the containing function.
    pub function_addr: u64,
    /// Name of the containing function. None when the function table gives
    /// it no name (garble's `-tiny` blanks them).
    pub function: Option<String>,
    pub site: Site,
}

/// How a use pairs the pointer with the length.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum Site {
    /// Two consecutive argument or result registers at a call or return.
    Registers,
    /// Two adjacent words stored off the same base.
    Store,
    /// The code loads the address of a static header that holds the pair.
    Header,
}

/// A static `{pointer, length}` header in data.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct Header {
    /// Address of the pointer word.
    pub addr: u64,
    /// Name of the section it sits in.
    pub section: String,
}

/// Every literal recovered from a binary, with what the scan could and
/// could not do.
#[derive(Debug, Clone, Serialize)]
#[non_exhaustive]
pub struct Literals {
    /// Sorted by address, then length.
    pub literals: Vec<Literal>,
    /// False when the architecture has no instruction scanner (anything but
    /// amd64, arm64 and 386). Then nothing is reported, because a static
    /// header is accepted only inside the span code-proven literals occupy.
    pub code_scanned: bool,
    /// Whether call and return sites were read with the register ABI (Go
    /// 1.17 and later on amd64, 1.18 and later on arm64).
    pub register_abi: bool,
    pub dropped: Dropped,
}

/// Pairs the scan found and refused, by reason.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct Dropped {
    /// The pointer is a type descriptor or an itab, or its bytes start with
    /// an address (a function value, an array of string headers).
    pub pointer_data: usize,
    /// A third word holds the same length: a slice header.
    pub slice: usize,
    /// The pointer is outside read-only data, or the bytes run past it.
    pub out_of_bounds: usize,
    /// The literal lies outside the string table.
    pub outside_table: usize,
    /// The literal breaks the table's length order or overlaps another one.
    pub conflicting: usize,
}

/// Recovers the string literals `bin` uses. See the module documentation
/// for what counts as proof.
pub fn literals(bin: &GoBinary, pcln: &Pclntab<'_>) -> Result<Literals> {
    let functions = pcln.functions_with_offsets()?;
    // Assembly functions move words around with no string semantics (the
    // runtime's bootstrap stores a pointer next to a small constant), and
    // the literals the compiler emits are all used from Go code.
    let assembly: HashSet<u64> = pcln
        .functions()?
        .into_iter()
        .filter(|f| f.file.as_deref().is_some_and(|file| file.ends_with(".s")))
        .map(|f| f.address)
        .collect();
    let register_abi = register_abi(bin, pcln);
    let ctx = CodeCtx {
        register_abi,
        write_barriers: functions
            .iter()
            .filter(|f| f.name.len() == 23 && f.name.starts_with("runtime.gcWriteBarrier"))
            .map(|f| f.address)
            .collect(),
        memequal: functions
            .iter()
            .find(|f| f.name == "runtime.memequal")
            .map(|f| f.address),
    };
    let mut scan = Scan::default();
    let code_scanned = match bin.arch {
        Arch::X86_64 if bin.little_endian => {
            for (idx, f) in functions.iter().enumerate() {
                if assembly.contains(&f.address) {
                    continue;
                }
                let Some(code) = function_code(bin, f.address, f.size) else {
                    continue;
                };
                scan_x86(code, f.address, idx, &ctx, &AMD64, &mut scan);
            }
            true
        }
        Arch::X86 if bin.little_endian => {
            for (idx, f) in functions.iter().enumerate() {
                if assembly.contains(&f.address) {
                    continue;
                }
                let Some(code) = function_code(bin, f.address, f.size) else {
                    continue;
                };
                scan_x86(code, f.address, idx, &ctx, &I386, &mut scan);
            }
            true
        }
        Arch::Aarch64 if bin.little_endian => {
            for (idx, f) in functions.iter().enumerate() {
                if assembly.contains(&f.address) {
                    continue;
                }
                let Some(code) = function_code(bin, f.address, f.size) else {
                    continue;
                };
                scan_arm64(code, f.address, idx, &ctx, &mut scan);
            }
            true
        }
        _ => false,
    };

    let mds = crate::moduledata::ModuleData::locate_all(bin).unwrap_or_default();
    let excluded = type_data_addrs(bin, &mds);
    let ps = bin.pointer_size() as u64;
    let mut dropped = Dropped::default();
    let mut by_extent: BTreeMap<(u64, u64), Vec<Use>> = BTreeMap::new();
    for pair in &scan.pairs {
        if excluded.contains(&pair.ptr) || (pair.len >= ps && starts_with_address(bin, pair.ptr)) {
            dropped.pointer_data += 1;
            continue;
        }
        if read_only_bytes(bin, pair.ptr, pair.len).is_none() {
            dropped.out_of_bounds += 1;
            continue;
        }
        let f = &functions[pair.func_idx];
        by_extent
            .entry((pair.ptr, pair.len))
            .or_default()
            .push(Use {
                pc: pair.pc,
                function_addr: f.address,
                function: (!f.name.is_empty()).then(|| f.name.clone()),
                site: pair.site,
            });
    }

    // The code-proven literals locate the linker's string table; a static
    // header is believed only when it points inside it. The function data
    // (`gofunc` in moduledata, Go 1.18 and later) comes after the table.
    let ceiling = mds.first().map(|md| md.gofunc).filter(|&g| g != 0);
    let table = Table::new(by_extent.keys().copied(), ceiling);
    let mut headers: BTreeMap<(u64, u64), Vec<Header>> = BTreeMap::new();
    if let Some(span) = table.span() {
        for (addr, section, ptr, len) in static_headers(bin, span, &excluded, &mut dropped) {
            headers
                .entry((ptr, len))
                .or_default()
                .push(Header { addr, section });
        }
    }
    let accepted = table.accept(by_extent.keys().chain(headers.keys()).copied());
    by_extent.retain(|extent, uses| {
        if accepted.contains(extent) {
            return true;
        }
        if table.contains(*extent) {
            dropped.conflicting += uses.len();
        } else {
            dropped.outside_table += uses.len();
        }
        false
    });
    headers.retain(|extent, hs| {
        if !accepted.contains(extent) {
            dropped.conflicting += hs.len();
            return false;
        }
        true
    });

    // Code that loads a header's address uses the literal it holds.
    scan.refs.sort_unstable();
    for (&(ptr, len), hs) in &headers {
        for h in hs {
            let lo = scan.refs.partition_point(|r| r.0 < h.addr);
            for &(target, pc, func_idx) in &scan.refs[lo..] {
                if target != h.addr {
                    break;
                }
                let f = &functions[func_idx];
                by_extent.entry((ptr, len)).or_default().push(Use {
                    pc,
                    function_addr: f.address,
                    function: (!f.name.is_empty()).then(|| f.name.clone()),
                    site: Site::Header,
                });
            }
        }
        by_extent.entry((ptr, len)).or_default();
    }

    let build_version = crate::buildinfo::BuildInfo::parse(bin)
        .ok()
        .map(|bi| bi.go_version);
    let mut out = Vec::with_capacity(by_extent.len());
    for ((addr, len), mut uses) in by_extent {
        // SAFETY: every extent was checked by `read_only_bytes` above, or
        // by `static_headers`, which checks the same way.
        let Some(bytes) = read_only_bytes(bin, addr, len) else {
            continue;
        };
        let bytes = bytes.to_vec();
        uses.sort_by_key(|u| (u.pc, u.site));
        uses.dedup_by(|a, b| a.pc == b.pc);
        let origin = if bytes.starts_with(&MODINFO_START)
            || build_version.as_deref().map(str::as_bytes) == Some(bytes.as_slice())
        {
            Origin::BuildInfo
        } else {
            Origin::Literal
        };
        let (text, hex) = match std::str::from_utf8(&bytes) {
            Ok(s) => (Some(s.to_string()), None),
            Err(_) => (
                None,
                Some(bytes.iter().map(|b| format!("{b:02x}")).collect()),
            ),
        };
        out.push(Literal {
            addr,
            len,
            bytes,
            text,
            hex,
            origin,
            uses,
            headers: headers.remove(&(addr, len)).unwrap_or_default(),
        });
    }
    Ok(Literals {
        literals: out,
        code_scanned,
        register_abi,
        dropped,
    })
}

/// The linker's string table (`go:string.*`), located by the literals code
/// proves.
///
/// The linker lays the bytes of every string literal end to end and sorts
/// them by length, so in the table a literal's length is no shorter than
/// the one before it and no longer than the one after, and no two literals
/// overlap. The longest run of code-proven literals whose lengths never
/// fall as their addresses rise is the table's spine; its first and last
/// literal bound the table. A pair the code proves but that lands outside
/// those bounds (a string in an assembly function's data, a literal the
/// linker deduplicated into other read-only data) is dropped with the rest.
struct Table {
    /// The spine, sorted by address.
    spine: Vec<(u64, u64)>,
    /// `[first byte, end)` of the table.
    span: Option<(u64, u64)>,
}

impl Table {
    /// `ceiling`, when known, is an address the table ends before.
    fn new(extents: impl Iterator<Item = (u64, u64)>, ceiling: Option<u64>) -> Table {
        let ceiling = ceiling.unwrap_or(u64::MAX);
        let mut extents: Vec<(u64, u64)> = extents
            .filter(|&(addr, len)| addr.saturating_add(len) <= ceiling)
            .collect();
        extents.sort_unstable();
        extents.dedup();
        // Longest non-decreasing subsequence by length, patience style:
        // `tails[k]` is the index of the smallest last length of a run of
        // length k + 1, and `prev` links each element to its predecessor.
        let mut tails: Vec<usize> = Vec::new();
        let mut prev = vec![usize::MAX; extents.len()];
        for (i, &(_, len)) in extents.iter().enumerate() {
            let k = tails.partition_point(|&t| extents[t].1 <= len);
            if k > 0 {
                prev[i] = tails[k - 1];
            }
            if k == tails.len() {
                tails.push(i);
            } else {
                tails[k] = i;
            }
        }
        let mut spine = Vec::with_capacity(tails.len());
        let mut at = tails.last().copied().unwrap_or(usize::MAX);
        while at != usize::MAX {
            spine.push(extents[at]);
            at = prev[at];
        }
        spine.reverse();
        // The longest run can still step from the table into other data
        // (a buffer whose length follows the table's longest literal). Cut
        // it where two neighbours cannot both be in a packed table, and
        // keep the longest piece.
        let mut best = 0..0;
        let mut start = 0;
        for i in 1..=spine.len() {
            if i == spine.len() || !packed(spine[i - 1], spine[i]) {
                if i - start > best.len() {
                    best = start..i;
                }
                start = i;
            }
        }
        let spine = spine[best].to_vec();
        let span = match (spine.first(), spine.iter().map(|&(a, n)| a + n).max()) {
            (Some(first), Some(end)) => Some((first.0, end)),
            _ => None,
        };
        Table { spine, span }
    }

    fn span(&self) -> Option<(u64, u64)> {
        self.span
    }

    fn contains(&self, (addr, len): (u64, u64)) -> bool {
        match self.span {
            Some((lo, hi)) => lo <= addr && addr.saturating_add(len) <= hi,
            None => false,
        }
    }

    /// The extents inside the table that keep its length order with the
    /// spine around them and overlap no other candidate.
    fn accept(&self, candidates: impl Iterator<Item = (u64, u64)>) -> HashSet<(u64, u64)> {
        let mut fits: Vec<(u64, u64)> = candidates
            .filter(|&e| self.contains(e) && self.in_order(e))
            .collect();
        fits.sort_unstable();
        fits.dedup();
        let mut clash = vec![false; fits.len()];
        for i in 0..fits.len() {
            let end = fits[i].0 + fits[i].1;
            for j in i + 1..fits.len() {
                if fits[j].0 >= end {
                    break;
                }
                clash[i] = true;
                clash[j] = true;
            }
        }
        fits.into_iter()
            .zip(clash)
            .filter(|&(_, c)| !c)
            .map(|(e, _)| e)
            .collect()
    }

    /// Whether `extent` keeps the length order and the packing with the
    /// spine literals on either side of it.
    fn in_order(&self, extent: (u64, u64)) -> bool {
        if self.spine.binary_search(&extent).is_ok() {
            return true;
        }
        let (addr, len) = extent;
        let before = self.spine.partition_point(|&(a, _)| a < addr);
        let after = self.spine.partition_point(|&(a, _)| a <= addr);
        if before != after {
            // Another spine literal starts at the same address.
            return false;
        }
        let prev = before.checked_sub(1).map(|i| self.spine[i]);
        let next = self.spine.get(after).copied();
        let floor = prev.map_or(0, |e| e.1);
        let ceiling = next.map_or(u64::MAX, |e| e.1);
        floor <= len
            && len <= ceiling
            && prev.is_none_or(|p| packed(p, extent))
            && next.is_none_or(|n| packed(extent, n))
    }
}

/// Whether `next` can follow `prev` in the string table: it starts at or
/// after `prev`'s end, and any gap between them is long enough to hold a
/// literal no shorter than `prev` (the table is sorted by length and has no
/// padding). The linker keeps one copy of each literal, so between two
/// one-byte literals there is room for fewer than 256 more.
fn packed(prev: (u64, u64), next: (u64, u64)) -> bool {
    let end = prev.0.saturating_add(prev.1);
    if next.0 < end {
        return false;
    }
    let gap = next.0 - end;
    if prev.1 == 1 && next.1 == 1 && gap >= 256 {
        return false;
    }
    gap == 0 || gap >= prev.1
}

/// The sentinel `cmd/go` puts in front of the module info string.
const MODINFO_START: [u8; 16] = [
    0x30, 0x77, 0xaf, 0x0c, 0x92, 0x74, 0x08, 0x02, 0x41, 0xe1, 0xc1, 0x07, 0xe6, 0xd6, 0x18, 0xe6,
];

/// A pointer/length pair proven at one instruction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Pair {
    ptr: u64,
    len: u64,
    pc: u64,
    func_idx: usize,
    site: Site,
}

/// What every function's scan needs to know about the binary.
struct CodeCtx {
    register_abi: bool,
    /// Entry PCs of `runtime.gcWriteBarrier1` to `8` (Go 1.21 and later).
    write_barriers: HashSet<u64>,
    /// Entry PC of `runtime.memequal(a, b, size)`, which `s == "lit"`
    /// calls with the literal as `a` or `b` and its length as `size`.
    memequal: Option<u64>,
}

#[derive(Debug, Default)]
struct Scan {
    pairs: Vec<Pair>,
    /// `(address, pc, function index)` for every instruction that names an
    /// address directly.
    refs: Vec<(u64, u64, usize)>,
}

/// Whether calls pass arguments in registers: amd64 from Go 1.17, arm64
/// from Go 1.18. The table layout says 1.18 or later even when garble has
/// rewritten the magic. The Go 1.16 layout covers 1.16 and 1.17, so there the
/// recorded version decides, and with none recorded the answer is no. A
/// wrong "no" only loses the register pairs; a wrong "yes" would read stale
/// registers as arguments.
fn register_abi(bin: &GoBinary, pcln: &Pclntab<'_>) -> bool {
    if pcln.is_go118_or_later() {
        return matches!(bin.arch, Arch::X86_64 | Arch::Aarch64);
    }
    bin.arch == Arch::X86_64
        && pcln.is_go116_or_go117()
        && crate::output::go_version(bin).is_some_and(|v| go_minor(&v) >= Some(17))
}

/// The minor release of a version string such as `go1.17.13`.
fn go_minor(version: &str) -> Option<u32> {
    let rest = version.strip_prefix("go1.")?;
    let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
    digits.parse().ok()
}

/// The bytes of a candidate literal, when they sit wholly inside one
/// read-only data section's file-backed bytes and it is not the pclntab.
fn read_only_bytes(bin: &GoBinary, addr: u64, len: u64) -> Option<&[u8]> {
    if len == 0 || len > MAX_LEN {
        return None;
    }
    let section = bin.section_for_addr(addr)?;
    if section.kind != SectionKind::ReadOnlyData {
        return None;
    }
    let pclntab_end = bin.pclntab_addr.saturating_add(bin.pclntab_size as u64);
    if bin.pclntab_addr <= addr && addr < pclntab_end {
        return None;
    }
    let start = section.file_offset_of(addr)?;
    let end = start.checked_add(usize::try_from(len).ok()?)?;
    if end > section.file_offset.saturating_add(section.file_size) {
        return None;
    }
    bin.bytes.get(start..end)
}

/// Whether the pointer-sized word at `addr` is itself an address inside
/// the image. A function value or an array of headers starts that way;
/// the text of a literal does not.
fn starts_with_address(bin: &GoBinary, addr: u64) -> bool {
    let ps = bin.pointer_size();
    let Some(bytes) = bin.read_at_addr(addr, ps) else {
        return false;
    };
    let mut word = 0u64;
    for k in 0..ps {
        let byte = if bin.little_endian {
            bytes[k]
        } else {
            bytes[ps - 1 - k]
        };
        word |= (byte as u64) << (8 * k);
    }
    word != 0 && bin.section_for_addr(word).is_some()
}

/// No Go string literal comes near this; the cap stops a stray immediate
/// from turning into a read of most of a section.
const MAX_LEN: u64 = 16 << 20;

/// Type descriptors and itabs, which code passes in the same register shape
/// as a string (`makemap(type, hint)`, `makechan(type, size)`).
fn type_data_addrs(bin: &GoBinary, mds: &[crate::moduledata::ModuleData]) -> HashSet<u64> {
    let mut out = HashSet::new();
    for md in mds {
        out.extend(md.type_addrs(bin).unwrap_or_default());
        out.extend(md.itab_addrs(bin).unwrap_or_default());
        if let Ok(types) = crate::types::recover_all(bin, md) {
            out.extend(types.iter().map(|t| t.addr));
        }
    }
    out
}

/// Static `{pointer, length}` headers in data whose pointer lands inside
/// `span` and whose bytes stay inside it: `(header address, section name,
/// pointer, length)`.
fn static_headers(
    bin: &GoBinary,
    span: (u64, u64),
    excluded: &HashSet<u64>,
    dropped: &mut Dropped,
) -> Vec<(u64, String, u64, u64)> {
    let ps = bin.pointer_size();
    let word = |b: &[u8]| -> u64 {
        let mut v = 0u64;
        for k in 0..ps {
            let byte = if bin.little_endian {
                b[k]
            } else {
                b[ps - 1 - k]
            };
            v |= (byte as u64) << (8 * k);
        }
        v
    };
    let mut out = Vec::new();
    for section in &bin.sections {
        if !matches!(
            section.kind,
            SectionKind::ReadOnlyData | SectionKind::NoPtrData | SectionKind::Data
        ) {
            continue;
        }
        let Some(bytes) = section_bytes(bin, section) else {
            continue;
        };
        let mut off = (ps as u64 - section.addr % ps as u64) as usize % ps;
        while off + 2 * ps <= bytes.len() {
            let addr = section.addr + off as u64;
            let ptr = word(&bytes[off..]);
            let in_span = span.0 <= ptr && ptr < span.1;
            // The string table itself holds no headers.
            if !in_span || (span.0 <= addr && addr < span.1) {
                off += ps;
                continue;
            }
            let len = word(&bytes[off + ps..]);
            if len == 0
                || ptr.saturating_add(len) > span.1
                || excluded.contains(&ptr)
                || (len >= ps as u64 && starts_with_address(bin, ptr))
            {
                off += ps;
                continue;
            }
            let cap = bytes.get(off + 2 * ps..off + 3 * ps).map(word);
            if cap == Some(len) {
                dropped.slice += 1;
                off += ps;
                continue;
            }
            if read_only_bytes(bin, ptr, len).is_none() {
                dropped.out_of_bounds += 1;
                off += ps;
                continue;
            }
            out.push((addr, section.name.clone(), ptr, len));
            off += 2 * ps;
        }
    }
    out
}

fn section_bytes<'a>(bin: &'a GoBinary, section: &Section) -> Option<&'a [u8]> {
    let end = section
        .file_offset
        .saturating_add(section.file_size)
        .min(bin.bytes.len());
    bin.bytes.get(section.file_offset..end)
}

/// The value a register or a stored word holds, as far as the scan knows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Val {
    Unknown,
    /// An address, loaded at `pc`.
    Addr {
        target: u64,
        pc: u64,
    },
    Imm(u64),
}

/// The base of a stored word: a register at one of its definitions (plus an
/// index register at one of its definitions, and the scale), or an
/// absolute address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum Base {
    Reg {
        reg: u8,
        def: u32,
        index: Option<(u8, u32, u8)>,
    },
    Abs,
}

/// Registers the scanner tracks: the 16 of amd64, the 32 of arm64.
const NREGS: usize = 32;

/// What the scan knows at one point of a function: register contents and
/// the pointer-sized words stored since the last unknown write.
///
/// Every register write gets a fresh definition number, so a word stored
/// off a register is keyed by the value the register held then, not by
/// the register's name.
#[derive(Debug, Clone)]
struct State {
    regs: [Val; NREGS],
    defs: [u32; NREGS],
    /// The definition that produced each register's value, which a copy
    /// carries along.
    born: [u32; NREGS],
    words: BTreeMap<(Base, i64), Val>,
}

impl State {
    fn empty(defs: &mut u32) -> State {
        let mut state = State {
            regs: [Val::Unknown; NREGS],
            defs: [0; NREGS],
            born: [0; NREGS],
            words: BTreeMap::new(),
        };
        for r in 0..NREGS {
            state.defs[r] = fresh(defs);
            state.born[r] = state.defs[r];
        }
        state
    }

    /// The facts that hold on both paths into a join.
    fn meet(&mut self, other: &State, defs: &mut u32) {
        for r in 0..NREGS {
            if self.defs[r] == other.defs[r] && self.regs[r] == other.regs[r] {
                continue;
            }
            if self.regs[r] != other.regs[r] {
                self.regs[r] = Val::Unknown;
            }
            self.defs[r] = fresh(defs);
            self.born[r] = self.defs[r];
        }
        self.words.retain(|k, v| other.words.get(k) == Some(v));
    }
}

fn fresh(defs: &mut u32) -> u32 {
    *defs += 1;
    *defs
}

/// One function's scan: the state flows forward through the code in
/// address order. At a branch target it is the meet of every jump to it
/// and the fall-through; a target some later jump reaches back to (a loop
/// head) starts from nothing, as does code after an unconditional jump
/// that no jump in the function names.
struct Walk<'a> {
    func_idx: usize,
    /// Pointer size in bytes.
    word: i64,
    defs: u32,
    /// The definition counter when the current basic block began.
    block_start: u32,
    state: State,
    /// Running meet of the states jumped from, by forward target.
    pending: HashMap<u64, State>,
    /// Store pairs: `(pointer, length, pc of the pointer)`.
    stored: Vec<(u64, u64, u64)>,
    scan: &'a mut Scan,
}

impl<'a> Walk<'a> {
    fn new(func_idx: usize, word: i64, scan: &'a mut Scan) -> Walk<'a> {
        let mut defs = 0;
        let state = State::empty(&mut defs);
        Walk {
            func_idx,
            word,
            defs,
            block_start: defs,
            state,
            pending: HashMap::new(),
            stored: Vec::new(),
            scan,
        }
    }

    /// Sets the state for the instruction at `pc`.
    fn enter(&mut self, pc: u64, falls_through: bool, loop_head: bool) {
        let jumped = self.pending.remove(&pc);
        if loop_head || jumped.is_some() || !falls_through {
            self.block_start = self.defs;
        }
        if loop_head {
            self.state = State::empty(&mut self.defs);
            return;
        }
        match (jumped, falls_through) {
            (Some(jumped), true) => self.state.meet(&jumped, &mut self.defs),
            (Some(jumped), false) => self.state = jumped,
            (None, true) => (),
            (None, false) => self.state = State::empty(&mut self.defs),
        }
    }

    fn jump_to(&mut self, target: u64) {
        match self.pending.get_mut(&target) {
            Some(state) => state.meet(&self.state, &mut self.defs),
            None => {
                self.pending.insert(target, self.state.clone());
            }
        }
    }

    fn write_reg(&mut self, reg: u8, val: Val) {
        let r = reg as usize % NREGS;
        self.state.regs[r] = val;
        self.state.defs[r] = fresh(&mut self.defs);
        self.state.born[r] = self.state.defs[r];
    }

    fn copy_reg(&mut self, dst: u8, src: u8) {
        let (d, s) = (dst as usize % NREGS, src as usize % NREGS);
        self.state.regs[d] = self.state.regs[s];
        self.state.defs[d] = fresh(&mut self.defs);
        self.state.born[d] = self.state.born[s];
    }

    fn reg(&self, reg: u8) -> Val {
        self.state.regs[reg as usize % NREGS]
    }

    fn base(&self, reg: u8, index: Option<(u8, u8)>) -> Base {
        Base::Reg {
            reg,
            def: self.state.defs[reg as usize % NREGS],
            index: index.map(|(r, scale)| (r, self.state.defs[r as usize % NREGS], scale)),
        }
    }

    /// Forgets the words a write of `width` bytes at `(base, disp)` may
    /// overlap.
    fn clobber(&mut self, base: Base, disp: i64, width: i64) {
        let lo = disp.saturating_sub(self.word - 1);
        let hi = disp.saturating_add(width);
        let doomed: Vec<(Base, i64)> = self
            .state
            .words
            .range((base, lo)..(base, hi))
            .map(|(k, _)| *k)
            .collect();
        for k in doomed {
            self.state.words.remove(&k);
        }
    }

    fn forget_words(&mut self) {
        self.state.words.clear();
    }

    /// A pointer-sized store. `step` is the pointer size.
    fn store(&mut self, base: Base, disp: i64, val: Val, step: i64) {
        self.clobber(base, disp, step);
        self.state.words.insert((base, disp), val);
        let words = &self.state.words;
        // A pointer word with a length word right after it, whichever was
        // stored first, is a string header in memory now.
        let at = match val {
            Val::Addr { .. } => disp,
            Val::Imm(_) => disp - step,
            Val::Unknown => return,
        };
        if let (Some(&Val::Addr { target, pc }), Some(&Val::Imm(len))) =
            (words.get(&(base, at)), words.get(&(base, at + step)))
        {
            self.stored.push((target, len, pc));
        }
    }

    /// Pairs held in consecutive argument registers of the register ABI at
    /// a call or a return. A register given its value before the block
    /// began is not counted: the code sets up arguments and results in the
    /// block that uses them, and an older value is more likely left over
    /// past the last argument than one of them.
    fn register_pairs(&mut self, abi: &[u8]) {
        for k in 0..abi.len().saturating_sub(1) {
            let (Val::Addr { target, pc }, Val::Imm(len)) =
                (self.reg(abi[k]), self.reg(abi[k + 1]))
            else {
                continue;
            };
            let fresh_here = |r: u8| self.state.born[r as usize % NREGS] > self.block_start;
            if !fresh_here(abi[k]) || !fresh_here(abi[k + 1]) {
                continue;
            }
            self.scan.pairs.push(Pair {
                ptr: target,
                len,
                pc,
                func_idx: self.func_idx,
                site: Site::Registers,
            });
        }
    }

    /// At a call to `runtime.memequal(a, b, size)`, the literal compared
    /// against is `a` or `b` and `size` is its length; `b` next to `size`
    /// is already a register pair, `a` is not.
    fn memequal_pair(&mut self, abi: &[u8]) {
        let (Val::Addr { target, pc }, Val::Imm(len)) = (self.reg(abi[0]), self.reg(abi[2])) else {
            return;
        };
        let fresh_here = |r: u8| self.state.born[r as usize % NREGS] > self.block_start;
        if !fresh_here(abi[0]) || !fresh_here(abi[2]) {
            return;
        }
        self.scan.pairs.push(Pair {
            ptr: target,
            len,
            pc,
            func_idx: self.func_idx,
            site: Site::Registers,
        });
    }

    /// The register effect of a move or an instruction that writes no
    /// memory, for replaying a function's return tail.
    fn registers_only(&mut self, kind: x86::Kind) {
        match kind {
            x86::Kind::MovImm { dst, value } => self.write_reg(dst, Val::Imm(value)),
            x86::Kind::MovReg { dst, src } => self.copy_reg(dst, src),
            x86::Kind::Other { writes, .. } => {
                for r in 0..16u8 {
                    if writes & (1 << r) != 0 {
                        self.write_reg(r, Val::Unknown);
                    }
                }
            }
            _ => (),
        }
    }

    /// A call clobbers every register but the stack pointer, and the callee
    /// may write any memory.
    fn call(&mut self, keep: u8) {
        for r in 0..NREGS as u8 {
            if r != keep {
                self.write_reg(r, Val::Unknown);
            }
        }
        self.forget_words();
    }

    fn finish(self) {
        for (ptr, len, pc) in self.stored {
            self.scan.pairs.push(Pair {
                ptr,
                len,
                pc,
                func_idx: self.func_idx,
                site: Site::Store,
            });
        }
    }
}

/// Integer argument and result registers of Go's amd64 register ABI, in
/// order.
const AMD64_ABI: [u8; 9] = [
    x86::RAX,
    x86::RBX,
    x86::RCX,
    x86::RDI,
    x86::RSI,
    8,
    9,
    10,
    11,
];

/// What sets the two x86 modes apart for the walk.
struct X86Mode {
    decode: fn(&[u8], u64) -> Option<x86::Insn>,
    /// Pointer size: a store this wide can hold a header word.
    word: u8,
    /// The one register `runtime.gcWriteBarrier1` to `8` change: they return
    /// the write barrier buffer slot there and save everything else.
    wb_scratch: u8,
}

const AMD64: X86Mode = X86Mode {
    decode: x86::decode,
    word: 8,
    wb_scratch: 11,
};

const I386: X86Mode = X86Mode {
    decode: x86::decode32,
    word: 4,
    wb_scratch: x86::RDI,
};

fn scan_x86(
    code: &[u8],
    entry: u64,
    func_idx: usize,
    ctx: &CodeCtx,
    mode: &X86Mode,
    scan: &mut Scan,
) {
    // First pass: decode, and note every jump target inside the function
    // and whether a jump reaches it from below (a loop head).
    let mut insns = Vec::new();
    let mut loop_heads = HashSet::new();
    let end = entry + code.len() as u64;
    let mut off = 0usize;
    while off < code.len() {
        let pc = entry + off as u64;
        let Some(insn) = (mode.decode)(&code[off..], pc) else {
            break;
        };
        if let x86::Kind::Jump {
            target: Some(t), ..
        } = insn.kind
        {
            if entry <= t && t <= pc {
                loop_heads.insert(t);
            }
        }
        insns.push((pc, insn));
        off += insn.len;
    }
    // Short tails that only move registers and return: a shared epilogue
    // (`MOVQ SI, AX; MOVQ CX, BX; POPQ BP; RET`). A jump to one returns
    // what the tail moves into the result registers.
    let mut tails: HashMap<u64, Vec<x86::Insn>> = HashMap::new();
    if ctx.register_abi {
        for (k, &(pc, insn)) in insns.iter().enumerate() {
            let x86::Kind::Jump {
                target: Some(t),
                conditional: false,
            } = insn.kind
            else {
                continue;
            };
            if t <= pc || t >= end || tails.contains_key(&t) {
                continue;
            }
            let start = insns[k..].partition_point(|&(p, _)| p < t) + k;
            let mut tail = Vec::new();
            for &(_, next) in insns[start..].iter().take(8) {
                match next.kind {
                    x86::Kind::Ret => {
                        tails.insert(t, tail);
                        break;
                    }
                    x86::Kind::MovReg { .. }
                    | x86::Kind::MovImm { .. }
                    | x86::Kind::Other {
                        mem_write: None, ..
                    } => tail.push(next),
                    _ => break,
                }
            }
        }
    }

    let mut walk = Walk::new(func_idx, i64::from(mode.word), scan);
    let mut falls_through = true;
    for &(pc, insn) in &insns {
        walk.enter(pc, falls_through, loop_heads.contains(&pc));
        falls_through = true;
        if let Some(t) = insn.mem_target {
            walk.scan.refs.push((t, pc, func_idx));
        }
        match insn.kind {
            x86::Kind::Lea { dst, target } => walk.write_reg(dst, Val::Addr { target, pc }),
            x86::Kind::MovImm { dst, value } => walk.write_reg(dst, Val::Imm(value)),
            x86::Kind::MovReg { dst, src } => walk.copy_reg(dst, src),
            x86::Kind::Store { mem, src, width } => {
                let val = match src {
                    _ if width != mode.word => Val::Unknown,
                    x86::Src::Reg(r) => walk.reg(r),
                    x86::Src::Imm(v) => Val::Imm(v),
                };
                let (base, disp) = match mem {
                    x86::Mem::Base { reg, index, disp } => (walk.base(reg, index), disp),
                    x86::Mem::Abs(a) => (Base::Abs, a as i64),
                    x86::Mem::Unknown => {
                        walk.forget_words();
                        continue;
                    }
                };
                if width == mode.word {
                    walk.store(base, disp, val, i64::from(mode.word));
                } else {
                    walk.clobber(base, disp, width as i64);
                }
            }
            x86::Kind::Call { target } => {
                if target.is_some_and(|t| ctx.write_barriers.contains(&t)) {
                    walk.write_reg(mode.wb_scratch, Val::Unknown);
                    continue;
                }
                if ctx.register_abi {
                    walk.register_pairs(&AMD64_ABI);
                    if target.is_some() && target == ctx.memequal {
                        walk.memequal_pair(&AMD64_ABI);
                    }
                }
                walk.call(x86::RSP);
            }
            x86::Kind::Jump {
                target,
                conditional,
            } => {
                if let Some(t) = target.filter(|&t| pc < t && t < end) {
                    if let (false, Some(tail)) = (conditional, tails.get(&t)) {
                        let saved = walk.state.clone();
                        for insn in tail {
                            walk.registers_only(insn.kind);
                        }
                        walk.register_pairs(&AMD64_ABI);
                        walk.state = saved;
                    }
                    walk.jump_to(t);
                }
                falls_through = conditional;
            }
            x86::Kind::Ret => {
                if ctx.register_abi {
                    walk.register_pairs(&AMD64_ABI);
                }
                falls_through = false;
            }
            x86::Kind::Stop => falls_through = false,
            x86::Kind::Other { writes, mem_write } => {
                for r in 0..16u8 {
                    if writes & (1 << r) != 0 {
                        walk.write_reg(r, Val::Unknown);
                    }
                }
                match mem_write {
                    None => (),
                    Some(x86::Mem::Base { reg, index, disp }) => {
                        let base = walk.base(reg, index);
                        walk.clobber(base, disp, 64);
                    }
                    Some(x86::Mem::Abs(a)) => walk.clobber(Base::Abs, a as i64, 64),
                    Some(x86::Mem::Unknown) => walk.forget_words(),
                }
            }
        }
    }
    walk.finish();
}

/// Integer argument and result registers of Go's arm64 register ABI, in
/// order.
const ARM64_ABI: [u8; 16] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];

/// R25, the register `runtime.gcWriteBarrier1` to `8` return the buffer
/// slot in on arm64; they save every other one.
const ARM64_WB_SCRATCH: u8 = 25;

fn scan_arm64(code: &[u8], entry: u64, func_idx: usize, ctx: &CodeCtx, scan: &mut Scan) {
    let insns: Vec<(u64, arm64::Kind)> = code
        .chunks_exact(4)
        .enumerate()
        .map(|(k, w)| {
            let pc = entry + 4 * k as u64;
            let word = u32::from_le_bytes([w[0], w[1], w[2], w[3]]);
            (pc, arm64::decode(word, pc))
        })
        .collect();
    let end = entry + code.len() as u64;
    let mut loop_heads = HashSet::new();
    for &(pc, kind) in &insns {
        if let arm64::Kind::Jump {
            target: Some(t), ..
        } = kind
        {
            if entry <= t && t <= pc {
                loop_heads.insert(t);
            }
        }
    }
    // Short tails that only restore the frame and return: a jump to one
    // returns what the result registers hold.
    let mut tails: HashMap<u64, Vec<arm64::Kind>> = HashMap::new();
    if ctx.register_abi {
        for &(pc, kind) in &insns {
            let arm64::Kind::Jump {
                target: Some(t),
                conditional: false,
            } = kind
            else {
                continue;
            };
            if t <= pc || t >= end || tails.contains_key(&t) {
                continue;
            }
            let start = ((t - entry) / 4) as usize;
            let mut tail = Vec::new();
            for &(_, next) in insns[start..].iter().take(8) {
                match next {
                    arm64::Kind::Ret => {
                        tails.insert(t, tail);
                        break;
                    }
                    arm64::Kind::MovReg { .. }
                    | arm64::Kind::MovImm { .. }
                    | arm64::Kind::AddImm { .. }
                    | arm64::Kind::Load { .. }
                    | arm64::Kind::Other { .. } => tail.push(next),
                    _ => break,
                }
            }
        }
    }

    let mut walk = Walk::new(func_idx, 8, scan);
    let mut falls_through = true;
    for &(pc, kind) in &insns {
        walk.enter(pc, falls_through, loop_heads.contains(&pc));
        falls_through = true;
        match kind {
            arm64::Kind::Store {
                base,
                offset,
                src,
                width,
                writeback,
            } => {
                let val = arm64_source(&walk, src);
                let base_key = walk.base(base, None);
                if width == 8 {
                    walk.store(base_key, offset, val, 8);
                } else {
                    walk.clobber(base_key, offset, width as i64);
                }
                if writeback {
                    walk.write_reg(base, Val::Unknown);
                }
            }
            arm64::Kind::StorePair {
                base,
                offset,
                first,
                second,
                writeback,
            } => {
                let (a, b) = (arm64_source(&walk, first), arm64_source(&walk, second));
                let base_key = walk.base(base, None);
                walk.store(base_key, offset, a, 8);
                walk.store(base_key, offset + 8, b, 8);
                if writeback {
                    walk.write_reg(base, Val::Unknown);
                }
            }
            arm64::Kind::Call { target } => {
                if target.is_some_and(|t| ctx.write_barriers.contains(&t)) {
                    walk.write_reg(ARM64_WB_SCRATCH, Val::Unknown);
                    continue;
                }
                if ctx.register_abi {
                    walk.register_pairs(&ARM64_ABI);
                    if target.is_some() && target == ctx.memequal {
                        walk.memequal_pair(&ARM64_ABI);
                    }
                }
                walk.call(arm64::SP);
            }
            arm64::Kind::Jump {
                target,
                conditional,
            } => {
                if let Some(t) = target.filter(|&t| pc < t && t < end) {
                    if let (false, Some(tail)) = (conditional, tails.get(&t)) {
                        let saved = walk.state.clone();
                        for &next in tail {
                            arm64_registers(&mut walk, pc, next);
                        }
                        walk.register_pairs(&ARM64_ABI);
                        walk.state = saved;
                    }
                    walk.jump_to(t);
                }
                falls_through = conditional;
            }
            arm64::Kind::Ret => {
                if ctx.register_abi {
                    walk.register_pairs(&ARM64_ABI);
                }
                falls_through = false;
            }
            arm64::Kind::Other {
                mem_base: Some(base),
                ..
            } => {
                let base_key = walk.base(base, None);
                walk.clobber(base_key, i64::MIN / 2, i64::MAX);
                arm64_registers(&mut walk, pc, kind);
            }
            _ => arm64_registers(&mut walk, pc, kind),
        }
    }
    walk.finish();
}

/// The value an arm64 store writes from register `src`, where 31 is the
/// zero register.
fn arm64_source(walk: &Walk<'_>, src: u8) -> Val {
    if src == 31 {
        Val::Imm(0)
    } else {
        walk.reg(src)
    }
}

/// The register effect of an arm64 instruction that is not a store or a
/// branch. A completed address is also recorded as a reference.
fn arm64_registers(walk: &mut Walk<'_>, pc: u64, kind: arm64::Kind) {
    match kind {
        arm64::Kind::Addr { dst, target } => walk.write_reg(dst, Val::Addr { target, pc }),
        arm64::Kind::AddImm { dst, src, imm } => {
            let val = match (src, walk.reg(src)) {
                (arm64::SP, _) => Val::Unknown,
                (_, Val::Addr { target, pc: at }) => {
                    let target = target.wrapping_add(imm);
                    walk.scan.refs.push((target, at, walk.func_idx));
                    Val::Addr { target, pc: at }
                }
                (_, Val::Imm(v)) => Val::Imm(v.wrapping_add(imm)),
                (_, Val::Unknown) => Val::Unknown,
            };
            walk.write_reg(dst, val);
        }
        arm64::Kind::MovImm { dst, value } => walk.write_reg(dst, Val::Imm(value)),
        arm64::Kind::MovK {
            dst,
            shift,
            imm,
            wide,
        } => {
            let val = match walk.reg(dst) {
                Val::Imm(v) => {
                    let v = (v & !(0xffff << shift)) | (imm << shift);
                    Val::Imm(if wide { v } else { v & 0xffff_ffff })
                }
                _ => Val::Unknown,
            };
            walk.write_reg(dst, val);
        }
        arm64::Kind::MovReg { dst, src } => walk.copy_reg(dst, src),
        arm64::Kind::Load { dst, base, offset } => {
            if let Val::Addr { target, pc: at } = walk.reg(base) {
                walk.scan
                    .refs
                    .push((target.wrapping_add(offset as u64), at, walk.func_idx));
            }
            walk.write_reg(dst, Val::Unknown);
        }
        arm64::Kind::Other { writes, .. } => {
            for r in 0..32u8 {
                if writes & (1 << r) != 0 {
                    walk.write_reg(r, Val::Unknown);
                }
            }
        }
        _ => (),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx(write_barriers: &[u64]) -> CodeCtx {
        CodeCtx {
            register_abi: true,
            write_barriers: write_barriers.iter().copied().collect(),
            memequal: None,
        }
    }

    fn pairs(scan: &Scan) -> Vec<(u64, u64, u64, Site)> {
        scan.pairs
            .iter()
            .map(|p| (p.ptr, p.len, p.pc, p.site))
            .collect()
    }

    #[test]
    fn amd64_call_pairs_consecutive_argument_registers() {
        let code = [
            0x48, 0x8d, 0x05, 0x00, 0x01, 0x00, 0x00, // LEAQ 0x100(IP), AX
            0xbb, 0x05, 0x00, 0x00, 0x00, // MOVL $5, BX
            0xe8, 0x00, 0x00, 0x00, 0x00, // CALL
            0xc3, // RET
        ];
        let mut scan = Scan::default();
        scan_x86(&code, 0x1000, 0, &ctx(&[]), &AMD64, &mut scan);
        assert_eq!(pairs(&scan), vec![(0x1107, 5, 0x1000, Site::Registers)]);
    }

    #[test]
    fn amd64_registers_set_before_a_join_are_not_arguments() {
        let code = [
            0x48, 0x8d, 0x05, 0x00, 0x01, 0x00, 0x00, // LEAQ 0x100(IP), AX
            0xbb, 0x05, 0x00, 0x00, 0x00, // MOVL $5, BX
            0x74, 0x00, // JEQ to the next instruction
            0xe8, 0x00, 0x00, 0x00, 0x00, // CALL
        ];
        let mut scan = Scan::default();
        scan_x86(&code, 0x1000, 0, &ctx(&[]), &AMD64, &mut scan);
        assert_eq!(pairs(&scan), vec![], "the call starts a new block");
    }

    #[test]
    fn amd64_store_pair_survives_a_write_barrier_check() {
        // MOVQ $21, 8(AX); CMPL wb(SB), $0; JEQ done; CALL gcWriteBarrier1;
        // done: LEAQ lit(SB), CX; MOVQ CX, (AX); RET
        let code = [
            0x48, 0xc7, 0x40, 0x08, 0x15, 0x00, 0x00, 0x00, // 0x1000
            0x83, 0x3d, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x1008
            0x74, 0x05, // 0x100f
            0xe8, 0x00, 0x10, 0x00, 0x00, // 0x1011, calls 0x2016
            0x48, 0x8d, 0x0d, 0x00, 0x02, 0x00, 0x00, // 0x1016
            0x48, 0x89, 0x08, // 0x101d
            0xc3,
        ];
        let mut scan = Scan::default();
        scan_x86(&code, 0x1000, 0, &ctx(&[0x2016]), &AMD64, &mut scan);
        assert_eq!(pairs(&scan), vec![(0x121d, 21, 0x1016, Site::Store)]);

        // Any other call may write the memory, so nothing pairs across it.
        let mut scan = Scan::default();
        scan_x86(&code, 0x1000, 0, &ctx(&[]), &AMD64, &mut scan);
        assert_eq!(pairs(&scan), vec![]);
    }

    #[test]
    fn i386_stack_argument_words_pair() {
        let code = [
            0x8d, 0x05, 0x00, 0x20, 0x00, 0x08, // LEAL lit(SB), AX
            0x89, 0x04, 0x24, // MOVL AX, 0(SP)
            0xc7, 0x44, 0x24, 0x04, 0x05, 0x00, 0x00, 0x00, // MOVL $5, 4(SP)
            0xe8, 0x00, 0x00, 0x00, 0x00, // CALL
            0xc3, // RET
        ];
        let mut ctx = ctx(&[]);
        ctx.register_abi = false;
        let mut scan = Scan::default();
        scan_x86(&code, 0x1000, 0, &ctx, &I386, &mut scan);
        assert_eq!(
            pairs(&scan),
            vec![(0x0800_2000, 5, 0x1000, Site::Store)],
            "a 4-byte store beside a 4-byte word leaves it standing"
        );
    }

    fn arm64_code(words: &[u32]) -> Vec<u8> {
        words.iter().flat_map(|w| w.to_le_bytes()).collect()
    }

    #[test]
    fn arm64_call_pairs_adrp_add_with_a_constant() {
        let code = arm64_code(&[
            0x9000_0000, // ADRP X0, page
            0x9104_8c00, // ADD X0, X0, #0x123
            0xb27e_0be1, // ORR X1, XZR, #28
            0x9400_0002, // BL
            0xd65f_03c0, // RET
        ]);
        let mut scan = Scan::default();
        scan_arm64(&code, 0x10000, 0, &ctx(&[]), &mut scan);
        assert_eq!(pairs(&scan), vec![(0x10123, 28, 0x10000, Site::Registers)]);
    }

    #[test]
    fn arm64_stp_stores_a_header() {
        let code = arm64_code(&[
            0x9000_0001, // ADRP X1, page
            0x9104_8c21, // ADD X1, X1, #0x123
            0xd280_01c2, // MOVZ X2, #14
            0xa900_0801, // STP X1, X2, [X0]
            0xd65f_03c0, // RET
        ]);
        let mut scan = Scan::default();
        let mut ctx = ctx(&[]);
        ctx.register_abi = false;
        scan_arm64(&code, 0x10000, 0, &ctx, &mut scan);
        assert_eq!(pairs(&scan), vec![(0x10123, 14, 0x10000, Site::Store)]);
    }

    #[test]
    fn table_spine_stops_where_packing_breaks() {
        // A buffer right after the table pairs with a length longer than the
        // table's last literal, which the gap before it cannot hold.
        let extents = [(0x100, 1), (0x101, 2), (0x103, 30), (0x130, 4000)];
        let table = Table::new(extents.into_iter(), None);
        assert_eq!(table.span(), Some((0x100, 0x121)));
        let accepted = table.accept(extents.into_iter());
        assert!(!accepted.contains(&(0x130, 4000)));
        assert_eq!(accepted.len(), 3);
    }

    #[test]
    fn table_holds_fewer_than_256_one_byte_literals() {
        // A one-byte pair far below the table (a type passed with a count of
        // one) does not join it.
        let extents = [(0x10, 1), (0x10000, 1), (0x10001, 1), (0x10002, 2)];
        let table = Table::new(extents.into_iter(), None);
        assert_eq!(table.span(), Some((0x10000, 0x10004)));
    }

    #[test]
    fn candidates_must_keep_order_and_not_overlap() {
        let spine = [(0, 1), (1, 2), (3, 5), (20, 9)];
        let table = Table::new(spine.into_iter(), None);
        assert_eq!(table.span(), Some((0, 29)));
        let accepted = table.accept([(8, 4), (8, 5), (8, 6), (3, 2), (30, 9)].into_iter());
        assert!(
            !accepted.contains(&(8, 4)),
            "shorter than the literal before it"
        );
        assert!(!accepted.contains(&(3, 2)), "a spine literal starts there");
        assert!(
            !accepted.contains(&(30, 9)),
            "past the last literal the code proves"
        );
        assert!(
            !accepted.contains(&(8, 5)) && !accepted.contains(&(8, 6)),
            "two lengths at one address cannot both be right"
        );
        assert!(table.accept([(8, 6)].into_iter()).contains(&(8, 6)));
    }

    #[test]
    fn packed_gaps_hold_at_least_one_literal() {
        assert!(packed((0, 4), (4, 4)), "back to back");
        assert!(
            !packed((0, 4), (6, 4)),
            "a two-byte gap holds no literal of four"
        );
        assert!(packed((0, 4), (8, 5)));
        assert!(!packed((0, 4), (2, 4)), "overlap");
    }
}
