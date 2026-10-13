//! Function-signature recovery for stripped Go binaries.
//!
//! The recoverable signal in a stripped binary comes from method tables,
//! not from a per-function signature record. The runtime stores method
//! tables in two places, and this module walks both:
//!
//!   1. `_type.uncommon().methods` for every defined type that has methods.
//!      Each entry carries the method's name, its mtyp (a TypeOff pointing
//!      at a funcType), and the entry PCs (ifn for interface dispatch, tfn
//!      for direct calls). See `recover_methods_from_types`.
//!
//!   2. Itab method tables. Same shape, attached per (interface, concrete)
//!      pair instead of per defined type. See `recover_methods_from_itabs`.
//!
//! The two sources overlap. Use `merge_methods` to combine them and
//! deduplicate by `(receiver, name, tfn_pc)`. Use `render_method_signature`
//! to turn each method's mtyp into a Go-syntax signature like
//! `"(_0 []uint8) (int, error)"`, and `signatures_by_pc` to build a
//! `HashMap<PC, signature>` that callers can look up by function entry PC.
//!
//! Free top-level functions do not appear in either table. The compiler
//! emits no per-function signature record for them. For stripped binaries,
//! their signatures are unrecoverable without DWARF.
//!
//! # Layout reference
//!
//! `internal/abi/type.go` in Go's source tree. Method (16 bytes), four
//! 4-byte offsets:
//!
//! ```text
//!   offset 0   Name NameOff   // resolves via md.types + nameOff
//!   offset 4   Mtyp TypeOff   // resolves via md.types + typeOff to a funcType
//!   offset 8   Ifn  TextOff   // resolves via md.text + textOff to the iface wrapper
//!   offset 12  Tfn  TextOff   // resolves via md.text + textOff to the direct-call body
//! ```
//!
//! UncommonType (16 bytes):
//!
//! ```text
//!   offset 0   PkgPath NameOff
//!   offset 4   Mcount  u16     // total methods
//!   offset 6   Xcount  u16     // exported methods
//!   offset 8   Moff    u32     // offset from this UncommonType to [Mcount]Method
//!   offset 12  _       u32     // unused padding
//! ```
//!
//! UncommonType sits at `type_addr + TYPE_HEADER_SIZE + kind_extension_size`,
//! i.e. right after the kind's whole `XxxType` struct *including its trailing
//! alignment padding* (`abi.Type.Uncommon` declares `struct { XxxType; u
//! UncommonType }`). The kind-extension size is per-kind and known statically
//! on 64-bit, except for maps, whose `MapType` changed shape in Go 1.24 (see
//! `map_extension_size`).
//!
//! Text offsets (Ifn/Tfn) resolve through `ModuleData::text_addr`, which
//! follows `textsectmap` the way the runtime's `moduledata.textAddr` does
//! when the linker split the text into several sections.

use std::collections::HashMap;

use serde::Serialize;

use crate::error::Error;
use crate::gobin::GoBinary;
use crate::moduledata::ModuleData;
use crate::types::{
    parse_type, read_name_public, KindData, KindName, Type, TFLAG_UNCOMMON, TYPE_HEADER_SIZE_64,
};
use crate::Result;

const METHOD_SIZE: usize = 16;
const UNCOMMON_TYPE_SIZE: usize = 16;

/// One recovered method from a `_type.uncommon().methods` table.
#[derive(Debug, Clone, Serialize)]
pub struct RecoveredMethod {
    /// Receiver type name (the type that owns this method).
    pub receiver: String,
    /// Method name. Empty if the name offset did not resolve.
    pub name: String,
    /// Absolute address of the funcType describing the method's signature
    /// (parameters and returns, without the receiver). Zero if Mtyp was -1.
    pub mtyp_addr: u64,
    /// Entry PC for the interface-dispatch wrapper. Zero if Ifn was -1.
    pub ifn_pc: u64,
    /// Entry PC for the direct-call method body. Zero if Tfn was -1.
    pub tfn_pc: u64,
}

/// Walk every type's uncommon methods table and return all recovered methods.
///
/// Each input type is processed best-effort: a malformed UncommonType or
/// out-of-bounds method-array read drops that type's methods and continues
/// with the next type. Sane caps on Mcount prevent attacker-crafted records
/// from triggering a huge allocation.
pub fn recover_methods_from_types(
    bin: &GoBinary,
    md: &ModuleData,
    types: &[Type],
) -> Vec<RecoveredMethod> {
    let mut out = Vec::new();
    for t in types {
        if t.tflag & TFLAG_UNCOMMON == 0 {
            continue;
        }
        match methods_for_type(bin, md, t) {
            Ok(methods) => out.extend(methods),
            Err(_) => {
                // Malformed uncommon block; skip. We deliberately do not
                // surface the error: per-type recovery is best-effort and
                // one bad type should not abort the whole pass.
            }
        }
    }
    out
}

/// Walk every itab and surface its per-slot dispatch as RecoveredMethod
/// records. The interface side supplies the method signature (funcType
/// address from `InterfaceMethod.typ`); the itab side supplies the
/// concrete entry PC (`ItabMethod.concrete_fn`). Together they form a
/// recovered method whose receiver is the concrete type and whose mtyp
/// points at the interface-declared funcType.
///
/// This complements `recover_methods_from_types`: the uncommon path
/// reaches methods that have a `_type.uncommon()` entry; the itab path
/// reaches the wrapper methods that implement interfaces, which are
/// often a different set.
pub fn recover_methods_from_itabs(
    types: &[Type],
    itabs: &[crate::itabs::Itab],
) -> Vec<RecoveredMethod> {
    // Index interface types by name so we can look up each itab's
    // interface declaration in O(1). The runtime stores the InterfaceType
    // extension on the bare interface type (`io.Reader`), but itablinks
    // records the interface column as the pointer-to-interface type
    // (`*io.Reader`). Map both spellings to the same record so an itab
    // lookup hits whichever form the recovered_types set carries.
    let mut iface_by_name: HashMap<String, &Type> = HashMap::new();
    for t in types
        .iter()
        .filter(|t| matches!(t.kind, KindName::Interface))
    {
        iface_by_name.insert(t.name.clone(), t);
        iface_by_name.insert(format!("*{}", t.name), t);
    }

    let mut out = Vec::new();
    for itab in itabs {
        // Try the as-recorded name first, then strip a leading `*` and
        // retry. The stripping handles the common `*main.Cipher` -> bare
        // `main.Cipher` mapping when only the bare interface type is in
        // the recovered set.
        let iface_t = iface_by_name
            .get(&itab.interface_name)
            .copied()
            .or_else(|| {
                itab.interface_name
                    .strip_prefix('*')
                    .and_then(|bare| iface_by_name.get(bare).copied())
            });
        let Some(iface_t) = iface_t else {
            // Interface type not in the recovered set. Some itabs reference
            // interfaces whose declarations live outside the typelinks walk;
            // skip them rather than fabricate signatures.
            continue;
        };
        let iface_methods = match &iface_t.kind_data {
            KindData::Interface { methods } => methods,
            _ => continue,
        };

        // Slot-by-slot merge. The runtime invariant: itab.methods is
        // declared in the same order as the interface's Methods slice
        // (sorted by hash by Go's linker). If the two lengths differ,
        // the itab is incomplete; merge what we have and drop the rest.
        for (slot_idx, slot) in itab.methods.iter().enumerate() {
            if slot.concrete_fn == 0 {
                continue;
            }
            let Some(iface_method) = iface_methods.get(slot_idx) else {
                continue;
            };
            out.push(RecoveredMethod {
                receiver: itab.concrete_name.clone(),
                name: slot.interface_method.clone(),
                mtyp_addr: iface_method.typ,
                ifn_pc: 0,
                tfn_pc: slot.concrete_fn,
            });
        }
    }
    out
}

/// Merge two RecoveredMethod sources into a single deduplicated list.
/// A method is identified by its (receiver, name, tfn_pc) triple: two
/// recoveries that agree on those three fields are the same method
/// reached by different paths. The first occurrence wins. Records with
/// tfn_pc == 0 are kept (no PC means no way to dedupe; they survive on
/// their own merits and may still carry a valid mtyp).
pub fn merge_methods(a: Vec<RecoveredMethod>, b: Vec<RecoveredMethod>) -> Vec<RecoveredMethod> {
    use std::collections::HashSet;
    let mut seen: HashSet<(String, String, u64)> = HashSet::new();
    let mut out = Vec::with_capacity(a.len() + b.len());
    for m in a.into_iter().chain(b) {
        if m.tfn_pc == 0 {
            out.push(m);
            continue;
        }
        let key = (m.receiver.clone(), m.name.clone(), m.tfn_pc);
        if seen.insert(key) {
            out.push(m);
        }
    }
    out
}

/// Recover the methods table for a single type. Returns Ok(empty) if the
/// type has TFlagUncommon but Mcount == 0 (rare but valid).
pub fn methods_for_type(bin: &GoBinary, md: &ModuleData, t: &Type) -> Result<Vec<RecoveredMethod>> {
    if t.tflag & TFLAG_UNCOMMON == 0 {
        return Ok(Vec::new());
    }

    let extra_size = match t.kind {
        KindName::Map => map_extension_size(bin, md, t.addr),
        kind => kind_extension_size(kind),
    }
    .ok_or_else(|| {
        Error::TypeRecovery(format!(
            "kind {:?} has no known extension size; cannot locate uncommon block (type {})",
            t.kind, t.name
        ))
    })?;

    let uncommon_addr = t.addr + TYPE_HEADER_SIZE_64 as u64 + extra_size as u64;

    let header = bin
        .read_at_addr(uncommon_addr, UNCOMMON_TYPE_SIZE)
        .ok_or_else(|| {
            Error::TypeRecovery(format!(
                "uncommon header at 0x{uncommon_addr:x} unmapped (type {})",
                t.name
            ))
        })?;

    // PkgPath NameOff at offset 0 (4 bytes, signed). Currently unused; we
    // already have the receiver name from t.name.
    let _pkg_path_off = i32::from_le_bytes(header[0..4].try_into().unwrap());
    let mcount = u16::from_le_bytes(header[4..6].try_into().unwrap());
    let _xcount = u16::from_le_bytes(header[6..8].try_into().unwrap());
    let moff = u32::from_le_bytes(header[8..12].try_into().unwrap());

    if mcount == 0 {
        return Ok(Vec::new());
    }

    // Sanity cap: a real Go type has at most a few dozen methods. 4096 is a
    // hard ceiling that prevents an attacker-crafted UncommonType from
    // triggering a multi-megabyte read.
    const MAX_METHODS: u16 = 4096;
    if mcount > MAX_METHODS {
        return Err(Error::TypeRecovery(format!(
            "method count {mcount} unreasonably large for type {}",
            t.name
        )));
    }

    let methods_array_addr = uncommon_addr + moff as u64;
    let total = mcount as usize * METHOD_SIZE;
    let buf = bin.read_at_addr(methods_array_addr, total).ok_or_else(|| {
        Error::TypeRecovery(format!(
            "methods array at 0x{methods_array_addr:x} ({total} bytes) unmapped (type {})",
            t.name
        ))
    })?;

    let mut out = Vec::with_capacity(mcount as usize);
    for i in 0..mcount as usize {
        let off = i * METHOD_SIZE;
        let name_off = i32::from_le_bytes(buf[off..off + 4].try_into().unwrap());
        let mtyp_off = i32::from_le_bytes(buf[off + 4..off + 8].try_into().unwrap());
        let ifn_off = i32::from_le_bytes(buf[off + 8..off + 12].try_into().unwrap());
        let tfn_off = i32::from_le_bytes(buf[off + 12..off + 16].try_into().unwrap());

        // A real method table names every method, live or dead (the linker
        // only blanks Mtyp/Ifn/Tfn), so a missing name means this is not a
        // method table at all: a misplaced UncommonType, or a false-positive
        // type from a linear scan. Reject the whole type rather than emit
        // nameless methods with made-up PCs.
        let reject = |what: &str| {
            Error::TypeRecovery(format!(
                "method {i} of type {} has {what}; not a method table",
                t.name
            ))
        };
        let name = (name_off >= 0)
            .then(|| read_name_public(bin, md, md.types.wrapping_add(name_off as u64)).ok())
            .flatten()
            .filter(|n| !n.is_empty())
            .ok_or_else(|| reject("no name"))?;

        // -1 is the linker's sentinel for a method part dead code removed
        // (the runtime maps a -1 text offset to `unreachableMethod`); any
        // other negative offset, or one landing outside its region, is junk.
        let mtyp_addr = match mtyp_off {
            -1 => 0,
            o if o >= 0 && md.types.wrapping_add(o as u64) < md.etypes => {
                md.types.wrapping_add(o as u64)
            }
            _ => return Err(reject("a method type outside the types region")),
        };
        let text_pc = |off: i32| match off {
            -1 => Some(0),
            o if o >= 0 => md
                .text_addr(bin, o as u32)
                .filter(|&pc| pc >= md.text && pc < md.etext),
            _ => None,
        };
        let ifn_pc = text_pc(ifn_off).ok_or_else(|| reject("an Ifn outside the text"))?;
        let tfn_pc = text_pc(tfn_off).ok_or_else(|| reject("a Tfn outside the text"))?;

        out.push(RecoveredMethod {
            receiver: t.name.clone(),
            name,
            mtyp_addr,
            ifn_pc,
            tfn_pc,
        });
    }

    Ok(out)
}

/// Size in bytes of the kind-specific extension that sits between the
/// `_type` header and the UncommonType block, on 64-bit.
///
/// Returns None for Map (its layout is decided per record by
/// `map_extension_size`) and for unknown kinds. A None here means we cannot
/// safely compute the UncommonType address and must skip the type rather
/// than read random bytes.
///
/// The values come from the Go struct definitions in `internal/abi/type.go`
/// (and `runtime/type.go` before 1.21; the shapes are identical back to
/// 1.17). Each is `unsafe.Sizeof(XxxType{}) - unsafe.Sizeof(Type{})`, so the
/// trailing alignment padding counts. Slice headers are 24 bytes (data, len,
/// cap); `Name` is a one-pointer wrapper around a byte slice in the names
/// blob.
fn kind_extension_size(kind: KindName) -> Option<usize> {
    match kind {
        // Primitives have no extension; UncommonType sits directly after
        // the type header.
        KindName::Bool
        | KindName::Int
        | KindName::Int8
        | KindName::Int16
        | KindName::Int32
        | KindName::Int64
        | KindName::Uint
        | KindName::Uint8
        | KindName::Uint16
        | KindName::Uint32
        | KindName::Uint64
        | KindName::Uintptr
        | KindName::Float32
        | KindName::Float64
        | KindName::Complex64
        | KindName::Complex128
        | KindName::String
        | KindName::UnsafePointer => Some(0),

        // Pointer / Slice: one *Type element pointer.
        KindName::Pointer | KindName::Slice => Some(8),

        // Array: elem *Type + slice *Type + len uintptr.
        KindName::Array => Some(24),

        // Chan: elem *Type + dir uintptr.
        KindName::Chan => Some(16),

        // Func: InCount u16 + OutCount u16 = 4 bytes, but FuncType embeds
        // the pointer-aligned Type header, so Sizeof(FuncType) rounds 52 up
        // to 56 and the UncommonType starts 8 bytes after the header, not 4.
        // (Reading at +4 decodes the real PkgPath NameOff as Mcount/Xcount
        // and the real Mcount/Xcount as Moff: thousands of junk methods per
        // binary once Go 1.23's `iter.Seq[...]` named func types appear.)
        // The parameter array is laid out AFTER the UncommonType, so it does
        // not contribute here; `types::decode_func` uses the same 8.
        KindName::Func => Some(8),

        // Struct: PkgPath Name (8) + Fields slice header (24).
        KindName::Struct => Some(32),

        // Interface: PkgPath Name (8) + Methods slice header (24).
        KindName::Interface => Some(32),

        // Map: the layout depends on the map implementation the binary was
        // built with, which only the type data itself can tell; see
        // `map_extension_size`.
        KindName::Map => None,

        // Unknown / Invalid: refuse rather than guess.
        KindName::Invalid | KindName::Unknown(_) => None,
    }
}

/// `MapType` extension size before Go 1.24 (and under 1.24/1.25's
/// `GOEXPERIMENT=noswissmap`): Key, Elem, Bucket, Hasher (4 pointers), then
/// KeySize u8, ValueSize u8, BucketSize u16, Flags u32.
const OLD_MAP_EXTENSION_SIZE: usize = 40;
/// Swiss-table `MapType` extension size (Go 1.24+ default, the only map in
/// 1.26): Key, Elem, Group, Hasher (4 pointers), GroupSize, SlotSize, ElemOff
/// (3 uintptrs), Flags u32, padded to 8 = 64.
const SWISS_MAP_EXTENSION_SIZE: usize = 64;

/// Extension size of the `MapType` at `type_addr`, decided from the record
/// itself rather than from a version guess. Both layouts keep the bucket/group
/// `*Type` at +16 and the hasher at +24, and both repeat that type's size right
/// after: the swiss layout as `GroupSize uintptr` at +32, the old layout as
/// `BucketSize uint16` at +34. The two checks are mutually exclusive for any
/// real map (a non-zero `BucketSize` at +34 makes the u64 at +32 at least
/// 65536, larger than any bucket; a group under 64 KiB has zero bytes at +34),
/// so exactly one of them matches. `None` when neither does.
fn map_extension_size(bin: &GoBinary, md: &ModuleData, type_addr: u64) -> Option<usize> {
    let ext = bin.read_at_addr(type_addr + TYPE_HEADER_SIZE_64 as u64, 40)?;
    let group = u64::from_le_bytes(ext[16..24].try_into().ok()?);
    if group < md.types || group >= md.etypes {
        return None;
    }
    let group_size = u64::from_le_bytes(bin.read_at_addr(group, 8)?.try_into().ok()?);
    map_extension_size_from(ext, group_size)
}

/// Pure part of `map_extension_size`: classify the first 40 bytes of a
/// `MapType` extension against the size of its bucket/group type.
fn map_extension_size_from(ext: &[u8], group_size: u64) -> Option<usize> {
    if group_size == 0 || ext.len() < 40 {
        return None;
    }
    let swiss_group_size = u64::from_le_bytes(ext[32..40].try_into().ok()?);
    let old_bucket_size = u16::from_le_bytes(ext[34..36].try_into().ok()?) as u64;
    match (
        swiss_group_size == group_size,
        old_bucket_size == group_size,
    ) {
        (true, false) => Some(SWISS_MAP_EXTENSION_SIZE),
        (false, true) => Some(OLD_MAP_EXTENSION_SIZE),
        _ => None,
    }
}

/// Build a PC -> signature map for every method whose signature renders.
/// The map is keyed by `tfn_pc` (the direct-call method body entry); the
/// value is the rendered signature string (e.g. `"(_0 []uint8) (int, error)"`).
///
/// Methods with `tfn_pc == 0` (iface-only wrappers with no direct-call
/// body) are not included since there is no PC to attach the signature to.
/// Methods whose mtyp does not render are also skipped.
///
/// Caller pattern: pass the full method set (uncommon + itab, deduped via
/// `merge_methods`) plus a TypeCache. The returned map is the lookup that
/// every output path uses to attach `(...) returns` to a function name.
pub fn signatures_by_pc(
    methods: &[RecoveredMethod],
    cache: &mut TypeCache<'_>,
) -> HashMap<u64, String> {
    let mut out = HashMap::with_capacity(methods.len());
    for m in methods {
        if m.tfn_pc == 0 {
            continue;
        }
        if let Some(sig) = render_method_signature(m, cache) {
            // First writer wins. Multiple methods can share a tfn_pc when
            // the compiler emits one body for several iface wrappers; the
            // first rendered signature is the canonical one.
            out.entry(m.tfn_pc).or_insert(sig);
        }
    }
    out
}

/// Type-by-address cache. Parsing the same `_type` record N times for N
/// methods that mention it is wasteful; a thin lookup cache amortizes that
/// across a whole binary's signature rendering pass.
///
/// Entries are computed lazily on first lookup. A failed parse caches `None`
/// so we don't repeatedly chase a bad address.
pub struct TypeCache<'a> {
    bin: &'a GoBinary,
    md: &'a ModuleData,
    cache: HashMap<u64, Option<Type>>,
}

impl<'a> TypeCache<'a> {
    pub fn new(bin: &'a GoBinary, md: &'a ModuleData) -> Self {
        Self {
            bin,
            md,
            cache: HashMap::new(),
        }
    }

    /// Seed the cache from an already-recovered `Vec<Type>`. Useful when the
    /// caller has run `types::recover_all` and wants to avoid re-parsing
    /// every named type the funcType walk will encounter.
    pub fn seed_from(&mut self, types: &[Type]) {
        for t in types {
            self.cache.entry(t.addr).or_insert_with(|| Some(t.clone()));
        }
    }

    /// Resolve an address to its parsed `Type`. Returns `None` when the
    /// address is zero (no type recorded) or when parsing fails.
    pub fn get(&mut self, addr: u64) -> Option<&Type> {
        if addr == 0 {
            return None;
        }
        if !self.cache.contains_key(&addr) {
            let parsed = parse_type(self.bin, self.md, addr).ok();
            self.cache.insert(addr, parsed);
        }
        self.cache.get(&addr).and_then(|v| v.as_ref())
    }
}

/// Render a Go-syntax signature for a method by walking its mtyp funcType.
///
/// Returns `None` when any of the following holds:
///   * `method.mtyp_addr` is zero (the runtime did not record a method type).
///   * The mtyp address does not parse as a `_type`.
///   * The parsed type is not a `Func` kind.
///   * Any of the parameter or return type addresses fails to resolve.
///
/// A successful return is a string like `"(p []byte) (n int, err error)"`.
/// Argument names are NOT in the binary; we emit positional placeholders
/// (`_0`, `_1`, ...) to keep the shape correct. Single unnamed return
/// renders without parentheses (`"() error"` not `"() (error)"`), matching
/// gofmt's convention for single results.
///
/// Limitations today:
///   * Variadic functions render `...T` for the last parameter.
///   * Generic functions render the shape; the type parameter bracket
///     (`[T any]`) is not reconstructed.
///   * Aggregate parameters (struct, interface) render by the type's own
///     name when it has one. Truly anonymous structs fall back to `struct{...}`.
pub fn render_method_signature(
    method: &RecoveredMethod,
    cache: &mut TypeCache<'_>,
) -> Option<String> {
    if method.mtyp_addr == 0 {
        return None;
    }
    let mtyp = cache.get(method.mtyp_addr)?.clone();
    let (in_types, out_types, variadic) = match &mtyp.kind_data {
        KindData::Func {
            in_types,
            out_types,
            variadic,
            ..
        } => (in_types.clone(), out_types.clone(), *variadic),
        _ => return None,
    };

    // Render parameters: (_0 T0, _1 T1, ...)
    let mut params = String::from("(");
    for (i, &addr) in in_types.iter().enumerate() {
        if i > 0 {
            params.push_str(", ");
        }
        let name = render_type_name(addr, cache);
        let is_last = i + 1 == in_types.len();
        if variadic && is_last {
            // The last parameter of a variadic is encoded as []T in the
            // funcType; render it as ...T to match Go source syntax. The
            // recovered name will start with "[]" for the slice; strip it
            // and prefix with "..." for the user-facing form.
            let elem = name.strip_prefix("[]").unwrap_or(&name).to_string();
            params.push_str(&format!("_{i} ...{elem}"));
        } else {
            params.push_str(&format!("_{i} {name}"));
        }
    }
    params.push(')');

    // Render returns. Go convention: 0 returns -> empty; 1 unnamed return
    // -> bare type without parens; N returns or any named return -> parens.
    let returns = match out_types.len() {
        0 => String::new(),
        1 => format!(" {}", render_type_name(out_types[0], cache)),
        _ => {
            let mut s = String::from(" (");
            for (i, &addr) in out_types.iter().enumerate() {
                if i > 0 {
                    s.push_str(", ");
                }
                s.push_str(&render_type_name(addr, cache));
            }
            s.push(')');
            s
        }
    };

    Some(format!("{params}{returns}"))
}

/// Resolve a `_type` address to a printable Go type name. The compiler
/// stores the human-readable form (`*http.Request`, `[]byte`, `map[string]int`)
/// directly in the names blob at `_type.Str`, so for any type with a non-
/// empty name we return it verbatim. The fallback for unnamed types or
/// failed lookups is `<addr>` so the surrounding output stays readable.
fn render_type_name(addr: u64, cache: &mut TypeCache<'_>) -> String {
    if addr == 0 {
        return "<nil>".to_string();
    }
    match cache.get(addr) {
        Some(t) if !t.name.is_empty() => t.name.clone(),
        Some(_) => format!("type@0x{addr:x}"),
        None => format!("type@0x{addr:x}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `unsafe.Sizeof(XxxType{}) - unsafe.Sizeof(Type{})` on 64-bit: the
    /// kind fields after the 48-byte header, with the struct rounded up to
    /// its 8-byte alignment (it embeds pointers via `Type`).
    fn go_extension(field_bytes: usize) -> usize {
        (TYPE_HEADER_SIZE_64 + field_bytes).next_multiple_of(8) - TYPE_HEADER_SIZE_64
    }

    #[test]
    fn kind_extension_sizes_match_go_layout() {
        // Each value is derived from the Go struct, not restated: a kind
        // whose layout changes upstream should fail here rather than
        // silently miscompute uncommon block addresses.
        assert_eq!(
            kind_extension_size(KindName::Pointer),
            Some(go_extension(8))
        );
        assert_eq!(kind_extension_size(KindName::Slice), Some(go_extension(8)));
        assert_eq!(kind_extension_size(KindName::Array), Some(go_extension(24)));
        assert_eq!(kind_extension_size(KindName::Chan), Some(go_extension(16)));
        assert_eq!(
            kind_extension_size(KindName::Struct),
            Some(go_extension(32))
        );
        assert_eq!(
            kind_extension_size(KindName::Interface),
            Some(go_extension(32))
        );
        assert_eq!(kind_extension_size(KindName::Map), None);
        assert_eq!(kind_extension_size(KindName::Bool), Some(0));
        assert_eq!(kind_extension_size(KindName::String), Some(0));
        assert_eq!(OLD_MAP_EXTENSION_SIZE, go_extension(4 * 8 + 1 + 1 + 2 + 4));
        assert_eq!(SWISS_MAP_EXTENSION_SIZE, go_extension(7 * 8 + 4));
    }

    #[test]
    fn func_uncommon_block_follows_padded_functype() {
        // FuncType is Type + InCount u16 + OutCount u16 = 52 bytes, padded
        // to 56. The UncommonType therefore starts 8 bytes after the header,
        // not 4. Reading at +4 was the Go 1.23+ regression: the real PkgPath
        // NameOff was decoded as Mcount/Xcount, yielding thousands of
        // nameless methods with wild PCs on every `iter.Seq[...]` type.
        assert_eq!(kind_extension_size(KindName::Func), Some(go_extension(4)));
        assert_eq!(kind_extension_size(KindName::Func), Some(8));
    }

    /// First 40 bytes of a MapType extension: Key, Elem, Group/Bucket,
    /// Hasher, then the layout-specific tail.
    fn map_ext(tail: [u8; 8]) -> Vec<u8> {
        let mut b = Vec::new();
        for p in [0x1000u64, 0x2000, 0x3000, 0x4000] {
            b.extend_from_slice(&p.to_le_bytes());
        }
        b.extend_from_slice(&tail);
        b
    }

    #[test]
    fn map_extension_size_tells_swiss_from_old_by_group_size() {
        // Swiss (Go 1.24+): GroupSize uintptr at +32 repeats the group type's size.
        let swiss = map_ext(200u64.to_le_bytes());
        assert_eq!(
            map_extension_size_from(&swiss, 200),
            Some(SWISS_MAP_EXTENSION_SIZE)
        );
        // Old hmap (<= 1.23): KeySize 16, ValueSize 8, BucketSize 208, Flags 0.
        let mut tail = [0u8; 8];
        tail[0] = 16;
        tail[1] = 8;
        tail[2..4].copy_from_slice(&208u16.to_le_bytes());
        let old = map_ext(tail);
        assert_eq!(
            map_extension_size_from(&old, 208),
            Some(OLD_MAP_EXTENSION_SIZE)
        );
        // Neither matches: refuse rather than guess.
        assert_eq!(map_extension_size_from(&swiss, 208), None);
        assert_eq!(map_extension_size_from(&old, 200), None);
        assert_eq!(map_extension_size_from(&swiss, 0), None);
        assert_eq!(map_extension_size_from(&swiss[..32], 200), None);
    }
}
