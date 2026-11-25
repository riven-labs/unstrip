//! The `UncommonType` block: a type's package path and method table.
//!
//! Layout from `internal/abi/type.go` (`runtime/type.go` before Go 1.21; the
//! shape is the same back to Go 1.7, where `Xcount` was an unused `uint16`):
//!
//! ```text
//!   UncommonType (16 bytes)
//!   offset 0   PkgPath NameOff
//!   offset 4   Mcount  u16     // total methods
//!   offset 6   Xcount  u16     // exported methods
//!   offset 8   Moff    u32     // offset from this UncommonType to [Mcount]Method
//!   offset 12  _       u32
//!
//!   Method (16 bytes)
//!   offset 0   Name NameOff   // md.types + off
//!   offset 4   Mtyp TypeOff   // md.types + off, a func type without the receiver
//!   offset 8   Ifn  TextOff   // the code an interface call reaches
//!   offset 12  Tfn  TextOff   // the code a direct call reaches
//! ```
//!
//! The block sits right after the kind's whole `XxxType` struct, trailing
//! alignment padding included (`abi.Type.Uncommon` declares
//! `struct { XxxType; u UncommonType }`). Text offsets resolve through
//! `ModuleData::text_addr`, which follows `textsectmap` the way the runtime's
//! `moduledata.textAddr` does when the linker split the text into sections.

use serde::Serialize;

use crate::error::Error;
use crate::gobin::GoBinary;
use crate::moduledata::ModuleData;
use crate::Result;

use super::{le_word, read_name, type_header_size, KindName};

pub(super) const UNCOMMON_TYPE_SIZE: usize = 16;
const METHOD_SIZE: usize = 16;

/// One entry of a type's method table (`abi.Method`). The table lists every
/// method of the type, exported or not, sorted by name.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct Method {
    pub name: String,
    /// The method's func type, without the receiver. None when the linker
    /// dropped it (the method is never called through reflection or an
    /// interface).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub typ: Option<u64>,
    /// Entry of the code an interface call reaches (`Ifn`). For a value
    /// receiver on a pointer-shaped type this is the method itself, otherwise
    /// a wrapper that loads the receiver. None when the linker dropped it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ifn: Option<u64>,
    /// Entry of the code a direct call reaches (`Tfn`). None when the linker
    /// dropped it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tfn: Option<u64>,
}

/// Address of the `UncommonType` of the `kind` type at `addr`, or None when
/// the kind's record size cannot be told (an unknown kind, or a map whose
/// record matches no layout).
pub(crate) fn uncommon_addr(
    bin: &GoBinary,
    md: &ModuleData,
    addr: u64,
    kind: KindName,
) -> Option<u64> {
    let ps = bin.pointer_size();
    let extension = match kind {
        KindName::Map => map_extension_size(bin, md, addr)?,
        kind => kind_extension_size(kind, ps)?,
    };
    Some(addr + (type_header_size(ps) + extension) as u64)
}

/// The import path an `UncommonType` records. Empty for the predeclared
/// types (`int`, `error`), whose `PkgPath` is zero.
pub(crate) fn read_pkg_path(bin: &GoBinary, md: &ModuleData, uncommon: u64) -> Result<String> {
    let header = bin.read_at_addr(uncommon, 4).ok_or_else(|| {
        Error::TypeRecovery(format!("uncommon header at 0x{uncommon:x} unmapped"))
    })?;
    let off = i32::from_le_bytes([header[0], header[1], header[2], header[3]]);
    if off == 0 {
        return Ok(String::new());
    }
    read_name(bin, md, md.types.wrapping_add(off as i64 as u64))
}

/// The method table an `UncommonType` points to. `owner` names the type in
/// errors.
///
/// A real table names every method, live or dead (the linker blanks only
/// Mtyp, Ifn and Tfn, to -1), and its offsets land in their regions. Any
/// entry that breaks this means the block is not an `UncommonType` (a
/// misplaced read, or a type a linear scan found by accident), so the whole
/// table is refused rather than returned with made-up entries.
pub(crate) fn read_methods(
    bin: &GoBinary,
    md: &ModuleData,
    uncommon: u64,
    owner: &str,
) -> Result<Vec<Method>> {
    let header = bin
        .read_at_addr(uncommon, UNCOMMON_TYPE_SIZE)
        .ok_or_else(|| {
            Error::TypeRecovery(format!(
                "uncommon header at 0x{uncommon:x} unmapped (type {owner})"
            ))
        })?;
    let mcount = u16::from_le_bytes([header[4], header[5]]);
    let moff = u32::from_le_bytes([header[8], header[9], header[10], header[11]]);
    if mcount == 0 {
        return Ok(Vec::new());
    }
    // A type with thousands of methods does not occur; the cap keeps a
    // crafted count from asking for a large read.
    const MAX_METHODS: u16 = 4096;
    if mcount > MAX_METHODS {
        return Err(Error::TypeRecovery(format!(
            "method count {mcount} unreasonably large for type {owner}"
        )));
    }

    let table = uncommon + moff as u64;
    let total = mcount as usize * METHOD_SIZE;
    let buf = bin.read_at_addr(table, total).ok_or_else(|| {
        Error::TypeRecovery(format!(
            "methods array at 0x{table:x} ({total} bytes) unmapped (type {owner})"
        ))
    })?;

    let mut methods = Vec::with_capacity(mcount as usize);
    for (i, entry) in buf.chunks_exact(METHOD_SIZE).enumerate() {
        let off = |at: usize| {
            i32::from_le_bytes([entry[at], entry[at + 1], entry[at + 2], entry[at + 3]])
        };
        let reject = |what: &str| {
            Error::TypeRecovery(format!(
                "method {i} of type {owner} has {what}; not a method table"
            ))
        };
        let name = match off(0) {
            o if o >= 0 => read_name(bin, md, md.types.wrapping_add(o as u64)).ok(),
            _ => None,
        };
        let name = match name {
            Some(name) if !name.is_empty() => name,
            _ => return Err(reject("no name")),
        };
        // -1 is the linker's mark for a part dead code removed (the runtime
        // maps a -1 text offset to `unreachableMethod`). Any other negative
        // offset, or one outside its region, is junk.
        let typ = match off(4) {
            -1 => None,
            o if o >= 0 && md.types.wrapping_add(o as u64) < md.etypes => {
                Some(md.types.wrapping_add(o as u64))
            }
            _ => return Err(reject("a method type outside the types region")),
        };
        let text = |o: i32| match o {
            -1 => Ok(None),
            o if o >= 0 => match md.text_addr(bin, o as u32) {
                Some(pc) if md.text <= pc && pc < md.etext => Ok(Some(pc)),
                _ => Err(()),
            },
            _ => Err(()),
        };
        let ifn = text(off(8)).map_err(|()| reject("an Ifn outside the text"))?;
        let tfn = text(off(12)).map_err(|()| reject("a Tfn outside the text"))?;
        methods.push(Method {
            name,
            typ,
            ifn,
            tfn,
        });
    }
    Ok(methods)
}

/// Size in bytes of the kind-specific record between the `_type` header and
/// the `UncommonType`, at pointer size `ps`.
///
/// None for Map (its layout is decided per record by `map_extension_size`)
/// and for unknown kinds, where reading on would mean reading random bytes.
///
/// Each value is `unsafe.Sizeof(XxxType{}) - unsafe.Sizeof(Type{})` from the
/// Go structs, so the trailing alignment padding counts. These shapes have
/// not changed since Go 1.7. Slice headers are three words; `Name` is one
/// pointer.
pub(crate) fn kind_extension_size(kind: KindName, ps: usize) -> Option<usize> {
    match kind {
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

        // Elem *Type.
        KindName::Pointer | KindName::Slice => Some(ps),

        // Elem *Type, Slice *Type, Len uintptr.
        KindName::Array => Some(3 * ps),

        // Elem *Type, Dir uintptr.
        KindName::Chan => Some(2 * ps),

        // InCount u16 and OutCount u16, but FuncType embeds the
        // pointer-aligned Type header, so on 64-bit Sizeof(FuncType) rounds
        // 52 up to 56 and the UncommonType starts 8 bytes after the header,
        // not 4. (Reading at +4 decodes the real PkgPath as Mcount/Xcount:
        // thousands of junk methods per binary once Go 1.23's `iter.Seq[...]`
        // named func types appear.) The parameter array comes after the
        // UncommonType. On 32-bit the 32-byte header plus 4 needs no padding.
        KindName::Func => Some(4usize.next_multiple_of(ps)),

        // PkgPath Name, then the fields or methods slice header.
        KindName::Struct | KindName::Interface => Some(4 * ps),

        KindName::Map => None,
        KindName::Invalid | KindName::Unknown(_) => None,
    }
}

/// `MapType` record size for Go 1.7 to 1.10 and 1.14 to 1.23 (and 1.24 and
/// 1.25 under `GOEXPERIMENT=noswissmap`): four pointers (Key, Elem, Bucket,
/// then `hmap *Type` up to 1.10 or `Hasher` from 1.14) and 8 bytes of sizes
/// and flags. 40 on 64-bit, 24 on 32-bit.
pub(crate) fn hmap_extension_size(ps: usize) -> usize {
    (4 * ps + 8).next_multiple_of(ps)
}

/// `MapType` record size for Go 1.11 to 1.13: Key, Elem, Bucket and 8 bytes
/// of sizes and flags, with neither `hmap` nor `Hasher`. 32 on 64-bit, 20 on
/// 32-bit.
pub(crate) fn go111_map_extension_size(ps: usize) -> usize {
    (3 * ps + 8).next_multiple_of(ps)
}

/// Swiss-table `MapType` record size (the Go 1.24 default, the only map in
/// 1.26): Key, Elem, Group, Hasher, then GroupSize, SlotSize, ElemOff
/// (uintptrs) and Flags u32, padded to the pointer. 64 on 64-bit, 32 on
/// 32-bit.
pub(crate) fn swiss_map_extension_size(ps: usize) -> usize {
    (7 * ps + 4).next_multiple_of(ps)
}

/// Go 1.27 `MapType` record size: Key, Elem, Group, Hasher, GroupSize, then
/// KeysOff, KeyStride, ElemsOff, ElemStride, ElemOff (uintptrs) and Flags
/// u32, padded to the pointer. 88 on 64-bit, 44 on 32-bit. `GroupSize` stays
/// at +32 (+16), so the record reads as swiss; the version tells them apart.
pub(crate) fn go127_map_extension_size(ps: usize) -> usize {
    (10 * ps + 4).next_multiple_of(ps)
}

/// Record size of the `MapType` at `type_addr`, decided from the record
/// rather than from a version guess. Every layout keeps the bucket or group
/// `*Type` at word 2 and repeats that type's size further on; where it does
/// so, and whether word 3 is a pointer (`hmap` up to Go 1.10, `Hasher` from
/// 1.14) or packed sizes (1.11 to 1.13), places the record. See
/// `map_extension_size_from`. Go 1.27 (the only release with `typedesclen`)
/// grew the swiss record.
pub(crate) fn map_extension_size(bin: &GoBinary, md: &ModuleData, type_addr: u64) -> Option<usize> {
    let ps = bin.pointer_size();
    if !matches!(ps, 4 | 8) {
        return None;
    }
    let ext = bin.read_at_addr(type_addr + type_header_size(ps) as u64, 4 * ps + 8)?;
    let in_types = |a: u64| md.types <= a && a < md.etypes;
    let group = le_word(ext, 2 * ps, ps);
    if !in_types(group) {
        return None;
    }
    let group_size = le_word(bin.read_at_addr(group, ps)?, 0, ps);
    let in_text = |a: u64| md.text <= a && a < md.etext;
    // `hmap` points into the types region. `Hasher` is a func value: a
    // pointer to a funcval whose first word is the code, wherever the linker
    // put the funcval (Go 1.27 puts it outside the types region).
    let word3 = le_word(ext, 3 * ps, ps);
    let funcval_code = bin.read_at_addr(word3, ps).map(|w| le_word(w, 0, ps));
    let word3_is_pointer = in_types(word3) || in_text(word3) || funcval_code.is_some_and(in_text);
    let size = map_extension_size_from(ext, group_size, ps, word3_is_pointer)?;
    if size == swiss_map_extension_size(ps) && md.typedesclen != 0 {
        return Some(go127_map_extension_size(ps));
    }
    Some(size)
}

/// Pure part of `map_extension_size`: classify the first `4 * ps + 8` bytes
/// of a `MapType` record against the size of its bucket or group type.
///
/// With a pointer in word 3 the record is one of three. Swiss stores
/// `GroupSize uintptr` at word 4. Go 1.14 to 1.23 store `BucketSize u16` at
/// word 4 + 2, Go 1.7 to 1.10 at word 4 + 4. The checks exclude each other
/// for any real map: a non-zero `BucketSize` inside word 4 makes that word at
/// least 65536, larger than any group, and a group under 64 KiB leaves bytes
/// 2 to 5 of word 4 zero, which no bucket size is. Without a pointer in word
/// 3 the record is Go 1.11's (`BucketSize` at word 3 + 4) or 1.12 and 1.13's
/// (word 3 + 2), the same size either way.
fn map_extension_size_from(
    ext: &[u8],
    group_size: u64,
    ps: usize,
    word3_is_pointer: bool,
) -> Option<usize> {
    if group_size == 0 || ext.len() < 4 * ps + 8 {
        return None;
    }
    let u16_at = |off: usize| u16::from_le_bytes([ext[off], ext[off + 1]]) as u64;
    if !word3_is_pointer {
        let go111 = u16_at(3 * ps + 2) == group_size || u16_at(3 * ps + 4) == group_size;
        return go111.then(|| go111_map_extension_size(ps));
    }
    let swiss = le_word(ext, 4 * ps, ps) == group_size;
    let hmap = u16_at(4 * ps + 2) == group_size || u16_at(4 * ps + 4) == group_size;
    match (swiss, hmap) {
        (true, false) => Some(swiss_map_extension_size(ps)),
        (false, true) => Some(hmap_extension_size(ps)),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `unsafe.Sizeof(XxxType{}) - unsafe.Sizeof(Type{})` at pointer size
    /// `ps`: the kind fields after the header, with the struct rounded up to
    /// its pointer alignment (it embeds pointers via `Type`).
    fn go_extension(field_bytes: usize, ps: usize) -> usize {
        let hdr = type_header_size(ps);
        (hdr + field_bytes).next_multiple_of(ps) - hdr
    }

    #[test]
    fn kind_extension_sizes_match_go_layout() {
        // Each value is derived from the Go struct, not restated: a kind
        // whose layout changes upstream should fail here rather than
        // silently miscompute uncommon block addresses.
        for ps in [8, 4] {
            let ext = |kind| kind_extension_size(kind, ps);
            assert_eq!(ext(KindName::Pointer), Some(go_extension(ps, ps)));
            assert_eq!(ext(KindName::Slice), Some(go_extension(ps, ps)));
            assert_eq!(ext(KindName::Array), Some(go_extension(3 * ps, ps)));
            assert_eq!(ext(KindName::Chan), Some(go_extension(2 * ps, ps)));
            assert_eq!(ext(KindName::Struct), Some(go_extension(4 * ps, ps)));
            assert_eq!(ext(KindName::Interface), Some(go_extension(4 * ps, ps)));
            assert_eq!(ext(KindName::Map), None);
            assert_eq!(ext(KindName::Bool), Some(0));
            assert_eq!(ext(KindName::String), Some(0));
            // Go 1.7 to 1.10: four pointers, then keysize, indirectkey,
            // valuesize, indirectvalue, bucketsize u16, two bools.
            assert_eq!(
                hmap_extension_size(ps),
                go_extension(4 * ps + 1 + 1 + 1 + 1 + 2 + 1 + 1, ps)
            );
            // Go 1.14 to 1.23: four pointers, keysize, elemsize, bucketsize
            // u16, flags u32.
            assert_eq!(
                hmap_extension_size(ps),
                go_extension(4 * ps + 1 + 1 + 2 + 4, ps)
            );
            // Go 1.12 and 1.13: three pointers, keysize, elemsize,
            // bucketsize u16, flags u32.
            assert_eq!(
                go111_map_extension_size(ps),
                go_extension(3 * ps + 1 + 1 + 2 + 4, ps)
            );
            assert_eq!(swiss_map_extension_size(ps), go_extension(7 * ps + 4, ps));
        }
        // The 64-bit values the layout comments state.
        assert_eq!(hmap_extension_size(8), 40);
        assert_eq!(go111_map_extension_size(8), 32);
        assert_eq!(go111_map_extension_size(4), 20);
        assert_eq!(swiss_map_extension_size(8), 64);
        assert_eq!(go127_map_extension_size(8), go_extension(10 * 8 + 4, 8));
        assert_eq!(go127_map_extension_size(8), 88);
        assert_eq!(go127_map_extension_size(4), 44);
        assert_eq!(kind_extension_size(KindName::Struct, 8), Some(32));
    }

    #[test]
    fn func_uncommon_block_follows_padded_functype() {
        // FuncType is Type + InCount u16 + OutCount u16 = 52 bytes, padded
        // to 56. The UncommonType therefore starts 8 bytes after the header,
        // not 4. Reading at +4 was the Go 1.23+ regression: the real PkgPath
        // NameOff was decoded as Mcount/Xcount, yielding thousands of
        // nameless methods with wild PCs on every `iter.Seq[...]` type.
        assert_eq!(
            kind_extension_size(KindName::Func, 8),
            Some(go_extension(4, 8))
        );
        assert_eq!(kind_extension_size(KindName::Func, 8), Some(8));
        // On 32-bit, 32 + 4 = 36 is already 4-aligned.
        assert_eq!(kind_extension_size(KindName::Func, 4), Some(4));
    }

    /// The first 40 bytes of a 64-bit MapType record: Key, Elem, Group or
    /// Bucket, word 3, then the layout-specific tail.
    fn map_ext(word3: u64, tail: [u8; 8]) -> Vec<u8> {
        let mut b = Vec::new();
        for p in [0x1000u64, 0x2000, 0x3000, word3] {
            b.extend_from_slice(&p.to_le_bytes());
        }
        b.extend_from_slice(&tail);
        b
    }

    #[test]
    fn map_extension_size_tells_the_layouts_apart_by_bucket_size() {
        // Swiss (Go 1.24+): GroupSize uintptr at +32 repeats the group size.
        let swiss = map_ext(0x4000, 200u64.to_le_bytes());
        assert_eq!(
            map_extension_size_from(&swiss, 200, 8, true),
            Some(swiss_map_extension_size(8))
        );
        // Go 1.14 to 1.23: KeySize 16, ValueSize 8, BucketSize 208, Flags 0.
        let mut tail = [0u8; 8];
        tail[0] = 16;
        tail[1] = 8;
        tail[2..4].copy_from_slice(&208u16.to_le_bytes());
        let go114 = map_ext(0x4000, tail);
        assert_eq!(
            map_extension_size_from(&go114, 208, 8, true),
            Some(hmap_extension_size(8))
        );
        // Go 1.7 to 1.10: keysize, indirectkey, valuesize, indirectvalue,
        // then BucketSize at +36.
        let go17 = map_ext(0x5000, [16, 0, 8, 0, 208, 0, 1, 0]);
        assert_eq!(
            map_extension_size_from(&go17, 208, 8, true),
            Some(hmap_extension_size(8))
        );
        // Go 1.12 and 1.13: word 3 holds keysize, elemsize, BucketSize, flags.
        let mut go112 = map_ext(0, [0; 8]);
        go112[24..32].copy_from_slice(&[16, 8, 208, 0, 0, 0, 0, 0]);
        assert_eq!(
            map_extension_size_from(&go112, 208, 8, false),
            Some(go111_map_extension_size(8))
        );
        // Go 1.11: keysize, indirectkey, valuesize, indirectvalue, BucketSize.
        let mut go111 = map_ext(0, [0; 8]);
        go111[24..32].copy_from_slice(&[16, 0, 8, 0, 208, 0, 1, 0]);
        assert_eq!(
            map_extension_size_from(&go111, 208, 8, false),
            Some(go111_map_extension_size(8))
        );
        // Nothing matches: refuse rather than guess.
        assert_eq!(map_extension_size_from(&swiss, 208, 8, true), None);
        assert_eq!(map_extension_size_from(&go114, 200, 8, true), None);
        assert_eq!(map_extension_size_from(&go114, 208, 8, false), None);
        assert_eq!(map_extension_size_from(&swiss, 0, 8, true), None);
        assert_eq!(map_extension_size_from(&swiss[..32], 200, 8, true), None);
        // 32-bit: the same tail a word in (GroupSize at +16, BucketSize at +18).
        let mut swiss32: Vec<u8> = [0x1000u32, 0x2000, 0x3000, 0x4000, 200, 0]
            .iter()
            .flat_map(|w| w.to_le_bytes())
            .collect();
        assert_eq!(
            map_extension_size_from(&swiss32, 200, 4, true),
            Some(swiss_map_extension_size(4))
        );
        swiss32[16..20].copy_from_slice(&[8, 4, 96, 0]);
        assert_eq!(
            map_extension_size_from(&swiss32, 96, 4, true),
            Some(hmap_extension_size(4))
        );
        assert_eq!(map_extension_size_from(&swiss32, 200, 4, true), None);
    }
}
