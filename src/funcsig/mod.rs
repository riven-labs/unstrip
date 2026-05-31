//! Function-signature recovery for stripped Go binaries.
//!
//! The recoverable signal in a stripped binary comes from method tables,
//! not from a per-function signature record. The runtime stores method
//! tables in two places:
//!
//!   1. `_type.uncommon().methods` for every defined type that has methods.
//!      Each entry carries the method's name, its mtyp (a TypeOff pointing
//!      at a funcType), and the entry PCs (ifn for interface dispatch, tfn
//!      for direct calls).
//!
//!   2. Itab method tables. Same shape, attached per (interface, concrete)
//!      pair instead of per defined type.
//!
//! Day 1 ships path (1): walk every type with `TFlagUncommon` set, decode
//! the UncommonType extension, walk the methods slice, return the raw
//! `(name, mtyp_off, ifn_off, tfn_off)` per method. Resolving mtyp to a
//! Go-syntax signature is Day 2. Cross-referencing tfn to the function
//! table is Day 4. The current entry just produces the raw method table.
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
//! UncommonType sits at `type_addr + TYPE_HEADER_SIZE + kind_extension_size`.
//! The kind-extension size is per-kind and known statically on 64-bit.

use serde::Serialize;

use crate::error::Error;
use crate::gobin::GoBinary;
use crate::moduledata::ModuleData;
use crate::types::{read_name_public, KindName, Type, TFLAG_UNCOMMON, TYPE_HEADER_SIZE_64};
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

/// Recover the methods table for a single type. Returns Ok(empty) if the
/// type has TFlagUncommon but Mcount == 0 (rare but valid).
pub fn methods_for_type(bin: &GoBinary, md: &ModuleData, t: &Type) -> Result<Vec<RecoveredMethod>> {
    if t.tflag & TFLAG_UNCOMMON == 0 {
        return Ok(Vec::new());
    }

    let extra_size = kind_extension_size(t.kind, t.size).ok_or_else(|| {
        Error::TypeRecovery(format!(
            "kind {:?} has no known extension size; cannot locate uncommon block",
            t.kind
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

        let name = if name_off >= 0 {
            let name_addr = md.types.wrapping_add(name_off as i64 as u64);
            read_name_public(bin, name_addr).unwrap_or_default()
        } else {
            String::new()
        };

        let mtyp_addr = if mtyp_off >= 0 {
            md.types.wrapping_add(mtyp_off as i64 as u64)
        } else {
            0
        };
        let ifn_pc = if ifn_off >= 0 {
            md.text.wrapping_add(ifn_off as i64 as u64)
        } else {
            0
        };
        let tfn_pc = if tfn_off >= 0 {
            md.text.wrapping_add(tfn_off as i64 as u64)
        } else {
            0
        };

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
/// Returns None for kinds whose extension layout we don't know yet (today:
/// Map). A None here means we cannot safely compute the UncommonType
/// address and must skip the type rather than read random bytes.
///
/// The values come from the Go struct definitions in `internal/abi/type.go`.
/// Slice headers are 24 bytes (data + len + cap); `Name` is a one-pointer
/// wrapper around a byte slice in the names blob.
fn kind_extension_size(kind: KindName, _size: u64) -> Option<usize> {
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

        // Func: InCount u16 + OutCount u16. The variable parameter array
        // is laid out AFTER the UncommonType, not before, so it does not
        // contribute to the extension size here.
        KindName::Func => Some(4),

        // Struct: PkgPath Name (8) + Fields slice header (24).
        KindName::Struct => Some(32),

        // Interface: PkgPath Name (8) + Methods slice header (24).
        KindName::Interface => Some(32),

        // Map: layout drifted across Go versions (Swisstable rewrite in
        // 1.24+); skipping until we have a witnessed decoder.
        KindName::Map => None,

        // Unknown / Invalid: refuse rather than guess.
        KindName::Invalid | KindName::Unknown(_) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kind_extension_sizes_match_go_layout() {
        // Sanity-check the static layout values against what we documented
        // in the doc comment. If a kind's size changes upstream we want
        // this test to fail loudly rather than silently miscompute uncommon
        // block addresses.
        assert_eq!(kind_extension_size(KindName::Pointer, 0), Some(8));
        assert_eq!(kind_extension_size(KindName::Slice, 0), Some(8));
        assert_eq!(kind_extension_size(KindName::Array, 0), Some(24));
        assert_eq!(kind_extension_size(KindName::Chan, 0), Some(16));
        assert_eq!(kind_extension_size(KindName::Func, 0), Some(4));
        assert_eq!(kind_extension_size(KindName::Struct, 0), Some(32));
        assert_eq!(kind_extension_size(KindName::Interface, 0), Some(32));
        assert_eq!(kind_extension_size(KindName::Map, 0), None);
        assert_eq!(kind_extension_size(KindName::Bool, 0), Some(0));
        assert_eq!(kind_extension_size(KindName::String, 0), Some(0));
    }
}
