use serde::Serialize;

use crate::error::Error;
use crate::gobin::GoBinary;
use crate::moduledata::ModuleData;
use crate::types;
use crate::Result;

/// A recovered (interface, concrete type) pairing from `runtime.itablinks`,
/// optionally with the method-by-method dispatch table populated.
#[derive(Debug, Clone, Serialize)]
pub struct Itab {
    pub addr: u64,
    pub interface_name: String,
    pub concrete_name: String,
    pub hash: u32,
    /// True if any method slot is zero, meaning the concrete type does not
    /// implement the interface. The Go runtime uses this as a "negative
    /// cache", rare but legitimate.
    pub incomplete: bool,
    /// Per-slot dispatch: (interface method name, concrete method pointer).
    /// Empty when method resolution failed; populated when the interface's
    /// method list was decoded successfully.
    pub methods: Vec<ItabMethod>,
    /// Canonical stdlib interface name when `interface_name` matches one
    /// of the well-known stdlib interfaces (see `stdlib::STDLIB_INTERFACES`).
    /// `None` for user-defined interfaces. JSON consumers can filter on
    /// this field without re-parsing.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stdlib_interface: Option<&'static str>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ItabMethod {
    pub interface_method: String,
    pub concrete_fn: u64,
}

/// Read a `ps`-byte pointer at `off` in the binary's endianness.
fn rd_ptr(buf: &[u8], off: usize, ps: usize, le: bool) -> Option<u64> {
    let b = buf.get(off..off + ps)?;
    Some(match (ps, le) {
        (8, true) => u64::from_le_bytes(b.try_into().ok()?),
        (8, false) => u64::from_be_bytes(b.try_into().ok()?),
        (_, true) => u32::from_le_bytes(b.try_into().ok()?) as u64,
        (_, false) => u32::from_be_bytes(b.try_into().ok()?) as u64,
    })
}

/// Read a u32 at `off` in the binary's endianness.
fn rd_u32(buf: &[u8], off: usize, le: bool) -> Option<u32> {
    let b: [u8; 4] = buf.get(off..off + 4)?.try_into().ok()?;
    Some(if le {
        u32::from_le_bytes(b)
    } else {
        u32::from_be_bytes(b)
    })
}

/// The `_type` (rtype) header: four uintptr fields (size, ptrdata, equal,
/// gcdata) plus the 4-byte hash, 4 flag bytes, and the str/ptrToThis offsets.
fn type_header_size(ps: usize) -> usize {
    4 * ps + 16
}

/// Byte offset of the `str` nameOff field inside the `_type` header.
fn type_str_offset(ps: usize) -> usize {
    4 * ps + 8
}

pub fn recover_all(bin: &GoBinary, md: &ModuleData) -> Result<Vec<Itab>> {
    let ps = bin.pointer_size();
    let le = bin.little_endian;

    const MAX_ITABS: u64 = 5_000_000;
    if md.itablinks.len > MAX_ITABS {
        return Err(Error::ItabRecovery(format!(
            "itablinks length {} exceeds sanity cap {}",
            md.itablinks.len, MAX_ITABS
        )));
    }
    let n = md.itablinks.len as usize;
    let table_bytes = bin.read_at_addr(md.itablinks.data, n * ps).ok_or_else(|| {
        Error::ItabRecovery(format!(
            "itablinks at 0x{:x} (len {}) unmapped",
            md.itablinks.data, md.itablinks.len
        ))
    })?;

    let mut out = Vec::with_capacity(n);
    for chunk in table_bytes.chunks_exact(ps) {
        let itab_addr = rd_ptr(chunk, 0, ps, le).unwrap_or(0);
        if itab_addr == 0 {
            continue;
        }
        match parse_itab(bin, md, itab_addr) {
            Ok(it) => out.push(it),
            Err(_) => continue,
        }
    }
    Ok(out)
}

fn parse_itab(bin: &GoBinary, md: &ModuleData, addr: u64) -> Result<Itab> {
    let ps = bin.pointer_size();
    let le = bin.little_endian;
    // itab header: inter *interfacetype, _type *_type, hash uint32, then a
    // 4-byte pad before the fun[] array.
    let header_size = 2 * ps + 8;
    let buf = bin
        .read_at_addr(addr, header_size)
        .ok_or_else(|| Error::ItabRecovery(format!("itab at 0x{addr:x} unmapped")))?;

    let inter_ptr = rd_ptr(buf, 0, ps, le).unwrap_or(0);
    let type_ptr = rd_ptr(buf, ps, ps, le).unwrap_or(0);
    let hash = rd_u32(buf, 2 * ps, le).unwrap_or(0);

    let interface_name =
        read_type_name(bin, md, inter_ptr).unwrap_or_else(|_| format!("iface@0x{inter_ptr:x}"));
    let concrete_name =
        read_type_name(bin, md, type_ptr).unwrap_or_else(|_| format!("type@0x{type_ptr:x}"));

    // Try to read the interface's method list to learn how long the fun array
    // is and what each slot maps to. Failure here is non-fatal, we still
    // return the basic pairing.
    let methods = read_interface_method_names(bin, md, inter_ptr).unwrap_or_default();

    // The fun[] array begins right after the itab header. Each entry is a
    // function pointer. A zero entry marks an incomplete itab.
    let mut populated_methods = Vec::new();
    let mut incomplete = false;
    let fun_base = addr + header_size as u64;
    for (i, name) in methods.iter().enumerate() {
        let slot_addr = fun_base + (i as u64) * ps as u64;
        let concrete_fn = match bin.read_at_addr(slot_addr, ps) {
            Some(b) => rd_ptr(b, 0, ps, le).unwrap_or(0),
            None => break,
        };
        if concrete_fn == 0 {
            incomplete = true;
        }
        populated_methods.push(ItabMethod {
            interface_method: name.clone(),
            concrete_fn,
        });
    }

    // If we couldn't enumerate methods (interface decode failed), still
    // check the first slot as a degraded "incomplete" signal.
    if populated_methods.is_empty() {
        if let Some(b) = bin.read_at_addr(fun_base, ps) {
            if rd_ptr(b, 0, ps, le).unwrap_or(0) == 0 {
                incomplete = true;
            }
        }
    }

    let stdlib_interface = crate::stdlib::STDLIB_INTERFACES
        .iter()
        .find(|s| **s == interface_name)
        .copied();

    Ok(Itab {
        addr,
        interface_name,
        concrete_name,
        hash,
        incomplete,
        methods: populated_methods,
        stdlib_interface,
    })
}

/// Read the interface's method-name list directly from its InterfaceType.
/// Used to know the `fun[]` array length on the itab.
///
/// Rejects interface addresses outside `[md.types, md.etypes)` before
/// dereferencing. Without that gate, an attacker-controlled `inter` pointer
/// in a hostile itab could make us read a `methods_len` from arbitrary
/// memory and then walk an N-sized array off that.
fn read_interface_method_names(
    bin: &GoBinary,
    md: &ModuleData,
    inter_addr: u64,
) -> Result<Vec<String>> {
    if inter_addr < md.types || inter_addr >= md.etypes {
        return Err(Error::ItabRecovery(format!(
            "interface ptr 0x{inter_addr:x} not in types region [0x{:x}, 0x{:x})",
            md.types, md.etypes
        )));
    }
    let ps = bin.pointer_size();
    let le = bin.little_endian;
    let extra = inter_addr + type_header_size(ps) as u64;
    // PkgPath Name (one pointer) then Methods slice header (data, len, cap).
    let buf = bin
        .read_at_addr(extra, 4 * ps)
        .ok_or_else(|| Error::ItabRecovery(format!("interface extra at 0x{extra:x} unmapped")))?;
    let methods_data = rd_ptr(buf, ps, ps, le).unwrap_or(0);
    let methods_len = rd_ptr(buf, 2 * ps, ps, le).unwrap_or(0);
    if methods_len == 0 || methods_len > 256 {
        return Ok(Vec::new());
    }
    // An imethod is two 4-byte offsets (name, typ), the same on every arch.
    let arr = bin
        .read_at_addr(methods_data, methods_len as usize * 8)
        .ok_or_else(|| {
            Error::ItabRecovery(format!("imethod array at 0x{methods_data:x} unmapped"))
        })?;
    let mut out = Vec::with_capacity(methods_len as usize);
    for chunk in arr.chunks_exact(8) {
        let name_off = rd_u32(chunk, 0, le).unwrap_or(0) as i32;
        let name_addr = md.types.wrapping_add(name_off as i64 as u64);
        let name = types::read_name_public(bin, md, name_addr).unwrap_or_else(|_| "?".into());
        out.push(name);
    }
    Ok(out)
}

fn read_type_name(bin: &GoBinary, md: &ModuleData, type_addr: u64) -> Result<String> {
    let ps = bin.pointer_size();
    let le = bin.little_endian;
    let buf = bin
        .read_at_addr(type_addr, type_header_size(ps))
        .ok_or_else(|| Error::ItabRecovery(format!("type header at 0x{type_addr:x} unmapped")))?;
    let str_off = rd_u32(buf, type_str_offset(ps), le).unwrap_or(0) as i32;
    let name_addr = md.types.wrapping_add(str_off as i64 as u64);
    types::read_name_public(bin, md, name_addr).map_err(|e| Error::ItabRecovery(e.to_string()))
}
