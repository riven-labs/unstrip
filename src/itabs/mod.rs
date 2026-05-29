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

const ITAB_HEADER_SIZE: usize = 24;
const TYPE_STR_OFFSET: usize = 40;
const TYPE_HEADER_SIZE: usize = 48;

pub fn recover_all(bin: &GoBinary, md: &ModuleData) -> Result<Vec<Itab>> {
    if bin.pointer_size() != 8 {
        return Err(Error::ItabRecovery(format!(
            "itab recovery requires pointer size 8, got {}",
            bin.pointer_size()
        )));
    }

    const MAX_ITABS: u64 = 5_000_000;
    if md.itablinks.len > MAX_ITABS {
        return Err(Error::ItabRecovery(format!(
            "itablinks length {} exceeds sanity cap {}",
            md.itablinks.len, MAX_ITABS
        )));
    }
    let n = md.itablinks.len as usize;
    let table_bytes = bin.read_at_addr(md.itablinks.data, n * 8).ok_or_else(|| {
        Error::ItabRecovery(format!(
            "itablinks at 0x{:x} (len {}) unmapped",
            md.itablinks.data, md.itablinks.len
        ))
    })?;

    let mut out = Vec::with_capacity(n);
    for chunk in table_bytes.chunks_exact(8) {
        let itab_addr = u64::from_le_bytes(chunk.try_into().unwrap());
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
    let buf = bin
        .read_at_addr(addr, ITAB_HEADER_SIZE)
        .ok_or_else(|| Error::ItabRecovery(format!("itab at 0x{addr:x} unmapped")))?;

    let inter_ptr = u64::from_le_bytes(buf[0..8].try_into().unwrap());
    let type_ptr = u64::from_le_bytes(buf[8..16].try_into().unwrap());
    let hash = u32::from_le_bytes(buf[16..20].try_into().unwrap());

    let interface_name =
        read_type_name(bin, md, inter_ptr).unwrap_or_else(|_| format!("iface@0x{inter_ptr:x}"));
    let concrete_name =
        read_type_name(bin, md, type_ptr).unwrap_or_else(|_| format!("type@0x{type_ptr:x}"));

    // Try to read the interface's method list to learn how long the fun array
    // is and what each slot maps to. Failure here is non-fatal, we still
    // return the basic pairing.
    let methods = read_interface_method_names(bin, md, inter_ptr).unwrap_or_default();

    // The fun[] array begins right after the 24-byte itab header. Each entry
    // is a function pointer (8 bytes on amd64). A zero entry marks an
    // incomplete itab.
    let mut populated_methods = Vec::new();
    let mut incomplete = false;
    let fun_base = addr + ITAB_HEADER_SIZE as u64;
    for (i, name) in methods.iter().enumerate() {
        let slot_addr = fun_base + (i as u64) * 8;
        let slot = bin.read_at_addr(slot_addr, 8);
        let concrete_fn = match slot {
            Some(b) => u64::from_le_bytes(b.try_into().unwrap()),
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
    // check the first slot as a degraded "incomplete" signal, same as
    // before.
    if populated_methods.is_empty() {
        if let Some(b) = bin.read_at_addr(fun_base, 8) {
            if u64::from_le_bytes(b.try_into().unwrap()) == 0 {
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
    let extra = inter_addr + TYPE_HEADER_SIZE as u64;
    // PkgPath Name (8 bytes) then Methods slice header (24 bytes).
    let buf = bin
        .read_at_addr(extra, 8 + 24)
        .ok_or_else(|| Error::ItabRecovery(format!("interface extra at 0x{extra:x} unmapped")))?;
    let methods_data = u64::from_le_bytes(buf[8..16].try_into().unwrap());
    let methods_len = u64::from_le_bytes(buf[16..24].try_into().unwrap());
    if methods_len == 0 || methods_len > 256 {
        return Ok(Vec::new());
    }
    let arr = bin
        .read_at_addr(methods_data, methods_len as usize * 8)
        .ok_or_else(|| {
            Error::ItabRecovery(format!("imethod array at 0x{methods_data:x} unmapped"))
        })?;
    let mut out = Vec::with_capacity(methods_len as usize);
    for chunk in arr.chunks_exact(8) {
        let name_off = i32::from_le_bytes(chunk[0..4].try_into().unwrap());
        let name_addr = md.types.wrapping_add(name_off as i64 as u64);
        let name = types::read_name_public(bin, name_addr).unwrap_or_else(|_| "?".into());
        out.push(name);
    }
    Ok(out)
}

fn read_type_name(bin: &GoBinary, md: &ModuleData, type_addr: u64) -> Result<String> {
    let buf = bin
        .read_at_addr(type_addr, TYPE_HEADER_SIZE)
        .ok_or_else(|| Error::ItabRecovery(format!("type header at 0x{type_addr:x} unmapped")))?;
    let str_off = i32::from_le_bytes(
        buf[TYPE_STR_OFFSET..TYPE_STR_OFFSET + 4]
            .try_into()
            .unwrap(),
    );
    let name_addr = md.types.wrapping_add(str_off as i64 as u64);
    types::read_name_public(bin, name_addr).map_err(|e| Error::ItabRecovery(e.to_string()))
}
