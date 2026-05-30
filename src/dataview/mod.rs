use serde::Serialize;

use crate::error::Error;
use crate::gobin::GoBinary;
use crate::itabs::Itab;
use crate::pclntab::{Function, Pclntab};
use crate::Result;

/// Display interpretation requested for the inspected bytes. Drives
/// the per-row formatter; the raw bytes are always available via the
/// `bytes` field on `DataView` regardless of choice.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum As {
    /// Hex dump, 16 bytes per row.
    Bytes,
    /// Little-endian u64 per 8-byte aligned slot.
    Qwords,
    /// u64 per slot, but every value passes through the symbolizer:
    /// known functions become `name @ off`, known itabs become
    /// `itab(iface=concrete)`, known section addresses become
    /// `<section>+0xN`, unknown stays as hex.
    Ptrs,
    /// 16-byte Go interface header per slot: (itab_ptr, data_ptr).
    /// Resolves itab_ptr against the recovered itab table to print
    /// the concrete type symbolically.
    Ifaces,
    /// 24-byte Go slice header per slot: (data_ptr, len, cap).
    SliceHeader,
    /// 16-byte Go string header per slot: (data_ptr, len). When the
    /// data_ptr resolves to a known section and the len is sane, the
    /// pointed-to bytes are printed as a quoted string.
    String,
}

/// One interpreted record from a `--data-at` scan. The wire shape is
/// stable: stdout text format is one row per record formatted via
/// `format_text`; JSON output emits each record directly.
#[derive(Debug, Clone, Serialize)]
pub struct DataRow {
    /// Address of this row inside the requested span.
    pub addr: u64,
    /// Raw bytes for this row, always present so JSON consumers can
    /// re-interpret without re-reading the binary.
    pub bytes: Vec<u8>,
    /// Human-readable rendering driven by the chosen `As` variant.
    /// For `As::Bytes` this is the hex dump; for symbolizing modes
    /// it is the resolved labels.
    pub rendering: String,
}

/// Resolved symbolic identity of a u64 value. The text formatter
/// renders each variant in a tight one-line form; downstream JSON
/// consumers can pattern-match on the discriminant.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum Symbol {
    /// `pkg.func @ off` when the address lies inside a recovered
    /// function (offset is bytes into the function, 0 at the entry
    /// point).
    Function {
        name: String,
        entry: u64,
        offset: u64,
    },
    /// `itab(iface=concrete)` when the address matches a recovered
    /// itab record's base. `methods` carries the recovered (method
    /// name, concrete fn address) pairs so callers that already know
    /// they are looking at an iface dispatch slot (e.g. `--data-as
    /// ifaces`) can print the dispatched body address inline without
    /// a second --itabs lookup. Empty when the itab was recovered
    /// without resolvable methods.
    Itab {
        interface: String,
        concrete: String,
        #[serde(skip_serializing_if = "Vec::is_empty")]
        methods: Vec<ItabMethodEntry>,
    },
    /// `<section>+0xN` when no closer symbol matches but the address
    /// lies within a known section.
    SectionOffset { section: String, offset: u64 },
    /// Address is not in any mapped section.
    Unmapped,
    /// Bit pattern that does not look like an address at all (zero,
    /// small ints, etc.). Surface verbatim as a u64 with no claims.
    Scalar { value: u64 },
}

/// One method entry carried inline on [`Symbol::Itab`] so iface
/// dispatch slots can resolve to a callable body in one query.
#[derive(Debug, Clone, Serialize)]
pub struct ItabMethodEntry {
    pub name: String,
    pub concrete_fn: u64,
}

impl Symbol {
    pub fn render(&self) -> String {
        match self {
            Symbol::Function {
                name,
                entry: _,
                offset,
            } if *offset == 0 => name.clone(),
            Symbol::Function { name, offset, .. } => format!("{name} + 0x{offset:x}"),
            Symbol::Itab {
                interface,
                concrete,
                methods,
            } => {
                let mut s = format!("itab({interface} = {concrete})");
                // Append every method's dispatched body address inline
                // so the operator does not have to bounce out to
                // --itabs just to learn where dispatch will land. For
                // the common single-method case (most stdlib ifaces
                // and chain-stage style ifaces), this collapses two
                // commands into one. Hidden when no methods resolved
                // so the simple case stays readable.
                if !methods.is_empty() {
                    s.push_str("  [");
                    for (i, m) in methods.iter().enumerate() {
                        if i > 0 {
                            s.push_str(", ");
                        }
                        s.push_str(&format!(".{}() -> 0x{:x}", m.name, m.concrete_fn));
                    }
                    s.push(']');
                }
                s
            }
            Symbol::SectionOffset { section, offset } => format!("{section}+0x{offset:x}"),
            Symbol::Unmapped => "(unmapped)".to_string(),
            Symbol::Scalar { value } => format!("0x{value:x}"),
        }
    }
}

/// Inspect `len` bytes at `addr`, returning interpreted rows for the
/// chosen presentation. The function reads the binary's loaded bytes
/// directly; it never re-opens the file.
pub fn inspect(
    bin: &GoBinary,
    pcln: &Pclntab<'_>,
    itabs_v: &[Itab],
    functions: &[Function],
    addr: u64,
    len: usize,
    mode: As,
) -> Result<Vec<DataRow>> {
    let (file_off, bounded_len) = bounded_read(bin, addr, len)?;
    let bytes = &bin.bytes[file_off..file_off + bounded_len];

    let ctx = SymCtx::new(bin, pcln, itabs_v, functions);

    match mode {
        As::Bytes => Ok(rows_bytes(addr, bytes)),
        As::Qwords => Ok(rows_qwords(addr, bytes, None)),
        As::Ptrs => Ok(rows_qwords(addr, bytes, Some(&ctx))),
        As::Ifaces => Ok(rows_ifaces(addr, bytes, &ctx)),
        As::SliceHeader => Ok(rows_slice_headers(addr, bytes, &ctx)),
        As::String => Ok(rows_strings(addr, bytes, bin, &ctx)),
    }
}

/// Resolve `addr` to its tightest symbolic identity using every map
/// the binary has produced. Public so callers can symbolize ad-hoc.
pub fn symbolize(
    bin: &GoBinary,
    pcln: &Pclntab<'_>,
    itabs_v: &[Itab],
    functions: &[Function],
    value: u64,
) -> Symbol {
    let ctx = SymCtx::new(bin, pcln, itabs_v, functions);
    ctx.symbolize(value)
}

fn bounded_read(bin: &GoBinary, addr: u64, len: usize) -> Result<(usize, usize)> {
    let s = bin
        .sections
        .iter()
        .find(|s| s.contains_addr(addr))
        .ok_or_else(|| Error::Xrefs(format!("address 0x{addr:x} is not in any mapped section")))?;
    let file_off = s.file_offset_of(addr).ok_or_else(|| {
        Error::Xrefs(format!(
            "address 0x{addr:x} lies past the file-backed portion of {}",
            s.name
        ))
    })?;
    let max_available = s.file_size - (addr - s.addr) as usize;
    let bounded = len.min(max_available);
    Ok((file_off, bounded))
}

fn rows_bytes(start: u64, bytes: &[u8]) -> Vec<DataRow> {
    let mut out = Vec::new();
    for (i, chunk) in bytes.chunks(16).enumerate() {
        let mut hex = String::with_capacity(48);
        for b in chunk {
            hex.push_str(&format!("{b:02x} "));
        }
        let mut ascii = String::with_capacity(16);
        for &b in chunk {
            ascii.push(if (0x20..=0x7E).contains(&b) {
                b as char
            } else {
                '.'
            });
        }
        out.push(DataRow {
            addr: start + (i as u64) * 16,
            bytes: chunk.to_vec(),
            rendering: format!("{hex:<48} |{ascii}|"),
        });
    }
    out
}

fn rows_qwords(start: u64, bytes: &[u8], ctx: Option<&SymCtx>) -> Vec<DataRow> {
    let mut out = Vec::new();
    for (i, chunk) in bytes.chunks(8).enumerate() {
        if chunk.len() < 8 {
            break;
        }
        let v = u64::from_le_bytes(chunk.try_into().unwrap());
        let rendering = match ctx {
            Some(c) => format!("0x{v:016x}  {}", c.symbolize(v).render()),
            None => format!("0x{v:016x}"),
        };
        out.push(DataRow {
            addr: start + (i as u64) * 8,
            bytes: chunk.to_vec(),
            rendering,
        });
    }
    out
}

fn rows_ifaces(start: u64, bytes: &[u8], ctx: &SymCtx) -> Vec<DataRow> {
    let mut out = Vec::new();
    for (i, chunk) in bytes.chunks(16).enumerate() {
        if chunk.len() < 16 {
            break;
        }
        let itab_ptr = u64::from_le_bytes(chunk[0..8].try_into().unwrap());
        let data_ptr = u64::from_le_bytes(chunk[8..16].try_into().unwrap());
        let itab_sym = ctx.symbolize(itab_ptr);
        let data_sym = ctx.symbolize(data_ptr);
        out.push(DataRow {
            addr: start + (i as u64) * 16,
            bytes: chunk.to_vec(),
            rendering: format!(
                "iface{{ itab=0x{:016x} ({}), data=0x{:016x} ({}) }}",
                itab_ptr,
                itab_sym.render(),
                data_ptr,
                data_sym.render(),
            ),
        });
    }
    out
}

fn rows_slice_headers(start: u64, bytes: &[u8], ctx: &SymCtx) -> Vec<DataRow> {
    let mut out = Vec::new();
    for (i, chunk) in bytes.chunks(24).enumerate() {
        if chunk.len() < 24 {
            break;
        }
        let data_ptr = u64::from_le_bytes(chunk[0..8].try_into().unwrap());
        let len = u64::from_le_bytes(chunk[8..16].try_into().unwrap());
        let cap = u64::from_le_bytes(chunk[16..24].try_into().unwrap());
        out.push(DataRow {
            addr: start + (i as u64) * 24,
            bytes: chunk.to_vec(),
            rendering: format!(
                "slice{{ data=0x{:016x} ({}), len={}, cap={} }}",
                data_ptr,
                ctx.symbolize(data_ptr).render(),
                len,
                cap,
            ),
        });
    }
    out
}

fn rows_strings(start: u64, bytes: &[u8], bin: &GoBinary, ctx: &SymCtx) -> Vec<DataRow> {
    let mut out = Vec::new();
    for (i, chunk) in bytes.chunks(16).enumerate() {
        if chunk.len() < 16 {
            break;
        }
        let data_ptr = u64::from_le_bytes(chunk[0..8].try_into().unwrap());
        let len = u64::from_le_bytes(chunk[8..16].try_into().unwrap());
        let preview = read_string_preview(bin, data_ptr, len);
        let preview_render = match preview {
            Some(s) => format!("{s:?}"),
            None => format!("({})", ctx.symbolize(data_ptr).render()),
        };
        out.push(DataRow {
            addr: start + (i as u64) * 16,
            bytes: chunk.to_vec(),
            rendering: format!(
                "string{{ ptr=0x{:016x}, len={} }} {}",
                data_ptr, len, preview_render,
            ),
        });
    }
    out
}

fn read_string_preview(bin: &GoBinary, ptr: u64, len: u64) -> Option<String> {
    if len == 0 || len > 4096 {
        return None;
    }
    let s = bin.sections.iter().find(|s| s.contains_addr(ptr))?;
    let off = s.file_offset_of(ptr)?;
    let end = off + (len as usize);
    if end > bin.bytes.len() {
        return None;
    }
    let raw = &bin.bytes[off..end];
    if raw
        .iter()
        .any(|&b| !((0x20..=0x7E).contains(&b) || b == b'\n' || b == b'\t'))
    {
        return None;
    }
    Some(String::from_utf8_lossy(raw).into_owned())
}

struct SymCtx<'a> {
    bin: &'a GoBinary,
    pcln: &'a Pclntab<'a>,
    itab_by_addr: std::collections::HashMap<u64, &'a Itab>,
    function_by_addr: std::collections::HashMap<u64, &'a Function>,
}

impl<'a> SymCtx<'a> {
    fn new(
        bin: &'a GoBinary,
        pcln: &'a Pclntab<'a>,
        itabs_v: &'a [Itab],
        functions: &'a [Function],
    ) -> Self {
        SymCtx {
            bin,
            pcln,
            itab_by_addr: itabs_v.iter().map(|it| (it.addr, it)).collect(),
            function_by_addr: functions.iter().map(|f| (f.address, f)).collect(),
        }
    }

    fn symbolize(&self, value: u64) -> Symbol {
        // Small integers and obvious non-addresses fall through to
        // Scalar so the output does not lie about random qwords being
        // pointers. Threshold matches the lowest plausible VA on
        // amd64 / arm64 user-space.
        if value < 0x1000 {
            return Symbol::Scalar { value };
        }

        if let Some(it) = self.itab_by_addr.get(&value) {
            return Symbol::Itab {
                interface: it.interface_name.clone(),
                concrete: it.concrete_name.clone(),
                methods: it
                    .methods
                    .iter()
                    .map(|m| ItabMethodEntry {
                        name: m.interface_method.clone(),
                        concrete_fn: m.concrete_fn,
                    })
                    .collect(),
            };
        }
        if let Some(f) = self.function_by_addr.get(&value) {
            return Symbol::Function {
                name: f.name.clone(),
                entry: f.address,
                offset: 0,
            };
        }
        // Mid-function PC: look up the containing function via pclntab.
        if let Some(f) = self.pcln.lookup(value) {
            let entry = f.address;
            return Symbol::Function {
                name: f.name,
                entry,
                offset: value - entry,
            };
        }
        for s in &self.bin.sections {
            if s.contains_addr(value) && !s.name.is_empty() {
                return Symbol::SectionOffset {
                    section: s.name.clone(),
                    offset: value - s.addr,
                };
            }
        }
        Symbol::Unmapped
    }
}
