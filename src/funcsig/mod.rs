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
//! The method table layout, and where a type's `UncommonType` sits for each
//! kind and Go release, is documented with its reader in `types::uncommon`.

use std::collections::HashMap;

use serde::Serialize;

use crate::gobin::GoBinary;
use crate::moduledata::ModuleData;
use crate::types::{self, parse_type, KindData, KindName, Type, TFLAG_UNCOMMON};
use crate::Result;

/// One recovered method from a `_type.uncommon().methods` table.
#[derive(Debug, Clone, Serialize)]
#[non_exhaustive]
pub struct RecoveredMethod {
    /// Receiver type name (the type that owns this method).
    pub receiver: String,
    /// Address of the receiver's type descriptor, the type whose method
    /// table this came from. Zero for a method read from an itab: the itab
    /// slot receives the interface's data word, whose type the slot does not
    /// record.
    pub receiver_type: u64,
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
                receiver_type: 0,
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
    let methods = types::read_methods(bin, md, t)?;
    let methods = methods
        .into_iter()
        .map(|m| RecoveredMethod {
            receiver: t.name.clone(),
            receiver_type: t.addr,
            name: m.name,
            mtyp_addr: m.typ.unwrap_or(0),
            ifn_pc: m.ifn.unwrap_or(0),
            tfn_pc: m.tfn.unwrap_or(0),
        })
        .collect();
    Ok(methods)
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

/// A method body's parameters and results as type descriptor addresses, for
/// callers that build a typed prototype rather than a Go-syntax string.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct Prototype {
    /// The receiver's type, the method body's first argument. None when the
    /// method came from an itab: the body then receives the interface's data
    /// word, one pointer-sized value whose type the itab does not record.
    pub receiver: Option<u64>,
    pub params: Vec<u64>,
    pub results: Vec<u64>,
    /// The last parameter is the `...T` one, stored as a `[]T`.
    pub variadic: bool,
}

/// Build a PC -> prototype map for every method whose funcType decodes, keyed
/// like [`signatures_by_pc`] by the direct-call body (`tfn_pc`). The first
/// method seen for a PC wins, so pass the uncommon-table methods first: they
/// carry the receiver's type.
pub fn prototypes_by_pc(
    methods: &[RecoveredMethod],
    cache: &mut TypeCache<'_>,
) -> HashMap<u64, Prototype> {
    let mut out = HashMap::with_capacity(methods.len());
    for m in methods {
        if m.tfn_pc == 0 || m.mtyp_addr == 0 || out.contains_key(&m.tfn_pc) {
            continue;
        }
        let Some(mtyp) = cache.get(m.mtyp_addr) else {
            continue;
        };
        let KindData::Func {
            in_count,
            out_count,
            variadic,
            in_types,
            out_types,
        } = &mtyp.kind_data
        else {
            continue;
        };
        // A funcType whose parameter array did not decode in full would give
        // a prototype with arguments missing.
        if in_types.len() != *in_count as usize || out_types.len() != *out_count as usize {
            continue;
        }
        let prototype = Prototype {
            receiver: (m.receiver_type != 0).then_some(m.receiver_type),
            params: in_types.clone(),
            results: out_types.clone(),
            variadic: *variadic,
        };
        out.insert(m.tfn_pc, prototype);
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
