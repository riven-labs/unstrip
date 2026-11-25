//! C declarations for recovered Go types, in the dialect each tool's parser
//! reads.
//!
//! Every declaration is packed (`#pragma pack(push, 1)`) and spells out Go's
//! alignment padding as byte arrays, so each field sits at the offset the
//! runtime recorded and each struct has the runtime's size whatever alignment
//! rules the tool would apply (386 aligns 8-byte fields to 4 in Go, to 8
//! under MSVC). The scripts check every parsed size against the recorded one.

use std::collections::{HashMap, HashSet};
use std::fmt::Write;

use crate::types::{KindData, KindName, Type};

/// The parsers differ in which integer spellings have a fixed width: Ghidra's
/// golang compiler spec makes `int` and `__int32` 8 bytes, IDA always knows
/// `__intN`, and Binary Ninja and Ghidra both know `intN_t`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Dialect {
    Ghidra,
    Ida,
    BinaryNinja,
}

impl Dialect {
    fn int(self, size: u64, signed: bool) -> &'static str {
        match (self, size, signed) {
            (Dialect::Ida, 1, true) => "__int8",
            (Dialect::Ida, 1, false) => "unsigned __int8",
            (Dialect::Ida, 2, true) => "__int16",
            (Dialect::Ida, 2, false) => "unsigned __int16",
            (Dialect::Ida, 4, true) => "__int32",
            (Dialect::Ida, 4, false) => "unsigned __int32",
            (Dialect::Ida, _, true) => "__int64",
            (Dialect::Ida, _, false) => "unsigned __int64",
            (_, 1, true) => "int8_t",
            (_, 1, false) => "uint8_t",
            (_, 2, true) => "int16_t",
            (_, 2, false) => "uint16_t",
            (_, 4, true) => "int32_t",
            (_, 4, false) => "uint32_t",
            (_, _, true) => "int64_t",
            (_, _, false) => "uint64_t",
        }
    }
}

/// One C declaration: a struct the script parses and checks.
#[derive(Debug, Clone)]
pub(super) struct Decl {
    /// The struct tag, a C identifier.
    pub name: String,
    /// The Go type it declares, for the tool's description field.
    pub go_name: String,
    pub text: String,
    /// The size the runtime recorded, which the parsed type must have.
    pub size: u64,
}

/// A C type expression: `base` then the declarator name then `dims`, as in
/// `struct GoString name[4]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct CType {
    pub base: String,
    pub dims: Vec<u64>,
}

impl CType {
    fn scalar(base: impl Into<String>) -> CType {
        CType {
            base: base.into(),
            dims: Vec::new(),
        }
    }

    pub fn declare(&self, name: &str) -> String {
        let mut res = if self.base.ends_with('*') {
            format!("{}{name}", self.base)
        } else {
            format!("{} {name}", self.base)
        };
        for dim in &self.dims {
            write!(res, "[{dim}]").unwrap();
        }
        res
    }
}

/// The Go runtime's own layouts for the values that are not structs in Go
/// but are in C. Declared first, under these tags, in every export.
const BUILTINS: [&str; 6] = [
    "GoString",
    "GoSlice",
    "GoIface",
    "GoEface",
    "GoComplex64",
    "GoComplex128",
];

/// Pointer chains deeper than this render as `void *`.
const MAX_POINTER_DEPTH: usize = 4;
/// Structs nested by value deeper than this render the innermost as bytes.
/// Real Go code nests a handful of levels; the cap keeps a crafted type
/// graph from exhausting the stack.
const MAX_NESTING: usize = 64;
/// Longest identifier emitted. IDA caps names at 511 bytes; anonymous Go
/// struct types (`struct { ... }` with every field spelled out) run longer.
const MAX_IDENTIFIER: usize = 160;

/// The recovered types, indexed for rendering, and the struct tags chosen
/// for the ones that get a declaration.
pub(super) struct CTypes<'a> {
    by_addr: HashMap<u64, &'a Type>,
    tags: HashMap<u64, String>,
    pointer_size: u64,
    dialect: Dialect,
    /// Structs whose declaration has been emitted, so a by-value use parses.
    done: HashSet<u64>,
    taken: HashSet<String>,
}

impl<'a> CTypes<'a> {
    pub fn new(types: &'a [Type], pointer_size: u64, dialect: Dialect) -> CTypes<'a> {
        let by_addr: HashMap<u64, &Type> = types.iter().map(|t| (t.addr, t)).collect();
        let mut taken: HashSet<String> = BUILTINS.iter().map(|s| s.to_string()).collect();
        let mut tags = HashMap::new();
        for t in types {
            if !matches!(t.kind_data, KindData::Struct { .. }) || t.size == 0 {
                continue;
            }
            if tags.contains_key(&t.addr) {
                continue;
            }
            // Two Go types can map to one identifier: `sync.Mutex` and
            // `internal/sync.Mutex` share a name, and `a.b_c` and `a_b.c`
            // share an identifier. The later one takes the Go type hash as a
            // suffix, which is the same in every build of the type.
            let mut tag = c_identifier(&t.name);
            if !taken.insert(tag.clone()) {
                tag = format!("{tag}_{:08x}", t.hash);
                if !taken.insert(tag.clone()) {
                    continue;
                }
            }
            tags.insert(t.addr, tag);
        }
        CTypes {
            by_addr,
            tags,
            pointer_size,
            dialect,
            done: HashSet::new(),
            taken,
        }
    }

    pub fn get(&self, addr: u64) -> Option<&'a Type> {
        self.by_addr.get(&addr).copied()
    }

    pub fn pointer_size(&self) -> u64 {
        self.pointer_size
    }

    /// Reserve a fresh tag for a struct this module did not recover, such as
    /// a prototype's result tuple. None when `name` is taken.
    pub fn reserve(&mut self, name: &str) -> Option<String> {
        let tag = c_identifier(name);
        self.taken.insert(tag.clone()).then_some(tag)
    }

    /// Every declaration: the builtins, then each recovered struct after the
    /// structs it holds by value.
    pub fn declarations(&mut self, types: &[Type]) -> Vec<Decl> {
        let mut decls = self.builtins();
        let mut visiting = HashSet::new();
        for t in types {
            self.declare_struct(t.addr, &mut visiting, &mut decls, 0);
        }
        decls
    }

    fn builtins(&mut self) -> Vec<Decl> {
        let int = self.dialect.int(self.pointer_size, true);
        let byte = self.dialect.int(1, false);
        let ps = self.pointer_size;
        let builtin = |name: &str, go_name: &str, fields: &[String], size: u64| Decl {
            name: name.to_string(),
            go_name: go_name.to_string(),
            text: packed(name, fields),
            size,
        };
        vec![
            builtin(
                "GoString",
                "string",
                &[format!("{byte} *str"), format!("{int} len")],
                2 * ps,
            ),
            builtin(
                "GoSlice",
                "[]T",
                &[
                    "void *array".to_string(),
                    format!("{int} len"),
                    format!("{int} cap"),
                ],
                3 * ps,
            ),
            builtin(
                "GoIface",
                "interface { ... }",
                &["void *tab".to_string(), "void *data".to_string()],
                2 * ps,
            ),
            builtin(
                "GoEface",
                "interface {}",
                &["void *_type".to_string(), "void *data".to_string()],
                2 * ps,
            ),
            builtin(
                "GoComplex64",
                "complex64",
                &["float real".to_string(), "float imag".to_string()],
                8,
            ),
            builtin(
                "GoComplex128",
                "complex128",
                &["double real".to_string(), "double imag".to_string()],
                16,
            ),
        ]
    }

    /// Emit the struct at `addr` once its by-value dependencies are out.
    fn declare_struct(
        &mut self,
        addr: u64,
        visiting: &mut HashSet<u64>,
        decls: &mut Vec<Decl>,
        depth: usize,
    ) {
        if self.done.contains(&addr) || !self.tags.contains_key(&addr) {
            return;
        }
        if depth > MAX_NESTING || !visiting.insert(addr) {
            return;
        }
        let Some(t) = self.get(addr) else {
            return;
        };
        let KindData::Struct { fields } = &t.kind_data else {
            return;
        };
        for field in fields {
            if let Some(dep) = self.by_value_struct(field.typ) {
                self.declare_struct(dep, visiting, decls, depth + 1);
            }
        }
        visiting.remove(&addr);

        let tag = self.tags[&addr].clone();
        let mut lines = Vec::new();
        let mut names: HashSet<String> = HashSet::new();
        let mut next_offset = 0u64;
        for (idx, field) in fields.iter().enumerate() {
            let field_type = self.get(field.typ);
            let size = match field_type {
                Some(ft) => ft.size,
                // An unrecovered field type spans up to the next field.
                None => fields
                    .iter()
                    .map(|f| f.offset)
                    .filter(|&o| o > field.offset)
                    .min()
                    .unwrap_or(t.size)
                    .saturating_sub(field.offset),
            };
            // Zero-size fields (struct{}, [0]T, the runtime's marker types)
            // have no C form, and a field before the cursor or past the end
            // would move every later offset.
            let overlaps = field.offset < next_offset;
            let overruns = field
                .offset
                .checked_add(size)
                .is_none_or(|end| end > t.size);
            if size == 0 || overlaps || overruns {
                continue;
            }
            if field.offset > next_offset {
                let byte = self.dialect.int(1, false);
                let pad = field.offset - next_offset;
                lines.push(format!("{byte} _pad_{idx}[{pad}]"));
            }
            let ctype = field_type
                .and_then(|_| self.render(field.typ, true, 0))
                .unwrap_or_else(|| self.bytes(size));
            let mut name = c_identifier(&field.name);
            if name == "_" || name.starts_with("_pad_") || name == "_tail" {
                name = format!("_anon_{idx}");
            }
            while !names.insert(name.clone()) {
                name.push('_');
            }
            lines.push(ctype.declare(&name));
            next_offset = field.offset + size;
        }
        if next_offset < t.size {
            let byte = self.dialect.int(1, false);
            lines.push(format!("{byte} _tail[{}]", t.size - next_offset));
        }
        decls.push(Decl {
            text: packed(&tag, &lines),
            name: tag,
            go_name: t.name.clone(),
            size: t.size,
        });
        self.done.insert(addr);
    }

    /// The declared struct a field of type `addr` holds by value, directly or
    /// as an array element.
    fn by_value_struct(&self, addr: u64) -> Option<u64> {
        let mut addr = addr;
        for _ in 0..MAX_NESTING {
            let t = self.get(addr)?;
            match &t.kind_data {
                KindData::Struct { .. } => return self.tags.contains_key(&addr).then_some(addr),
                KindData::Array { elem, .. } => addr = *elem,
                _ => return None,
            }
        }
        None
    }

    /// A byte array of `size`.
    pub fn bytes(&self, size: u64) -> CType {
        CType {
            base: self.dialect.int(1, false).to_string(),
            dims: vec![size],
        }
    }

    /// The C type of the Go type at `addr`, or None when it has no C form
    /// that keeps its size. `by_value` says whether a struct is allowed to
    /// appear whole, which needs its declaration already out; behind a
    /// pointer any declared struct will do.
    pub fn render(&self, addr: u64, by_value: bool, depth: usize) -> Option<CType> {
        let t = self.get(addr)?;
        let ps = self.pointer_size;
        let int = |size: u64, signed: bool| Some(CType::scalar(self.dialect.int(size, signed)));
        match t.kind {
            KindName::Bool => Some(CType::scalar("bool")),
            KindName::Int8 => int(1, true),
            KindName::Uint8 => int(1, false),
            KindName::Int16 => int(2, true),
            KindName::Uint16 => int(2, false),
            KindName::Int32 => int(4, true),
            KindName::Uint32 => int(4, false),
            KindName::Int64 => int(8, true),
            KindName::Uint64 => int(8, false),
            KindName::Int => int(ps, true),
            KindName::Uint | KindName::Uintptr => int(ps, false),
            KindName::Float32 => Some(CType::scalar("float")),
            KindName::Float64 => Some(CType::scalar("double")),
            KindName::Complex64 => Some(CType::scalar("struct GoComplex64")),
            KindName::Complex128 => Some(CType::scalar("struct GoComplex128")),
            KindName::String => Some(CType::scalar("struct GoString")),
            KindName::Slice => Some(CType::scalar("struct GoSlice")),
            KindName::Interface => match &t.kind_data {
                KindData::Interface { methods } if methods.is_empty() => {
                    Some(CType::scalar("struct GoEface"))
                }
                _ => Some(CType::scalar("struct GoIface")),
            },
            KindName::Pointer => {
                let pointee = match &t.kind_data {
                    KindData::Pointer { elem } if depth < MAX_POINTER_DEPTH => {
                        self.render(*elem, false, depth + 1)
                    }
                    _ => None,
                };
                match pointee {
                    Some(p) if p.dims.is_empty() => Some(CType::scalar(format!("{} *", p.base))),
                    _ => Some(CType::scalar("void *")),
                }
            }
            KindName::UnsafePointer | KindName::Map | KindName::Chan | KindName::Func => {
                Some(CType::scalar("void *"))
            }
            KindName::Struct => {
                let tag = self.tags.get(&addr)?;
                if by_value && !self.done.contains(&addr) {
                    return None;
                }
                Some(CType::scalar(format!("struct {tag}")))
            }
            KindName::Array => {
                let KindData::Array { elem, len } = &t.kind_data else {
                    return None;
                };
                let elem_type = self.get(*elem)?;
                if *len == 0
                    || elem_type.size == 0
                    || elem_type.size.checked_mul(*len) != Some(t.size)
                {
                    return None;
                }
                let mut ctype = self.render(*elem, by_value, depth)?;
                ctype.dims.insert(0, *len);
                Some(ctype)
            }
            KindName::Invalid | KindName::Unknown(_) => None,
        }
    }
}

/// `struct tag { fields; };` between `#pragma pack` lines.
pub(super) fn packed(tag: &str, fields: &[String]) -> String {
    let mut res = String::from("#pragma pack(push, 1)\n");
    writeln!(res, "struct {tag} {{").unwrap();
    for field in fields {
        writeln!(res, "    {field};").unwrap();
    }
    res.push_str("};\n#pragma pack(pop)\n");
    res
}

/// A C identifier for a Go name, for the declarations the tools' C parsers
/// read. Those accept letters, digits and `_` only, so `.` and the rest of
/// Go's punctuation map to `_`. A leading digit gets a `_` prefix and a C
/// keyword a `_` suffix. A name past [`MAX_IDENTIFIER`] is cut and keeps a
/// hash of the whole name, so two long names stay apart.
pub(super) fn c_identifier(name: &str) -> String {
    let mut res: String = name
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect();
    if res.is_empty() || res.starts_with(|c: char| c.is_ascii_digit()) {
        res.insert(0, '_');
    }
    if res.len() > MAX_IDENTIFIER {
        res.truncate(MAX_IDENTIFIER - 9);
        write!(res, "_{:08x}", fnv1a(name.as_bytes())).unwrap();
    }
    if is_c_reserved(&res) {
        res.push('_');
    }
    res
}

/// FNV-1a, 32-bit: a stable hash that needs no dependency.
fn fnv1a(bytes: &[u8]) -> u32 {
    let mut hash: u32 = 0x811c_9dc5;
    for &b in bytes {
        hash ^= b as u32;
        hash = hash.wrapping_mul(0x0100_0193);
    }
    hash
}

/// C keywords, and the type names every dialect predefines, that a Go
/// identifier can spell. `runtime.boundsError` has a field named `signed`.
fn is_c_reserved(name: &str) -> bool {
    matches!(
        name,
        "auto"
            | "bool"
            | "break"
            | "case"
            | "char"
            | "const"
            | "continue"
            | "default"
            | "do"
            | "double"
            | "else"
            | "enum"
            | "extern"
            | "float"
            | "for"
            | "goto"
            | "if"
            | "inline"
            | "int"
            | "long"
            | "register"
            | "restrict"
            | "return"
            | "short"
            | "signed"
            | "sizeof"
            | "static"
            | "struct"
            | "switch"
            | "typedef"
            | "union"
            | "unsigned"
            | "void"
            | "volatile"
            | "while"
            | "_Alignas"
            | "_Alignof"
            | "_Atomic"
            | "_Bool"
            | "_Complex"
            | "_Generic"
            | "_Imaginary"
            | "_Noreturn"
            | "_Static_assert"
            | "_Thread_local"
            | "int8_t"
            | "int16_t"
            | "int32_t"
            | "int64_t"
            | "uint8_t"
            | "uint16_t"
            | "uint32_t"
            | "uint64_t"
            | "__int8"
            | "__int16"
            | "__int32"
            | "__int64"
    )
}
