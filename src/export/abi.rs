//! Where a Go method body finds its arguments and leaves its results, worked
//! out from the recovered types with the rules of Go's internal ABI
//! (`src/cmd/compile/abi-internal.md`), so a tool can be given exact storage
//! instead of a C calling convention that would place them wrongly.
//!
//! Two conventions are modeled. The stack one (ABI0) covers 386 and amd64
//! before Go 1.17: arguments and then results in the caller's frame. The
//! amd64 register one covers Go 1.17 and later: each value goes whole into
//! integer and float registers when enough are left, otherwise on the stack.

use std::collections::HashMap;

use crate::funcsig::Prototype;
use crate::types::{KindData, KindName, Type};

use super::c::{packed, CTypes, Decl};
use super::Abi;

/// amd64 integer argument registers, in assignment order.
const AMD64_INT: [&str; 9] = ["RAX", "RBX", "RCX", "RDI", "RSI", "R8", "R9", "R10", "R11"];
/// amd64 float argument registers X0 to X14, by their Ghidra names.
const AMD64_FLOAT: [&str; 15] = [
    "XMM0", "XMM1", "XMM2", "XMM3", "XMM4", "XMM5", "XMM6", "XMM7", "XMM8", "XMM9", "XMM10",
    "XMM11", "XMM12", "XMM13", "XMM14",
];

/// Part of a value's storage: the low `size` bytes of a register, or `size`
/// bytes at an offset from the stack pointer at function entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Piece {
    Register(&'static str, u64),
    Stack(u64, u64),
}

/// A value's storage, its pieces in the value's byte order (lowest first).
pub(super) type Storage = Vec<Piece>;

/// A prototype placed under one of the conventions, ready to print as a C
/// declaration plus storage.
#[derive(Debug, Clone)]
pub(super) struct Placed {
    /// `recv`, `p0`, `p1`, ... with their C type text and storage.
    pub params: Vec<(String, String, Storage)>,
    /// The result's C type and storage; None for a function with no results.
    pub result: Option<(String, Storage)>,
}

/// Results of more than one value come back as one struct, declared once per
/// distinct tuple.
#[derive(Default)]
pub(super) struct ResultTuples {
    by_key: HashMap<Vec<u64>, String>,
    pub decls: Vec<Decl>,
}

/// One value's place in the convention, before it is turned into storage.
enum Slot {
    Registers(Vec<Piece>),
    /// Offset into the argument area (from the first argument).
    Stack(u64),
}

/// Place `prototype` under `abi`. None when a type is unknown or a value's
/// storage cannot be written as pieces that cover it exactly: a struct with
/// padding passed in registers, results split between registers and the
/// stack, or a value with no C form.
pub(super) fn place(
    prototype: &Prototype,
    abi: Abi,
    ctypes: &mut CTypes<'_>,
    tuples: &mut ResultTuples,
) -> Option<Placed> {
    let ps = ctypes.pointer_size();
    let receiver_word = Type {
        kind: KindName::UnsafePointer,
        size: ps,
        ..Default::default()
    };
    let mut args: Vec<(String, &Type)> = Vec::new();
    match prototype.receiver {
        Some(addr) => args.push(("recv".to_string(), ctypes.get(addr)?)),
        // An itab slot's receiver is the interface's data word.
        None => args.push(("recv".to_string(), &receiver_word)),
    }
    for (i, addr) in prototype.params.iter().enumerate() {
        args.push((format!("p{i}"), ctypes.get(*addr)?));
    }
    let mut results: Vec<&Type> = Vec::new();
    for addr in &prototype.results {
        results.push(ctypes.get(*addr)?);
    }
    if args.iter().any(|(_, t)| t.size == 0) || results.iter().any(|t| t.size == 0) {
        return None;
    }

    let mut stack = 0u64;
    let mut registers = Registers::default();
    let mut params = Vec::new();
    for (name, t) in &args {
        let slot = assign(t, abi, ctypes, &mut registers, &mut stack)?;
        let ctype = c_type_of(t, ctypes)?;
        params.push((name.clone(), ctype, storage(slot, t.size, ps)));
    }
    // Results start a fresh register sequence and, on the stack, the next
    // pointer-aligned offset after the arguments.
    stack = stack.next_multiple_of(ps);
    let mut registers = Registers::default();
    let mut slots = Vec::new();
    for t in &results {
        slots.push(assign(t, abi, ctypes, &mut registers, &mut stack)?);
    }

    let result = match results.len() {
        0 => None,
        1 => {
            let ctype = c_type_of(results[0], ctypes)?;
            let slot = slots.pop()?;
            Some((ctype, storage(slot, results[0].size, ps)))
        }
        _ => Some(tuple(&results, slots, ctypes, tuples)?),
    };
    Some(Placed { params, result })
}

/// The C type text of an argument or result. The receiver word of an itab
/// slot is `void *`.
fn c_type_of(t: &Type, ctypes: &CTypes<'_>) -> Option<String> {
    if t.addr == 0 {
        return Some("void *".to_string());
    }
    let ctype = ctypes.render(t.addr, true, 0)?;
    // An array argument has no C form as a value.
    if !ctype.dims.is_empty() {
        return None;
    }
    Some(ctype.base)
}

/// Storage for a whole value from its slot.
fn storage(slot: Slot, size: u64, ps: u64) -> Storage {
    match slot {
        Slot::Registers(pieces) => pieces,
        // The return address sits at the stack pointer on entry, so the
        // argument area starts one word up.
        Slot::Stack(offset) => vec![Piece::Stack(ps + offset, size)],
    }
}

/// Several results as one struct. In registers the struct is the results
/// back to back, matching the pieces; on the stack it is the stretch of the
/// frame that holds them, padding included. A mix of the two has no single
/// storage and is refused.
fn tuple(
    results: &[&Type],
    slots: Vec<Slot>,
    ctypes: &mut CTypes<'_>,
    tuples: &mut ResultTuples,
) -> Option<(String, Storage)> {
    let ps = ctypes.pointer_size();
    let in_registers = slots.iter().all(|s| matches!(s, Slot::Registers(_)));
    let on_stack = slots.iter().all(|s| matches!(s, Slot::Stack(_)));
    let mut fields = Vec::new();
    let mut key: Vec<u64> = results.iter().map(|t| t.addr).collect();
    let (storage, size) = if in_registers {
        let mut pieces = Vec::new();
        for (i, (t, slot)) in results.iter().zip(slots).enumerate() {
            let Slot::Registers(p) = slot else {
                return None;
            };
            pieces.extend(p);
            fields.push(ctypes.render(t.addr, true, 0)?.declare(&format!("r{i}")));
        }
        let size = results.iter().map(|t| t.size).sum();
        (pieces, size)
    } else if on_stack {
        key.push(u64::MAX);
        let offsets: Vec<u64> = slots
            .iter()
            .map(|s| match s {
                Slot::Stack(o) => *o,
                Slot::Registers(_) => 0,
            })
            .collect();
        let start = offsets[0];
        let mut cursor = start;
        for (i, (t, offset)) in results.iter().zip(&offsets).enumerate() {
            if *offset > cursor {
                fields.push(ctypes.bytes(offset - cursor).declare(&format!("_pad_{i}")));
            }
            fields.push(ctypes.render(t.addr, true, 0)?.declare(&format!("r{i}")));
            cursor = offset + t.size;
        }
        let size = cursor - start;
        (vec![Piece::Stack(ps + start, size)], size)
    } else {
        return None;
    };

    let name = match tuples.by_key.get(&key) {
        Some(name) => name.clone(),
        None => {
            let go_names: Vec<&str> = results.iter().map(|t| t.name.as_str()).collect();
            let base = format!("GoResults_{}", go_names.join("_"));
            let name = match ctypes.reserve(&base) {
                Some(name) => name,
                None => ctypes.reserve(&format!("{base}_{}", tuples.decls.len()))?,
            };
            tuples.decls.push(Decl {
                text: packed(&name, &fields),
                name: name.clone(),
                go_name: format!("({})", go_names.join(", ")),
                size,
            });
            tuples.by_key.insert(key, name.clone());
            name
        }
    };
    Some((format!("struct {name}"), storage))
}

/// Assign one value: registers when the convention has them and enough are
/// left for the whole value, else the next stack slot at the value's
/// alignment.
fn assign(
    t: &Type,
    abi: Abi,
    ctypes: &CTypes<'_>,
    registers: &mut Registers,
    stack: &mut u64,
) -> Option<Slot> {
    if abi == Abi::Amd64Register {
        // A value that does not fit leaves the registers as they were.
        let mut attempt = Registers {
            ints: registers.ints,
            floats: registers.floats,
        };
        let mut pieces = Vec::new();
        if attempt.take(t, ctypes, &mut pieces, 0) {
            // Padding inside a value means its pieces do not cover it, and
            // Ghidra rejects storage whose size differs from the type's.
            let covered: u64 = pieces
                .iter()
                .map(|p| match p {
                    Piece::Register(_, size) | Piece::Stack(_, size) => *size,
                })
                .sum();
            if covered != t.size {
                return None;
            }
            *registers = attempt;
            return Some(Slot::Registers(pieces));
        }
    }
    let align = alignment(t, ctypes, 0)?;
    let offset = stack.next_multiple_of(align);
    *stack = offset + t.size;
    Some(Slot::Stack(offset))
}

/// Integer and float registers taken so far in one sequence (the arguments,
/// or the results).
#[derive(Default)]
struct Registers {
    ints: usize,
    floats: usize,
}

impl Registers {
    /// Assign `t` to registers, field by field. False when it needs more
    /// than are left or is an array of more than one element, which Go
    /// passes on the stack.
    fn take(&mut self, t: &Type, ctypes: &CTypes<'_>, out: &mut Vec<Piece>, depth: usize) -> bool {
        if depth > 32 {
            return false;
        }
        let ps = ctypes.pointer_size();
        match t.kind {
            KindName::Bool
            | KindName::Int8
            | KindName::Uint8
            | KindName::Int16
            | KindName::Uint16
            | KindName::Int32
            | KindName::Uint32
            | KindName::Int64
            | KindName::Uint64
            | KindName::Int
            | KindName::Uint
            | KindName::Uintptr
            | KindName::Pointer
            | KindName::UnsafePointer
            | KindName::Map
            | KindName::Chan
            | KindName::Func => self.int(t.size, out),
            KindName::Float32 | KindName::Float64 => self.float(t.size, out),
            KindName::Complex64 => self.float(4, out) && self.float(4, out),
            KindName::Complex128 => self.float(8, out) && self.float(8, out),
            KindName::String | KindName::Interface => self.int(ps, out) && self.int(ps, out),
            KindName::Slice => self.int(ps, out) && self.int(ps, out) && self.int(ps, out),
            KindName::Struct => {
                let KindData::Struct { fields } = &t.kind_data else {
                    return false;
                };
                for field in fields {
                    let Some(ft) = ctypes.get(field.typ) else {
                        return false;
                    };
                    if !self.take(ft, ctypes, out, depth + 1) {
                        return false;
                    }
                }
                true
            }
            KindName::Array => match &t.kind_data {
                KindData::Array { len: 0, .. } => true,
                KindData::Array { elem, len: 1 } => match ctypes.get(*elem) {
                    Some(et) => self.take(et, ctypes, out, depth + 1),
                    None => false,
                },
                _ => false,
            },
            KindName::Invalid | KindName::Unknown(_) => false,
        }
    }

    fn int(&mut self, size: u64, out: &mut Vec<Piece>) -> bool {
        let Some(reg) = AMD64_INT.get(self.ints) else {
            return false;
        };
        self.ints += 1;
        out.push(Piece::Register(reg, size));
        true
    }

    fn float(&mut self, size: u64, out: &mut Vec<Piece>) -> bool {
        let Some(reg) = AMD64_FLOAT.get(self.floats) else {
            return false;
        };
        self.floats += 1;
        out.push(Piece::Register(reg, size));
        true
    }
}

/// Go's alignment for `t`: its size for scalars up to a word (8-byte scalars
/// align to 4 on 32-bit), a word for strings, slices, interfaces and
/// pointers, the strictest field for a struct and the element for an array.
fn alignment(t: &Type, ctypes: &CTypes<'_>, depth: usize) -> Option<u64> {
    let ps = ctypes.pointer_size();
    if depth > 32 {
        return None;
    }
    let align = match t.kind {
        KindName::Bool | KindName::Int8 | KindName::Uint8 => 1,
        KindName::Int16 | KindName::Uint16 => 2,
        KindName::Int32 | KindName::Uint32 | KindName::Float32 | KindName::Complex64 => 4,
        KindName::Int64 | KindName::Uint64 | KindName::Float64 | KindName::Complex128 => 8.min(ps),
        KindName::Int
        | KindName::Uint
        | KindName::Uintptr
        | KindName::Pointer
        | KindName::UnsafePointer
        | KindName::Map
        | KindName::Chan
        | KindName::Func
        | KindName::String
        | KindName::Slice
        | KindName::Interface => ps,
        KindName::Struct => {
            let KindData::Struct { fields } = &t.kind_data else {
                return None;
            };
            let mut align = 1;
            for field in fields {
                align = align.max(alignment(ctypes.get(field.typ)?, ctypes, depth + 1)?);
            }
            align
        }
        KindName::Array => match &t.kind_data {
            KindData::Array { elem, .. } => alignment(ctypes.get(*elem)?, ctypes, depth + 1)?,
            _ => return None,
        },
        KindName::Invalid | KindName::Unknown(_) => return None,
    };
    Some(align)
}
