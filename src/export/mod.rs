//! Scripts that apply recovered names, types, prototypes and labels inside a
//! reverse engineering tool: IDA (IDAPython), Ghidra (PyGhidra) and Binary
//! Ninja.
//!
//! Each script is plain data calls (`_type(...)`, `_func(...)`, `_proto(...)`,
//! `_label(...)`) behind a few helpers that do the tool's API work and count
//! what applied. It ends with one line per kind and a total,
//! `unstrip: done, N failures`, that a headless run can check.
//!
//! What each tool gets:
//!
//! - Types: every recovered struct as a packed C declaration with typed
//!   fields, after the builtin `GoString`, `GoSlice`, `GoIface`, `GoEface`,
//!   `GoComplex64` and `GoComplex128`. Each script checks the parsed size
//!   against the recorded one. Ghidra keeps the Go type name as the type's
//!   description.
//! - Functions: the Go name as the label (sanitized for IDA, which rejects
//!   Go punctuation), with the full Go name, signature and file:line as the
//!   comment. An ABI wrapper and its target share a pclntab name; the ABI0
//!   one of the pair gets the `.abi0` suffix the Go linker gives it.
//! - Prototypes, Ghidra only: parameter and result types with the storage
//!   Go's ABI gives them, set as custom storage. No C calling convention
//!   describes Go's, and IDA and Binary Ninja could not be checked here, so
//!   those two keep the signature in the comment only.
//! - Labels: itabs, type descriptors and moduledata under the linker's names.

mod abi;
mod c;

use std::collections::HashMap;
use std::io::{self, Write};

use crate::funcsig::Prototype;
use crate::itabs::Itab;
use crate::pclntab::Function;
use crate::types::{KindName, Type};

use self::c::{CTypes, Decl, Dialect};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Target {
    Ida,
    Ghidra,
    BinaryNinja,
}

/// The calling convention of the binary's Go code, which decides where a
/// prototype's arguments and results live.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub enum Abi {
    /// Not known: no prototypes are applied.
    #[default]
    Unknown,
    /// ABI0: arguments, then results, in the caller's frame. 386, and amd64
    /// before Go 1.17.
    Stack,
    /// ABIInternal on amd64, Go 1.17 and later: integer and float registers,
    /// the stack for what does not fit.
    Amd64Register,
}

/// How the Go linker spells the symbols the labels are named after. Go 1.20
/// renamed `type.` to `type:` and `go.itab.` to `go:itab.`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub enum LinkerNames {
    #[default]
    Go120,
    Legacy,
}

/// What a script applies. Start from [`Export::new`] and set the fields that
/// apply; the defaults apply function names only.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct Export<'a> {
    pub functions: &'a [Function],
    /// Recovered types: every struct becomes a C declaration, every named
    /// type a descriptor label. Prototype types must be in here too.
    pub types: &'a [Type],
    /// Go-syntax signature by entry PC, for the function comments.
    pub signatures: Option<&'a HashMap<u64, String>>,
    /// Typed prototypes by entry PC, applied where the tool can place them.
    pub prototypes: Option<&'a HashMap<u64, Prototype>>,
    pub abi: Abi,
    pub itabs: &'a [Itab],
    /// Address of the module's `runtime.moduledata`.
    pub moduledata: Option<u64>,
    /// 4 or 8.
    pub pointer_size: u64,
    pub linker_names: LinkerNames,
    /// Named in the header and in the script's output.
    pub generator: &'a str,
}

impl<'a> Export<'a> {
    pub fn new(functions: &'a [Function], generator: &'a str) -> Export<'a> {
        Export {
            functions,
            types: &[],
            signatures: None,
            prototypes: None,
            abi: Abi::Unknown,
            itabs: &[],
            moduledata: None,
            pointer_size: 8,
            linker_names: LinkerNames::Go120,
            generator,
        }
    }
}

/// Emit a script that, run inside the target reverse engineering tool,
/// applies every recovered function name (with file:line as a function
/// comment) and every recovered struct type (as a C declaration the tool
/// can parse).
///
/// Pass `types` as an empty slice to emit functions only. Pass
/// `signatures = None` to emit bare function names without the recovered
/// Go-syntax signature in the per-function comment. [`write`] takes the full
/// set of inputs.
pub fn write_script<W: Write>(
    w: &mut W,
    target: Target,
    funcs: &[Function],
    types: &[Type],
    signatures: Option<&HashMap<u64, String>>,
    generator: &str,
) -> io::Result<()> {
    let mut export = Export::new(funcs, generator);
    export.types = types;
    export.signatures = signatures;
    // Without a pointer size given, a pointer type's size says it.
    if let Some(t) = types.iter().find(|t| t.kind == KindName::Pointer) {
        if t.size == 4 {
            export.pointer_size = 4;
        }
    }
    write(w, target, &export)
}

/// Emit the script for `target` from everything in `export`.
pub fn write<W: Write>(w: &mut W, target: Target, export: &Export<'_>) -> io::Result<()> {
    let plan = Plan::new(target, export);
    let tool = match target {
        Target::Ida => Tool::IDA,
        Target::Ghidra => Tool::GHIDRA,
        Target::BinaryNinja => Tool::BINJA,
    };
    let generator = export.generator;

    for line in tool.header {
        writeln!(w, "{}", line.replace("{generator}", generator))?;
    }
    writeln!(
        w,
        "# {} type declarations, {} functions ({} ABI wrapper pairs marked), {} prototypes, {} labels ({} itabs, {} type descriptors, {} moduledata).",
        plan.decls.len(),
        plan.functions.len(),
        plan.abi_pairs,
        plan.prototypes.len(),
        plan.labels.len(),
        plan.n_itabs,
        plan.n_descriptors,
        plan.n_moduledata,
    )?;
    writeln!(w)?;
    w.write_all(tool.imports.as_bytes())?;
    writeln!(w)?;
    w.write_all(STATS.as_bytes())?;
    writeln!(w)?;
    w.write_all(tool.helpers.as_bytes())?;
    writeln!(w)?;

    writeln!(w, "# Type declarations ({})", plan.decls.len())?;
    for decl in &plan.decls {
        writeln!(
            w,
            "_type({}, {}, {}, {})",
            py_str(&decl.name),
            py_str(&decl.text),
            decl.size,
            py_str(&decl.go_name),
        )?;
    }
    writeln!(w)?;
    writeln!(w, "# Functions ({})", plan.functions.len())?;
    for (addr, label, comment) in &plan.functions {
        writeln!(
            w,
            "_func(0x{addr:x}, {}, {})",
            py_str(label),
            py_str(comment)
        )?;
    }
    if tool.prototypes {
        writeln!(w)?;
        writeln!(w, "# Prototypes ({})", plan.prototypes.len())?;
        for (addr, decl, params, result, convention) in &plan.prototypes {
            writeln!(
                w,
                "_proto(0x{addr:x}, {}, {params}, {result}, {})",
                py_str(decl),
                py_str(convention)
            )?;
        }
    }
    writeln!(w)?;
    writeln!(w, "# Labels ({})", plan.labels.len())?;
    for (addr, label) in &plan.labels {
        writeln!(w, "_label(0x{addr:x}, {})", py_str(label))?;
    }
    writeln!(w)?;
    w.write_all(SUMMARY.replace("{generator}", generator).as_bytes())?;
    Ok(())
}

/// Everything a script will emit, decided before any of it is written so
/// the header counts are the emitted ones.
struct Plan {
    decls: Vec<Decl>,
    /// (address, label, comment)
    functions: Vec<(u64, String, String)>,
    abi_pairs: usize,
    /// (address, C declaration, parameter storage, result storage,
    /// convention), the storage as Python literals.
    prototypes: Vec<(u64, String, String, String, String)>,
    labels: Vec<(u64, String)>,
    n_itabs: usize,
    n_descriptors: usize,
    n_moduledata: usize,
}

impl Plan {
    fn new(target: Target, export: &Export<'_>) -> Plan {
        let dialect = match target {
            Target::Ida => Dialect::Ida,
            Target::Ghidra => Dialect::Ghidra,
            Target::BinaryNinja => Dialect::BinaryNinja,
        };
        let label = |name: &str| match target {
            Target::Ida => sanitize_label(name),
            Target::Ghidra => ghidra_label(name),
            Target::BinaryNinja => name.to_string(),
        };

        let mut ctypes = CTypes::new(export.types, export.pointer_size, dialect);
        let mut decls = ctypes.declarations(export.types);

        let abi_names = abi_wrapper_names(export.functions);
        let mut functions = Vec::with_capacity(export.functions.len());
        for f in export.functions {
            let (go_label, note) = match abi_names.get(&f.address) {
                Some((name, note)) => (name.as_str(), Some(note.as_str())),
                None => (f.name.as_str(), None),
            };
            let signature = export
                .signatures
                .and_then(|m| m.get(&f.address))
                .map(String::as_str);
            let comment = function_comment(f, signature, note);
            functions.push((f.address, label(go_label), comment));
        }

        let mut prototypes = Vec::new();
        let can_place = target == Target::Ghidra
            && matches!(export.abi, Abi::Stack | Abi::Amd64Register)
            && matches!(export.pointer_size, 4 | 8);
        if let (true, Some(protos)) = (can_place, export.prototypes) {
            let convention = match export.abi {
                Abi::Amd64Register => "abi-internal",
                _ => "abi0",
            };
            let mut tuples = abi::ResultTuples::default();
            let mut pcs: Vec<u64> = export.functions.iter().map(|f| f.address).collect();
            pcs.sort_unstable();
            pcs.dedup();
            for pc in pcs {
                let Some(proto) = protos.get(&pc) else {
                    continue;
                };
                let Some(placed) = abi::place(proto, export.abi, &mut ctypes, &mut tuples) else {
                    continue;
                };
                let args: Vec<String> = placed
                    .params
                    .iter()
                    .map(|(name, ctype, _)| format!("{ctype} {name}"))
                    .collect();
                let ret = match &placed.result {
                    Some((ctype, _)) => ctype.as_str(),
                    None => "void",
                };
                let decl = format!("{ret} f({});", args.join(", "));
                let params: Vec<String> = placed
                    .params
                    .iter()
                    .map(|(name, _, storage)| {
                        format!("({}, {})", py_str(name), py_storage(storage))
                    })
                    .collect();
                let result = match &placed.result {
                    Some((_, storage)) => py_storage(storage),
                    None => "None".to_string(),
                };
                prototypes.push((
                    pc,
                    decl,
                    format!("[{}]", params.join(", ")),
                    result,
                    convention.to_string(),
                ));
            }
            decls.extend(tuples.decls);
        }

        let (type_prefix, itab_prefix) = match export.linker_names {
            LinkerNames::Go120 => ("type:", "go:itab."),
            LinkerNames::Legacy => ("type.", "go.itab."),
        };
        let mut labels = Vec::new();
        for itab in export.itabs {
            let name = format!(
                "{itab_prefix}{},{}",
                itab.concrete_name, itab.interface_name
            );
            labels.push((itab.addr, label(&name)));
        }
        let n_itabs = labels.len();
        for t in export.types {
            if t.name.is_empty() {
                continue;
            }
            labels.push((t.addr, label(&format!("{type_prefix}{}", t.name))));
        }
        let n_descriptors = labels.len() - n_itabs;
        if let Some(addr) = export.moduledata {
            labels.push((addr, label("runtime.firstmoduledata")));
        }
        let n_moduledata = labels.len() - n_itabs - n_descriptors;

        Plan {
            decls,
            functions,
            abi_pairs: abi_names.len() / 2,
            prototypes,
            labels,
            n_itabs,
            n_descriptors,
            n_moduledata,
        }
    }
}

/// The label and comment note of each function in an ABI wrapper pair. Go
/// 1.17 and later compile a wrapper between the stack ABI (ABI0, assembly)
/// and the register ABI (ABIInternal, Go) wherever one calls the other, and
/// the pclntab names it after its target. The wrapper is the one whose file
/// is `<autogenerated>`. The linker's symbol table calls the ABI0 side
/// `name.abi0`: the wrapper when the target is Go, the target when it is
/// assembly.
fn abi_wrapper_names(functions: &[Function]) -> HashMap<u64, (String, String)> {
    let mut by_name: HashMap<&str, Vec<&Function>> = HashMap::new();
    for f in functions {
        by_name.entry(f.name.as_str()).or_default().push(f);
    }
    let is_generated = |f: &Function| f.file.as_deref() == Some("<autogenerated>");
    let mut res = HashMap::new();
    for (name, group) in by_name {
        let [a, b] = group.as_slice() else {
            continue;
        };
        let (wrapper, target) = match (is_generated(a), is_generated(b)) {
            (true, false) => (*a, *b),
            (false, true) => (*b, *a),
            _ => continue,
        };
        let target_is_asm = target.file.as_deref().is_some_and(|f| f.ends_with(".s"));
        let abi0 = format!("{name}.abi0");
        let (wrapper_name, wrapper_note, target_name, target_note) = if target_is_asm {
            (
                name.to_string(),
                format!(
                    "ABIInternal wrapper of the assembly (ABI0) body at 0x{:x}",
                    target.address
                ),
                abi0,
                format!(
                    "assembly (ABI0) body; its ABIInternal wrapper is at 0x{:x}",
                    wrapper.address
                ),
            )
        } else {
            (
                abi0,
                format!("ABI0 wrapper of the Go body at 0x{:x}", target.address),
                name.to_string(),
                format!("Go body; its ABI0 wrapper is at 0x{:x}", wrapper.address),
            )
        };
        res.insert(wrapper.address, (wrapper_name, wrapper_note));
        res.insert(target.address, (target_name, target_note));
    }
    res
}

/// The function comment: `go: <full name><signature>`, then the ABI note
/// and `<file>:<line>` when known.
fn function_comment(f: &Function, signature: Option<&str>, note: Option<&str>) -> String {
    let mut res = format!("go: {}", f.name);
    if let Some(sig) = signature {
        res.push_str(sig);
    }
    if let Some(note) = note {
        res.push('\n');
        res.push_str(note);
    }
    if let Some(file) = &f.file {
        res.push('\n');
        res.push_str(file);
        if let Some(line) = f.start_line {
            res.push(':');
            res.push_str(&line.to_string());
        }
    }
    res
}

/// Storage as a Python list, most significant piece first, the order Ghidra
/// takes for a value split over several registers. A register piece is
/// `('RAX', 8)`, a stack piece `(16, 8)`.
fn py_storage(storage: &abi::Storage) -> String {
    let pieces: Vec<String> = storage
        .iter()
        .rev()
        .map(|piece| match piece {
            abi::Piece::Register(reg, size) => format!("('{reg}', {size})"),
            abi::Piece::Stack(offset, size) => format!("({offset}, {size})"),
        })
        .collect();
    format!("[{}]", pieces.join(", "))
}

/// Sanitize a Go symbol name into a label IDA accepts. Go names contain `.`,
/// `(`, `)`, `*`, `[`, `]`, `/`, `,`, spaces and more; IDA keeps `.` and `$`
/// and rejects the rest, which map to `_`. The full name stays in the
/// function comment.
fn sanitize_label(name: &str) -> String {
    let mut res: String = name
        .chars()
        .map(|c| match c {
            'a'..='z' | 'A'..='Z' | '0'..='9' | '_' | '.' | '$' => c,
            _ => '_',
        })
        .collect();
    if res.is_empty() || res.starts_with(|c: char| c.is_ascii_digit()) {
        res.insert(0, '_');
    }
    res
}

/// A Go name as a Ghidra label. Ghidra takes Go's punctuation as is and
/// rejects whitespace, which only anonymous struct types in generic shapes
/// (`go.shape.struct { X int }`) put in a name.
fn ghidra_label(name: &str) -> String {
    let res: String = name
        .chars()
        .map(|c| {
            if c.is_whitespace() || c.is_control() {
                '_'
            } else {
                c
            }
        })
        .collect();
    if res.is_empty() {
        return "_".to_string();
    }
    res
}

/// A Python single-quoted string literal. Go names hold no quotes, but
/// comments and declarations span lines and file paths hold backslashes.
fn py_str(s: &str) -> String {
    let mut res = String::with_capacity(s.len() + 2);
    res.push('\'');
    for c in s.chars() {
        match c {
            '\\' => res.push_str("\\\\"),
            '\'' => res.push_str("\\'"),
            '\n' => res.push_str("\\n"),
            '\r' => res.push_str("\\r"),
            '\t' => res.push_str("\\t"),
            c if (c as u32) < 0x20 || c == '\u{7f}' => {
                res.push_str(&format!("\\x{:02x}", c as u32))
            }
            c => res.push(c),
        }
    }
    res.push('\'');
    res
}

/// The per-tool parts of a script.
struct Tool {
    header: &'static [&'static str],
    imports: &'static str,
    helpers: &'static str,
    prototypes: bool,
}

impl Tool {
    const IDA: Tool = Tool {
        header: &[
            "# Generated by {generator}. Run inside IDA: File -> Script file... (IDAPython 3).",
        ],
        imports: IDA_IMPORTS,
        helpers: IDA_HELPERS,
        prototypes: false,
    };
    const GHIDRA: Tool = Tool {
        header: &[
            "# Generated by {generator}. Run inside Ghidra with PyGhidra (Ghidra 12 runs Python",
            "# scripts only through PyGhidra: support/pyghidraRun, or pyghidraRun -H for headless).",
            "# @author Riven Labs",
            "# @category {generator}",
            "# @keybinding",
            "# @menupath Tools.{generator}.Apply recovered symbols",
            "# @toolbar",
            "# @runtime PyGhidra",
            "# @description Apply {generator}-recovered Go types, function names, prototypes and labels to the current program.",
        ],
        imports: GHIDRA_IMPORTS,
        helpers: GHIDRA_HELPERS,
        prototypes: true,
    };
    const BINJA: Tool = Tool {
        header: &[
            "# Generated by {generator}. Run inside Binary Ninja's Python console with `bv` set:",
            "#   exec(open('this.py').read())",
        ],
        imports: BINJA_IMPORTS,
        helpers: BINJA_HELPERS,
        prototypes: false,
    };
}

/// Counters every script shares, and the failure recorder.
const STATS: &str = r#"_stats = {}
_failures = []

def _ok(kind):
    _stats.setdefault(kind, [0, 0])[0] += 1

def _fail(kind, key, reason):
    _stats.setdefault(kind, [0, 0])[1] += 1
    _failures.append((kind, key, reason))
"#;

const IDA_IMPORTS: &str = r#"import ida_funcs, ida_name, ida_typeinf, idc
"#;

const IDA_HELPERS: &str = r#"_til = ida_typeinf.get_idati()
_parse_flags = ida_typeinf.HTI_DCL | getattr(ida_typeinf, 'HTI_PAK1', 0)

def _type(name, decl, size, go_name):
    try:
        errors = ida_typeinf.parse_decls(_til, decl, None, _parse_flags)
        if errors != 0:
            _fail('type', name, 'parse_decls reported {} errors'.format(errors))
            return
        tif = ida_typeinf.tinfo_t()
        if not tif.get_named_type(_til, name):
            _fail('type', name, 'not found after parsing')
            return
        if tif.get_size() != size:
            _fail('type', name, 'parsed size {} differs from the recorded {}'.format(tif.get_size(), size))
            return
        _ok('type')
    except Exception as e:
        _fail('type', name, repr(e))

def _func(addr, name, comment):
    try:
        ida_funcs.add_func(addr)
        if not ida_name.set_name(addr, name, ida_name.SN_NOCHECK | ida_name.SN_FORCE):
            _fail('func', '0x{:x} {}'.format(addr, name), 'set_name refused')
            return
        if comment:
            idc.set_func_cmt(addr, comment, 0)
        _ok('func')
    except Exception as e:
        _fail('func', '0x{:x} {}'.format(addr, name), repr(e))

def _label(addr, name):
    try:
        if not ida_name.set_name(addr, name, ida_name.SN_NOCHECK | ida_name.SN_FORCE):
            _fail('label', '0x{:x} {}'.format(addr, name), 'set_name refused')
            return
        _ok('label')
    except Exception as e:
        _fail('label', '0x{:x} {}'.format(addr, name), repr(e))
"#;

const GHIDRA_IMPORTS: &str = r#"from java.util import ArrayList
from ghidra.app.util.cparser.C import CParser
from ghidra.program.model.data import DataTypeConflictHandler, VoidDataType
from ghidra.program.model.listing import Function, ParameterImpl, ReturnParameterImpl, VariableStorage
from ghidra.program.model.pcode import Varnode
from ghidra.program.model.symbol import SourceType
"#;

const GHIDRA_HELPERS: &str = r#"_program = currentProgram
_dtm = _program.getDataTypeManager()
_fm = _program.getFunctionManager()
_conventions = [c.getName() for c in _program.getCompilerSpec().getCallingConventions()]

def _type(name, decl, size, go_name):
    try:
        parsed = CParser(_dtm).parse(decl)
        if parsed is None:
            _fail('type', name, 'CParser returned None')
            return
        added = _dtm.addDataType(parsed, DataTypeConflictHandler.REPLACE_HANDLER)
        if added.getName() != name:
            _fail('type', name, 'added as {}'.format(added.getName()))
            return
        if added.getLength() != size:
            _fail('type', name, 'parsed size {} differs from the recorded {}'.format(added.getLength(), size))
            return
        added.setDescription('go: ' + go_name)
        _ok('type')
    except Exception as e:
        _fail('type', name, repr(e))

def _func(addr, name, comment):
    key = '0x{:x} {}'.format(addr, name)
    try:
        a = toAddr(addr)
        f = _fm.getFunctionAt(a)
        if f is None:
            disassemble(a)
            f = createFunction(a, name)
            if f is None:
                _fail('func', key, 'createFunction returned None')
                return
        else:
            f.setName(name, SourceType.USER_DEFINED)
        if comment:
            f.setComment(comment)
        _ok('func')
    except Exception as e:
        _fail('func', key, repr(e))

def _storage(pieces):
    # Most significant piece first. ('RAX', 8) is the low 8 bytes of a
    # register, (16, 8) is 8 bytes at entry SP + 16.
    if len(pieces) == 1 and not isinstance(pieces[0][0], str):
        return VariableStorage(_program, pieces[0][0], pieces[0][1])
    varnodes = []
    for where, size in pieces:
        if isinstance(where, str):
            varnodes.append(Varnode(_program.getRegister(where).getAddress(), size))
        else:
            varnodes.append(Varnode(_program.getAddressFactory().getStackSpace().getAddress(where), size))
    return VariableStorage(_program, *varnodes)

def _proto(addr, decl, params, result, convention):
    key = '0x{:x}'.format(addr)
    try:
        f = _fm.getFunctionAt(toAddr(addr))
        if f is None:
            _fail('proto', key, 'no function')
            return
        parsed = CParser(_dtm).parse(decl)
        args = parsed.getArguments()
        if len(args) != len(params):
            _fail('proto', key, 'parsed {} arguments, expected {}'.format(len(args), len(params)))
            return
        plist = ArrayList()
        for arg, (name, pieces) in zip(args, params):
            plist.add(ParameterImpl(name, arg.getDataType(), _storage(pieces), _program))
        if result is None:
            ret = ReturnParameterImpl(VoidDataType.dataType, VariableStorage.VOID_STORAGE, _program)
        else:
            ret = ReturnParameterImpl(parsed.getReturnType(), _storage(result), _program)
        if convention not in _conventions:
            convention = f.getCallingConventionName()
        f.updateFunction(convention, ret, plist, Function.FunctionUpdateType.CUSTOM_STORAGE, True, SourceType.USER_DEFINED)
        _ok('proto')
    except Exception as e:
        _fail('proto', key, repr(e))

def _label(addr, name):
    try:
        createLabel(toAddr(addr), name, True, SourceType.USER_DEFINED)
        _ok('label')
    except Exception as e:
        _fail('label', '0x{:x} {}'.format(addr, name), repr(e))
"#;

const BINJA_IMPORTS: &str = r#"from binaryninja import Symbol, SymbolType
"#;

const BINJA_HELPERS: &str = r#"def _type(name, decl, size, go_name):
    try:
        parsed = bv.parse_types_from_string(decl)
        for type_name, typ in parsed.types.items():
            bv.define_user_type(type_name, typ)
        typ = bv.get_type_by_name(name)
        if typ is None:
            _fail('type', name, 'not found after parsing')
            return
        if typ.width != size:
            _fail('type', name, 'parsed size {} differs from the recorded {}'.format(typ.width, size))
            return
        _ok('type')
    except Exception as e:
        _fail('type', name, repr(e))

def _func(addr, name, comment):
    try:
        bv.add_function(addr)
        bv.define_user_symbol(Symbol(SymbolType.FunctionSymbol, addr, name))
        if comment:
            f = bv.get_function_at(addr)
            if f is not None:
                f.comment = comment
        _ok('func')
    except Exception as e:
        _fail('func', '0x{:x} {}'.format(addr, name), repr(e))

def _label(addr, name):
    try:
        bv.define_user_symbol(Symbol(SymbolType.DataSymbol, addr, name))
        _ok('label')
    except Exception as e:
        _fail('label', '0x{:x} {}'.format(addr, name), repr(e))
"#;

/// The closing report every script prints.
const SUMMARY: &str = r#"for _kind, _title in (('type', 'type declarations'), ('func', 'functions'), ('proto', 'prototypes'), ('label', 'labels')):
    _ok_n, _fail_n = _stats.get(_kind, [0, 0])
    print('{generator}: applied {}/{} {} ({} failed)'.format(_ok_n, _ok_n + _fail_n, _title, _fail_n))
for _kind, _key, _reason in _failures[:20]:
    print('{generator}: failed {} {}: {}'.format(_kind, _key, _reason))
if len(_failures) > 20:
    print('{generator}: and {} more failures'.format(len(_failures) - 20))
print('{generator}: done, {} failures'.format(len(_failures)))
"#;

#[cfg(test)]
mod tests;
