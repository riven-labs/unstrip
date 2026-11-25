//! A document with the shape and field names of GoReSym's JSON output, so a
//! script or pipeline written for GoReSym reads unstrip's output.
//!
//! The schema is `ExtractMetadata` in GoReSym's `main.go` (mandiant/GoReSym
//! master, commit `fa3f0577`), as `GoReSym -t -d -p` fills it, plus `Strings`
//! as `-strings` fills it. Field names, nesting and JSON types are GoReSym's.
//! Values come from unstrip's own readers, and where those differ from what
//! GoReSym computes, `docs/USAGE.md` lists the difference.

use std::collections::{HashMap, HashSet};

use serde::Serialize;

use crate::buildinfo::BuildInfo;
use crate::gobin::GoBinary;
use crate::itabs;
use crate::moduledata::{ModuleData, SliceHeader};
use crate::pclntab::{Function, Pclntab, MAGIC_1_16, MAGIC_1_18, MAGIC_1_2, MAGIC_1_20};
use crate::types::{self, KindData, KindName, Type, TypeNames};

/// The parts of the document to fill. A part left out is `null`, as in a
/// GoReSym run without the matching flag.
#[derive(Debug, Clone, Copy)]
pub struct Config {
    /// `Types` and `Interfaces` (GoReSym `-t`).
    pub types: bool,
    /// `StdFunctions` (GoReSym `-d`).
    pub std_functions: bool,
    /// `Files` (GoReSym `-p`).
    pub files: bool,
    /// `Strings` (GoReSym `-strings`), from the string literals
    /// [`crate::strings::literals`] proves.
    pub strings: bool,
}

impl Default for Config {
    /// What `GoReSym -t -d -p` prints.
    fn default() -> Self {
        Config {
            types: true,
            std_functions: true,
            files: true,
            strings: false,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "PascalCase")]
#[non_exhaustive]
pub struct Document {
    /// The Go release without the `go` prefix: `1.22.3`.
    pub version: String,
    pub build_id: String,
    pub arch: String,
    #[serde(rename = "OS")]
    pub os: String,
    pub tab_meta: TabMeta,
    pub module_meta: ModuleMeta,
    pub types: Option<Vec<TypeEntry>>,
    pub interfaces: Option<Vec<TypeEntry>>,
    pub build_info: BuildInfoEntry,
    pub files: Option<Vec<String>>,
    pub user_functions: Option<Vec<FuncEntry>>,
    pub std_functions: Option<Vec<FuncEntry>>,
    pub strings: Option<Vec<StringEntry>>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "PascalCase")]
#[non_exhaustive]
pub struct TabMeta {
    #[serde(rename = "VA")]
    pub va: u64,
    /// The table layout: `1.2`, `1.16`, `1.18` or `1.20`.
    pub version: String,
    /// GoReSym's spelling.
    pub endianess: String,
    pub cpu_quantum: u32,
    pub cpu_quantum_str: String,
    pub pointer_size: u32,
}

#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "PascalCase")]
#[non_exhaustive]
pub struct ModuleMeta {
    #[serde(rename = "VA")]
    pub va: u64,
    #[serde(rename = "TextVA")]
    pub text_va: u64,
    pub types: u64,
    #[serde(rename = "ETypes")]
    pub etypes: u64,
    pub typelinks: GoSlice,
    #[serde(rename = "ITablinks")]
    pub itablinks: GoSlice,
    /// The Go 1.5 and 1.6 type list. unstrip reads types from Go 1.7, so this
    /// is always zero.
    pub legacy_types: GoSlice,
}

#[derive(Debug, Clone, Copy, Default, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct GoSlice {
    pub data: u64,
    pub len: u64,
    pub capacity: u64,
}

#[derive(Debug, Clone, Serialize)]
#[non_exhaustive]
pub struct TypeEntry {
    #[serde(rename = "VA")]
    pub va: u64,
    /// The type as `reflect.Type.String()` gives it.
    #[serde(rename = "Str")]
    pub name: String,
    /// `Str` made into a C identifier the way GoReSym's `typename_to_c` does.
    #[serde(rename = "CStr")]
    pub c_name: String,
    #[serde(rename = "Kind")]
    pub kind: &'static str,
    /// The Go declaration of a struct or interface type.
    #[serde(rename = "Reconstructed", skip_serializing_if = "String::is_empty")]
    pub reconstructed: String,
}

/// `debug.BuildInfo` as GoReSym serializes it.
#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "PascalCase")]
#[non_exhaustive]
pub struct BuildInfoEntry {
    pub go_version: String,
    pub path: String,
    pub main: ModuleEntry,
    pub deps: Option<Vec<ModuleEntry>>,
    pub settings: Option<Vec<SettingEntry>>,
}

#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "PascalCase")]
#[non_exhaustive]
pub struct ModuleEntry {
    pub path: String,
    pub version: String,
    pub sum: String,
    pub replace: Option<Box<ModuleEntry>>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "PascalCase")]
#[non_exhaustive]
pub struct SettingEntry {
    pub key: String,
    pub value: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "PascalCase")]
#[non_exhaustive]
pub struct FuncEntry {
    pub start: u64,
    /// The next function's entry, as `debug/gosym` gives `Func.End`.
    pub end: u64,
    pub package_name: String,
    pub full_name: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "PascalCase")]
#[non_exhaustive]
pub struct StringEntry {
    pub str: String,
    pub start: u64,
}

/// Builds the document. A part that does not read (no moduledata, no type
/// table) is left at its zero value or `null`, as GoReSym leaves it.
pub fn document(bin: &GoBinary, pcln: &Pclntab<'_>, config: Config) -> Document {
    let functions = pcln.functions().unwrap_or_default();
    let info = BuildInfo::parse(bin).ok();
    let triage = crate::triage::triage(bin, pcln, &functions);
    let version = triage
        .go_version
        .as_deref()
        .map(|v| v.strip_prefix("go").unwrap_or(v).to_string())
        .unwrap_or_default();

    let md = ModuleData::locate(bin).ok();
    let (types, interfaces) = match (&md, config.types) {
        (Some(md), true) => match type_entries(bin, md) {
            Some((types, interfaces)) => (Some(types), Some(interfaces)),
            None => (None, None),
        },
        _ => (None, None),
    };

    let table_version = table_version(pcln);
    let mut user_functions: Vec<FuncEntry> = Vec::new();
    let mut std_functions: Vec<FuncEntry> = Vec::new();
    for f in &functions {
        let entry = func_entry(f, table_version);
        if is_std_package(&entry.package_name) {
            std_functions.push(entry);
        } else {
            user_functions.push(entry);
        }
    }

    let strings = if config.strings {
        let literals = crate::strings::literals(bin, pcln).ok();
        let entries = literals
            .into_iter()
            .flat_map(|l| l.literals)
            .filter_map(|l| {
                Some(StringEntry {
                    str: l.text?,
                    start: l.addr,
                })
            })
            .collect();
        Some(entries)
    } else {
        None
    };

    let quantum = pcln.quantum() as u32;
    Document {
        version,
        build_id: triage.build_id.unwrap_or_default(),
        arch: triage.goarch.unwrap_or_default(),
        os: triage.goos.unwrap_or_default(),
        tab_meta: TabMeta {
            va: bin.pclntab_addr,
            version: table_version.to_string(),
            endianess: if bin.little_endian {
                "LittleEndian"
            } else {
                "BigEndian"
            }
            .to_string(),
            cpu_quantum: quantum,
            cpu_quantum_str: match quantum {
                2 => "s390x",
                4 => "arm/mips/ppc/riscv",
                _ => "x86/x64/wasm",
            }
            .to_string(),
            pointer_size: pcln.ptrsize() as u32,
        },
        module_meta: match &md {
            Some(md) => ModuleMeta {
                va: md.addr,
                text_va: md.text,
                types: md.types,
                etypes: md.etypes,
                typelinks: go_slice(md.typelinks),
                itablinks: go_slice(md.itablinks),
                legacy_types: GoSlice::default(),
            },
            None => ModuleMeta::default(),
        },
        types,
        interfaces,
        build_info: info.as_ref().map(build_info_entry).unwrap_or_default(),
        files: if config.files {
            Some(pcln.files())
        } else {
            None
        },
        user_functions: Some(user_functions),
        std_functions: if config.std_functions {
            Some(std_functions)
        } else {
            None
        },
        strings,
    }
}

/// The recovered types, every one once, and what GoReSym lists as
/// interfaces: for each itab, the types reached from its interface and its
/// concrete type, then an entry for the itab itself.
/// None when the type table does not read (big-endian binaries, which the
/// type reader does not support).
fn type_entries(bin: &GoBinary, md: &ModuleData) -> Option<(Vec<TypeEntry>, Vec<TypeEntry>)> {
    let ps = bin.ptr_size;
    let itabs = itabs::recover_all(bin, md).unwrap_or_default();
    // An itab starts with its interface type and its concrete type.
    let word = |w: &[u8]| match (ps, bin.little_endian) {
        (8, true) => u64::from_le_bytes(w.try_into().unwrap_or_default()),
        (8, false) => u64::from_be_bytes(w.try_into().unwrap_or_default()),
        (_, true) => u32::from_le_bytes(w.try_into().unwrap_or_default()) as u64,
        (_, false) => u32::from_be_bytes(w.try_into().unwrap_or_default()) as u64,
    };
    let mut pairs: Vec<(u64, u64, u64)> = Vec::new();
    for itab in &itabs {
        let Some(words) = bin.read_at_addr(itab.addr, 2 * ps) else {
            continue;
        };
        pairs.push((itab.addr, word(&words[..ps]), word(&words[ps..])));
    }
    let roots: Vec<u64> = pairs.iter().flat_map(|&(_, i, c)| [i, c]).collect();
    let recovered = types::recover_with_roots(bin, md, types::Mode::Focused, &roots).ok()?;
    let names = TypeNames::new(&recovered);
    let by_addr: HashMap<u64, &Type> = recovered.iter().map(|t| (t.addr, t)).collect();
    let entries: Vec<TypeEntry> = recovered
        .iter()
        .map(|t| type_entry(t, &names, &by_addr))
        .collect();
    let entry_at: HashMap<u64, &TypeEntry> = entries.iter().map(|e| (e.va, e)).collect();

    // GoReSym walks each itab's two types through their elements, fields,
    // interface methods, parameters, maps' bucket types and arrays' slice
    // types, and lists every type it meets. It
    // repeats a type each time a walk meets it; here each is listed once.
    let mut interfaces: Vec<TypeEntry> = Vec::new();
    let mut listed: HashSet<u64> = HashSet::new();
    for &(itab, inter, concrete) in &pairs {
        let mut stack = vec![concrete, inter];
        while let Some(addr) = stack.pop() {
            let (Some(t), Some(entry)) = (by_addr.get(&addr), entry_at.get(&addr)) else {
                continue;
            };
            if !listed.insert(addr) {
                continue;
            }
            interfaces.push((*entry).clone());
            let children: Vec<u64> = match &t.kind_data {
                KindData::Pointer { elem } | KindData::Slice { elem } => vec![*elem],
                // An array type also points at the slice type of its element,
                // right after the element (`arraytype.slice`).
                KindData::Array { elem, .. } => {
                    let slice_at = addr + (types::type_header_size(ps) + ps) as u64;
                    match bin.read_at_addr(slice_at, ps) {
                        Some(w) => vec![*elem, word(w)],
                        None => vec![*elem],
                    }
                }
                KindData::Chan { elem, .. } => vec![*elem],
                KindData::Map { key, elem, bucket } => [Some(*key), Some(*elem), *bucket]
                    .into_iter()
                    .flatten()
                    .collect(),
                KindData::Struct { fields } => fields.iter().map(|f| f.typ).collect(),
                KindData::Interface { methods } => methods.iter().map(|m| m.typ).collect(),
                KindData::Func {
                    in_types,
                    out_types,
                    ..
                } => in_types.iter().chain(out_types).copied().collect(),
                _ => Vec::new(),
            };
            stack.extend(children.into_iter().rev());
        }
        let (Some(i), Some(c)) = (by_addr.get(&inter), by_addr.get(&concrete)) else {
            continue;
        };
        interfaces.push(TypeEntry {
            va: itab,
            name: format!("interface_{}_impl_{}", i.name, c.name),
            c_name: String::new(),
            kind: "Interface",
            reconstructed: String::new(),
        });
    }
    Some((entries, interfaces))
}

fn type_entry(t: &Type, names: &TypeNames<'_>, by_addr: &HashMap<u64, &Type>) -> TypeEntry {
    let reconstructed = match &t.kind_data {
        KindData::Struct { fields } => {
            let mut out = format!("type {} struct {{\n", t.name);
            for field in fields {
                out.push_str("    ");
                out.push_str(&names.field(field));
                out.push('\n');
            }
            out.push('}');
            out
        }
        KindData::Interface { methods } => {
            let mut out = format!("type {} interface {{\n", t.name);
            for method in methods {
                out.push_str("    ");
                out.push_str(&method.name);
                out.push_str(&names.signature(method.typ));
                out.push('\n');
            }
            out.push('}');
            out
        }
        _ => String::new(),
    };
    TypeEntry {
        va: t.addr,
        name: t.name.clone(),
        c_name: c_name(t, by_addr, 0),
        kind: kind_name(t.kind),
        reconstructed,
    }
}

/// GoReSym's `CStr`: [`typename_to_c`] of the name, except that a func type
/// is written as a C prototype, `ret (arg, arg)` (`void` for none,
/// `tuple(a, b)` for several results, `, ...` when variadic), and a channel
/// as `chan_` and its element.
fn c_name(t: &Type, by_addr: &HashMap<u64, &Type>, depth: usize) -> String {
    const MAX_DEPTH: usize = 32;
    let named = |addr: &u64| match by_addr.get(addr) {
        Some(t) if depth < MAX_DEPTH => c_name(t, by_addr, depth + 1),
        Some(t) => typename_to_c(&t.name),
        None => "void*".to_string(),
    };
    match &t.kind_data {
        KindData::Func {
            in_types,
            out_types,
            variadic,
            ..
        } => {
            let ins: Vec<String> = in_types.iter().map(named).collect();
            let outs: Vec<String> = out_types.iter().map(named).collect();
            let ret = match outs.len() {
                0 => "void".to_string(),
                1 => outs[0].clone(),
                _ => format!("tuple({})", outs.join(", ")),
            };
            let mut args = ins.join(", ");
            if args.is_empty() {
                args.push_str("void");
            } else if *variadic {
                args.push_str(", ...");
            }
            format!("{ret} ({args})")
        }
        KindData::Chan { elem, .. } => format!("chan_{}", named(elem)),
        _ => typename_to_c(&t.name),
    }
}

/// GoReSym's `typename_to_c`, replacement for replacement.
fn typename_to_c(name: &str) -> String {
    name.replace('*', "_ptr_")
        .replace("[]", "_slice_")
        .replace("<-", "_chan_left_")
        .replace(['.', '[', ']', ' '], "_")
        .replace("{}", "")
}

/// GoReSym's `Kind.String()` names, which are `reflect.Kind`'s capitalized,
/// with `Pointer` for `Ptr`.
fn kind_name(kind: KindName) -> &'static str {
    match kind {
        KindName::Bool => "Bool",
        KindName::Int => "Int",
        KindName::Int8 => "Int8",
        KindName::Int16 => "Int16",
        KindName::Int32 => "Int32",
        KindName::Int64 => "Int64",
        KindName::Uint => "Uint",
        KindName::Uint8 => "Uint8",
        KindName::Uint16 => "Uint16",
        KindName::Uint32 => "Uint32",
        KindName::Uint64 => "Uint64",
        KindName::Uintptr => "Uintptr",
        KindName::Float32 => "Float32",
        KindName::Float64 => "Float64",
        KindName::Complex64 => "Complex64",
        KindName::Complex128 => "Complex128",
        KindName::Array => "Array",
        KindName::Chan => "Chan",
        KindName::Func => "Func",
        KindName::Interface => "Interface",
        KindName::Map => "Map",
        KindName::Pointer => "Pointer",
        KindName::Slice => "Slice",
        KindName::String => "String",
        KindName::Struct => "Struct",
        KindName::UnsafePointer => "UnsafePointer",
        KindName::Invalid | KindName::Unknown(_) => "Invalid",
    }
}

fn go_slice(s: SliceHeader) -> GoSlice {
    GoSlice {
        data: s.data,
        len: s.len,
        capacity: s.cap,
    }
}

/// The table layout as GoReSym's `version.String()` names it. A magic no
/// Go release writes (garble rewrites it) is named for the layout the table
/// has, as GoReSym's parser does: the 1.18 and 1.20 layouts are the same
/// table, and GoReSym calls it `1.20`.
fn table_version(pcln: &Pclntab<'_>) -> &'static str {
    match pcln.magic() {
        MAGIC_1_2 => "1.2",
        MAGIC_1_16 => "1.16",
        MAGIC_1_18 => "1.18",
        MAGIC_1_20 => "1.20",
        _ if pcln.is_go118_or_later() => "1.20",
        _ if pcln.is_go116_or_go117() => "1.16",
        _ => "1.2",
    }
}

fn func_entry(f: &Function, table_version: &str) -> FuncEntry {
    FuncEntry {
        start: f.address,
        end: f.address.saturating_add(f.size.unwrap_or(0)),
        package_name: package_name(&f.name, table_version),
        full_name: f.name.clone(),
    }
}

/// `debug/gosym`'s `Sym.PackageName`, which GoReSym reports: the name without
/// its type arguments, up to the first dot after the last slash. Compiler
/// symbols (`go:` and `type:` from Go 1.20, `go.` and `type.` up to 1.18)
/// belong to no package.
fn package_name(name: &str, table_version: &str) -> String {
    let name = match (name.find('['), name.rfind(']')) {
        (Some(open), Some(close)) if open < close => {
            format!("{}{}", &name[..open], &name[close + 1..])
        }
        _ => name.to_string(),
    };
    let compiler_prefixes: &[&str] = match table_version {
        "1.20" => &["go:", "type:"],
        _ => &["go.", "type."],
    };
    if compiler_prefixes.iter().any(|p| name.starts_with(p)) {
        return String::new();
    }
    let path_end = name.rfind('/').unwrap_or(0);
    match name[path_end..].find('.') {
        Some(dot) => name[..path_end + dot].to_string(),
        None => String::new(),
    }
}

/// Whether a package belongs to the Go distribution: its first path element
/// is one of the standard library's top-level directories. A symbol with no
/// package (compiler-generated) counts as standard, as in GoReSym. A garbled
/// package name matches none, so it is a user package, as in GoReSym.
fn is_std_package(package: &str) -> bool {
    // The top-level directories of `$GOROOT/src` that hold packages, Go 1.2
    // to 1.27. `vendor` holds the copies of golang.org/x the library uses.
    const STD_ROOTS: &[&str] = &[
        "archive",
        "bufio",
        "bytes",
        "cmp",
        "compress",
        "container",
        "context",
        "crypto",
        "database",
        "debug",
        "embed",
        "encoding",
        "errors",
        "expvar",
        "flag",
        "fmt",
        "go",
        "hash",
        "html",
        "image",
        "index",
        "internal",
        "io",
        "iter",
        "log",
        "maps",
        "math",
        "mime",
        "net",
        "os",
        "path",
        "plugin",
        "reflect",
        "regexp",
        "runtime",
        "slices",
        "sort",
        "strconv",
        "strings",
        "structs",
        "sync",
        "syscall",
        "testing",
        "text",
        "time",
        "unicode",
        "unique",
        "unsafe",
        "vendor",
        "weak",
    ];
    if package.is_empty() {
        return true;
    }
    let first = package.split('/').next().unwrap_or(package);
    STD_ROOTS.contains(&first)
}

fn build_info_entry(info: &BuildInfo) -> BuildInfoEntry {
    let module_entry = |m: &crate::buildinfo::Module| {
        let replace = info
            .replaces
            .iter()
            .find(|r| r.from.path == m.path && r.from.version == m.version)
            .map(|r| {
                Box::new(ModuleEntry {
                    path: r.to.path.clone(),
                    version: r.to.version.clone(),
                    sum: r.to.sum.clone().unwrap_or_default(),
                    replace: None,
                })
            });
        ModuleEntry {
            path: m.path.clone(),
            version: m.version.clone(),
            sum: m.sum.clone().unwrap_or_default(),
            replace,
        }
    };
    let deps: Vec<ModuleEntry> = info.deps.iter().map(module_entry).collect();
    let settings: Vec<SettingEntry> = info
        .settings
        .iter()
        .map(|s| SettingEntry {
            key: s.key.clone(),
            value: s.value.clone(),
        })
        .collect();
    BuildInfoEntry {
        go_version: info.go_version.clone(),
        path: info.path.clone().unwrap_or_default(),
        main: info.main.as_ref().map(module_entry).unwrap_or_default(),
        deps: if deps.is_empty() { None } else { Some(deps) },
        settings: if settings.is_empty() {
            None
        } else {
            Some(settings)
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn package_names_follow_debug_gosym() {
        let cases = [
            ("main.main", "1.20", "main"),
            ("github.com/a/b.(*T).M", "1.20", "github.com/a/b"),
            ("example.com/x/y.F[...]", "1.20", "example.com/x/y"),
            ("slices.Sort[go.shape.[]a/b.T]", "1.20", "slices"),
            ("type:.eq.main.T", "1.20", ""),
            ("go:buildid", "1.20", ""),
            ("type..eq.main.T", "1.16", ""),
            ("go.uber.org/zap.New", "1.20", "go.uber.org/zap"),
            ("runtime.morestack", "1.2", "runtime"),
            ("go.uber.org/zap.New", "1.16", ""),
            ("_rt0_amd64_linux", "1.20", ""),
        ];
        for (name, table, want) in cases {
            assert_eq!(package_name(name, table), want, "{name} on a {table} table");
        }
    }

    #[test]
    fn std_is_a_standard_library_root() {
        assert!(is_std_package("runtime"));
        assert!(is_std_package("internal/runtime/sys"));
        assert!(is_std_package("vendor/golang.org/x/net/dns/dnsmessage"));
        assert!(
            is_std_package(""),
            "compiler symbols count as std, as in GoReSym"
        );
        assert!(!is_std_package("main"));
        assert!(!is_std_package("github.com/spf13/cobra"));
        assert!(
            !is_std_package("myapp/internal/config"),
            "a module path without a dot"
        );
        assert!(!is_std_package("iz6vkWmjF"), "a garbled package");
    }

    #[test]
    fn c_names_match_goresym() {
        assert_eq!(typename_to_c("*[1024]uintptr"), "_ptr__1024_uintptr");
        assert_eq!(typename_to_c("helper.Codec"), "helper_Codec");
        assert_eq!(typename_to_c("map[string]int"), "map_string_int");
        assert_eq!(typename_to_c("[]*main.T"), "_slice__ptr_main_T");
        assert_eq!(typename_to_c("interface {}"), "interface_");
    }

    #[test]
    fn top_level_names_are_goresyms() {
        let doc = Document {
            version: String::new(),
            build_id: String::new(),
            arch: String::new(),
            os: String::new(),
            tab_meta: TabMeta {
                va: 0,
                version: String::new(),
                endianess: String::new(),
                cpu_quantum: 1,
                cpu_quantum_str: String::new(),
                pointer_size: 8,
            },
            module_meta: ModuleMeta::default(),
            types: None,
            interfaces: None,
            build_info: BuildInfoEntry::default(),
            files: None,
            user_functions: None,
            std_functions: None,
            strings: None,
        };
        let value = serde_json::to_value(&doc).unwrap();
        let keys: Vec<&str> = value
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        let mut want = vec![
            "Version",
            "BuildId",
            "Arch",
            "OS",
            "TabMeta",
            "ModuleMeta",
            "Types",
            "Interfaces",
            "BuildInfo",
            "Files",
            "UserFunctions",
            "StdFunctions",
            "Strings",
        ];
        let mut got = keys.clone();
        got.sort();
        want.sort();
        assert_eq!(got, want);
        let module_meta = value["ModuleMeta"].as_object().unwrap();
        for key in [
            "VA",
            "TextVA",
            "Types",
            "ETypes",
            "Typelinks",
            "ITablinks",
            "LegacyTypes",
        ] {
            assert!(module_meta.contains_key(key), "ModuleMeta.{key}");
        }
        for key in [
            "VA",
            "Version",
            "Endianess",
            "CpuQuantum",
            "CpuQuantumStr",
            "PointerSize",
        ] {
            assert!(value["TabMeta"].get(key).is_some(), "TabMeta.{key}");
        }
        let main = &value["BuildInfo"]["Main"];
        assert!(main["Replace"].is_null() && main.get("Sum").is_some());
        assert!(value["BuildInfo"]["Deps"].is_null());
    }
}
