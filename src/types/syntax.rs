//! Go-syntax names for a recovered type set.
//!
//! The compiler stores every type's `reflect.Type.String()` form in the
//! binary (`*main.Node`, `map[string][]uint8`, `func([]uint8) (int, error)`),
//! so most references render as the referenced type's own name. That form
//! writes a package by its name, not its path, and two packages can share a
//! name: from Go 1.24 `sync.Mutex` holds an `internal/sync.Mutex`, and both
//! print as `sync.Mutex`. Where named types collide like that, the collided
//! ones are written with their import path, and every unnamed type that
//! mentions one is rebuilt from its parts so the path shows there too.

use std::collections::{HashMap, HashSet};

use super::{KindData, StructField, Type};

/// Unnamed types nest no deeper than this in real code; the cap stops a
/// crafted cycle of unnamed types from recursing without end.
const MAX_DEPTH: usize = 64;

/// Renders type references in a recovered type set as Go source would write
/// them. References to a type outside the set render as `type@0x...`.
#[derive(Debug)]
pub struct TypeNames<'a> {
    by_addr: HashMap<u64, &'a Type>,
    /// Named types written with their import path: another named type in
    /// the set has the same name and a different package path.
    qualified: HashSet<u64>,
    /// Unnamed types that mention a qualified type somewhere inside, so
    /// their stored name would hide the path.
    rebuilt: HashSet<u64>,
}

impl<'a> TypeNames<'a> {
    pub fn new(types: &'a [Type]) -> Self {
        let by_addr: HashMap<u64, &Type> = types.iter().map(|t| (t.addr, t)).collect();

        let mut paths_by_name: HashMap<&str, HashSet<&str>> = HashMap::new();
        for t in types.iter().filter(|t| t.named) {
            paths_by_name
                .entry(t.name.as_str())
                .or_default()
                .insert(t.pkg_path.as_str());
        }
        let qualified: HashSet<u64> = types
            .iter()
            .filter(|t| {
                t.named && !t.pkg_path.is_empty() && paths_by_name[t.name.as_str()].len() > 1
            })
            .map(|t| t.addr)
            .collect();

        let mut names = TypeNames {
            by_addr,
            qualified,
            rebuilt: HashSet::new(),
        };
        if !names.qualified.is_empty() {
            let mut memo = HashMap::new();
            for t in types {
                if !t.named && names.mentions_qualified(t.addr, &mut memo, 0) {
                    names.rebuilt.insert(t.addr);
                }
            }
        }
        names
    }

    /// The type at `addr` as Go source writes it: `*main.Node`,
    /// `[]main.Item`, `internal/sync.Mutex` where the package name alone is
    /// ambiguous.
    pub fn name(&self, addr: u64) -> String {
        let mut out = String::new();
        self.write_name(addr, &mut out, 0);
        out
    }

    /// The signature of the func type at `addr` without the `func` keyword:
    /// `([]uint8) ([]uint8, error)`, as an interface method is declared.
    pub fn signature(&self, addr: u64) -> String {
        let mut out = String::new();
        self.write_signature(addr, &mut out, 0);
        out
    }

    /// A struct field as declared in Go source: `Next *main.Node`, the bare
    /// type for an embedded field, and the tag in backquotes.
    pub fn field(&self, field: &StructField) -> String {
        let mut out = String::new();
        if !field.embedded {
            out.push_str(&field.name);
            out.push(' ');
        }
        self.write_name(field.typ, &mut out, 0);
        if !field.tag.is_empty() {
            out.push(' ');
            if field.tag.contains('`') {
                out.push_str(&quote(&field.tag));
            } else {
                out.push('`');
                out.push_str(&field.tag);
                out.push('`');
            }
        }
        out
    }

    fn mentions_qualified(&self, addr: u64, memo: &mut HashMap<u64, bool>, depth: usize) -> bool {
        if self.qualified.contains(&addr) {
            return true;
        }
        if let Some(&known) = memo.get(&addr) {
            return known;
        }
        let Some(t) = self.by_addr.get(&addr) else {
            return false;
        };
        if t.named || depth > MAX_DEPTH {
            return false;
        }
        // Seeded false so a cycle back to this type ends the walk.
        memo.insert(addr, false);
        let found = super::child_addrs(&t.kind_data)
            .into_iter()
            .any(|child| self.mentions_qualified(child, memo, depth + 1));
        memo.insert(addr, found);
        found
    }

    fn write_name(&self, addr: u64, out: &mut String, depth: usize) {
        let Some(t) = self.by_addr.get(&addr) else {
            out.push_str(&format!("type@0x{addr:x}"));
            return;
        };
        if self.qualified.contains(&addr) {
            out.push_str(&qualify(&t.name, &t.pkg_path));
            return;
        }
        if !self.rebuilt.contains(&addr) || depth > MAX_DEPTH || !reads_as_syntax(t) {
            out.push_str(&t.name);
            return;
        }
        let depth = depth + 1;
        match &t.kind_data {
            KindData::Pointer { elem } => {
                out.push('*');
                self.write_name(*elem, out, depth);
            }
            KindData::Slice { elem } => {
                out.push_str("[]");
                self.write_name(*elem, out, depth);
            }
            KindData::Array { elem, len } => {
                out.push_str(&format!("[{len}]"));
                self.write_name(*elem, out, depth);
            }
            KindData::Chan { elem, dir } => {
                // reflect.ChanDir: RecvDir 1, SendDir 2, BothDir 3. A
                // bidirectional chan of a receive-only chan needs parentheses
                // (`chan (<-chan int)`), or it would read as `chan<- chan int`.
                let recv_elem = self.by_addr.get(elem).is_some_and(|e| {
                    !e.named && matches!(e.kind_data, KindData::Chan { dir: 1, .. })
                });
                match dir {
                    1 => out.push_str("<-chan "),
                    2 => out.push_str("chan<- "),
                    _ => out.push_str("chan "),
                }
                if *dir == 3 && recv_elem {
                    out.push('(');
                    self.write_name(*elem, out, depth);
                    out.push(')');
                } else {
                    self.write_name(*elem, out, depth);
                }
            }
            KindData::Map { key, elem, .. } => {
                out.push_str("map[");
                self.write_name(*key, out, depth);
                out.push(']');
                self.write_name(*elem, out, depth);
            }
            KindData::Func { .. } => {
                out.push_str("func");
                self.write_signature(addr, out, depth);
            }
            KindData::Struct { fields } => {
                if fields.is_empty() {
                    out.push_str("struct {}");
                    return;
                }
                out.push_str("struct { ");
                for (i, field) in fields.iter().enumerate() {
                    if i > 0 {
                        out.push_str("; ");
                    }
                    if !field.embedded {
                        // Closure context structs name the code pointer
                        // `.F`; the compiler's string drops the dot.
                        out.push_str(field.name.trim_start_matches('.'));
                        out.push(' ');
                    }
                    self.write_name(field.typ, out, depth);
                    if !field.tag.is_empty() {
                        out.push(' ');
                        out.push_str(&quote(&field.tag));
                    }
                }
                out.push_str(" }");
            }
            KindData::Interface { methods } => {
                if methods.is_empty() {
                    out.push_str("interface {}");
                    return;
                }
                out.push_str("interface { ");
                for (i, method) in methods.iter().enumerate() {
                    if i > 0 {
                        out.push_str("; ");
                    }
                    out.push_str(&method.name);
                    self.write_signature(method.typ, out, depth);
                }
                out.push_str(" }");
            }
            KindData::None => out.push_str(&t.name),
        }
    }

    fn write_signature(&self, addr: u64, out: &mut String, depth: usize) {
        let func = self.by_addr.get(&addr);
        let stored = func.and_then(|t| t.name.strip_prefix("func"));
        if let Some(stored) = stored {
            if !self.rebuilt.contains(&addr) || depth > MAX_DEPTH {
                out.push_str(stored);
                return;
            }
        }
        let Some(KindData::Func {
            in_count,
            out_count,
            variadic,
            in_types,
            out_types,
        }) = func.map(|t| &t.kind_data)
        else {
            out.push_str(&format!("(type@0x{addr:x})"));
            return;
        };
        if in_types.len() != *in_count as usize || out_types.len() != *out_count as usize {
            out.push_str(&format!("(type@0x{addr:x})"));
            return;
        }
        let depth = depth + 1;
        out.push('(');
        for (i, param) in in_types.iter().enumerate() {
            if i > 0 {
                out.push_str(", ");
            }
            let last = i + 1 == in_types.len();
            let elem = match self.by_addr.get(param).map(|t| &t.kind_data) {
                Some(KindData::Slice { elem }) if *variadic && last => Some(*elem),
                _ => None,
            };
            match elem {
                Some(elem) => {
                    out.push_str("...");
                    self.write_name(elem, out, depth);
                }
                None => self.write_name(*param, out, depth),
            }
        }
        out.push(')');
        match out_types.as_slice() {
            [] => (),
            [result] => {
                out.push(' ');
                self.write_name(*result, out, depth);
            }
            results => {
                out.push_str(" (");
                for (i, result) in results.iter().enumerate() {
                    if i > 0 {
                        out.push_str(", ");
                    }
                    self.write_name(*result, out, depth);
                }
                out.push(')');
            }
        }
    }
}

/// Whether the stored name of unnamed `t` is the Go syntax of its kind. The
/// compiler's own map buckets and groups are unnamed structs that carry a
/// name instead (`map.bucket[string]int`, `map.group[string]int`); those
/// keep it.
fn reads_as_syntax(t: &Type) -> bool {
    let prefix = match t.kind_data {
        KindData::Pointer { .. } => "*",
        KindData::Slice { .. } => "[]",
        KindData::Array { .. } => "[",
        KindData::Chan { .. } => return t.name.starts_with("chan") || t.name.starts_with("<-chan"),
        KindData::Map { .. } => "map[",
        KindData::Func { .. } => "func(",
        KindData::Struct { .. } => "struct {",
        KindData::Interface { .. } => "interface {",
        KindData::None => return false,
    };
    t.name.starts_with(prefix)
}

/// `name` with its package written as `pkg_path`: `sync.Mutex` from
/// `internal/sync` gives `internal/sync.Mutex`. The package is the text up to
/// the first dot outside a generic's type arguments.
fn qualify(name: &str, pkg_path: &str) -> String {
    let head = name.split('[').next().unwrap_or(name);
    match head.find('.') {
        Some(dot) => format!("{pkg_path}{}", &name[dot..]),
        None => name.to_string(),
    }
}

/// A Go interpreted string literal, as `strconv.Quote` writes a struct tag
/// inside a type's name.
fn quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\t' => out.push_str("\\t"),
            '\r' => out.push_str("\\r"),
            c if (c as u32) < 0x20 || c == '\u{7f}' => {
                out.push_str(&format!("\\x{:02x}", c as u32))
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::types::{InterfaceMethod, KindName};

    fn named(addr: u64, name: &str, pkg_path: &str, kind: KindName, kind_data: KindData) -> Type {
        Type {
            addr,
            name: name.to_string(),
            pkg_path: pkg_path.to_string(),
            named: true,
            kind,
            kind_data,
            ..Default::default()
        }
    }

    fn unnamed(addr: u64, name: &str, kind: KindName, kind_data: KindData) -> Type {
        Type {
            addr,
            name: name.to_string(),
            kind,
            kind_data,
            ..Default::default()
        }
    }

    fn field(name: &str, typ: u64, tag: &str, embedded: bool) -> StructField {
        StructField {
            name: name.to_string(),
            typ,
            offset: 0,
            embedded,
            tag: tag.to_string(),
        }
    }

    fn func(addr: u64, name: &str, ins: &[u64], outs: &[u64], variadic: bool) -> Type {
        unnamed(
            addr,
            name,
            KindName::Func,
            KindData::Func {
                in_count: ins.len() as u16,
                out_count: outs.len() as u16,
                variadic,
                in_types: ins.to_vec(),
                out_types: outs.to_vec(),
            },
        )
    }

    /// `main.Node`, `string`, `error`, `uint8`, `[]uint8`, `*main.Node` and
    /// `func([]uint8) ([]uint8, error)` at small addresses.
    fn base() -> Vec<Type> {
        vec![
            named(1, "string", "", KindName::String, KindData::None),
            named(
                2,
                "error",
                "",
                KindName::Interface,
                KindData::Interface {
                    methods: Vec::new(),
                },
            ),
            named(3, "uint8", "", KindName::Uint8, KindData::None),
            unnamed(4, "[]uint8", KindName::Slice, KindData::Slice { elem: 3 }),
            named(
                5,
                "main.Node",
                "main",
                KindName::Struct,
                KindData::Struct {
                    fields: vec![
                        field("Next", 6, "", false),
                        field("C2", 1, r#"json:"c2""#, false),
                    ],
                },
            ),
            unnamed(
                6,
                "*main.Node",
                KindName::Pointer,
                KindData::Pointer { elem: 5 },
            ),
            func(7, "func([]uint8) ([]uint8, error)", &[4], &[4, 2], false),
        ]
    }

    #[test]
    fn references_render_as_the_stored_go_names() {
        let types = base();
        let names = TypeNames::new(&types);
        let KindData::Struct { fields } = &types[4].kind_data else {
            unreachable!()
        };
        assert_eq!(names.field(&fields[0]), "Next *main.Node");
        assert_eq!(names.field(&fields[1]), "C2 string `json:\"c2\"`");
        assert_eq!(names.signature(7), "([]uint8) ([]uint8, error)");
        assert_eq!(
            names.name(99),
            "type@0x63",
            "a type outside the set keeps its address"
        );
    }

    #[test]
    fn colliding_names_are_written_with_their_import_path() {
        let mut types = base();
        types.push(named(
            10,
            "sync.Mutex",
            "sync",
            KindName::Struct,
            KindData::Struct { fields: vec![] },
        ));
        types.push(named(
            11,
            "sync.Mutex",
            "internal/sync",
            KindName::Struct,
            KindData::Struct { fields: vec![] },
        ));
        types.push(unnamed(
            12,
            "*sync.Mutex",
            KindName::Pointer,
            KindData::Pointer { elem: 11 },
        ));
        types.push(unnamed(
            13,
            "[]*sync.Mutex",
            KindName::Slice,
            KindData::Slice { elem: 12 },
        ));
        types.push(unnamed(
            14,
            "map[string]*sync.Mutex",
            KindName::Map,
            KindData::Map {
                key: 1,
                elem: 12,
                bucket: None,
            },
        ));
        types.push(func(15, "func(...*sync.Mutex) error", &[13], &[2], true));
        types.push(unnamed(
            16,
            "interface { Lock(*sync.Mutex) }",
            KindName::Interface,
            KindData::Interface {
                methods: vec![InterfaceMethod {
                    name: "Lock".into(),
                    typ: 17,
                }],
            },
        ));
        types.push(func(17, "func(*sync.Mutex)", &[12], &[], false));
        types.push(unnamed(
            18,
            "struct { sync.Mutex; N string \"n\" }",
            KindName::Struct,
            KindData::Struct {
                fields: vec![field("Mutex", 11, "", true), field("N", 1, "n", false)],
            },
        ));
        let names = TypeNames::new(&types);
        assert_eq!(
            names.name(10),
            "sync.Mutex",
            "the stdlib one keeps its short name: path and name agree"
        );
        assert_eq!(names.name(11), "internal/sync.Mutex");
        assert_eq!(names.name(12), "*internal/sync.Mutex");
        assert_eq!(names.name(13), "[]*internal/sync.Mutex");
        assert_eq!(names.name(14), "map[string]*internal/sync.Mutex");
        assert_eq!(names.name(15), "func(...*internal/sync.Mutex) error");
        assert_eq!(names.name(16), "interface { Lock(*internal/sync.Mutex) }");
        assert_eq!(
            names.name(18),
            "struct { internal/sync.Mutex; N string \"n\" }"
        );
        assert_eq!(
            names.name(6),
            "*main.Node",
            "types away from the collision keep the stored name"
        );
    }

    #[test]
    fn rebuilt_names_match_the_stored_ones() {
        // With a collision present every unnamed type that mentions it is
        // rebuilt; the rebuild must agree with the compiler's own form for
        // the parts that are not qualified.
        let mut types = base();
        types.push(named(20, "x.T", "a/x", KindName::Int, KindData::None));
        types.push(named(21, "x.T", "b/x", KindName::Int, KindData::None));
        types.push(unnamed(
            22,
            "chan int",
            KindName::Chan,
            KindData::Chan { elem: 30, dir: 3 },
        ));
        types.push(named(30, "int", "", KindName::Int, KindData::None));
        types.push(unnamed(
            23,
            "<-chan int",
            KindName::Chan,
            KindData::Chan { elem: 30, dir: 1 },
        ));
        types.push(unnamed(
            24,
            "chan (<-chan int)",
            KindName::Chan,
            KindData::Chan { elem: 23, dir: 3 },
        ));
        types.push(unnamed(
            25,
            "chan<- int",
            KindName::Chan,
            KindData::Chan { elem: 30, dir: 2 },
        ));
        types.push(unnamed(
            26,
            "[4]int",
            KindName::Array,
            KindData::Array { elem: 30, len: 4 },
        ));
        types.push(unnamed(
            27,
            "struct {}",
            KindName::Struct,
            KindData::Struct { fields: vec![] },
        ));
        types.push(unnamed(
            28,
            "interface {}",
            KindName::Interface,
            KindData::Interface { methods: vec![] },
        ));
        let mut names = TypeNames::new(&types);
        names.rebuilt = types.iter().filter(|t| !t.named).map(|t| t.addr).collect();
        for t in types.iter().filter(|t| !t.named) {
            assert_eq!(names.name(t.addr), t.name, "rebuilt form of {}", t.name);
        }
    }

    /// Every fixture under `testdata` that was built. Rebuilding is what a
    /// collision triggers, and fixtures seldom have one, so the test forces
    /// it on every unnamed type and holds it to the compiler's own string.
    #[test]
    fn rebuilt_names_match_the_compiler_on_the_fixtures() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("testdata");
        let Ok(entries) = std::fs::read_dir(&dir) else {
            return;
        };
        let mut n_checked = 0;
        for entry in entries.flatten() {
            let path = entry.path();
            if !path.to_string_lossy().contains(".stripped") {
                continue;
            }
            let Ok(bin) = crate::gobin::GoBinary::open(&path) else {
                continue;
            };
            let Ok(md) = crate::moduledata::ModuleData::locate(&bin) else {
                continue;
            };
            let Ok(types) = crate::types::recover_all(&bin, &md) else {
                continue;
            };
            let mut names = TypeNames::new(&types);
            names.qualified.clear();
            names.rebuilt = types.iter().filter(|t| !t.named).map(|t| t.addr).collect();
            for t in types.iter().filter(|t| !t.named) {
                assert_eq!(
                    names.name(t.addr),
                    t.name,
                    "{}: rebuilt type at 0x{:x}",
                    path.display(),
                    t.addr
                );
                n_checked += 1;
            }
        }
        if n_checked == 0 {
            eprintln!("skipping: no fixtures built (run testdata/build-fixtures.sh)");
        }
    }

    #[test]
    fn tags_with_backquotes_are_quoted() {
        let f = field("A", 1, "x:`y`", false);
        let types = base();
        assert_eq!(TypeNames::new(&types).field(&f), "A string \"x:`y`\"");
        assert_eq!(quote("a\"b\\c\n"), "\"a\\\"b\\\\c\\n\"");
    }
}
