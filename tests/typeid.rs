//! Type identity and Go-syntax rendering on `testdata/typeid`, built for the
//! targets `testdata/build-fixtures.sh` lists. A fixture that was not built
//! is skipped.
//!
//! The expectations are the program's source, as `reflect` prints it: the
//! binary run with `dump` prints the same names. They hold for any Go
//! release from 1.7, so offsets and sizes, which depend on the target, are
//! not pinned here.

use std::collections::HashMap;
use std::path::PathBuf;

use unstrip::gobin::GoBinary;
use unstrip::moduledata::ModuleData;
use unstrip::pclntab::Pclntab;
use unstrip::types::{self, KindData, Type, TypeNames};

fn fixture(name: &str) -> Option<GoBinary> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("testdata")
        .join(name);
    if !path.exists() {
        eprintln!("skipping: fixture {name} not built (run testdata/build-fixtures.sh)");
        return None;
    }
    Some(GoBinary::open(&path).expect("fixture parses"))
}

/// The one named type called `name` in package `pkg_path`.
fn named<'a>(types: &'a [Type], name: &str, pkg_path: &str) -> &'a Type {
    let found: Vec<&Type> = types
        .iter()
        .filter(|t| t.named && t.name == name && t.pkg_path == pkg_path)
        .collect();
    assert_eq!(found.len(), 1, "one {name} in {pkg_path}");
    found[0]
}

/// `main.Config`'s fields as declared, with the two `sync` packages told
/// apart.
const CONFIG_FIELDS: [&str; 24] = [
    "C2 string `json:\"c2\"`",
    "Port uint16 `json:\"port\"`",
    "Items []main.Item",
    "Headers map[string][]string",
    "Index map[int64]*main.Item",
    "Root *main.Node",
    "Ring [4]uint8",
    "Grid [2][3]int16",
    "Done chan struct {}",
    "Events <-chan main.Event",
    "Sink chan<- []uint8",
    "Pipes chan (<-chan int)",
    "OnError func(error) bool",
    "Format func(string, ...interface {}) (int, error)",
    "Handler main.Handler",
    "Any interface {}",
    "Inline struct { A int; B int }",
    "Tagged struct { X int \"x:\\\"1\\\"\" }",
    "mu sync.Mutex",
    "local typeid/sync.Mutex",
    "ptrs []*typeid/sync.Mutex",
    "locks map[string]*sync.Mutex",
    "deadline time.Time",
    "ctx context.Context",
];

fn check_typeid(name: &str) {
    let Some(bin) = fixture(name) else {
        return;
    };
    let md = ModuleData::locate(&bin).expect("moduledata");
    let all = types::recover_all(&bin, &md).expect("types");
    let names = TypeNames::new(&all);
    let ps = bin.pointer_size() as u8;

    // Two packages named sync, each with a Mutex, and from Go 1.24 a third in
    // internal/sync. Only the path tells them apart.
    let std_mutex = named(&all, "sync.Mutex", "sync");
    let own_mutex = named(&all, "sync.Mutex", "typeid/sync");
    assert_eq!(names.name(std_mutex.addr), "sync.Mutex");
    assert_eq!(names.name(own_mutex.addr), "typeid/sync.Mutex");
    assert_eq!(
        own_mutex.align, ps,
        "{name}: typeid/sync.Mutex holds a pointer"
    );

    let config = named(&all, "main.Config", "main");
    let KindData::Struct { fields } = &config.kind_data else {
        panic!("{name}: main.Config is a struct");
    };
    let rendered: Vec<String> = fields.iter().map(|f| names.field(f)).collect();
    assert_eq!(rendered, CONFIG_FIELDS, "{name}: main.Config fields");

    let handler = named(&all, "main.Handler", "main");
    let KindData::Interface { methods } = &handler.kind_data else {
        panic!("{name}: main.Handler is an interface");
    };
    let signatures: Vec<String> = methods
        .iter()
        .map(|m| format!("{}{}", m.name, names.signature(m.typ)))
        .collect();
    assert_eq!(
        signatures,
        ["Handle([]uint8) ([]uint8, error)", "Name() string"],
        "{name}: main.Handler methods"
    );

    let derived = named(&all, "main.Derived", "main");
    let KindData::Struct { fields } = &derived.kind_data else {
        panic!("{name}: main.Derived is a struct");
    };
    let rendered: Vec<String> = fields.iter().map(|f| names.field(f)).collect();
    assert_eq!(
        rendered,
        [
            "main.Base",
            "*typeid/sync.Mutex",
            "io.Reader",
            "Extra []string `json:\"extra\"`"
        ],
        "{name}: main.Derived embeds three types"
    );

    // Unnamed types carry no package; reflect says the same.
    let config_ptr = all
        .iter()
        .find(|t| t.name == "*main.Config")
        .expect("*main.Config");
    assert!(!config_ptr.named && config_ptr.pkg_path.is_empty());
    assert!(config.named);

    // Method tables: every method, unexported ones too, with entries that
    // are the functions the source declares.
    let pcln = Pclntab::parse(&bin).expect("pclntab");
    let by_entry: HashMap<u64, String> = pcln
        .functions()
        .expect("functions")
        .into_iter()
        .map(|f| (f.address, f.name))
        .collect();
    let tfn = |t: &Type, method: &str| -> Option<String> {
        let m = t.methods.iter().find(|m| m.name == method)?;
        by_entry.get(&m.tfn?).cloned()
    };
    let headers = named(&all, "main.Headers", "main");
    assert!(matches!(headers.kind_data, KindData::Map { .. }));
    assert_eq!(
        tfn(headers, "Get").as_deref(),
        Some("main.Headers.Get"),
        "{name}: a named map's method table reads"
    );
    let kind = named(&all, "main.EventKind", "main");
    assert_eq!(
        tfn(kind, "String").as_deref(),
        Some("main.EventKind.String")
    );
    let echo = all
        .iter()
        .find(|t| t.name == "*main.echo")
        .expect("*main.echo");
    let method_names: Vec<&str> = echo.methods.iter().map(|m| m.name.as_str()).collect();
    assert_eq!(method_names, ["Close", "Handle", "Name", "flush"]);
    assert_eq!(
        tfn(echo, "Handle").as_deref(),
        Some("main.(*echo).Handle"),
        "{name}: *main.echo.Handle"
    );
    assert_eq!(
        tfn(own_mutex, "Held").as_deref(),
        Some("typeid/sync.Mutex.Held")
    );
}

#[test]
fn typeid_linux_amd64() {
    check_typeid("typeid.linux-amd64.stripped");
}

#[test]
fn typeid_linux_arm64() {
    check_typeid("typeid.linux-arm64.stripped");
}

#[test]
fn typeid_linux_386() {
    check_typeid("typeid.linux-386.stripped");
}

#[test]
fn typeid_windows_amd64() {
    check_typeid("typeid.windows-amd64.stripped.exe");
}

#[test]
fn typeid_darwin_arm64() {
    check_typeid("typeid.darwin-arm64.stripped");
}

#[test]
fn typeid_go112_linux_amd64() {
    // Go 1.12's map record has no hasher, so the named map's method table
    // sits a word earlier than in 1.14 to 1.23.
    check_typeid("typeid.go112.linux-amd64.stripped");
}

#[test]
fn typeid_go115_linux_amd64() {
    check_typeid("typeid.go115.linux-amd64.stripped");
}
