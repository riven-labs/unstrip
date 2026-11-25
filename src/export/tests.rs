use super::*;

use crate::types::{InterfaceMethod, KindData, StructField};

fn scalar(addr: u64, name: &str, kind: KindName, size: u64) -> Type {
    Type {
        addr,
        name: name.to_string(),
        kind,
        size,
        ..Default::default()
    }
}

fn field(name: &str, typ: u64, offset: u64) -> StructField {
    StructField {
        name: name.to_string(),
        typ,
        offset,
        ..Default::default()
    }
}

/// A small type graph at pointer size `ps`: `main.Outer` holds a string, a
/// `main.Inner` by value, behind a pointer and as an array, and both kinds of
/// interface. `main.Inner` has padding after its first field. Outer is
/// listed first, so declaring it needs Inner moved ahead.
fn universe(ps: u64) -> Vec<Type> {
    let inner_b = 8.min(ps);
    let inner_size = inner_b + 8;
    let o_in = 2 * ps;
    let o_p = o_in + inner_size;
    let o_arr = o_p + ps;
    let o_e = o_arr + 2 * inner_size;
    let o_any = o_e + 2 * ps;
    vec![
        Type {
            kind_data: KindData::Struct {
                fields: vec![
                    field("Name", 0x30, 0),
                    field("In", 0x70, o_in),
                    field("P", 0x80, o_p),
                    field("Arr", 0x90, o_arr),
                    field("E", 0x50, o_e),
                    field("Any", 0x60, o_any),
                ],
            },
            ..scalar(0xa0, "main.Outer", KindName::Struct, o_any + 2 * ps)
        },
        scalar(0x10, "uint8", KindName::Uint8, 1),
        scalar(0x20, "int64", KindName::Int64, 8),
        scalar(0x30, "string", KindName::String, 2 * ps),
        Type {
            kind_data: KindData::Slice { elem: 0x10 },
            ..scalar(0x40, "[]uint8", KindName::Slice, 3 * ps)
        },
        Type {
            kind_data: KindData::Interface {
                methods: vec![InterfaceMethod {
                    name: "Error".to_string(),
                    typ: 0,
                }],
            },
            ..scalar(0x50, "error", KindName::Interface, 2 * ps)
        },
        Type {
            kind_data: KindData::Interface {
                methods: Vec::new(),
            },
            ..scalar(0x60, "interface {}", KindName::Interface, 2 * ps)
        },
        Type {
            kind_data: KindData::Struct {
                fields: vec![field("A", 0x10, 0), field("B", 0x20, inner_b)],
            },
            ..scalar(0x70, "main.Inner", KindName::Struct, inner_size)
        },
        Type {
            kind_data: KindData::Pointer { elem: 0x70 },
            ..scalar(0x80, "*main.Inner", KindName::Pointer, ps)
        },
        Type {
            kind_data: KindData::Array { elem: 0x70, len: 2 },
            ..scalar(0x90, "[2]main.Inner", KindName::Array, 2 * inner_size)
        },
    ]
}

fn declarations(types: &[Type], ps: u64, dialect: Dialect) -> Vec<Decl> {
    CTypes::new(types, ps, dialect).declarations(types)
}

fn decl<'a>(decls: &'a [Decl], name: &str) -> &'a Decl {
    decls
        .iter()
        .find(|d| d.name == name)
        .unwrap_or_else(|| panic!("no declaration of {name}"))
}

#[test]
fn fields_are_typed_and_nested_structs_come_first() {
    let types = universe(8);
    let decls = declarations(&types, 8, Dialect::Ghidra);
    let names: Vec<&str> = decls.iter().map(|d| d.name.as_str()).collect();
    assert_eq!(
        names,
        [
            "GoString",
            "GoSlice",
            "GoIface",
            "GoEface",
            "GoComplex64",
            "GoComplex128",
            "main_Inner",
            "main_Outer",
        ],
        "Inner is held by value, so it is declared before Outer"
    );
    let outer = decl(&decls, "main_Outer");
    for line in [
        "struct GoString Name;",
        "struct main_Inner In;",
        "struct main_Inner *P;",
        "struct main_Inner Arr[2];",
        "struct GoIface E;",
        "struct GoEface Any;",
    ] {
        assert!(outer.text.contains(line), "{line} in {}", outer.text);
    }
    assert_eq!(outer.size, 104);
    assert_eq!(outer.go_name, "main.Outer");
    let inner = decl(&decls, "main_Inner");
    assert_eq!(
        inner.text,
        "#pragma pack(push, 1)\nstruct main_Inner {\n    uint8_t A;\n    uint8_t _pad_1[7];\n    int64_t B;\n};\n#pragma pack(pop)\n",
        "Go's padding is spelled out and the struct packed"
    );
}

#[test]
fn layout_follows_the_recorded_offsets_on_386() {
    let types = universe(4);
    let decls = declarations(&types, 4, Dialect::Ida);
    let inner = decl(&decls, "main_Inner");
    assert!(
        inner
            .text
            .contains("unsigned __int8 _pad_1[3];\n    __int64 B;"),
        "Go aligns int64 to 4 on 386: {}",
        inner.text
    );
    assert_eq!(inner.size, 12);
    let string = decl(&decls, "GoString");
    assert!(string.text.contains("__int32 len;"), "{}", string.text);
    assert_eq!(string.size, 8);
}

#[test]
fn unrecovered_and_overlapping_fields_keep_the_size() {
    let mut types = universe(8);
    types.push(Type {
        kind_data: KindData::Struct {
            fields: vec![
                field("Unknown", 0xdead, 0),
                field("B", 0x20, 8),
                field("Overlap", 0x20, 12),
                field("Empty", 0xe0, 16),
            ],
        },
        ..scalar(0xb0, "main.Odd", KindName::Struct, 24)
    });
    types.push(Type {
        kind_data: KindData::Struct { fields: Vec::new() },
        ..scalar(0xe0, "struct {}", KindName::Struct, 0)
    });
    let decls = declarations(&types, 8, Dialect::BinaryNinja);
    let odd = decl(&decls, "main_Odd");
    assert_eq!(
        odd.text,
        "#pragma pack(push, 1)\nstruct main_Odd {\n    uint8_t Unknown[8];\n    int64_t B;\n    uint8_t _tail[8];\n};\n#pragma pack(pop)\n",
        "an unknown type spans to the next field; an overlap and a zero-size field are dropped"
    );
    assert!(
        !decls.iter().any(|d| d.go_name == "struct {}"),
        "zero-size structs have no declaration"
    );
}

#[test]
fn struct_declarations_use_unique_c_identifiers() {
    let structure = |addr: u64, name: &str, hash: u32| Type {
        hash,
        kind_data: KindData::Struct {
            fields: vec![field("signed", 0x20, 0)],
        },
        ..scalar(addr, name, KindName::Struct, 8)
    };
    let types = vec![
        scalar(0x20, "int64", KindName::Int64, 8),
        structure(0x110, "main.Config", 1),
        structure(0x120, "sync.Mutex", 2),
        structure(0x130, "sync.Mutex", 3),
        structure(0x140, "a.b_c", 4),
        structure(0x150, "a_b.c", 5),
        structure(0x160, "main.Set[go.shape.string]", 6),
    ];
    let decls = declarations(&types, 8, Dialect::Ghidra);
    let names: Vec<&str> = decls[6..].iter().map(|d| d.name.as_str()).collect();
    assert_eq!(
        names,
        [
            "main_Config",
            "sync_Mutex",
            "sync_Mutex_00000003",
            "a_b_c",
            "a_b_c_00000005",
            "main_Set_go_shape_string_",
        ]
    );
    assert!(
        decls[6].text.contains("int64_t signed_;"),
        "a field named after a C keyword is renamed: {}",
        decls[6].text
    );
}

#[test]
fn c_identifiers_hold_only_letters_digits_and_underscores() {
    assert_eq!(c::c_identifier("errors.errorString"), "errors_errorString");
    assert_eq!(c::c_identifier("*main.T"), "_main_T");
    assert_eq!(c::c_identifier("1x"), "_1x");
    assert_eq!(c::c_identifier("int"), "int_");
    assert_eq!(c::c_identifier("int64_t"), "int64_t_");
    assert_eq!(c::c_identifier("café.T"), "caf__T");
    let long = format!("struct {{ {} }}", "X int; ".repeat(40));
    let id = c::c_identifier(&long);
    assert_eq!(id.len(), 160, "long names are cut: {id}");
    assert_ne!(
        id,
        c::c_identifier(&format!("struct {{ {} }}", "Y int; ".repeat(40))),
        "cut names keep a hash of the whole name"
    );
}

fn prototype(receiver: Option<u64>, params: &[u64], results: &[u64]) -> Prototype {
    Prototype {
        receiver,
        params: params.to_vec(),
        results: results.to_vec(),
        variadic: false,
    }
}

fn place(
    prototype: &Prototype,
    abi: Abi,
    types: &[Type],
    ps: u64,
) -> (Option<abi::Placed>, Vec<Decl>) {
    let mut ctypes = CTypes::new(types, ps, Dialect::Ghidra);
    ctypes.declarations(types);
    let mut tuples = abi::ResultTuples::default();
    let placed = abi::place(prototype, abi, &mut ctypes, &mut tuples);
    (placed, tuples.decls)
}

#[test]
fn amd64_register_abi_assigns_integer_registers_in_order() {
    let types = universe(8);
    let proto = prototype(Some(0x80), &[0x30, 0x20], &[0x20, 0x50]);
    let (placed, tuples) = place(&proto, Abi::Amd64Register, &types, 8);
    let placed = placed.expect("every value fits in registers");
    let storage: Vec<String> = placed.params.iter().map(|p| py_storage(&p.2)).collect();
    assert_eq!(
        storage,
        ["[('RAX', 8)]", "[('RCX', 8), ('RBX', 8)]", "[('RDI', 8)]"],
        "the receiver, then the string's two words (most significant listed first)"
    );
    let types_text: Vec<&str> = placed.params.iter().map(|p| p.1.as_str()).collect();
    assert_eq!(
        types_text,
        ["struct main_Inner *", "struct GoString", "int64_t"]
    );
    let (ret, storage) = placed.result.expect("two results");
    assert_eq!(ret, "struct GoResults_int64_error");
    assert_eq!(
        py_storage(&storage),
        "[('RCX', 8), ('RBX', 8), ('RAX', 8)]",
        "results restart at RAX"
    );
    assert_eq!(tuples.len(), 1);
    assert_eq!(tuples[0].size, 24);
    assert!(tuples[0]
        .text
        .contains("int64_t r0;\n    struct GoIface r1;"));
}

#[test]
fn amd64_register_abi_spills_what_does_not_fit_and_refuses_padding() {
    let types = universe(8);
    // The receiver and four strings take all nine integer registers.
    let proto = prototype(Some(0x80), &[0x30, 0x30, 0x30, 0x30, 0x30, 0x20], &[]);
    let (placed, _) = place(&proto, Abi::Amd64Register, &types, 8);
    let placed = placed.expect("placed");
    let last: Vec<String> = placed.params[5..]
        .iter()
        .map(|p| py_storage(&p.2))
        .collect();
    assert_eq!(
        last,
        ["[(8, 16)]", "[(24, 8)]"],
        "the fifth string and the int64 go on the stack, above the return address"
    );
    assert!(placed.result.is_none());

    // main.Inner has 7 padding bytes, which register pieces cannot cover.
    let proto = prototype(Some(0x70), &[], &[]);
    let (placed, _) = place(&proto, Abi::Amd64Register, &types, 8);
    assert!(placed.is_none(), "a padded struct in registers is refused");
}

#[test]
fn stack_abi_lays_out_arguments_then_aligned_results() {
    let types = universe(4);
    let proto = prototype(None, &[0x10, 0x20], &[0x20, 0x50]);
    let (placed, tuples) = place(&proto, Abi::Stack, &types, 4);
    let placed = placed.expect("placed");
    let storage: Vec<String> = placed.params.iter().map(|p| py_storage(&p.2)).collect();
    assert_eq!(
        storage,
        ["[(4, 4)]", "[(8, 1)]", "[(12, 8)]"],
        "an itab receiver word, a byte, an int64 aligned to 4"
    );
    assert_eq!(placed.params[0].1, "void *");
    let (_, storage) = placed.result.expect("results");
    assert_eq!(
        py_storage(&storage),
        "[(20, 16)]",
        "results start at the next word after the arguments, offset 16"
    );
    assert_eq!(tuples[0].size, 16);

    // A byte result followed by a word leaves a gap the stack tuple keeps.
    let proto = prototype(None, &[], &[0x10, 0x30]);
    let (placed, tuples) = place(&proto, Abi::Stack, &types, 4);
    let (_, storage) = placed.expect("placed").result.expect("results");
    assert_eq!(py_storage(&storage), "[(8, 12)]");
    assert!(
        tuples[0]
            .text
            .contains("uint8_t r0;\n    uint8_t _pad_1[3];\n    struct GoString r1;"),
        "{}",
        tuples[0].text
    );
}

fn function(address: u64, name: &str, file: &str) -> Function {
    Function {
        address,
        name: name.to_string(),
        file: Some(file.to_string()),
        start_line: Some(1),
        size: None,
    }
}

#[test]
fn abi0_side_of_a_wrapper_pair_gets_the_linker_suffix() {
    let functions = vec![
        function(0x100, "runtime.args", "/go/src/runtime/runtime1.go"),
        function(0x200, "runtime.reflectcall", "/go/src/runtime/asm_amd64.s"),
        function(0x300, "runtime.args", "<autogenerated>"),
        function(0x400, "runtime.reflectcall", "<autogenerated>"),
        function(0x500, "main.(*T).M", "<autogenerated>"),
    ];
    let names = abi_wrapper_names(&functions);
    let label = |addr: u64| names.get(&addr).map(|(name, _)| name.as_str());
    assert_eq!(label(0x100), Some("runtime.args"));
    assert_eq!(
        label(0x300),
        Some("runtime.args.abi0"),
        "a Go body's wrapper is ABI0"
    );
    assert_eq!(
        label(0x200),
        Some("runtime.reflectcall.abi0"),
        "an assembly body is ABI0"
    );
    assert_eq!(label(0x400), Some("runtime.reflectcall"));
    assert_eq!(label(0x500), None, "a method wrapper is not an ABI pair");
    assert!(
        names[&0x300].1.contains("0x100"),
        "the note names the target"
    );
}

#[test]
fn header_counts_are_the_emitted_counts() {
    let types = universe(8);
    let functions = vec![
        function(0x1000, "runtime.args", "/go/src/runtime/runtime1.go"),
        function(0x2000, "runtime.args", "<autogenerated>"),
        function(0x3000, "main.(*Inner).Get", "/src/main.go"),
    ];
    let mut prototypes = HashMap::new();
    prototypes.insert(0x3000, prototype(Some(0x80), &[0x30], &[0x20, 0x50]));
    let itabs = vec![Itab {
        addr: 0x9000,
        interface_name: "error".to_string(),
        concrete_name: "*main.Inner".to_string(),
        hash: 0,
        incomplete: false,
        methods: Vec::new(),
        stdlib_interface: None,
    }];
    let mut export = Export::new(&functions, "unstrip");
    export.types = &types;
    export.prototypes = Some(&prototypes);
    export.abi = Abi::Amd64Register;
    export.itabs = &itabs;
    export.moduledata = Some(0xa000);

    for target in [Target::Ghidra, Target::Ida, Target::BinaryNinja] {
        let mut buf = Vec::new();
        write(&mut buf, target, &export).unwrap();
        let script = String::from_utf8(buf).unwrap();
        let count = |prefix: &str| script.lines().filter(|l| l.starts_with(prefix)).count();
        let n_protos = if target == Target::Ghidra { 1 } else { 0 };
        let header = format!(
            "# {} type declarations, 3 functions (1 ABI wrapper pairs marked), {n_protos} prototypes, 12 labels (1 itabs, 10 type descriptors, 1 moduledata).",
            count("_type("),
        );
        assert!(script.contains(&header), "{target:?}: {header}");
        assert_eq!(count("_func("), 3);
        assert_eq!(count("_proto("), n_protos, "{target:?}");
        assert_eq!(count("_label("), 12);
        let n_types = if target == Target::Ghidra { 9 } else { 8 };
        assert_eq!(
            count("_type("),
            n_types,
            "{target:?}: the result tuple is Ghidra's"
        );
        assert!(script.ends_with("print('unstrip: done, {} failures'.format(len(_failures)))\n"));
    }
}

#[test]
fn labels_use_the_linker_names_each_tool_accepts() {
    let types = vec![scalar(0x10, "struct { X int }", KindName::Struct, 0)];
    let itabs = vec![Itab {
        addr: 0x9000,
        interface_name: "io.Writer".to_string(),
        concrete_name: "*os.File".to_string(),
        hash: 0,
        incomplete: false,
        methods: Vec::new(),
        stdlib_interface: None,
    }];
    let mut export = Export::new(&[], "unstrip");
    export.types = &types;
    export.itabs = &itabs;
    let labels = |target: Target, export: &Export<'_>| -> Vec<String> {
        Plan::new(target, export)
            .labels
            .into_iter()
            .map(|(_, name)| name)
            .collect()
    };
    assert_eq!(
        labels(Target::Ghidra, &export),
        ["go:itab.*os.File,io.Writer", "type:struct_{_X_int_}"]
    );
    assert_eq!(
        labels(Target::BinaryNinja, &export),
        ["go:itab.*os.File,io.Writer", "type:struct { X int }"]
    );
    assert_eq!(
        labels(Target::Ida, &export),
        ["go_itab._os.File_io.Writer", "type_struct___X_int__"]
    );
    export.linker_names = LinkerNames::Legacy;
    assert_eq!(
        labels(Target::Ghidra, &export),
        ["go.itab.*os.File,io.Writer", "type.struct_{_X_int_}"],
        "before Go 1.20 the linker used dots"
    );
}

#[test]
fn ida_labels_drop_go_punctuation() {
    assert_eq!(sanitize_label("main.main"), "main.main");
    assert_eq!(sanitize_label("(*os.File).Read"), "__os.File_.Read");
    assert_eq!(
        sanitize_label("main.Set[go.shape.string]"),
        "main.Set_go.shape.string_"
    );
    assert_eq!(sanitize_label("123main"), "_123main");
}

#[test]
fn python_literals_escape_quotes_backslashes_and_newlines() {
    assert_eq!(py_str("a'b"), "'a\\'b'");
    assert_eq!(py_str("a\\b"), "'a\\\\b'");
    assert_eq!(py_str("a\nb"), "'a\\nb'");
    assert_eq!(py_str("(*os.File).Read"), "'(*os.File).Read'");
}

#[test]
fn write_script_keeps_its_behavior_for_existing_callers() {
    let types = universe(4);
    let functions = vec![function(0x1000, "main.main", "/src/main.go")];
    let mut buf = Vec::new();
    write_script(&mut buf, Target::Ida, &functions, &types, None, "relift").unwrap();
    let script = String::from_utf8(buf).unwrap();
    assert!(script.contains("Generated by relift"));
    assert!(
        script.contains("__int32 len;"),
        "the pointer size comes from the types"
    );
    assert!(script.contains("_func(0x1000, 'main.main', 'go: main.main\\n/src/main.go:1')"));
}
