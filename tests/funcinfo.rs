//! Per-function metadata readers against real Go binaries.
//!
//! `testdata/funcinfo.go` is built by `testdata/build-fixtures.sh` with each
//! toolchain the layouts differ on (Go 1.17, 1.18, 1.20, 1.22, and the current
//! one); a fixture that is not built is skipped. The relift eval fixtures, when
//! a sibling relift checkout has built them, are checked too.

use std::path::PathBuf;

use unstrip::gobin::GoBinary;
use unstrip::moduledata::ModuleData;
use unstrip::pclntab::{ArgComp, FuncEntry, Inlining, OpenDeferFormat, Pclntab, MAGIC_1_16};

fn open(path: PathBuf) -> Option<GoBinary> {
    if path.exists() {
        Some(GoBinary::open(&path).expect("open fixture"))
    } else {
        eprintln!("skipping: {} not built", path.display());
        None
    }
}

fn fixture(name: &str) -> Option<GoBinary> {
    open(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("testdata")
            .join(name),
    )
}

fn pclntab(bin: &GoBinary) -> Pclntab<'_> {
    let p = Pclntab::parse(bin).expect("parse pclntab");
    match ModuleData::locate(bin) {
        Ok(md) => p.with_gofunc(md.gofunc),
        Err(_) => p,
    }
}

fn func(funcs: &[FuncEntry], name: &str) -> FuncEntry {
    funcs
        .iter()
        .find(|f| f.name == name)
        .unwrap_or_else(|| panic!("{name} not found"))
        .clone()
}

const WORD: ArgComp = ArgComp::Word { off: 0, size: 8 };

/// Shape of an ArgInfo list with offsets erased: W = word, A(n) = aggregate.
fn shape(a: &[ArgComp]) -> String {
    a.iter()
        .map(|c| match c {
            ArgComp::Word { size, .. } => format!("W{size}"),
            ArgComp::Agg(v) => format!("A({})", shape(v)),
            ArgComp::Ellipsis => "...".to_string(),
            ArgComp::TooLarge => "_".to_string(),
            _ => "?".to_string(),
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// (fixture suffix, Go minor) for every funcinfo build.
const VERSIONS: [(&str, u32); 5] = [
    ("117", 17),
    ("118", 18),
    ("120", 20),
    ("122", 22),
    ("126", 26),
];

#[test]
fn funcinfo_fixtures_across_releases() {
    for (suffix, minor) in VERSIONS {
        let Some(bin) = fixture(&format!("funcinfo.go{suffix}.stripped")) else {
            continue;
        };
        let p = pclntab(&bin);
        let funcs = p.functions_with_offsets().expect("functab");
        let ctx = format!("go1.{minor}");

        // _func fields: startLine only from 1.20.
        let add = func(&funcs, "main.add");
        let ff = p.func_fields(&add).expect("fields");
        assert_eq!(ff.entry, add.address, "{ctx}");
        assert_eq!(ff.args, 16, "{ctx}: two int params");
        assert_eq!(ff.start_line, (minor >= 20).then_some(12), "{ctx}");

        // ArgInfo: exact parameter layouts.
        let a = p.arg_info(&add).expect("add arginfo");
        assert_eq!(a.len(), 2, "{ctx}: add(a, b int)");
        assert_eq!(a[0], WORD, "{ctx}");
        assert_eq!(a[1], ArgComp::Word { off: 8, size: 8 }, "{ctx}");
        let greet = p
            .arg_info(&func(&funcs, "main.greet"))
            .expect("greet arginfo");
        assert_eq!(shape(&greet), "A(W8 W8)", "{ctx}: greet(name string)");
        let many = p
            .arg_info(&func(&funcs, "main.many"))
            .expect("many arginfo");
        assert_eq!(many.len(), 11, "{ctx}: 10 components then ...");
        assert_eq!(many[10], ArgComp::Ellipsis, "{ctx}");
        assert_eq!(
            p.arg_info(&func(&funcs, "main.main")),
            None,
            "{ctx}: no params"
        );

        // Open-coded defers: two defers in withDefers.
        let wd = func(&funcs, "main.withDefers");
        assert_ne!(p.func_fields(&wd).unwrap().deferreturn, 0, "{ctx}");
        let od = p
            .open_coded_defer_info(&wd)
            .expect("open-coded defer record");
        let want = match minor {
            ..=17 => OpenDeferFormat::Go114,
            18..=21 => OpenDeferFormat::Go118,
            _ => OpenDeferFormat::Go122,
        };
        assert_eq!(od.format, want, "{ctx}");
        assert!(od.defer_bits_offset > 0, "{ctx}");
        if minor < 22 {
            assert_eq!(od.num_defers, Some(2), "{ctx}");
            assert_eq!(od.closure_slot_offsets.len(), 2, "{ctx}");
            assert_eq!(od.slots_offset, od.closure_slot_offsets[0], "{ctx}");
        } else {
            assert_eq!(od.num_defers, None, "{ctx}");
            assert!(
                od.slots_offset >= 16,
                "{ctx}: room for two contiguous slots"
            );
        }
        assert_eq!(p.open_coded_defer_info(&add), None, "{ctx}");

        // Wrappers: the defer wrapper and the *counter method wrapper.
        assert_eq!(p.is_wrapper(&add), Some(false), "{ctx}");
        assert_eq!(
            p.is_wrapper(&func(&funcs, "main.(*counter).Get")),
            Some(true),
            "{ctx}"
        );
        assert_eq!(
            p.is_wrapper(&func(&funcs, "main.counter.Get")),
            Some(false),
            "{ctx}"
        );
        let defer_wrapper = funcs.iter().any(|f| {
            f.name.starts_with("main.withDefers")
                && f.name != "main.withDefers.func1"
                && f.name != "main.withDefers"
                && p.is_wrapper(f) == Some(true)
        });
        assert!(defer_wrapper, "{ctx}: the defer cleanup(\"first\") wrapper");

        // Line table of main.main: increasing, disjoint, inside the function,
        // covering every source line of main (53..=58) and the inlined triple.
        let main = func(&funcs, "main.main");
        let lt = p.line_table(&main);
        assert!(!lt.is_empty(), "{ctx}");
        for w in lt.windows(2) {
            assert!(w[0].pc_hi <= w[1].pc_lo, "{ctx}: spans out of order");
        }
        for s in &lt {
            assert!(s.pc_lo < s.pc_hi, "{ctx}");
            assert!(
                s.pc_lo >= main.address && s.pc_hi <= main.address + main.size,
                "{ctx}"
            );
        }
        let main_lines: Vec<u32> = lt
            .iter()
            .filter(|s| s.file.ends_with("funcinfo.go"))
            .map(|s| s.line)
            .collect();
        for line in 53..=58 {
            assert!(
                main_lines.contains(&line),
                "{ctx}: main.main line {line} in {main_lines:?}"
            );
        }
        assert!(
            main_lines.contains(&40),
            "{ctx}: inlined triple body at line 40"
        );
        assert_eq!(p.sp_delta_at(&main, main.address), Some(0), "{ctx}");

        // Inline leaf: the inlined triple's body reports triple, line 40, and a
        // call site in main at line 56.
        let span = lt
            .iter()
            .find(|s| s.line == 40 && s.file.ends_with("funcinfo.go"))
            .unwrap();
        let leaf = p.inline_leaf(&main, span.pc_lo).expect("inlined pc");
        assert_eq!(leaf.func_name, "main.triple", "{ctx}");
        assert_eq!(leaf.line, Some(40), "{ctx}");
        assert_eq!(leaf.start_line, (minor >= 20).then_some(39), "{ctx}");
        assert!(leaf.parent_pc >= main.address && leaf.parent_pc < main.address + main.size);
        let call_site = lt
            .iter()
            .find(|s| s.pc_lo <= leaf.parent_pc && leaf.parent_pc < s.pc_hi)
            .expect("call-site pc has a line");
        assert_eq!(call_site.line, 56, "{ctx}");
        assert_eq!(
            p.inline_leaf(&main, main.address),
            None,
            "{ctx}: entry is not inlined"
        );

        // lookup_inline agrees, on every layout (the Go 1.17 offsets were wrong).
        let frames = p.lookup_inline(&bin, span.pc_lo);
        assert_eq!(frames.len(), 2, "{ctx}");
        assert_eq!(frames[0].name, "main.triple");
        assert_eq!(frames[0].line, Some(40), "{ctx}");
        assert!(frames[0].file.as_deref().unwrap().ends_with("funcinfo.go"));
        assert_eq!(frames[1].name, "main.main");
        assert_eq!(
            frames[1].line,
            Some(56),
            "{ctx}: the physical frame is at the call site"
        );
        assert!(frames[1].file.as_deref().unwrap().ends_with("funcinfo.go"));
    }
}

#[test]
fn pc_location_gives_every_frame_its_own_line() {
    // main.triple (line 40) is inlined into main.main at line 56. At a PC of
    // triple's body the runtime reports triple at 40, then main.main at the
    // call, read at the inline record's parentPc.
    for (suffix, minor) in VERSIONS {
        let Some(bin) = fixture(&format!("funcinfo.go{suffix}.stripped")) else {
            continue;
        };
        let ctx = format!("go1.{minor}");
        let p = pclntab(&bin);
        let funcs = p.functions_with_offsets().expect("functab");
        let main = func(&funcs, "main.main");
        let span = p
            .line_table(&main)
            .into_iter()
            .find(|s| s.line == 40 && s.file.ends_with("funcinfo.go"))
            .expect("triple's body is inlined into main.main");
        let pc = span.pc_hi - 1;
        let location = p.pc_location(pc).expect("main.main covers the PC");
        assert_eq!(location.pc, pc, "{ctx}");
        assert_eq!(location.entry, main.address, "{ctx}");
        assert_eq!(location.inlining, Inlining::Complete, "{ctx}");
        let parent_pc = p.inline_leaf(&main, pc).expect("inlined pc").parent_pc;
        let frames: Vec<(Option<&str>, Option<u32>, u64, bool)> = location
            .frames
            .iter()
            .map(|f| (f.function.as_deref(), f.line, f.pc, f.inlined))
            .collect();
        assert_eq!(
            frames,
            [
                (Some("main.triple"), Some(40), pc, true),
                (Some("main.main"), Some(56), parent_pc, false),
            ],
            "{ctx}"
        );
        for f in &location.frames {
            assert!(
                f.file
                    .as_deref()
                    .is_some_and(|f| f.ends_with("funcinfo.go")),
                "{ctx}: {:?}",
                f.file
            );
        }

        // Outside inlined code there is one frame, at the PC's own line.
        let entry = p.pc_location(main.address).expect("entry of main.main");
        assert_eq!(entry.inlining, Inlining::Complete, "{ctx}");
        assert_eq!(entry.frames.len(), 1, "{ctx}");
        assert_eq!(
            (entry.frames[0].file.clone(), entry.frames[0].line),
            p.pc_position(main.address),
            "{ctx}"
        );

        // From Go 1.18 the tree is reached through gofunc. Without it the
        // inlined PC is unread and only the physical frame is listed, at the
        // PC's own position; a PC outside inlined code is still complete.
        let bare = Pclntab::parse(&bin).expect("parse pclntab");
        let location = bare.pc_location(pc).expect("main.main covers the PC");
        let want = if minor >= 18 {
            Inlining::Unread
        } else {
            Inlining::Complete
        };
        assert_eq!(location.inlining, want, "{ctx}");
        if minor >= 18 {
            assert_eq!(location.frames.len(), 1, "{ctx}");
            assert_eq!(location.frames[0].function.as_deref(), Some("main.main"));
            assert_eq!(
                location.frames[0].line,
                Some(40),
                "{ctx}: the PC's own line"
            );
        }
        let entry = bare.pc_location(main.address).expect("entry of main.main");
        assert_eq!(entry.inlining, Inlining::Complete, "{ctx}");
    }
}

#[test]
fn a_pc_reports_its_own_line_not_the_function_start() {
    // main.main opens on line 52 and its body runs 53..=58. Every PC the line
    // table covers resolves to that span's line, through pc_position and the
    // physical frame of lookup_inline alike.
    for (suffix, minor) in VERSIONS {
        let Some(bin) = fixture(&format!("funcinfo.go{suffix}.stripped")) else {
            continue;
        };
        let ctx = format!("go1.{minor}");
        let p = pclntab(&bin);
        let funcs = p.functions_with_offsets().expect("functab");
        let main = func(&funcs, "main.main");
        let mut body_pcs = 0;
        for s in p.line_table(&main) {
            for pc in [s.pc_lo, s.pc_hi - 1] {
                let (file, line) = p.pc_position(pc);
                assert_eq!(file.as_deref(), Some(s.file.as_str()), "{ctx}: 0x{pc:x}");
                assert_eq!(line, Some(s.line), "{ctx}: 0x{pc:x}");
                let frames = p.lookup_inline(&bin, pc);
                if frames.len() == 1 {
                    assert_eq!(frames[0].line, Some(s.line), "{ctx}: 0x{pc:x}");
                    if (53..=58).contains(&s.line) {
                        body_pcs += 1;
                    }
                }
            }
        }
        assert!(body_pcs > 0, "{ctx}: no PC on a body line of main.main");
    }
}

#[test]
fn go117_inline_frames_use_the_pre118_func_offsets() {
    // hello.go117: every inlined frame across the binary must carry the file
    // and line the pcfile/pcln tables give, now read at the 1.16/1.17 offsets.
    let Some(bin) = fixture("hello.go117.stripped") else {
        return;
    };
    let p = pclntab(&bin);
    assert_eq!(p.magic(), MAGIC_1_16);
    let funcs = p.functions_with_offsets().unwrap();
    let mut inlined = 0usize;
    for f in funcs
        .iter()
        .filter(|f| f.name.starts_with("fmt.") || f.name.starts_with("main."))
    {
        let lt = p.line_table(f);
        for s in &lt {
            let frames = p.lookup_inline(&bin, s.pc_lo);
            if frames.len() > 1 {
                inlined += 1;
                assert_eq!(
                    frames[0].file.as_deref(),
                    Some(s.file.as_str()),
                    "{}",
                    f.name
                );
                assert_eq!(frames[0].line, Some(s.line), "{}", f.name);
            }
        }
    }
    assert!(inlined > 0, "no inlined frames found in fmt.* / main.*");
}

fn relift_eval(name: &str) -> Option<GoBinary> {
    open(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("relift")
            .join("testdata")
            .join("eval")
            .join(name)
            .join("bin"),
    )
}

#[test]
fn relift_eval_fixtures_if_present() {
    // l10_errors: parse(s string) (int, error); main.go lines 18..=28.
    if let Some(bin) = relift_eval("l10_errors") {
        let p = pclntab(&bin);
        let funcs = p.functions_with_offsets().unwrap();
        let parse = func(&funcs, "main.parse");
        assert_eq!(shape(&p.arg_info(&parse).unwrap()), "A(W8 W8)");
        let main = func(&funcs, "main.main");
        let lines: Vec<u32> = p
            .line_table(&main)
            .iter()
            .filter(|s| s.file.ends_with("main.go"))
            .map(|s| s.line)
            .collect();
        for line in [18, 20, 21, 23, 24, 25, 28] {
            assert!(
                lines.contains(&line),
                "l10 main.main line {line} in {lines:?}"
            );
        }
    }
    // l06_structmethod: (p Point) Sum() with Point{X, Y int}.
    if let Some(bin) = relift_eval("l06_structmethod") {
        let p = pclntab(&bin);
        let funcs = p.functions_with_offsets().unwrap();
        let sum = func(&funcs, "main.Point.Sum");
        assert_eq!(shape(&p.arg_info(&sum).unwrap()), "A(W8 W8)");
    }
    // l14_variadic: sum(nums ...int) is one slice.
    if let Some(bin) = relift_eval("l14_variadic") {
        let p = pclntab(&bin);
        let funcs = p.functions_with_offsets().unwrap();
        let sum = func(&funcs, "main.sum");
        assert_eq!(shape(&p.arg_info(&sum).unwrap()), "A(W8 W8 W8)");
    }
}

#[test]
fn addr_prints_every_frame_in_text_and_json() {
    let Some(bin) = fixture("funcinfo.go126.stripped") else {
        return;
    };
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("testdata/funcinfo.go126.stripped");
    let p = pclntab(&bin);
    let funcs = p.functions_with_offsets().expect("functab");
    let main = func(&funcs, "main.main");
    let span = p
        .line_table(&main)
        .into_iter()
        .find(|s| s.line == 40 && s.file.ends_with("funcinfo.go"))
        .expect("triple's body is inlined into main.main");
    let pc = span.pc_lo;
    let run = |args: &[&str], stdin: &str| {
        use std::io::Write;
        let mut child = std::process::Command::new(env!("CARGO_BIN_EXE_unstrip"))
            .arg(&path)
            .args(args)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .spawn()
            .expect("run unstrip");
        child
            .stdin
            .take()
            .unwrap()
            .write_all(stdin.as_bytes())
            .unwrap();
        let out = child.wait_with_output().expect("wait for unstrip");
        assert!(out.status.success());
        String::from_utf8(out.stdout).unwrap()
    };
    let addr = format!("{pc:#x}");

    let text = run(&["--addr", &addr, "--no-signatures"], "");
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines.len(), 3, "{text}");
    assert_eq!(
        lines[0],
        format!("0x{pc:016x}  main.main+0x{:x}", pc - main.address)
    );
    assert!(lines[1].starts_with("(inlined)  main.triple  "), "{text}");
    assert!(lines[1].ends_with("funcinfo.go:40"), "{text}");
    assert!(lines[2].starts_with("(physical) main.main  "), "{text}");
    assert!(lines[2].ends_with("funcinfo.go:56"), "{text}");

    let json = run(&["--addr", &addr, "--no-signatures", "-f", "json"], "");
    let v: serde_json::Value = serde_json::from_str(&json).expect("--addr json");
    assert_eq!(v["pc"], pc);
    assert_eq!(v["entry"], main.address);
    assert_eq!(v["inlining"], "complete");
    let frames = v["frames"].as_array().expect("frames");
    assert_eq!(frames.len(), 2, "{json}");
    assert_eq!(frames[0]["function"], "main.triple");
    assert_eq!(frames[0]["line"], 40);
    assert_eq!(frames[0]["inlined"], true);
    assert_eq!(frames[1]["function"], "main.main");
    assert_eq!(frames[1]["line"], 56);
    assert_eq!(frames[1]["inlined"], false);

    let batch = run(
        &["--addr-file", "-", "-f", "json"],
        &format!("{addr}\n0x1\nnot-a-pc\n"),
    );
    let v: serde_json::Value = serde_json::from_str(&batch).expect("--addr-file json");
    let entries = v.as_array().expect("one entry per line");
    assert_eq!(entries.len(), 3, "{batch}");
    assert_eq!(entries[0]["frames"].as_array().map(|f| f.len()), Some(2));
    assert_eq!(entries[1]["pc"], 1);
    assert_eq!(entries[1]["error"], "no function covers this PC");
    assert_eq!(entries[2]["line"], 3);
}
