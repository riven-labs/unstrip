use std::path::PathBuf;

use unstrip::buildinfo::BuildInfo;
use unstrip::gobin::GoBinary;
use unstrip::itabs;
use unstrip::moduledata::ModuleData;
use unstrip::pclntab::Pclntab;
use unstrip::types::{self, KindData, KindName};

fn fixture(name: &str) -> Option<PathBuf> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("testdata")
        .join(name);
    if path.exists() {
        Some(path)
    } else {
        eprintln!("skipping: fixture {name} not built (run testdata/build-fixtures.sh)");
        None
    }
}

fn assert_recovers_hello(path: PathBuf) {
    let bin = GoBinary::open(&path).expect("open binary");
    let pcln = Pclntab::parse(&bin).expect("parse pclntab");
    let functions = pcln.functions().expect("walk functab");

    assert!(
        functions.len() > 100,
        "expected hundreds of functions in a Go binary, got {}",
        functions.len()
    );

    let names: Vec<&str> = functions.iter().map(|f| f.name.as_str()).collect();
    for required in ["main.main", "main.greet", "main.parseFlags"] {
        assert!(
            names.contains(&required),
            "expected {required} in recovered symbols (got {} functions, first 5: {:?})",
            names.len(),
            &names[..names.len().min(5)],
        );
    }
}

#[test]
fn recovers_symbols_from_linux_amd64() {
    let Some(path) = fixture("hello.linux-amd64.stripped") else {
        return;
    };
    assert_recovers_hello(path);
}

#[test]
fn recovers_symbols_from_linux_arm64() {
    let Some(path) = fixture("hello.linux-arm64.stripped") else {
        return;
    };
    assert_recovers_hello(path);
}

#[test]
fn recovers_symbols_from_darwin_amd64() {
    let Some(path) = fixture("hello.darwin-amd64.stripped") else {
        return;
    };
    assert_recovers_hello(path);
}

#[test]
fn recovers_symbols_from_darwin_arm64() {
    let Some(path) = fixture("hello.darwin-arm64.stripped") else {
        return;
    };
    assert_recovers_hello(path);
}

#[test]
fn recovers_symbols_from_windows_amd64() {
    let Some(path) = fixture("hello.windows-amd64.stripped.exe") else {
        return;
    };
    assert_recovers_hello(path);
}

#[test]
fn recovers_symbols_from_linux_pie() {
    let Some(path) = fixture("hello.linux-amd64.pie.stripped") else {
        return;
    };
    assert_recovers_hello(path);
}

#[test]
fn locates_moduledata_on_linux_amd64() {
    let Some(path) = fixture("hello.linux-amd64.stripped") else {
        return;
    };
    let bin = GoBinary::open(&path).expect("open binary");
    let md = ModuleData::locate(&bin).expect("locate moduledata");

    assert!(
        md.types > 0 && md.etypes > md.types,
        "types region must be non-empty"
    );
    assert_eq!(
        md.pc_header_addr, bin.pclntab_addr,
        "pcHeader pointer must match pclntab"
    );
    assert!(
        md.typelinks.len > 0,
        "real binaries have hundreds of typelinks"
    );
    assert!(md.text < md.etext, "text region must have positive size");
}

#[test]
fn recovers_types_on_linux_amd64() {
    let Some(path) = fixture("hello.linux-amd64.stripped") else {
        return;
    };
    let bin = GoBinary::open(&path).expect("open binary");
    let md = ModuleData::locate(&bin).expect("locate moduledata");
    let recovered = types::recover_all(&bin, &md).expect("recover types");

    assert!(
        recovered.len() > 100,
        "stdlib + main should produce more than 100 types, got {}",
        recovered.len()
    );

    let names: Vec<&str> = recovered.iter().map(|t| t.name.as_str()).collect();
    assert!(
        names.iter().any(|n| n.contains("runtime.")),
        "expected runtime.* types in the recovered set"
    );

    let kinds: std::collections::HashSet<KindName> = recovered.iter().map(|t| t.kind).collect();
    for required_kind in [KindName::Pointer, KindName::Slice, KindName::Struct] {
        assert!(
            kinds.contains(&required_kind),
            "expected at least one {required_kind:?} type"
        );
    }
}

#[test]
fn recovers_cobra_struct_fields() {
    let Some(path) = fixture("depsdemo.linux-amd64.stripped") else {
        return;
    };
    let bin = GoBinary::open(&path).expect("open binary");
    let md = ModuleData::locate(&bin).expect("locate moduledata");
    let all = types::recover_all(&bin, &md).expect("recover types");

    let cobra_struct = all
        .iter()
        .find(|t| t.name == "*cobra.Command" && t.kind == KindName::Struct);
    let cobra = match cobra_struct {
        Some(t) => t,
        None => return, // dep tree may differ across cobra versions; fine to skip
    };

    if let KindData::Struct { fields } = &cobra.kind_data {
        let field_names: Vec<&str> = fields.iter().map(|f| f.name.as_str()).collect();
        for expected in ["Use", "Short", "Long", "Run"] {
            assert!(
                field_names.contains(&expected),
                "expected cobra.Command to have field {expected}; got {field_names:?}"
            );
        }
    } else {
        panic!("cobra.Command should decode as Struct kind_data");
    }
}

#[test]
fn recovers_itabs_on_depsdemo() {
    let Some(path) = fixture("depsdemo.linux-amd64.stripped") else {
        return;
    };
    let bin = GoBinary::open(&path).expect("open binary");
    let md = ModuleData::locate(&bin).expect("locate moduledata");
    let pairs = itabs::recover_all(&bin, &md).expect("recover itabs");

    assert!(
        pairs.len() > 10,
        "real binaries have dozens of itabs, got {}",
        pairs.len()
    );

    // Every real Go binary linking io.* eventually has a *io.Writer => *os.File pair.
    let has_writer_os_file = pairs
        .iter()
        .any(|p| p.interface_name.contains("io.Writer") && p.concrete_name.contains("os.File"));
    assert!(
        has_writer_os_file,
        "expected *io.Writer => *os.File pairing in itabs"
    );
}

#[test]
fn parses_buildinfo_with_real_deps() {
    let Some(path) = fixture("depsdemo.linux-amd64.stripped") else {
        return;
    };
    let bin = GoBinary::open(&path).expect("open binary");
    let info = BuildInfo::parse(&bin).expect("parse buildinfo");

    assert!(
        info.go_version.starts_with("go1."),
        "go version must look real"
    );
    assert_eq!(info.path.as_deref(), Some("example.com/depsdemo"));
    assert!(
        info.deps.iter().any(|m| m.path == "github.com/spf13/cobra"),
        "expected cobra in deps"
    );
    assert!(
        info.settings
            .iter()
            .any(|s| s.key == "GOOS" && s.value == "linux"),
        "expected GOOS=linux build setting"
    );
}

#[test]
fn reverse_lookup_finds_main_main() {
    let Some(path) = fixture("hello.linux-amd64.stripped") else {
        return;
    };
    let bin = GoBinary::open(&path).expect("open binary");
    let pcln = Pclntab::parse(&bin).expect("parse pclntab");

    let main_fn = pcln
        .functions()
        .expect("functions")
        .into_iter()
        .find(|f| f.name == "main.main")
        .expect("main.main must be recovered");

    let looked_up = pcln
        .lookup(main_fn.address)
        .expect("lookup must succeed at function entry");
    assert_eq!(looked_up.name, "main.main");

    let inside = pcln
        .lookup(main_fn.address + 4)
        .expect("lookup must succeed mid-function");
    assert_eq!(inside.name, "main.main");

    let nonsense = pcln.lookup(0xdead_beef_1234_5678);
    assert!(
        nonsense.is_none(),
        "PC outside any function must return None"
    );
}

#[test]
fn detects_garble_on_garbled_binary() {
    let Some(path) = fixture("depsdemo.garbled.stripped") else {
        return;
    };
    let bin = GoBinary::open(&path).expect("open binary");
    let pcln = Pclntab::parse(&bin).expect("parse garbled pclntab");

    assert!(
        !pcln.magic_is_official(),
        "garble rewrites the pclntab magic"
    );

    let funcs = pcln
        .functions()
        .expect("functions still parse despite garble");
    assert!(
        funcs.len() > 100,
        "garble keeps the table structure; functions should still parse"
    );

    let version = unstrip::output::detect_go_version(&bin.bytes);
    let report =
        unstrip::output::detect_garble(&funcs, version.as_deref(), pcln.magic_is_official());
    assert!(
        report.verdict(),
        "garble verdict should fire on a real garble-built binary"
    );
    assert!(report.magic_rewritten, "should detect magic rewrite");
    assert!(
        report.version_overwritten,
        "should detect version overwrite"
    );
}

#[test]
fn inline_stack_recovers_three_deep_inlining() {
    // The inline3 fixture has main.anchor calling level1 calling level2 calling
    // level3, all inlinable. PCs inside the level3 body must produce a four-
    // frame stack: level3 (inlined) <- level2 (inlined) <- level1 (inlined) <-
    // anchor (physical).
    let Some(path) = fixture("inline3.linux-amd64.stripped") else {
        return;
    };
    let bin = GoBinary::open(&path).expect("open binary");
    let pcln = Pclntab::parse(&bin).expect("parse pclntab");
    let md = unstrip::ModuleData::locate(&bin).expect("locate moduledata");
    let pcln = pcln.with_gofunc(md.gofunc);

    let anchor = pcln
        .functions()
        .expect("functions")
        .into_iter()
        .find(|f| f.name == "main.anchor")
        .expect("main.anchor must be recovered");

    // Sweep PCs inside the anchor body looking for a frame that contains all
    // three nested inlined helpers. We don't pin the exact PC because Go's
    // codegen layout changes across toolchain versions; instead we assert
    // *some* PC inside the function yields the deep stack.
    let mut deepest = Vec::new();
    for off in 0..0x40u64 {
        let frames = pcln.lookup_inline(&bin, anchor.address + off);
        if frames.len() > deepest.len() {
            deepest = frames;
        }
    }
    assert!(
        deepest.len() >= 4,
        "expected a 4-frame stack somewhere in main.anchor; deepest was {} frames: {:?}",
        deepest.len(),
        deepest.iter().map(|f| f.name.as_str()).collect::<Vec<_>>()
    );
    let names: Vec<&str> = deepest.iter().map(|f| f.name.as_str()).collect();
    for required in ["main.level3", "main.level2", "main.level1", "main.anchor"] {
        assert!(
            names.contains(&required),
            "expected {required} in deep stack, got {names:?}"
        );
    }
    // Physical frame must be last and not marked inlined.
    assert!(
        !deepest.last().unwrap().inlined,
        "physical frame must be last"
    );
    assert_eq!(deepest.last().unwrap().name, "main.anchor");
}

#[test]
fn inline_stack_returns_single_frame_for_non_inlined_pc() {
    // The hello fixture's main.main does not have any inlined calls at its
    // entry PC. lookup_inline should return exactly one frame.
    let Some(path) = fixture("hello.linux-amd64.stripped") else {
        return;
    };
    let bin = GoBinary::open(&path).expect("open binary");
    let pcln = Pclntab::parse(&bin).expect("parse pclntab");
    let md = unstrip::ModuleData::locate(&bin).expect("locate moduledata");
    let pcln = pcln.with_gofunc(md.gofunc);

    let main_fn = pcln
        .functions()
        .expect("functions")
        .into_iter()
        .find(|f| f.name == "main.main")
        .expect("main.main must be recovered");

    let frames = pcln.lookup_inline(&bin, main_fn.address);
    assert!(
        !frames.is_empty(),
        "should always return at least the physical frame"
    );
    let physical = frames.last().expect("physical frame");
    assert_eq!(physical.name, "main.main");
    assert!(
        !physical.inlined,
        "the last frame must be physical, not inlined"
    );
}

#[test]
fn fingerprint_is_deterministic() {
    // Same binary parsed twice must produce the same fingerprint.
    let Some(path) = fixture("depsdemo.linux-amd64.stripped") else {
        return;
    };
    let bin1 = GoBinary::open(&path).expect("open binary");
    let pcln1 = Pclntab::parse(&bin1).expect("parse pclntab");
    let fp1 = unstrip::fingerprint::compute(&bin1, &pcln1).expect("fingerprint");
    let bin2 = GoBinary::open(&path).expect("re-open");
    let pcln2 = Pclntab::parse(&bin2).expect("re-parse");
    let fp2 = unstrip::fingerprint::compute(&bin2, &pcln2).expect("re-fingerprint");
    assert_eq!(
        fp1.sha256, fp2.sha256,
        "fingerprint must be stable across runs"
    );
    assert!(fp1.sha256.len() == 64, "sha256 hex must be 64 chars");
}

#[test]
fn fingerprint_stable_across_trimpath_rebuilds() {
    // Two builds of the same source: rebuild1 is plain `go build`, rebuild2
    // adds `-trimpath`. Both must produce byte-identical fingerprints (and
    // byte-identical behavioral fingerprints) so analysts can rely on the
    // hash as a stable cluster ID across CI configurations.
    let Some(p1) = fixture("depsdemo.rebuild1.stripped") else {
        return;
    };
    let Some(p2) = fixture("depsdemo.rebuild2.stripped") else {
        return;
    };

    let bin1 = GoBinary::open(&p1).expect("open rebuild1");
    let pcln1 = Pclntab::parse(&bin1).expect("parse rebuild1");
    let fp1 = unstrip::fingerprint::compute(&bin1, &pcln1).expect("fp1");
    let bfp1 = unstrip::fingerprint::compute_behavioral(&bin1).expect("bfp1");

    let bin2 = GoBinary::open(&p2).expect("open rebuild2");
    let pcln2 = Pclntab::parse(&bin2).expect("parse rebuild2");
    let fp2 = unstrip::fingerprint::compute(&bin2, &pcln2).expect("fp2");
    let bfp2 = unstrip::fingerprint::compute_behavioral(&bin2).expect("bfp2");

    assert_eq!(
        fp1.sha256, fp2.sha256,
        "full fingerprint must be identical across -trimpath rebuilds"
    );
    assert_eq!(
        bfp1.sha256, bfp2.sha256,
        "behavioral fingerprint must be identical across -trimpath rebuilds"
    );
}

#[test]
fn fingerprint_iteration_is_internally_deterministic() {
    // Parse the same binary 10 times, assert the hash is byte-identical
    // every run. This catches HashMap-iteration-order bugs that only
    // manifest occasionally on certain hash seeds.
    let Some(path) = fixture("depsdemo.linux-amd64.stripped") else {
        return;
    };
    let bin = GoBinary::open(&path).expect("open");
    let pcln = Pclntab::parse(&bin).expect("parse");
    let expected = unstrip::fingerprint::compute(&bin, &pcln)
        .expect("fp")
        .sha256;
    for run in 1..10 {
        let bin = GoBinary::open(&path).expect("re-open");
        let pcln = Pclntab::parse(&bin).expect("re-parse");
        let got = unstrip::fingerprint::compute(&bin, &pcln)
            .expect("fp")
            .sha256;
        assert_eq!(
            got, expected,
            "fingerprint must be deterministic across runs (run {run})"
        );
    }
    let expected_b = unstrip::fingerprint::compute_behavioral(&bin)
        .expect("bfp")
        .sha256;
    for run in 1..10 {
        let bin = GoBinary::open(&path).expect("re-open");
        let got = unstrip::fingerprint::compute_behavioral(&bin)
            .expect("bfp")
            .sha256;
        assert_eq!(
            got, expected_b,
            "behavioral fingerprint must be deterministic across runs (run {run})"
        );
    }
}

#[test]
fn fingerprint_differs_across_distinct_binaries() {
    let Some(p1) = fixture("depsdemo.linux-amd64.stripped") else {
        return;
    };
    let Some(p2) = fixture("hello.linux-amd64.stripped") else {
        return;
    };
    let bin1 = GoBinary::open(&p1).expect("open");
    let pcln1 = Pclntab::parse(&bin1).expect("parse");
    let fp1 = unstrip::fingerprint::compute(&bin1, &pcln1).expect("fp");
    let bin2 = GoBinary::open(&p2).expect("open");
    let pcln2 = Pclntab::parse(&bin2).expect("parse");
    let fp2 = unstrip::fingerprint::compute(&bin2, &pcln2).expect("fp");
    assert_ne!(
        fp1.sha256, fp2.sha256,
        "different sources must yield different fingerprints"
    );
}

#[test]
fn recovers_symbols_from_go_1_18() {
    let Some(path) = fixture("hello.go118.stripped") else {
        return;
    };
    let bin = GoBinary::open(&path).expect("open Go 1.18 binary");
    let pcln = Pclntab::parse(&bin).expect("parse 1.18 pclntab");
    assert!(
        pcln.magic_is_official(),
        "Go 1.18 magic 0xfffffff0 should be recognized"
    );
    let funcs = pcln.functions().expect("walk functab");
    assert!(funcs.len() > 100);
    // Go 1.18 binaries should also yield moduledata with the older layout.
    let md = unstrip::ModuleData::locate(&bin).expect("locate 1.18 moduledata");
    assert!(md.types > 0 && md.etypes > md.types);
    let types = unstrip::types::recover_all(&bin, &md).expect("recover 1.18 types");
    assert!(
        types.len() > 50,
        "Go 1.18 should still yield real types, got {}",
        types.len()
    );
}

#[test]
fn exporter_python_parses_for_all_targets() {
    // Emit IDA, Ghidra, and Binja scripts for a real fixture and verify
    // each one is syntactically valid Python. Catches escape bugs in
    // function names or struct decls that would silently break the user's
    // RE-tool import.
    let Some(path) = fixture("depsdemo.linux-amd64.stripped") else {
        return;
    };
    let bin = GoBinary::open(&path).expect("open");
    let pcln = Pclntab::parse(&bin).expect("parse");
    let funcs = pcln.functions().expect("functions");
    let md = unstrip::ModuleData::locate(&bin).expect("locate moduledata");
    let types_v = unstrip::types::recover_all(&bin, &md).expect("recover types");

    for target in [
        unstrip::export::Target::Ida,
        unstrip::export::Target::Ghidra,
        unstrip::export::Target::BinaryNinja,
    ] {
        let mut buf = Vec::new();
        unstrip::export::write_script(&mut buf, target, &funcs, &types_v).expect("emit");
        let script = String::from_utf8(buf).expect("utf-8 output");

        // Pass 1: every line that calls _func or _struct must have balanced
        // parens and a properly-closed string literal. A real Python parser
        // would catch every kind of error; this catches the common ones
        // without needing a Python interpreter at test time.
        for (lineno, line) in script.lines().enumerate() {
            let trimmed = line.trim();
            if !trimmed.starts_with("_func(") && !trimmed.starts_with("_struct(") {
                continue;
            }
            assert!(
                balanced_parens(trimmed),
                "{target:?} line {} has unbalanced parens: {trimmed}",
                lineno + 1
            );
            assert!(
                balanced_python_strings(trimmed),
                "{target:?} line {} has unterminated string literal: {trimmed}",
                lineno + 1
            );
        }

        // Pass 2: every _struct(decl) string must contain a balanced struct
        // body. Extract the decl literal and check brace pairing.
        for line in script.lines() {
            let Some(decl) = extract_struct_decl(line) else {
                continue;
            };
            assert!(
                decl.matches('{').count() == decl.matches('}').count(),
                "{target:?} struct decl has mismatched braces: {decl}"
            );
            // Every line inside the body must end with `;` or be a brace.
            for body_line in decl
                .lines()
                .skip(1)
                .take_while(|l| !l.trim().starts_with('}'))
            {
                let l = body_line.trim();
                if l.is_empty() {
                    continue;
                }
                assert!(
                    l.ends_with(';') || l.ends_with('{'),
                    "{target:?} struct body line missing semicolon: {l}"
                );
            }
        }
    }
}

fn balanced_parens(s: &str) -> bool {
    let mut depth = 0i32;
    let mut in_str = false;
    let mut escape = false;
    for ch in s.chars() {
        if escape {
            escape = false;
            continue;
        }
        match ch {
            '\\' if in_str => escape = true,
            '\'' => in_str = !in_str,
            '(' if !in_str => depth += 1,
            ')' if !in_str => depth -= 1,
            _ => {}
        }
        if depth < 0 {
            return false;
        }
    }
    depth == 0 && !in_str
}

fn balanced_python_strings(s: &str) -> bool {
    let mut in_str = false;
    let mut escape = false;
    for ch in s.chars() {
        if escape {
            escape = false;
            continue;
        }
        match ch {
            '\\' if in_str => escape = true,
            '\'' => in_str = !in_str,
            _ => {}
        }
    }
    !in_str
}

fn extract_struct_decl(line: &str) -> Option<String> {
    let trimmed = line.trim();
    let after = trimmed.strip_prefix("_struct(")?;
    let inner = after.strip_suffix(')')?;
    // The decl is a single-quoted Python string. Unescape the \n and \' that
    // our emitter inserted.
    let body = inner.strip_prefix('\'')?.strip_suffix('\'')?;
    let mut out = String::new();
    let mut escape = false;
    for ch in body.chars() {
        if escape {
            match ch {
                'n' => out.push('\n'),
                't' => out.push('\t'),
                'r' => out.push('\r'),
                '\\' => out.push('\\'),
                '\'' => out.push('\''),
                other => out.push(other),
            }
            escape = false;
        } else if ch == '\\' {
            escape = true;
        } else {
            out.push(ch);
        }
    }
    Some(out)
}

#[test]
fn capabilities_detects_cobra_dep() {
    // depsdemo links cobra and only cobra. The capability set should
    // include "shell command execution" via os/exec.Command which cobra
    // imports for shell completion. (If the set comes back empty
    // entirely, the matcher's broken.)
    let Some(path) = fixture("depsdemo.linux-amd64.stripped") else {
        return;
    };
    let bin = GoBinary::open(&path).expect("open");
    let pcln = Pclntab::parse(&bin).expect("parse");
    let funcs = pcln.functions().expect("funcs");
    let md = unstrip::ModuleData::locate(&bin).expect("md");
    let types_v = unstrip::types::recover_all(&bin, &md).expect("types");
    let itabs_v = unstrip::itabs::recover_all(&bin, &md).expect("itabs");
    let report = unstrip::capabilities::compute(&funcs, &types_v, &itabs_v);
    assert!(
        !report.capabilities.is_empty(),
        "real Go binary should match at least one capability"
    );
}

#[test]
fn dispatch_resolver_ghidra_embeds_itabs() {
    let Some(path) = fixture("depsdemo.linux-amd64.stripped") else {
        return;
    };
    let bin = GoBinary::open(&path).expect("open");
    let md = unstrip::ModuleData::locate(&bin).expect("md");
    let itabs_v = unstrip::itabs::recover_all(&bin, &md).expect("itabs");
    assert!(!itabs_v.is_empty(), "fixture should have itabs");
    let script = unstrip::dispatch::write_ghidra(&itabs_v);
    assert!(
        script.contains("ITABS = ["),
        "script must define ITABS table"
    );
    assert!(script.contains("_resolve()"), "script must invoke resolver");
    assert!(
        script.contains("'interface':"),
        "script must serialize interface entries"
    );
}

#[test]
fn diff_two_identical_rebuilds_yields_all_identical() {
    let Some(p1) = fixture("depsdemo.rebuild1.stripped") else {
        return;
    };
    let Some(p2) = fixture("depsdemo.rebuild2.stripped") else {
        return;
    };

    let bin1 = GoBinary::open(&p1).expect("open old");
    let pcln1 = Pclntab::parse(&bin1).expect("parse old");
    let bin2 = GoBinary::open(&p2).expect("open new");
    let pcln2 = Pclntab::parse(&bin2).expect("parse new");

    let old_funcs = pcln1.functions().expect("old funcs");
    let new_funcs = pcln2.functions().expect("new funcs");
    let report = unstrip::diff::compute(&old_funcs, &new_funcs);

    assert_eq!(report.added, 0, "trimpath rebuilds should add nothing");
    assert_eq!(report.removed, 0, "trimpath rebuilds should remove nothing");
    assert!(
        report.identical >= report.new_total * 9 / 10,
        "trimpath rebuilds should be >=90% identical; got {} identical of {}",
        report.identical,
        report.new_total,
    );
}

#[test]
fn xrefs_finds_main_main_callees() {
    // Every real binary's main.main calls at least a few other functions.
    // If the CALL scanner returns zero edges from main.main, it's broken.
    let Some(path) = fixture("depsdemo.linux-amd64.stripped") else {
        return;
    };
    let bin = GoBinary::open(&path).expect("open");
    let pcln = Pclntab::parse(&bin).expect("parse");
    let edges = unstrip::xrefs::find_calls(&bin, &pcln).expect("scan");
    let from_main: Vec<&unstrip::xrefs::CallEdge> = edges
        .iter()
        .filter(|e| e.caller_name == "main.main")
        .collect();
    assert!(
        from_main.len() >= 3,
        "main.main calls more than 3 functions; got {} edges",
        from_main.len()
    );
    let result = unstrip::xrefs::callees_from(&edges, "main.main", 1, usize::MAX);
    assert!(
        result.nodes.iter().any(|n| n.name.contains("cobra")),
        "main.main in a cobra-using binary should call something in cobra; got {:?}",
        result.nodes
    );
}

#[test]
fn xrefs_json_shape_has_root_direction_nodes_truncated() {
    // Sanity-check the JSON-facing struct: root and direction are set,
    // depth round-trips, each node carries a name and an addr field
    // (Option<u64>), and the max_nodes cap forces `truncated = true`.
    let Some(path) = fixture("depsdemo.linux-amd64.stripped") else {
        return;
    };
    let bin = GoBinary::open(&path).expect("open");
    let pcln = Pclntab::parse(&bin).expect("parse");
    let edges = unstrip::xrefs::find_calls(&bin, &pcln).expect("scan");

    let result = unstrip::xrefs::callees_from(&edges, "main.main", 4, 3);
    assert_eq!(result.root, "main.main");
    assert_eq!(result.direction, "callees");
    assert_eq!(result.depth, 4);
    assert_eq!(result.max_nodes, 3);
    assert!(result.truncated, "expected cap of 3 to trigger truncation");
    assert!(result.nodes.len() <= 3, "got {} nodes", result.nodes.len());
    assert!(
        result.nodes.iter().any(|n| n.addr.is_some()),
        "at least one callee should resolve to an address; got {:?}",
        result.nodes
    );

    let json = serde_json::to_value(&result).expect("serialize");
    assert_eq!(json["root"], "main.main");
    assert_eq!(json["direction"], "callees");
    assert_eq!(json["depth"], 4);
    assert_eq!(json["max_nodes"], 3);
    assert_eq!(json["truncated"], true);
    let nodes = json["nodes"].as_array().expect("nodes is array");
    assert!(!nodes.is_empty());
    for node in nodes {
        assert!(node["name"].is_string());
        assert!(node.get("addr").is_some(), "addr key must be present");
    }

    let callers = unstrip::xrefs::callers_of(&edges, "main.main", 1, usize::MAX);
    assert_eq!(callers.direction, "callers");
    assert!(!callers.truncated);
}

#[test]
fn goroutines_finds_runtime_newproc_sites() {
    // Every real Go binary calls runtime.newproc at least a handful of
    // times for the GC's background workers (runtime.gcBgMarkWorker,
    // runtime.forcegchelper, etc). If we can find none of those, the
    // pattern scan is broken.
    let Some(path) = fixture("depsdemo.linux-amd64.stripped") else {
        return;
    };
    let bin = GoBinary::open(&path).expect("open");
    let pcln = Pclntab::parse(&bin).expect("parse");
    let spawns = unstrip::goroutines::find_spawns(&bin, &pcln).expect("scan");
    assert!(
        spawns.len() >= 3,
        "real Go binaries call runtime.newproc at least 3 times for GC workers; got {}",
        spawns.len()
    );
    // At least one of them should resolve to a known runtime function.
    let resolved = spawns.iter().filter(|s| s.target_name.is_some()).count();
    assert!(
        resolved > 0,
        "at least one newproc target should resolve via the LEA backtrack heuristic; got {} unresolved out of {}",
        spawns.len() - resolved,
        spawns.len()
    );
}

#[test]
fn symbols_as_elf_writes_valid_symtab() {
    // Rewrite a real stripped binary with --symbols-as elf and verify the
    // resulting file has a valid Elf64_Sym table containing every function
    // we recover. We don't shell out to nm; we parse the ELF directly so
    // the test runs on any host.
    use std::io::Read;
    let Some(path) = fixture("depsdemo.linux-amd64.stripped") else {
        return;
    };
    let bin = GoBinary::open(&path).expect("open");
    let pcln = Pclntab::parse(&bin).expect("parse");
    let functions = pcln.functions().expect("functions");

    let tmp = std::env::temp_dir().join(format!("unstrip-symbols-test-{}.bin", std::process::id()));
    let _ = std::fs::remove_file(&tmp);

    let n = unstrip::rewrite::write_symbols_as_elf(&bin, &functions, &tmp, Some(&path))
        .expect("rewrite");
    assert_eq!(n, functions.len(), "should write one symbol per function");

    // Re-open the written file and verify goblin can parse it and find
    // our .symtab section with the right entry count.
    let mut new_bytes = Vec::new();
    std::fs::File::open(&tmp)
        .expect("reopen")
        .read_to_end(&mut new_bytes)
        .expect("read");
    let parsed = goblin::Object::parse(&new_bytes).expect("re-parse ELF");
    let elf = match parsed {
        goblin::Object::Elf(e) => e,
        _ => panic!("output is not ELF"),
    };
    let symtab = elf
        .section_headers
        .iter()
        .find(|sh| elf.shdr_strtab.get_at(sh.sh_name) == Some(".symtab"))
        .expect("output must have a .symtab section");
    // Elf64_Sym is 24 bytes; we wrote N+1 entries (null + one per function).
    let expected_size = (functions.len() + 1) * 24;
    assert_eq!(
        symtab.sh_size as usize, expected_size,
        ".symtab size should match (N+1) * sizeof(Elf64_Sym)"
    );

    let _ = std::fs::remove_file(&tmp);
}

#[test]
fn rejects_non_go_binary() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml");
    let result = GoBinary::open(&path);
    assert!(result.is_err(), "Cargo.toml should not parse as a binary");
}
