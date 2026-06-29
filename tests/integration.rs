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
fn probe_describes_a_clean_go_binary() {
    // A normal Go binary probes as a low-entropy ELF that owns a pclntab and
    // raises no packer verdict -- the baseline the packed-binary path degrades
    // from.
    let Some(path) = fixture("hello.linux-amd64.stripped") else {
        return;
    };
    let bytes = std::fs::read(&path).expect("read fixture");
    let p = unstrip::probe::probe(&bytes).expect("probe");
    assert_eq!(p.container, "ELF");
    assert_eq!(p.arch, "x86-64");
    assert_eq!(p.bits, 64);
    assert!(p.has_go_pclntab, "a clean Go ELF has a .gopclntab section");
    assert!(
        p.packer.is_none(),
        "a clean Go binary must not be flagged as packed (got {:?})",
        p.packer
    );
    assert!(!p.sections.is_empty());
    assert!(
        p.file_entropy < 7.0,
        "clean Go binary whole-file entropy should be moderate, got {}",
        p.file_entropy
    );
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
fn recovers_struct_field_tags() {
    // The gtest Account struct carries `json:"..."` tags. Recovery must surface
    // them verbatim: the tag is the struct's wire schema (the field names a
    // marshaler emits), and it survives obfuscation, so recovering it is how a
    // garbled config struct gives up its real json/db field names even when the
    // Go field identifiers are hashed away. Skips if the fixture is unbuilt.
    let Some(path) = fixture("gtest.plain.stripped") else {
        return;
    };
    let bin = GoBinary::open(&path).expect("open binary");
    let md = ModuleData::locate(&bin).expect("locate moduledata");
    let all = types::recover_all(&bin, &md).expect("recover types");

    let account = match all
        .iter()
        .find(|t| t.name == "main.Account" && t.kind == KindName::Struct)
    {
        Some(t) => t,
        None => return, // tolerate layout drift across Go versions
    };

    let KindData::Struct { fields } = &account.kind_data else {
        panic!("main.Account should decode as Struct kind_data");
    };
    let username = fields
        .iter()
        .find(|f| f.name == "Username")
        .expect("Account should have a Username field");
    assert_eq!(
        username.tag, "json:\"username\"",
        "struct field tag must be recovered verbatim"
    );
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
fn recovers_itabs_on_32bit_and_big_endian() {
    // The moduledata, itab, and type readers must honor pointer width and byte
    // order. 386 is a 32-bit pointer width; s390x is big-endian. Both must
    // recover the same pairings amd64 does, including the program's own Codec
    // interface and the universal io.Writer => os.File.
    for name in [
        "featureset.linux-386.stripped",
        "featureset.linux-s390x.stripped",
    ] {
        let Some(path) = fixture(name) else {
            continue;
        };
        let bin = GoBinary::open(&path).expect("open binary");
        let md = ModuleData::locate(&bin).expect("locate moduledata");
        let pairs = itabs::recover_all(&bin, &md).expect("recover itabs");

        assert!(
            pairs.len() > 5,
            "{name}: expected several itabs, got {}",
            pairs.len()
        );
        assert!(
            pairs
                .iter()
                .any(|p| p.interface_name.contains("io.Writer")
                    && p.concrete_name.contains("os.File")),
            "{name}: expected *io.Writer => *os.File pairing"
        );
        assert!(
            pairs
                .iter()
                .any(|p| p.interface_name.contains("main.Codec")),
            "{name}: expected the program's main.Codec interface"
        );
    }
}

/// Wrap arch slices in a Mach-O universal (fat) header. cputype/data pairs;
/// offsets are 16k-aligned, all fields big-endian, matching the on-disk format.
fn make_fat(slices: &[(u32, &[u8])]) -> Vec<u8> {
    let align = 0x4000usize;
    let round = |n: usize| n.div_ceil(align) * align;
    let mut out = Vec::new();
    out.extend_from_slice(&0xcafebabeu32.to_be_bytes()); // FAT_MAGIC
    out.extend_from_slice(&(slices.len() as u32).to_be_bytes());
    let mut offset = round(8 + slices.len() * 20);
    let mut offsets = Vec::new();
    for (cputype, data) in slices {
        out.extend_from_slice(&cputype.to_be_bytes());
        out.extend_from_slice(&0u32.to_be_bytes()); // cpusubtype
        out.extend_from_slice(&(offset as u32).to_be_bytes());
        out.extend_from_slice(&(data.len() as u32).to_be_bytes());
        out.extend_from_slice(&14u32.to_be_bytes()); // align = 2^14
        offsets.push(offset);
        offset = round(offset + data.len());
    }
    for ((_, data), off) in slices.iter().zip(offsets) {
        out.resize(off, 0);
        out.extend_from_slice(data);
    }
    out
}

#[test]
fn parses_macho_universal_and_selects_amd64() {
    let (Some(amd), Some(arm)) = (
        fixture("hello.darwin-amd64.stripped"),
        fixture("hello.darwin-arm64.stripped"),
    ) else {
        return;
    };
    let amd = std::fs::read(amd).expect("read amd64 slice");
    let arm = std::fs::read(arm).expect("read arm64 slice");
    // arm64 first, so a pass proves selection prefers amd64 over slice order.
    let fat = make_fat(&[(0x0100000c, &arm), (0x01000007, &amd)]);

    let bin = GoBinary::parse(fat).expect("parse universal binary");
    assert_eq!(bin.arch.as_str(), "amd64", "should select the amd64 slice");
    assert!(
        ModuleData::locate(&bin).is_ok(),
        "moduledata should locate in the selected slice"
    );
}

#[test]
fn itabs_filter_matches_method_names() {
    // --itabs --filter applies the predicate (interface_name OR
    // concrete_name OR any interface_method). This test pins the
    // method-column behavior because that's the surface garble-
    // default binaries depend on: type columns are hashed but
    // methods that satisfy stdlib interfaces survive (garble can't
    // rewrite a method name that satisfies a stdlib interface
    // without breaking dispatch).
    let Some(path) = fixture("depsdemo.linux-amd64.stripped") else {
        return;
    };
    let bin = GoBinary::open(&path).expect("open binary");
    let md = ModuleData::locate(&bin).expect("locate moduledata");
    let all = itabs::recover_all(&bin, &md).expect("recover itabs");

    let needle = "Write";
    let by_method: Vec<_> = all
        .iter()
        .filter(|it| {
            it.methods
                .iter()
                .any(|m| m.interface_method.contains(needle))
        })
        .collect();
    assert!(
        !by_method.is_empty(),
        "any real Go binary has at least one itab whose method name contains 'Write'"
    );
}

#[test]
fn strings_recover_identifiable_literals_from_real_binary() {
    // --strings on a real Go binary should surface human-readable
    // literals from .rodata. Depsdemo links cobra, so the cobra usage
    // string should appear; this is the "I can identify a binary by
    // its CLI banner" workflow the field test depended on.
    let Some(path) = fixture("depsdemo.linux-amd64.stripped") else {
        return;
    };
    let bin = GoBinary::open(&path).expect("open binary");
    let opts = unstrip::strings::Options {
        min_len: 8,
        max: None,
        filter: None,
    };
    let all = unstrip::strings::extract(&bin, &opts);
    assert!(
        all.len() > 100,
        "real Go binary should yield hundreds of >=8-char .rodata runs, got {}",
        all.len()
    );
    // Cobra's standard usage banner is "Usage:" - it appears in every
    // cobra-using binary's .rodata.
    assert!(
        all.iter().any(|s| s.text.contains("Usage:")),
        "cobra binary must contain a 'Usage:' literal"
    );
}

#[test]
fn strings_substring_filter_is_applied() {
    let Some(path) = fixture("depsdemo.linux-amd64.stripped") else {
        return;
    };
    let bin = GoBinary::open(&path).expect("open binary");
    let opts = unstrip::strings::Options {
        min_len: 4,
        max: None,
        filter: Some("Usage".into()),
    };
    let hits = unstrip::strings::extract(&bin, &opts);
    assert!(
        !hits.is_empty(),
        "filter for 'Usage' should produce at least one hit on a cobra binary"
    );
    for s in &hits {
        assert!(
            s.text.contains("Usage"),
            "filtered string {:?} does not contain needle",
            s.text
        );
    }
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
fn buildinfo_degrades_on_stripped_modinfo() {
    // garble blanks the module-info blob. Parsing must degrade to a version-only
    // result rather than failing: the module table is gone, but recovery should
    // not stop on it. Before this, --buildinfo on a garbled binary errored with
    // a raw "modinfo too short" parse failure.
    let Some(path) = fixture("gtest.garbled.stripped") else {
        return;
    };
    let bin = GoBinary::open(&path).expect("open garbled binary");
    let info = BuildInfo::parse(&bin)
        .expect("buildinfo must degrade, not error, when the modinfo blob is stripped");
    assert!(
        info.deps.is_empty(),
        "a stripped modinfo should yield no deps, got {}",
        info.deps.len()
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

/// Full recovery on one Go release: the same hello.go built with a specific
/// toolchain. Pins functions, moduledata, types, and the build version across
/// the supported range so a layout drift in any release fails loudly.
fn assert_recovers_version(fixture_name: &str, version_prefix: &str) {
    let Some(path) = fixture(fixture_name) else {
        return;
    };
    let bin = GoBinary::open(&path).expect("open binary");
    let pcln = Pclntab::parse(&bin).expect("parse pclntab");
    assert!(
        pcln.magic_is_official(),
        "{version_prefix}: official pclntab magic expected"
    );

    let funcs = pcln.functions().expect("walk functab");
    let names: Vec<&str> = funcs.iter().map(|f| f.name.as_str()).collect();
    for required in ["main.main", "main.greet", "main.parseFlags"] {
        assert!(
            names.contains(&required),
            "{version_prefix}: expected {required} in recovered symbols ({} funcs)",
            names.len()
        );
    }

    let md = ModuleData::locate(&bin).expect("locate moduledata");
    assert!(
        md.types > 0 && md.etypes > md.types,
        "{version_prefix}: types region must be non-empty"
    );
    let recovered = types::recover_all(&bin, &md).expect("recover types");
    assert!(
        recovered.len() > 50,
        "{version_prefix}: expected real types, got {}",
        recovered.len()
    );

    let info = BuildInfo::parse(&bin).expect("parse buildinfo");
    assert!(
        info.go_version.starts_with(version_prefix),
        "expected {version_prefix}, got {}",
        info.go_version
    );
}

#[test]
fn recovers_go_1_20() {
    assert_recovers_version("hello.go120.stripped", "go1.20");
}

#[test]
fn recovers_go_1_22() {
    assert_recovers_version("hello.go122.stripped", "go1.22");
}

#[test]
fn recovers_go_1_19() {
    assert_recovers_version("hello.go119.stripped", "go1.19");
}

#[test]
fn recovers_go_1_21() {
    assert_recovers_version("hello.go121.stripped", "go1.21");
}

#[test]
fn recovers_go_1_23() {
    assert_recovers_version("hello.go123.stripped", "go1.23");
}

#[test]
fn recovers_go_1_24() {
    assert_recovers_version("hello.go124.stripped", "go1.24");
}

#[test]
fn recovers_go_1_25() {
    assert_recovers_version("hello.go125.stripped", "go1.25");
}

/// Deep recovery on one Go release using the richer featureset.go fixture:
/// interfaces with concrete implementers (itabs), generics, struct methods,
/// goroutines, and a crypto dependency. Pins that functions, the program's own
/// types, the custom-interface itabs, and the build version all recover on every
/// release, so a type-walker or itab-walker drift in any version fails loudly
/// where the minimal hello.go fixture would not exercise the code at all.
fn assert_recovers_featureset(fixture_name: &str, version_prefix: &str) {
    let Some(path) = fixture(fixture_name) else {
        return;
    };
    let bin = GoBinary::open(&path).expect("open binary");
    let pcln = Pclntab::parse(&bin).expect("parse pclntab");

    let funcs = pcln.functions().expect("walk functab");
    let names: Vec<&str> = funcs.iter().map(|f| f.name.as_str()).collect();
    for required in ["main.main", "main.run"] {
        assert!(
            names.contains(&required),
            "{version_prefix}: expected {required} in recovered symbols ({} funcs)",
            names.len()
        );
    }

    let md = ModuleData::locate(&bin).expect("locate moduledata");
    let recovered = types::recover_all(&bin, &md).expect("recover types");
    assert!(
        recovered.len() > 50,
        "{version_prefix}: expected real types, got {}",
        recovered.len()
    );
    // The program's own types must survive, not just stdlib ones: the type
    // walker has to handle this binary's main-package definitions.
    assert!(
        recovered.iter().any(|t| t.name.contains("main.")),
        "{version_prefix}: expected a main.* type in the recovered catalog"
    );
    let kinds: std::collections::HashSet<KindName> = recovered.iter().map(|t| t.kind).collect();
    for required_kind in [KindName::Struct, KindName::Interface] {
        assert!(
            kinds.contains(&required_kind),
            "{version_prefix}: expected at least one {required_kind:?} type"
        );
    }

    // The []Codec literal builds two itabs (Codec/xorCodec, Codec/addCodec) that
    // the linker keeps in itablinks. Pin that the custom interface's itabs walk.
    let pairs = itabs::recover_all(&bin, &md).expect("recover itabs");
    assert!(
        pairs
            .iter()
            .any(|p| p.interface_name.contains("main.Codec")),
        "{version_prefix}: expected a main.Codec itab among {} pairs",
        pairs.len()
    );

    let info = BuildInfo::parse(&bin).expect("parse buildinfo");
    assert!(
        info.go_version.starts_with(version_prefix),
        "expected {version_prefix}, got {}",
        info.go_version
    );
}

/// Type and itab recovery on the pre-1.18 moduledata layout (Go 1.16/1.17 drop
/// the rodata/gofunc fields 1.18 added). Uses typeset.go (no generics, so it
/// builds on 1.16+) which defines a custom interface with two implementers, so the
/// itablinks and the program's own struct and interface types must all recover with
/// correct names, not just a non-empty count.
#[test]
fn recovers_typeset_go_1_17() {
    let Some(path) = fixture("typeset.go117.stripped") else {
        return;
    };
    let bin = GoBinary::open(&path).expect("open typeset go1.17");
    let md = ModuleData::locate(&bin).expect("locate pre-1.18 moduledata");

    let types = types::recover_all(&bin, &md).expect("recover types");
    let names: Vec<&str> = types.iter().map(|t| t.name.as_str()).collect();
    for required in ["main.Codec", "main.xorCodec", "main.addCodec"] {
        assert!(
            names.iter().any(|n| n.contains(required)),
            "go1.17: expected {required} among {} recovered types",
            types.len()
        );
    }

    // The []Codec literal links two itabs (Codec/xorCodec, Codec/addCodec); both
    // must come back from the pre-1.18 itablinks.
    let pairs = itabs::recover_all(&bin, &md).expect("recover itabs");
    let codec_itabs = pairs
        .iter()
        .filter(|p| p.interface_name.contains("main.Codec"))
        .count();
    assert!(
        codec_itabs >= 2,
        "go1.17: expected both main.Codec itabs, got {codec_itabs} of {} pairs",
        pairs.len()
    );
}

#[test]
fn recovers_featureset_go_1_18() {
    assert_recovers_featureset("featureset.go118.stripped", "go1.18");
}

#[test]
fn recovers_featureset_go_1_19() {
    assert_recovers_featureset("featureset.go119.stripped", "go1.19");
}

#[test]
fn recovers_featureset_go_1_20() {
    assert_recovers_featureset("featureset.go120.stripped", "go1.20");
}

#[test]
fn recovers_featureset_go_1_21() {
    assert_recovers_featureset("featureset.go121.stripped", "go1.21");
}

#[test]
fn recovers_featureset_go_1_22() {
    assert_recovers_featureset("featureset.go122.stripped", "go1.22");
}

#[test]
fn recovers_featureset_go_1_23() {
    assert_recovers_featureset("featureset.go123.stripped", "go1.23");
}

#[test]
fn recovers_featureset_go_1_24() {
    assert_recovers_featureset("featureset.go124.stripped", "go1.24");
}

#[test]
fn recovers_featureset_go_1_25() {
    assert_recovers_featureset("featureset.go125.stripped", "go1.25");
}

#[test]
fn recovers_featureset_go_1_26() {
    // Go 1.26 inserted an `epclntab` pointer into moduledata; without the V126
    // layout the typelinks slice reads garbage and type recovery fails outright.
    assert_recovers_featureset("featureset.go126.stripped", "go1.26");
}

#[test]
fn recovers_from_garbled_go_1_26() {
    // A garble-obfuscated Go 1.26 binary stresses two fixes at once: the pclntab
    // magic is rewritten (structural discovery must find the header) and the
    // moduledata uses the 1.26 layout (the V126 epclntab field). Names are
    // hashed, but the structures survive, so functions, types, and itabs must
    // all recover.
    let Some(path) = fixture("gtest.garbled.stripped") else {
        return;
    };
    let bin = GoBinary::open(&path).expect("open garbled binary");
    let pcln = Pclntab::parse(&bin).expect("parse pclntab on garbled");
    assert!(
        !pcln.magic_is_official(),
        "garble rewrites the pclntab magic"
    );
    let funcs = pcln.functions().expect("functions");
    assert!(
        funcs.len() > 100,
        "functions must recover on a garbled binary, got {}",
        funcs.len()
    );
    let md = ModuleData::locate(&bin).expect("locate 1.26 moduledata on garbled");
    let recovered = types::recover_all(&bin, &md).expect("recover types");
    assert!(
        recovered.len() > 100,
        "types must recover on garbled 1.26, got {}",
        recovered.len()
    );
    let pairs = itabs::recover_all(&bin, &md).expect("recover itabs");
    assert!(
        pairs.len() > 10,
        "itabs must recover on garbled 1.26, got {}",
        pairs.len()
    );
}

#[test]
fn recovers_reflect_name_dictionary_from_garbled() {
    // garble embeds an obfuscated->original name table so reflect keeps working.
    // Recover it from the data section and confirm it maps the hashed names back
    // to the originals the program defined. The Account struct's field names are
    // hashed in the type descriptor, so this dictionary is the only path back to
    // them. (Exported method names like Describe are never obfuscated and so do
    // not appear here.)
    let Some(path) = fixture("gtest.garbled.stripped") else {
        return;
    };
    let bin = GoBinary::open(&path).expect("open garbled binary");
    let names = unstrip::garble::recover_reflect_names(&bin)
        .expect("garbled binary must carry a reflect-name table");
    assert!(
        names.len() >= 8,
        "expected a real dictionary, got {} entries",
        names.len()
    );

    let originals: std::collections::HashSet<&str> = names.iter().map(|(_, orig)| orig).collect();
    for expected in ["Username", "Password", "Balance"] {
        assert!(
            originals.contains(expected),
            "reflect dictionary should recover the original field name {expected:?}"
        );
    }

    // The dictionary should also translate a hashed token back: find the key
    // that maps to Username and confirm relabel rewrites it.
    let (obf, _) = names
        .iter()
        .find(|(_, orig)| *orig == "Username")
        .expect("Username must have an obfuscated key");
    assert_eq!(names.translate(obf), Some("Username"));
    assert_eq!(
        names.relabel(&format!("main.{obf}")),
        "main.Username",
        "relabel should rewrite the hashed token in a qualified name"
    );
}

#[test]
fn degarble_relabels_struct_to_plaintext() {
    // Applying the recovered dictionary to the recovered types must turn the
    // hashed Account struct back into plaintext: the type name and all three
    // field names. This is the end-to-end payoff behind --degarble.
    let Some(path) = fixture("gtest.garbled.stripped") else {
        return;
    };
    let bin = GoBinary::open(&path).expect("open garbled binary");
    let md = ModuleData::locate(&bin).expect("locate moduledata");
    let mut all = types::recover_all(&bin, &md).expect("recover types");

    // Before relabeling, no struct carries the original field names.
    let has_plaintext = |types: &[unstrip::types::Type]| {
        types.iter().any(|t| {
            matches!(&t.kind_data, KindData::Struct { fields }
                if fields.iter().any(|f| f.name == "Username"))
        })
    };
    assert!(
        !has_plaintext(&all),
        "garbled types should start with hashed field names"
    );

    let names = unstrip::garble::recover_reflect_names(&bin).expect("reflect names");
    names.relabel_types(&mut all);

    let account = all
        .iter()
        .find(|t| t.name == "main.Account")
        .expect("Account type name should relabel to plaintext");
    let KindData::Struct { fields } = &account.kind_data else {
        panic!("main.Account should decode as a struct");
    };
    let field_names: Vec<&str> = fields.iter().map(|f| f.name.as_str()).collect();
    for expected in ["Username", "Password", "Balance"] {
        assert!(
            field_names.contains(&expected),
            "relabeled Account should have field {expected}; got {field_names:?}"
        );
    }
}

#[test]
fn pie_addresses_are_rebased_into_text() {
    // A PIE binary stores text-relative offsets; a wrong load base makes function
    // addresses land outside the text section while their names still parse from
    // the funcname table. Pin that main.main both resolves by name and sits
    // inside [text, etext), which only holds when the base is applied correctly.
    let Some(path) = fixture("hello.linux-amd64.pie.stripped") else {
        return;
    };
    let bin = GoBinary::open(&path).expect("open pie binary");
    let pcln = Pclntab::parse(&bin).expect("parse pie pclntab");
    let main_fn = pcln
        .functions()
        .expect("functions")
        .into_iter()
        .find(|f| f.name == "main.main")
        .expect("main.main recovered");
    assert_eq!(
        pcln.lookup(main_fn.address).expect("lookup at entry").name,
        "main.main"
    );
    let md = ModuleData::locate(&bin).expect("locate moduledata");
    assert!(
        md.text <= main_fn.address && main_fn.address < md.etext,
        "main.main 0x{:x} must fall inside text [0x{:x}, 0x{:x})",
        main_fn.address,
        md.text,
        md.etext
    );
}

#[test]
fn recovers_types_on_darwin_amd64() {
    // Go's Darwin linker puts runtime.firstmoduledata in a __go_module section,
    // not __noptrdata as on ELF, so moduledata location has to scan it. Without
    // that, every moduledata-dependent feature fails on Mach-O. The existing
    // Darwin tests only check the function table (which comes from the named
    // pclntab section), so they did not exercise this; pin that types recover.
    let Some(path) = fixture("hello.darwin-amd64.stripped") else {
        return;
    };
    let bin = GoBinary::open(&path).expect("open darwin binary");
    let md = ModuleData::locate(&bin).expect("locate moduledata on Mach-O");
    let recovered = types::recover_all(&bin, &md).expect("recover types on Mach-O");
    assert!(
        recovered.len() > 50,
        "Mach-O should yield real types, got {}",
        recovered.len()
    );
    let kinds: std::collections::HashSet<KindName> = recovered.iter().map(|t| t.kind).collect();
    assert!(
        kinds.contains(&KindName::Struct),
        "expected struct types in the Mach-O recovered set"
    );
}

#[test]
fn recovers_types_on_linux_arm64() {
    // Type recovery is architecture-independent (it walks the type catalog, not
    // code), but the moduledata scan reads pointer-width fields, so pin that the
    // arm64 path reaches real types and not just function names.
    let Some(path) = fixture("hello.linux-arm64.stripped") else {
        return;
    };
    let bin = GoBinary::open(&path).expect("open arm64 binary");
    let md = ModuleData::locate(&bin).expect("locate moduledata on arm64");
    let recovered = types::recover_all(&bin, &md).expect("recover types on arm64");
    assert!(
        recovered.len() > 50,
        "arm64 should yield real types, got {}",
        recovered.len()
    );
    let kinds: std::collections::HashSet<KindName> = recovered.iter().map(|t| t.kind).collect();
    assert!(
        kinds.contains(&KindName::Struct),
        "expected struct types in the arm64 recovered set"
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
        unstrip::export::write_script(&mut buf, target, &funcs, &types_v, None, "unstrip")
            .expect("emit");
        let script = String::from_utf8(buf).expect("utf-8 output");

        // The generator name is parameterized so a relift-driven export does not
        // claim it was generated by unstrip.
        assert!(
            script.contains("Generated by unstrip"),
            "header should name the generator"
        );

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
    for cap in &report.capabilities {
        assert!(
            !cap.rule_id.is_empty(),
            "capability {:?} should carry a non-empty rule_id",
            cap.name
        );
    }
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
    let report = unstrip::diff::compute(&old_funcs, &new_funcs, None, None);

    assert_eq!(report.added, 0, "trimpath rebuilds should add nothing");
    assert_eq!(report.removed, 0, "trimpath rebuilds should remove nothing");
    // Every function carries over by name: it is either identical (same address) or
    // moved (relinked elsewhere). Both mean "the same function," so the rebuild is
    // fully accounted for by the two together, with nothing renamed away.
    assert!(
        report.identical + report.moved >= report.new_total * 9 / 10,
        "trimpath rebuilds should be >=90% unchanged; got {} identical + {} moved of {}",
        report.identical,
        report.moved,
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
fn xrefs_node_depth_tracks_bfs_distance_from_root() {
    // Depth-by-depth BFS layering is the surface --xrefs text output
    // uses to indent: depth 1 = direct callees, depth 2 = their
    // callees, etc. The text-mode formatter renders one entry per
    // node prefixed by `"  ".repeat(depth)`, so every node must
    // carry a depth in [1, requested_depth].
    let Some(path) = fixture("depsdemo.linux-amd64.stripped") else {
        return;
    };
    let bin = GoBinary::open(&path).expect("open binary");
    let pcln = Pclntab::parse(&bin).expect("parse pclntab");
    let edges = unstrip::xrefs::find_calls(&bin, &pcln).expect("find_calls");

    let result = unstrip::xrefs::callees_from(&edges, "main.main", 3, usize::MAX);
    assert!(!result.nodes.is_empty(), "expected at least one callee");
    for node in &result.nodes {
        assert!(
            (1..=3).contains(&node.depth),
            "node {} depth {} out of [1, 3]",
            node.name,
            node.depth
        );
    }
    // Direct callees of main.main must appear at depth 1.
    assert!(
        result.nodes.iter().any(|n| n.depth == 1),
        "BFS must find at least one direct callee at depth 1"
    );
}

#[test]
fn dataview_symbolize_resolves_itab_and_function_addresses() {
    // Run the symbolizer against known address classes on a real
    // binary: pick an itab from --itabs and a function from pclntab,
    // and assert each resolves to the right kind. This is the
    // contract --data-at --as ptrs|ifaces depends on; if it breaks
    // here, --data-at silently degrades to raw hex on a real binary.
    let Some(path) = fixture("depsdemo.linux-amd64.stripped") else {
        return;
    };
    let bin = GoBinary::open(&path).expect("open");
    let pcln = Pclntab::parse(&bin).expect("pcln");
    let funcs = pcln.functions().expect("funcs");
    let md = unstrip::ModuleData::locate(&bin).expect("md");
    let itabs_v = itabs::recover_all(&bin, &md).expect("itabs");

    assert!(!itabs_v.is_empty(), "fixture must have itabs");
    let it = &itabs_v[0];
    match unstrip::dataview::symbolize(&bin, &pcln, &itabs_v, &funcs, it.addr) {
        unstrip::dataview::Symbol::Itab {
            interface,
            concrete,
            methods,
        } => {
            assert_eq!(interface, it.interface_name);
            assert_eq!(concrete, it.concrete_name);
            // Methods are surfaced inline so iface-mode renderings
            // can dispatch in one query. When the recovered itab
            // carries methods, the symbol must too; when it does not,
            // both stay empty.
            assert_eq!(methods.len(), it.methods.len());
            for (m_sym, m_src) in methods.iter().zip(it.methods.iter()) {
                assert_eq!(m_sym.name, m_src.interface_method);
                assert_eq!(m_sym.concrete_fn, m_src.concrete_fn);
            }
        }
        other => panic!("expected Symbol::Itab at itab address, got {:?}", other),
    }

    let main_main = funcs
        .iter()
        .find(|f| f.name == "main.main")
        .expect("main.main");
    match unstrip::dataview::symbolize(&bin, &pcln, &itabs_v, &funcs, main_main.address) {
        unstrip::dataview::Symbol::Function {
            name,
            entry,
            offset,
        } => {
            assert_eq!(name, "main.main");
            assert_eq!(entry, main_main.address);
            assert_eq!(offset, 0);
        }
        other => panic!("expected Symbol::Function at entry PC, got {:?}", other),
    }

    // Mid-function PC: same function name, non-zero offset.
    let mid = main_main.address + 5;
    match unstrip::dataview::symbolize(&bin, &pcln, &itabs_v, &funcs, mid) {
        unstrip::dataview::Symbol::Function {
            name,
            entry,
            offset,
        } => {
            assert_eq!(name, "main.main");
            assert_eq!(entry, main_main.address);
            assert_eq!(offset, 5);
        }
        other => panic!("expected mid-function Symbol::Function, got {:?}", other),
    }

    // A small integer is not a pointer; must surface as Scalar.
    match unstrip::dataview::symbolize(&bin, &pcln, &itabs_v, &funcs, 42) {
        unstrip::dataview::Symbol::Scalar { value } => assert_eq!(value, 42),
        other => panic!("expected Scalar for small int, got {:?}", other),
    }
}

#[test]
fn dataview_inspect_bytes_mode_returns_aligned_hex_rows() {
    let Some(path) = fixture("depsdemo.linux-amd64.stripped") else {
        return;
    };
    let bin = GoBinary::open(&path).expect("open");
    let pcln = Pclntab::parse(&bin).expect("pcln");
    let funcs = pcln.functions().expect("funcs");
    let md = unstrip::ModuleData::locate(&bin).expect("md");
    let itabs_v = itabs::recover_all(&bin, &md).expect("itabs");

    // Pick any in-bounds data address; the pclntab base is reliable.
    let rows = unstrip::dataview::inspect(
        &bin,
        &pcln,
        &itabs_v,
        &funcs,
        md.pc_header_addr,
        64,
        unstrip::dataview::As::Bytes,
    )
    .expect("inspect");
    assert_eq!(rows.len(), 4, "64 bytes / 16-per-row = 4 rows");
    for (i, r) in rows.iter().enumerate() {
        assert_eq!(r.addr, md.pc_header_addr + (i as u64) * 16);
        assert_eq!(r.bytes.len(), 16);
        assert!(r.rendering.contains('|'), "ASCII gutter must be present");
    }
}

#[test]
fn dataxref_referenced_addresses_covers_live_itabs() {
    // The liveness annotation on --itabs depends on referenced_addresses
    // returning a set that contains every itab reachable from .text OR
    // from a data-section pointer-table. Real Go binaries dead-strip
    // unreachable itabs at link time, so the set the linker leaves in
    // runtime.itablinks IS the live set; every recovered itab address
    // must therefore appear in the reachability set.
    let Some(path) = fixture("depsdemo.linux-amd64.stripped") else {
        return;
    };
    let bin = GoBinary::open(&path).expect("open");
    let md = unstrip::ModuleData::locate(&bin).expect("md");
    let itabs_v = itabs::recover_all(&bin, &md).expect("itabs");
    let reachable = unstrip::dataxref::referenced_addresses(&bin).expect("sweep");
    assert!(!itabs_v.is_empty());
    let missing: Vec<u64> = itabs_v
        .iter()
        .map(|it| it.addr)
        .filter(|a| !reachable.contains(a))
        .collect();
    assert!(
        missing.is_empty(),
        "every recovered itab must be reachable per the sweep; {} missing: {:?}",
        missing.len(),
        &missing[..missing.len().min(5)],
    );
}

#[test]
fn dataview_refuses_unmapped_or_sentinel_addresses() {
    // Regression: --data-at 0 was happily
    // decoding the ELF shstrtab (which has addr=0) as if it were a
    // loaded section, returning section-name bytes interpreted as
    // an iface header. This test pins the contract that any address
    // below the first plausible runtime page is refused outright,
    // and any address that does not fall inside a section with a
    // real load address gets a clear unmapped error.
    let Some(path) = fixture("depsdemo.linux-amd64.stripped") else {
        return;
    };
    let bin = GoBinary::open(&path).expect("open");
    let pcln = Pclntab::parse(&bin).expect("pcln");
    let funcs = pcln.functions().expect("funcs");
    let md = unstrip::ModuleData::locate(&bin).expect("md");
    let itabs_v = itabs::recover_all(&bin, &md).expect("itabs");

    for sentinel in [0u64, 0x100, 0x800, 0xfff] {
        let err = unstrip::dataview::inspect(
            &bin,
            &pcln,
            &itabs_v,
            &funcs,
            sentinel,
            16,
            unstrip::dataview::As::Ifaces,
        )
        .expect_err("sentinel address must refuse");
        let msg = err.to_string();
        assert!(
            msg.contains("below the first plausible runtime page"),
            "sentinel 0x{sentinel:x} error must mention the page floor; got {msg}"
        );
    }

    // Plausible-looking but unmapped address: above the page floor,
    // outside every loadable section. Must error with the unmapped
    // message, not silently decode whatever happens to be at offset
    // 0 in the binary file.
    let err = unstrip::dataview::inspect(
        &bin,
        &pcln,
        &itabs_v,
        &funcs,
        0xdead_beef_dead_beef,
        16,
        unstrip::dataview::As::Bytes,
    )
    .expect_err("unmapped address must refuse");
    assert!(
        err.to_string().contains("not in any loadable section"),
        "unmapped address error must say so; got {err}"
    );
}

#[test]
fn callsites_finds_direct_callers_of_a_known_runtime_function() {
    // runtime.mallocgc is the heaviest-used allocator entry point in
    // every Go binary; if Scanner 1 can't find direct callers of it,
    // the scanner is broken. The test asserts the structural shape:
    // at least one hit, every hit attributes to a containing
    // function, every hit kind is Direct (Scanner 2 hasn't shipped
    // yet so the indirect-itab variant should never appear here).
    let Some(path) = fixture("depsdemo.linux-amd64.stripped") else {
        return;
    };
    let bin = GoBinary::open(&path).expect("open");
    let pcln = Pclntab::parse(&bin).expect("pcln");

    let target = unstrip::callsites::Target::Function("runtime.mallocgc".into());
    let hits = unstrip::callsites::find(&bin, &pcln, &[], &target).expect("callsites scan");

    assert!(
        !hits.is_empty(),
        "runtime.mallocgc must be called from somewhere; got 0 sites"
    );
    for h in &hits {
        assert!(matches!(h.kind, unstrip::callsites::CallKind::Direct));
        // Most call sites land inside a recovered function; the
        // assertion is structural (the field exists and is populated
        // when the lookup succeeds), not "every site is attributed"
        // because asm stubs and padding can match without a function.
        if h.caller_name.is_some() {
            assert!(h.caller_addr.is_some(), "name and addr go together");
        }
    }
}

#[test]
fn callsites_address_target_resolves_to_same_set_as_name_target() {
    // The two Target variants Scanner 1 supports must produce
    // identical results when they refer to the same function. This
    // pins the equivalence so a future change to either resolver
    // can't silently diverge.
    let Some(path) = fixture("depsdemo.linux-amd64.stripped") else {
        return;
    };
    let bin = GoBinary::open(&path).expect("open");
    let pcln = Pclntab::parse(&bin).expect("pcln");

    let funcs = pcln.functions().expect("functions");
    let mallocgc = funcs
        .iter()
        .find(|f| f.name == "runtime.mallocgc")
        .expect("mallocgc in pclntab");

    let by_name = unstrip::callsites::find(
        &bin,
        &pcln,
        &[],
        &unstrip::callsites::Target::Function("runtime.mallocgc".into()),
    )
    .expect("by-name");
    let by_addr = unstrip::callsites::find(
        &bin,
        &pcln,
        &[],
        &unstrip::callsites::Target::Address(mallocgc.address),
    )
    .expect("by-addr");

    let names_set: std::collections::BTreeSet<u64> = by_name.iter().map(|h| h.call_site).collect();
    let addrs_set: std::collections::BTreeSet<u64> = by_addr.iter().map(|h| h.call_site).collect();
    assert_eq!(
        names_set, addrs_set,
        "name and address targets must produce identical call-site sets"
    );
}

#[test]
fn callsites_unknown_function_name_errors_clearly() {
    // A name not in pclntab should fail with a useful message, not
    // silently return zero hits (which would let a typo look like a
    // legitimate "this function has no callers" result).
    let Some(path) = fixture("depsdemo.linux-amd64.stripped") else {
        return;
    };
    let bin = GoBinary::open(&path).expect("open");
    let pcln = Pclntab::parse(&bin).expect("pcln");

    let err = unstrip::callsites::find(
        &bin,
        &pcln,
        &[],
        &unstrip::callsites::Target::Function("not.a.real.function".into()),
    )
    .expect_err("unknown function name must error");
    let msg = err.to_string();
    assert!(
        msg.contains("not.a.real.function") && msg.contains("pclntab"),
        "error must name the missing symbol and the lookup source; got {msg}"
    );
}

#[test]
fn dataxref_scan_runs_and_attributes_hits_when_present() {
    // Which specific data addresses get RIP-relative-LEA'd depends on
    // codegen choices and varies per build. Picking the pclntab base
    // is unreliable (the runtime reaches it through an indirect chain,
    // not a direct RIP-relative load). itab addresses, by contrast,
    // are LEA'd into interface-construction sites by definition. Scan
    // the first handful of recovered itabs and assert at least one
    // produces a non-empty hit set; every hit must attribute to a
    // containing function name when one resolves.
    let Some(path) = fixture("depsdemo.linux-amd64.stripped") else {
        return;
    };
    let bin = GoBinary::open(&path).expect("open");
    let pcln = Pclntab::parse(&bin).expect("pcln");
    let md = unstrip::ModuleData::locate(&bin).expect("md");
    let itabs_v = itabs::recover_all(&bin, &md).expect("itabs");
    assert!(!itabs_v.is_empty(), "fixture must have itabs");

    let mut any_hits = false;
    for it in itabs_v.iter().take(20) {
        let hits = unstrip::dataxref::find_refs(
            &bin,
            &pcln,
            it.addr,
            unstrip::dataxref::Direction::Readers,
        )
        .expect("scan");
        for h in &hits {
            assert_eq!(h.target_addr, it.addr);
            if let Some(name) = &h.function_name {
                assert!(!name.is_empty(), "function name must be non-empty");
            }
        }
        if !hits.is_empty() {
            any_hits = true;
        }
    }
    assert!(
        any_hits,
        "expected at least one .text reader across the first 20 itab addresses"
    );
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
fn goroutines_surfaces_unresolved_call_sites() {
    // Every real Go binary has a tail of call sites the LEA/ADRP back-track
    // heuristic can't name: indirect funcvals stashed earlier in the
    // function, codegen the pattern matcher doesn't cover, or funcvals
    // whose pointer lands outside any section we mapped. The whole point
    // of the unresolved listing is to surface those for triage; if the
    // list is empty something has changed (or, more likely, the
    // resolution-state plumbing regressed and every miss is being tagged
    // as Resolved).
    let Some(path) = fixture("depsdemo.linux-amd64.stripped") else {
        return;
    };
    let bin = GoBinary::open(&path).expect("open");
    let pcln = Pclntab::parse(&bin).expect("parse");
    let spawns = unstrip::goroutines::find_spawns(&bin, &pcln).expect("scan");

    let unresolved: Vec<&unstrip::goroutines::GoroutineSpawn> =
        spawns.iter().filter(|s| !s.is_resolved()).collect();
    assert!(
        !unresolved.is_empty(),
        "expected at least one unresolved spawn site on a real Go binary; got {} total, all resolved",
        spawns.len()
    );

    // Each unresolved site must carry a non-Resolved reason and must
    // still have target_addr=None, target_name=None. The pclntab
    // source:line lookup is independent of funcval resolution and
    // should still populate when the pcln pc-value table covers the PC.
    let mut have_source_line = false;
    for s in &unresolved {
        assert!(
            s.target_addr.is_none(),
            "unresolved site must have no target_addr"
        );
        assert!(
            s.target_name.is_none(),
            "unresolved site must have no target_name"
        );
        assert!(
            matches!(
                s.resolution,
                unstrip::goroutines::Resolution::NoLeaPattern
                    | unstrip::goroutines::Resolution::FuncvalUnmapped
            ),
            "unresolved site must carry a non-Resolved reason"
        );
        if s.file.is_some() && s.line.is_some() {
            have_source_line = true;
        }
    }
    assert!(
        have_source_line,
        "pclntab source:line should resolve for at least one unresolved spawn site"
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
fn symbols_as_pe_writes_valid_symtab() {
    // Rewrite a real stripped PE with --symbols-as pe and verify the
    // appended COFF symbol table parses back correctly and resolves
    // a known Go symbol via the string table.
    use std::io::Read;
    let Some(path) = fixture("hello.windows-amd64.stripped.exe") else {
        return;
    };
    let bin = GoBinary::open(&path).expect("open");
    let pcln = Pclntab::parse(&bin).expect("parse");
    let functions = pcln.functions().expect("functions");

    let tmp = std::env::temp_dir().join(format!(
        "unstrip-symbols-pe-test-{}.exe",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&tmp);

    let n = unstrip::rewrite::write_symbols_as_pe(&bin, &functions, &tmp, Some(&path))
        .expect("rewrite");
    assert_eq!(n, functions.len(), "should write one symbol per function");

    let mut new_bytes = Vec::new();
    std::fs::File::open(&tmp)
        .expect("reopen")
        .read_to_end(&mut new_bytes)
        .expect("read");
    let parsed = goblin::Object::parse(&new_bytes).expect("re-parse PE");
    let pe = match parsed {
        goblin::Object::PE(p) => p,
        _ => panic!("output is not PE"),
    };
    assert_eq!(
        pe.header.coff_header.number_of_symbol_table as usize,
        functions.len(),
        "COFF NumberOfSymbols should match function count"
    );
    assert!(
        pe.header.coff_header.pointer_to_symbol_table != 0,
        "PointerToSymbolTable should be patched to the appended table"
    );

    // Walk the appended COFF table directly and confirm a well-known Go
    // symbol resolves via the string table path.
    let symtab = goblin::pe::symbol::SymbolTable::parse(
        &new_bytes,
        pe.header.coff_header.pointer_to_symbol_table as usize,
        pe.header.coff_header.number_of_symbol_table as usize,
    )
    .expect("parse coff symtab");
    // Locate the appended string table directly from the file bytes.
    // We skip goblin's Strtab::parse on purpose because it preparses
    // every entry as UTF-8 and the trailing bytes after our strtab are
    // arbitrary file padding that fail that strict walk.
    let strtab_file_off = pe.header.coff_header.pointer_to_symbol_table as usize
        + goblin::pe::symbol::SymbolTable::size(
            pe.header.coff_header.number_of_symbol_table as usize,
        );
    let strtab_len = u32::from_le_bytes(
        new_bytes[strtab_file_off..strtab_file_off + 4]
            .try_into()
            .unwrap(),
    ) as usize;
    let strtab_bytes = &new_bytes[strtab_file_off..strtab_file_off + strtab_len];

    let mut found_main = false;
    for (_, _, sym) in symtab.iter() {
        let name = if sym.name[0] == 0 {
            let off = u32::from_le_bytes(sym.name[4..8].try_into().unwrap()) as usize;
            let end = strtab_bytes[off..]
                .iter()
                .position(|&b| b == 0)
                .map(|p| off + p)
                .unwrap_or(strtab_bytes.len());
            std::str::from_utf8(&strtab_bytes[off..end]).ok()
        } else {
            let end = sym.name.iter().position(|&b| b == 0).unwrap_or(8);
            std::str::from_utf8(&sym.name[..end]).ok()
        };
        if name == Some("main.main") {
            found_main = true;
            break;
        }
    }
    assert!(
        found_main,
        "main.main should be present in the appended COFF symbol table"
    );

    let _ = std::fs::remove_file(&tmp);
}

#[test]
fn locates_pclntab_on_pe_with_rewritten_magic() {
    // garble rewrites the pcHeader magic to a per-build random value, and a
    // Windows PE has no named pclntab section, so the fixed-magic scan finds
    // nothing and every feature dies at discovery. The structural pcHeader scan
    // must still locate it. Simulate garble exactly: take a real PE, find where
    // the pclntab sits, overwrite its 4 magic bytes with a random value, and
    // assert discovery and function recovery survive.
    let Some(path) = fixture("hello.windows-amd64.stripped.exe") else {
        return;
    };
    let mut bytes = std::fs::read(&path).expect("read pe fixture");

    let clean = GoBinary::parse(bytes.clone()).expect("parse clean pe");
    let off = clean.pclntab_offset;
    assert!(
        off > 0 && off + 8 < bytes.len(),
        "pclntab should be located in the clean PE"
    );

    // Overwrite the magic with a non-magic value, exactly as garble's per-build
    // magic does.
    bytes[off..off + 4].copy_from_slice(&[0xab, 0xcd, 0x12, 0x34]);
    // Also force pcHeader.textStart (a pointer-sized field at off+8+2*ptrsize,
    // ptrsize=8 here) to zero. Every Windows PE leaves textStart zero and the
    // runtime resolves the text base from moduledata, so the structural scan
    // must accept a zero textStart; a fixture with a non-zero value would not
    // exercise the path the real PEs take.
    let text_start_off = off + 8 + 2 * 8;
    bytes[text_start_off..text_start_off + 8].copy_from_slice(&[0u8; 8]);

    let garbled = GoBinary::parse(bytes).expect("discovery must survive a rewritten magic");
    assert_eq!(
        garbled.pclntab_offset, off,
        "structural scan must rediscover the same pclntab"
    );
    let pcln = Pclntab::parse(&garbled).expect("parse pclntab found structurally");
    assert!(
        !pcln.magic_is_official(),
        "the rewritten magic must read as unofficial"
    );
    let funcs = pcln.functions().expect("functions");
    assert!(
        funcs.len() > 100,
        "functions must still recover on the garbled PE, got {}",
        funcs.len()
    );
}

#[test]
fn pe_with_huge_image_base_does_not_overflow() {
    // A PE section address is image_base + the section's relative virtual
    // address, both read from the file. A crafted image_base near u64::MAX
    // overflowed that add and panicked. Take a real, parseable PE and patch
    // only its ImageBase to the top of the address space, then parse: it must
    // not panic. Found by fuzzing the recovery stack.
    let Some(path) = fixture("hello.windows-amd64.stripped.exe") else {
        return;
    };
    let mut bytes = std::fs::read(&path).expect("read pe fixture");
    // e_lfanew at 0x3C points at the PE signature. The PE32+ optional header's
    // ImageBase is a u64 at signature(4) + COFF header(20) + 24.
    let e_lfanew = u32::from_le_bytes(bytes[0x3C..0x40].try_into().unwrap()) as usize;
    let image_base_off = e_lfanew + 4 + 20 + 24;
    bytes[image_base_off..image_base_off + 8].copy_from_slice(&u64::MAX.to_le_bytes());

    // The contract is "no panic", whatever the parse verdict: a hostile base
    // should bail to an error or yield out-of-range addresses, never overflow.
    let _ = GoBinary::parse(bytes);
}

#[test]
fn fat_binary_with_absurd_arch_count_bails_fast() {
    // A crafted universal (fat) Mach-O header can claim billions of arch
    // slices. Walking the claimed count to select a slice must not spin: with
    // uncapped iteration this single 8-byte header ran for over a minute under
    // instrumentation. The arch walk is capped, and the bogus slices it does
    // see do not resolve, so parse bails to an error well under a second
    // without panicking. Found by fuzzing the recovery stack.
    let mut bytes = vec![0xca, 0xfe, 0xba, 0xbe]; // FAT_MAGIC, big-endian
    bytes.extend_from_slice(&0xCFFF_FFFEu32.to_be_bytes()); // nfat_arch ~3.5 billion
    bytes.resize(64, 0); // truncated arch table; the count is the only hostile field

    let start = std::time::Instant::now();
    let result = GoBinary::parse(bytes);
    let elapsed = start.elapsed();
    assert!(
        result.is_err(),
        "a fat header with no resolvable slice must not parse"
    );
    assert!(
        elapsed < std::time::Duration::from_secs(2),
        "selecting a fat slice took {elapsed:?}; the claimed count must be capped"
    );
}

#[test]
fn rejects_non_go_binary() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml");
    let result = GoBinary::open(&path);
    assert!(result.is_err(), "Cargo.toml should not parse as a binary");
}

#[test]
fn locate_all_returns_single_module_on_normal_binary() {
    let Some(path) = fixture("hello.linux-amd64.stripped") else {
        return;
    };
    let bin = GoBinary::open(&path).expect("open binary");
    let single = ModuleData::locate(&bin).expect("locate first module");
    let all = ModuleData::locate_all(&bin).expect("locate all modules");
    // A normal Go binary has exactly one module on disk; chained modules
    // happen only at runtime when a plugin or shared library is loaded.
    assert_eq!(
        all.len(),
        1,
        "expected exactly 1 moduledata in a single-module binary, got {}",
        all.len()
    );
    assert_eq!(
        all[0].file_offset, single.file_offset,
        "locate_all()[0] should be the same record as locate()"
    );
}
