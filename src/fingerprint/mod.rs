use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::buildinfo::BuildInfo;
use crate::gobin::GoBinary;
use crate::itabs::Itab;
use crate::moduledata::ModuleData;
use crate::pclntab::{Function, Pclntab};
use crate::types::Type;
use crate::Result;

/// A stable hash over the structural identity of a Go binary's recovered
/// metadata, the names of user-package functions, types, interface bindings,
/// and module dependencies. Two builds of the same source produce the same
/// fingerprint even with different `-trimpath`/`-buildvcs` flags, different
/// host machines, or different ldflags-injected variables.
///
/// Use case: clustering malware families across recompiles, identifying
/// "this binary is built from xyz fork of cobra at commit abc". Not a hash
/// of the file bytes, that changes every build.
#[derive(Debug, Clone, Serialize)]
pub struct Fingerprint {
    pub sha256: String,
    pub function_count: usize,
    pub type_count: usize,
    pub itab_count: usize,
    pub dep_count: usize,
    /// What contributed to the hash, for transparency.
    pub components: Components,
}

#[derive(Debug, Clone, Serialize)]
pub struct Components {
    pub main_module_path: Option<String>,
    pub user_function_count: usize,
    pub user_type_count: usize,
    pub deps: Vec<String>,
}

/// Compute the fingerprint by extracting all the structural identity bits
/// and hashing them in a canonical order.
pub fn compute(
    bin: &GoBinary,
    pcln: &Pclntab<'_>,
) -> Result<Fingerprint> {
    let functions = pcln.functions().unwrap_or_default();
    let buildinfo = BuildInfo::parse(bin).ok();
    let md = ModuleData::locate(bin).ok();
    let types = md
        .as_ref()
        .and_then(|m| crate::types::recover_all(bin, m).ok())
        .unwrap_or_default();
    let itabs = md
        .as_ref()
        .and_then(|m| crate::itabs::recover_all(bin, m).ok())
        .unwrap_or_default();

    Ok(compute_from(&functions, &types, &itabs, buildinfo.as_ref()))
}

/// Compute a behavioral fingerprint: a SHA-256 over the stdlib-interface
/// implementation-count vector.
///
/// Two binaries with the same behavioral surface (same set of stdlib
/// interfaces implemented the same number of times) hash identically.
/// This is much coarser than the regular fingerprint: it identifies
/// "shape" rather than "source." Two unrelated tools that happen to
/// implement `io.Writer` and `net.Conn` the same number of times will
/// collide. Use it as a clustering signal, not a unique ID.
///
/// Garble caveat: garble v0.13+ also rewrites stdlib interface type names
/// (e.g. `*io.Writer` becomes `*vGj9_a_I.GzonM4C`), so a garbled rebuild
/// does NOT produce the same behavioral hash as its un-garbled source. The
/// behavioral fingerprint clusters within obfuscation cohorts (all
/// non-garbled builds of one family, or all garbled builds of one family),
/// not across them.
pub fn compute_behavioral(bin: &GoBinary) -> Result<BehavioralFingerprint> {
    let md = ModuleData::locate(bin).ok();
    let itabs = md
        .as_ref()
        .and_then(|m| crate::itabs::recover_all(bin, m).ok())
        .unwrap_or_default();
    Ok(compute_behavioral_from(&itabs))
}

pub fn compute_behavioral_from(itabs: &[Itab]) -> BehavioralFingerprint {
    let counts = crate::stdlib::classify_itabs(itabs);
    let mut hasher = Sha256::new();
    hasher.update(b"behavioral-v1:\n");
    for (name, count) in &counts {
        hasher.update(name.as_bytes());
        hasher.update(b"=");
        hasher.update(count.to_string().as_bytes());
        hasher.update(b"\n");
    }
    let digest = hasher.finalize();
    let sha256 = digest.iter().map(|b| format!("{b:02x}")).collect::<String>();
    BehavioralFingerprint {
        sha256,
        interface_count: counts.len(),
        total_implementations: counts.iter().map(|(_, c)| c).sum(),
        counts: counts.into_iter().map(|(n, c)| (n.to_string(), c)).collect(),
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct BehavioralFingerprint {
    pub sha256: String,
    pub interface_count: usize,
    pub total_implementations: usize,
    pub counts: Vec<(String, usize)>,
}

pub fn compute_from(
    functions: &[Function],
    types: &[Type],
    itabs: &[Itab],
    buildinfo: Option<&BuildInfo>,
) -> Fingerprint {
    let mut hasher = Sha256::new();

    // 1. Main module path. Stable across rebuilds; identifies the project.
    let main_module = buildinfo.and_then(|b| b.main.as_ref().map(|m| m.path.clone()));
    if let Some(path) = &main_module {
        hasher.update(b"main:");
        hasher.update(path.as_bytes());
        hasher.update(b"\n");
    }

    // 2. Dependency set: (path, version) sorted. Version may change between
    // builds with different lockfiles; we still include it because the
    // fingerprint should distinguish "same source, different dep versions".
    let mut deps: Vec<String> = buildinfo
        .map(|b| b.deps.iter().map(|m| format!("{}@{}", m.path, m.version)).collect())
        .unwrap_or_default();
    deps.sort();
    hasher.update(b"deps:\n");
    for d in &deps {
        hasher.update(d.as_bytes());
        hasher.update(b"\n");
    }

    // 3. User-package function names. Filter out runtime/std-library functions
    // which are toolchain-dependent and noisy.
    let mut user_fns: Vec<&str> = functions
        .iter()
        .map(|f| f.name.as_str())
        .filter(|n| is_user_symbol(n))
        .collect();
    user_fns.sort_unstable();
    user_fns.dedup();
    hasher.update(b"functions:\n");
    for n in &user_fns {
        hasher.update(n.as_bytes());
        hasher.update(b"\n");
    }

    // 4. User type names. Same filter rationale.
    let mut user_types: Vec<&str> = types
        .iter()
        .map(|t| t.name.as_str())
        .filter(|n| is_user_symbol(n))
        .collect();
    user_types.sort_unstable();
    user_types.dedup();
    hasher.update(b"types:\n");
    for n in &user_types {
        hasher.update(n.as_bytes());
        hasher.update(b"\n");
    }

    // 5. Itab bindings: (interface, concrete) name pairs sorted. Encodes the
    // actual interface dispatch graph the program uses.
    let mut bindings: Vec<String> = itabs
        .iter()
        .filter(|i| is_user_symbol(&i.concrete_name) || is_user_symbol(&i.interface_name))
        .map(|i| format!("{} => {}", i.interface_name, i.concrete_name))
        .collect();
    bindings.sort();
    bindings.dedup();
    hasher.update(b"itabs:\n");
    for b in &bindings {
        hasher.update(b.as_bytes());
        hasher.update(b"\n");
    }

    let digest = hasher.finalize();
    let sha256 = digest.iter().map(|b| format!("{b:02x}")).collect::<String>();

    Fingerprint {
        sha256,
        function_count: functions.len(),
        type_count: types.len(),
        itab_count: itabs.len(),
        dep_count: deps.len(),
        components: Components {
            main_module_path: main_module,
            user_function_count: user_fns.len(),
            user_type_count: user_types.len(),
            deps,
        },
    }
}

/// True if a symbol name is from user/application code, not the Go runtime
/// or standard library. The fingerprint hashes only user symbols so it
/// doesn't change when the Go toolchain updates.
fn is_user_symbol(name: &str) -> bool {
    // Runtime and stdlib prefixes. Exhaustive enough that fingerprints stay
    // stable across Go minor versions while still including app code.
    const STDLIB_PREFIXES: &[&str] = &[
        "runtime.", "runtime/", "internal/", "sync.", "sync/", "syscall.", "syscall/",
        "reflect.", "reflect/", "fmt.", "fmt/", "io.", "io/", "os.", "os/", "errors.",
        "strconv.", "strings.", "strings/", "bytes.", "bytes/", "encoding/", "crypto/",
        "math.", "math/", "sort.", "sort/", "time.", "time/", "context.", "context/",
        "bufio.", "bufio/", "regexp.", "regexp/", "path.", "path/", "net.", "net/",
        "hash.", "hash/", "html.", "html/", "log.", "log/", "unicode.", "unicode/",
        "compress/", "container/", "database/", "debug/", "image.", "image/", "mime.",
        "mime/", "plugin.", "runtime_", "text.", "text/", "vendor/", "cmd/",
        "type:", "type.", "go:", "go.", "_cgo_", "x_cgo_",
    ];
    !STDLIB_PREFIXES.iter().any(|p| name.starts_with(p))
}
