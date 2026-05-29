//! Garble obfuscation detection from recovered function names.
//!
//! The `output::detect_garble` entry point answers a coarse "are any of the
//! three big garble signals (rewritten pclntab magic, missing buildVersion,
//! hashed-looking user names) tripped". This module is the finer-grained
//! pass: it ignores metadata entirely and looks only at the shape of the
//! USER-space function name distribution. Real Go binaries have a long-tail
//! mix of `pkg.Func` dotted names; garble rewrites the user packages into
//! short, uniform, Go-identifier-safe hashes (`_xUmF`, `KbZxz_a`). The
//! signals are:
//!
//!   H1 dotless ratio   share of user names without a package dot
//!   H2 uniform length  mean length in [3, 9] and stdev < 2.5
//!   H3 charset shape   short identifier with underscore-or-mixed-case
//!
//! H1 + H2 together fire the verdict; H3 only nudges confidence. Falls
//! back to "indeterminate" below a 50-function sample. See the README for
//! the rationale on the thresholds.
//!
//! `detect()` here is heuristic-only and metadata-free, so it is unit-
//! testable against synthetic Function lists. The richer combined report
//! (this plus magic and buildVersion signals) lives in
//! `crate::output::detect_garble` and gates the warning emitted from
//! `--info` and `--buildinfo`.

use crate::pclntab::Function;

/// Minimum number of user-space functions required before the heuristic
/// will commit to a verdict. Below this the result is always "indeterminate".
pub const MIN_SAMPLE: usize = 50;

/// Verdict shape from `detect()`. `is_garbled` only fires when there were
/// enough samples AND H1 + H2 both tripped; `confidence` is 0.0 when we
/// declined for lack of evidence.
#[derive(Debug, Clone, Default)]
pub struct GarbleVerdict {
    pub is_garbled: bool,
    pub confidence: f32,
    pub evidence: Vec<String>,
}

/// Run the name-shape heuristic over the recovered function set. Pure
/// function of the names; no I/O. Returns `is_garbled = false` with
/// confidence 0.0 and an "insufficient sample" evidence line when fewer
/// than `MIN_SAMPLE` user-space names are present.
pub fn detect(functions: &[Function]) -> GarbleVerdict {
    let user: Vec<&str> = functions
        .iter()
        .map(|f| f.name.as_str())
        .filter(|n| is_user_space(n))
        .collect();

    if user.len() < MIN_SAMPLE {
        return GarbleVerdict {
            is_garbled: false,
            confidence: 0.0,
            evidence: vec![format!(
                "insufficient sample: {} user-space functions (need {})",
                user.len(),
                MIN_SAMPLE
            )],
        };
    }

    let total = user.len() as f32;
    let dotless: Vec<&str> = user.iter().copied().filter(|n| !n.contains('.')).collect();
    let dotless_ratio = dotless.len() as f32 / total;
    let h1 = dotless_ratio >= 0.50;

    let lens: Vec<f32> = dotless.iter().map(|n| n.len() as f32).collect();
    let (mean_len, stdev) = mean_stdev(&lens);
    let h2 = !dotless.is_empty() && (3.0..=9.0).contains(&mean_len) && stdev < 2.5;

    let short_hits = dotless
        .iter()
        .filter(|n| looks_like_garbled_identifier(n))
        .count();
    let short_ratio = if dotless.is_empty() {
        0.0
    } else {
        short_hits as f32 / dotless.len() as f32
    };
    let h3 = short_ratio >= 0.60;

    let mut evidence = Vec::new();
    evidence.push(format!(
        "dotless user-name ratio: {:.2} ({}/{})",
        dotless_ratio,
        dotless.len(),
        user.len()
    ));
    evidence.push(format!(
        "dotless name length: mean {:.2}, stdev {:.2}",
        mean_len, stdev
    ));
    evidence.push(format!(
        "short identifier ratio: {:.2} ({}/{})",
        short_ratio,
        short_hits,
        dotless.len().max(1)
    ));

    let mut is_garbled = false;
    let confidence: f32;
    if h1 && h2 {
        is_garbled = true;
        let mut c = 0.9_f32;
        if h3 {
            c += 0.05;
            evidence.push("charset signal (H3) present".into());
        }
        confidence = c;
    } else {
        confidence = (dotless_ratio * 0.5).clamp(0.0, 0.49);
        if !h1 {
            evidence.push("H1 dotless ratio below 0.50".into());
        }
        if !h2 {
            evidence.push("H2 uniform length signal absent".into());
        }
    }

    GarbleVerdict {
        is_garbled,
        confidence: confidence.min(1.0),
        evidence,
    }
}

/// True when the name belongs to user (main / first-party) space. We filter
/// out runtime, reflect, type metadata, special compiler symbols, and any
/// import-path-shaped name (slash or double-dot), so the remaining set is
/// the surface garble actually rewrites.
fn is_user_space(name: &str) -> bool {
    if name.starts_with("runtime.")
        || name.starts_with("reflect.")
        || name.starts_with("type:")
        || name.starts_with("type..")
        || name.starts_with("go:")
        || name.starts_with("go.")
        || name.starts_with("gcWriteBarrier")
        || name.starts_with("$f64.")
        || name.starts_with("$f32.")
    {
        return false;
    }
    if name.contains('/') || name.contains("..") {
        return false;
    }
    true
}

/// Garble's hashed identifiers are Go-identifier-safe, short, and either
/// carry a leading underscore or mix case. Real short symbols (asm stubs,
/// closures) don't cluster on that pattern.
fn looks_like_garbled_identifier(name: &str) -> bool {
    let len = name.len();
    if !(3..=9).contains(&len) {
        return false;
    }
    let mut chars = name.chars();
    let first = match chars.next() {
        Some(c) => c,
        None => return false,
    };
    if !(first.is_ascii_alphabetic() || first == '_') {
        return false;
    }
    let body_ok = name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_');
    if !body_ok {
        return false;
    }
    let has_underscore = name.contains('_');
    let has_lower = name.chars().any(|c| c.is_ascii_lowercase());
    let has_upper = name.chars().any(|c| c.is_ascii_uppercase());
    has_underscore || (has_lower && has_upper)
}

fn mean_stdev(xs: &[f32]) -> (f32, f32) {
    if xs.is_empty() {
        return (0.0, 0.0);
    }
    let n = xs.len() as f32;
    let mean = xs.iter().sum::<f32>() / n;
    let var = xs.iter().map(|x| (x - mean).powi(2)).sum::<f32>() / n;
    (mean, var.sqrt())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn func(name: &str) -> Function {
        Function {
            address: 0,
            name: name.to_string(),
            file: None,
            start_line: None,
        }
    }

    fn synthetic_normal(n: usize) -> Vec<Function> {
        // A spread of dotted user names plus the usual runtime padding.
        // Lengths and shapes vary so the variance check stays high.
        let mut out = Vec::new();
        for i in 0..n {
            out.push(func(&format!("main.handleRequest{i}")));
            out.push(func(&format!("github.com/acme/proj/api.Server{i}.Serve")));
            out.push(func(&format!("runtime.gcMark{i}")));
        }
        out
    }

    fn synthetic_garbled(n: usize) -> Vec<Function> {
        // Garble-shaped hashes: short, identifier-safe, no dots, mixed
        // case or underscored, uniform length.
        let samples = [
            "_xUmF", "KbZxz_a", "_qq3w", "Vn4Hp", "_aA1bC", "kkLmN", "_z0pQr", "Ww8eR_", "_b3LpQ",
            "Tt9_kX",
        ];
        let mut out = Vec::new();
        for i in 0..n {
            out.push(func(samples[i % samples.len()]));
        }
        // Garble still leaves runtime alone; include some so the filter
        // path is exercised.
        for i in 0..20 {
            out.push(func(&format!("runtime.gcMark{i}")));
        }
        out
    }

    #[test]
    fn declines_below_sample_threshold() {
        let funcs = synthetic_normal(5);
        let v = detect(&funcs);
        assert!(!v.is_garbled);
        assert_eq!(v.confidence, 0.0);
        assert!(v.evidence.iter().any(|e| e.contains("insufficient sample")));
    }

    #[test]
    fn normal_binary_does_not_trip() {
        let funcs = synthetic_normal(60);
        let v = detect(&funcs);
        assert!(!v.is_garbled, "verdict: {v:?}");
        assert!(v.confidence < 0.5, "confidence: {v:?}");
    }

    #[test]
    fn garbled_binary_trips_with_high_confidence() {
        let funcs = synthetic_garbled(80);
        let v = detect(&funcs);
        assert!(v.is_garbled, "verdict: {v:?}");
        assert!(v.confidence >= 0.9, "confidence: {v:?}");
        assert!(v.evidence.iter().any(|e| e.contains("dotless")));
    }

    #[test]
    fn runtime_only_is_insufficient_sample() {
        // 100 runtime names should all get filtered out, leaving zero
        // user-space samples.
        let funcs: Vec<Function> = (0..100)
            .map(|i| func(&format!("runtime.gcMark{i}")))
            .collect();
        let v = detect(&funcs);
        assert!(!v.is_garbled);
        assert!(v.evidence[0].contains("insufficient sample"));
    }

    #[test]
    fn import_paths_are_filtered_from_user_space() {
        // Names with slashes (vendor / module paths) are not user-space for
        // the purposes of this heuristic.
        assert!(!is_user_space("github.com/foo/bar.Baz"));
        assert!(!is_user_space("type:.eq.[3]int"));
        assert!(is_user_space("main.run"));
        assert!(is_user_space("_xUmF"));
    }

    #[test]
    fn charset_check_rejects_plain_lowercase_words() {
        assert!(!looks_like_garbled_identifier("hello"));
        assert!(!looks_like_garbled_identifier("server"));
        assert!(looks_like_garbled_identifier("_xUmF"));
        assert!(looks_like_garbled_identifier("KbZxz_a"));
    }
}
