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

// ---------------------------------------------------------------------------
//
// Unified garble assessment.
//
// `detect()` above is the name-shape detector and runs metadata-free for
// unit testability. `crate::output::detect_garble` is the structural
// detector (pclntab magic + buildVersion + name hashing). On obfuscated
// binaries the two can legitimately disagree: garble's default mode
// keeps method names intact (so dotted `pkg.Method` symbols survive in
// many user packages and the dotless-ratio statistic stays low), even
// though pclntab magic and buildVersion are clearly rewritten.
//
// Surfacing two separate "is_garbled" verdicts on the same binary made
// the tool look like it was contradicting itself in two adjacent
// invocations (`--info` vs `--detect-garble`). [`assess`] is the
// reconciliation: one verdict, one confidence, plus a structured
// breakdown of every individual signal's vote so the operator can audit
// why we landed where we did.
//
// Verdict precedence (intentional, not weighted-vote):
//   1. Structural evidence dominates. A rewritten pclntab magic byte is
//      a thing garble does and nothing else does; if we see it we are
//      garbled, even when the name-shape statistic disagrees.
//   2. Below that, a two-of-three majority across {magic, buildVersion,
//      hashed-names structural ratio, name-shape verdict} fires garbled.
//   3. Below that, indeterminate.
//
// Indeterminate exists because zero-sample, runtime-only inputs and
// otherwise-clean binaries should not be force-classified.

/// Vote of a single underlying heuristic.
#[derive(Debug, Clone, serde::Serialize)]
pub struct Signal {
    /// Stable identifier for grep/CI gating (e.g. `pclntab.magic`,
    /// `runtime.build_version`, `names.hashed_ratio`,
    /// `names.shape_heuristic`).
    pub id: &'static str,
    /// Did this signal fire?
    pub fired: bool,
    /// One-sentence justification of why it did or didn't fire.
    pub detail: String,
}

/// The fused verdict surfaced by `--detect-garble` and the warning block
/// in `--info` / `--buildinfo`. One answer, one confidence, structured
/// per-signal evidence.
#[derive(Debug, Clone, serde::Serialize)]
pub struct GarbleAssessment {
    /// Three-state verdict: `Garbled`, `Clean`, or `Indeterminate`. Use
    /// this for routing; use the [`GarbleAssessment::exit_code`] helper
    /// for CI gating.
    pub verdict: Verdict,
    /// Combined confidence in `[0.0, 1.0]`. 1.0 when the magic signal
    /// fires (structural evidence is conclusive); lower when we relied
    /// on a majority vote of weaker signals.
    pub confidence: f32,
    /// Every signal we evaluated, in stable order. Lets CI gate on a
    /// specific signal id rather than the fused verdict.
    pub signals: Vec<Signal>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Verdict {
    Garbled,
    Clean,
    Indeterminate,
}

impl GarbleAssessment {
    /// Exit code for `--detect-garble`:
    ///   0 = garbled, 1 = clean, 2 = indeterminate. CI scripts gate on
    /// these and the values are part of the public contract.
    pub fn exit_code(&self) -> i32 {
        match self.verdict {
            Verdict::Garbled => 0,
            Verdict::Clean => 1,
            Verdict::Indeterminate => 2,
        }
    }

    /// `true` when the fused verdict is `Garbled`. Convenience for
    /// callers that don't care about the indeterminate case.
    pub fn is_garbled(&self) -> bool {
        matches!(self.verdict, Verdict::Garbled)
    }
}

/// Fuse the structural garble report with the name-shape heuristic into
/// a single authoritative verdict. Both `--detect-garble` and the
/// garble warning block in `--info` / `--buildinfo` route through this
/// function so they always agree byte-for-byte on the verdict and the
/// per-signal evidence.
pub fn assess(
    functions: &[Function],
    go_version: Option<&str>,
    magic_is_official: bool,
) -> GarbleAssessment {
    let structural = crate::output::detect_garble(functions, go_version, magic_is_official);
    let shape = detect(functions);

    let mut signals = Vec::with_capacity(4);
    signals.push(Signal {
        id: "pclntab.magic",
        fired: structural.magic_rewritten,
        detail: if structural.magic_rewritten {
            "pclntab magic is not 0xfffffff1 / 0xfffffff0 (garble rewrites it)".into()
        } else {
            "pclntab magic matches an official Go release".into()
        },
    });
    signals.push(Signal {
        id: "runtime.build_version",
        fired: structural.version_overwritten,
        detail: if structural.version_overwritten {
            "runtime.buildVersion missing or non-standard (garble overwrites it)".into()
        } else {
            "runtime.buildVersion looks like a real Go release".into()
        },
    });
    let names_ratio_fired = structural
        .hashed_names
        .map(|(h, t)| t > 0 && (h * 5) > (t * 2))
        .unwrap_or(false);
    signals.push(Signal {
        id: "names.hashed_ratio",
        fired: names_ratio_fired,
        detail: match structural.hashed_names {
            Some((h, t)) => {
                format!("{h}/{t} user-package function names look hashed (threshold > 40%)")
            }
            None => "fewer than 20 user-space functions to evaluate".into(),
        },
    });
    signals.push(Signal {
        id: "names.shape_heuristic",
        fired: shape.is_garbled,
        detail: if shape.evidence.is_empty() {
            format!(
                "dotless-name shape heuristic (confidence {:.2})",
                shape.confidence
            )
        } else {
            // Pull the first two evidence lines — they are the
            // ratio and length numbers the heuristic actually voted
            // on.
            let mut joined = shape
                .evidence
                .iter()
                .take(2)
                .cloned()
                .collect::<Vec<_>>()
                .join("; ");
            joined.push_str(&format!(
                "; H1+H2 verdict: {} (confidence {:.2})",
                shape.is_garbled, shape.confidence
            ));
            joined
        },
    });

    // Magic-byte signal is conclusive on its own: nothing else in the
    // Go ecosystem rewrites that constant. When it fires we are
    // garbled with confidence 1.0, regardless of what the name-shape
    // heuristic thinks.
    if structural.magic_rewritten {
        return GarbleAssessment {
            verdict: Verdict::Garbled,
            confidence: 1.0,
            signals,
        };
    }

    let fired = signals.iter().filter(|s| s.fired).count();
    let evaluable = signals
        .iter()
        .filter(|s| {
            // names.hashed_ratio with `None` evidence means we did not
            // evaluate it; don't count it against indeterminacy. All
            // other signals are always evaluable.
            !(s.id == "names.hashed_ratio" && s.detail.starts_with("fewer than 20"))
        })
        .count();

    if fired >= 2 {
        let confidence = match fired {
            2 => 0.75,
            3 => 0.9,
            _ => 0.95,
        };
        GarbleAssessment {
            verdict: Verdict::Garbled,
            confidence,
            signals,
        }
    } else if evaluable < 2 {
        GarbleAssessment {
            verdict: Verdict::Indeterminate,
            confidence: 0.0,
            signals,
        }
    } else {
        GarbleAssessment {
            verdict: Verdict::Clean,
            confidence: 1.0 - (fired as f32) * 0.2,
            signals,
        }
    }
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

    // ---- assess() unification tests --------------------------------
    //
    // The point of `assess` is that `--detect-garble` and the warning
    // in `--info` / `--buildinfo` never disagree on the same input.
    // These tests pin the precedence the implementation depends on:
    // rewritten magic is conclusive on its own; otherwise majority of
    // evaluable signals fires the verdict; otherwise indeterminate.

    #[test]
    fn assess_magic_alone_is_conclusive() {
        // Pclntab magic rewrite is a thing garble does and nothing else
        // does. On its own it should fire Garbled at confidence 1.0
        // even when the name-shape heuristic would have voted clean.
        let funcs = synthetic_normal(60);
        let a = assess(&funcs, Some("go1.22.2"), /* magic_is_official */ false);
        assert_eq!(a.verdict, Verdict::Garbled);
        assert_eq!(a.confidence, 1.0);
        assert_eq!(a.exit_code(), 0);
        let magic = a.signals.iter().find(|s| s.id == "pclntab.magic").unwrap();
        assert!(magic.fired, "magic signal must have fired");
    }

    #[test]
    fn assess_clean_binary_is_clean() {
        let funcs = synthetic_normal(60);
        let a = assess(&funcs, Some("go1.22.2"), true);
        assert_eq!(a.verdict, Verdict::Clean);
        assert_eq!(a.exit_code(), 1);
    }

    #[test]
    fn assess_majority_of_evaluable_signals_fires() {
        // No magic rewrite, but version is overwritten AND the
        // name-shape heuristic fires AND most user names look hashed.
        // That's 3 of 4 signals, well over the 2-of-evaluable bar.
        let funcs = synthetic_garbled(80);
        let a = assess(&funcs, None, true);
        assert_eq!(a.verdict, Verdict::Garbled);
        assert!(a.confidence >= 0.75);
        assert_eq!(a.exit_code(), 0);
    }

    #[test]
    fn assess_signal_count_matches_emitted_signals() {
        // Stable contract for CI gating: callers grep on signal ids.
        // Adding or removing a signal here is a public-API change.
        let funcs = synthetic_normal(60);
        let a = assess(&funcs, Some("go1.22.2"), true);
        let ids: Vec<&str> = a.signals.iter().map(|s| s.id).collect();
        assert_eq!(
            ids,
            vec![
                "pclntab.magic",
                "runtime.build_version",
                "names.hashed_ratio",
                "names.shape_heuristic",
            ]
        );
    }

    #[test]
    fn assess_resolves_field_test_self_contradiction() {
        // Regression test for the field-test pain point. On the actual
        // garbled shfmt sample `--info` reported "likely garbled" with
        // three structural reasons while `--detect-garble` reported
        // `is_garbled: false, confidence: 0.01` because the name-shape
        // statistic alone disagreed. assess() must collapse these to
        // one Garbled verdict no matter which signals the caller asks
        // about. Simulated by: magic rewritten, build version wiped,
        // user names still mostly dotted (name-shape heuristic clean).
        let mut funcs = Vec::new();
        for i in 0..120 {
            // Garble default keeps method names visible, so the
            // package-half is hashed but a dot survives in the symbol.
            // Name-shape's dotless-ratio statistic stays low here.
            funcs.push(func(&format!("Hx7m{}.Method", i)));
        }
        let a = assess(&funcs, None, /* magic_is_official */ false);
        assert_eq!(
            a.verdict,
            Verdict::Garbled,
            "structural magic rewrite must dominate even when name-shape disagrees"
        );
        // The name-shape detector ran but voted clean; that's a
        // signal we surface in the breakdown, not a contradiction the
        // operator sees.
        let shape = a
            .signals
            .iter()
            .find(|s| s.id == "names.shape_heuristic")
            .unwrap();
        assert!(
            !shape.fired,
            "name-shape signal must not fire on dotted obfuscated names"
        );
    }
}
