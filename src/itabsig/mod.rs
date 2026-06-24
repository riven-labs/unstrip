//! Interface fingerprinting by method set, for garbled binaries.
//!
//! garble hashes type names but never renames exported methods (they may satisfy
//! an interface, so the names must survive). An itab therefore still carries the
//! real exported method names of the interface it dispatches, even when both the
//! interface and concrete type names are hashed. We match the exact set of those
//! names against a small table of distinctive interfaces, which recovers
//! capabilities the name- and type-keyed rules cannot see on a garbled binary,
//! including dependency interfaces (golang.org/x/crypto/ssh.Conn) that the
//! standard-library code-signature database does not cover.
//!
//! This is deliberately conservative. A fingerprint fires only on an exact set
//! match of at least three exported methods, with no extra methods of any kind on
//! the itab. A wrong capability verdict is worse than a missing one, so common
//! one- and two-method interfaces (io.Reader, http.Handler, error) are not in the
//! table at all.

use crate::capabilities::Capability;
use crate::itabs::Itab;

/// One interface identified by the exact set of its exported method names.
struct Fingerprint {
    /// Exported method names, sorted and unique. Must be the complete method set
    /// of the interface (all exported), so an exact match means the itab has these
    /// methods and no others.
    methods: &'static [&'static str],
    /// Stable rule id, in the `iface.*` namespace. Several fingerprints may share
    /// one id (ssh.Conn and ssh.Channel both map to `iface.ssh`).
    rule_id: &'static str,
    /// Human capability name, chosen distinct from the name- and type-keyed rules
    /// so the two channels read as separate evidence, not duplicates.
    name: &'static str,
    category: &'static str,
    /// Canonical interface name, reported as evidence so an analyst can verify the
    /// method set.
    interface: &'static str,
}

/// The fingerprint table. Every entry is checked by the unit tests for minimum
/// cardinality, sorted-unique methods, and a globally unique method set.
static FINGERPRINTS: &[Fingerprint] = &[
    Fingerprint {
        methods: &[
            "ClientVersion",
            "Close",
            "LocalAddr",
            "OpenChannel",
            "RemoteAddr",
            "SendRequest",
            "ServerVersion",
            "SessionID",
            "User",
            "Wait",
        ],
        rule_id: "iface.ssh",
        name: "SSH transport",
        category: "network",
        interface: "golang.org/x/crypto/ssh.Conn",
    },
    Fingerprint {
        methods: &[
            "Close",
            "CloseWrite",
            "Read",
            "SendRequest",
            "Stderr",
            "Write",
        ],
        rule_id: "iface.ssh",
        name: "SSH transport",
        category: "network",
        interface: "golang.org/x/crypto/ssh.Channel",
    },
    Fingerprint {
        methods: &[
            "Close",
            "LocalAddr",
            "Read",
            "RemoteAddr",
            "SetDeadline",
            "SetReadDeadline",
            "SetWriteDeadline",
            "Write",
        ],
        rule_id: "iface.net.conn",
        name: "network connection (net.Conn)",
        category: "network",
        interface: "net.Conn",
    },
    Fingerprint {
        methods: &[
            "Close",
            "LocalAddr",
            "ReadFrom",
            "SetDeadline",
            "SetReadDeadline",
            "SetWriteDeadline",
            "WriteTo",
        ],
        rule_id: "iface.net.packetconn",
        name: "packet socket (net.PacketConn)",
        category: "network",
        interface: "net.PacketConn",
    },
    Fingerprint {
        methods: &["Begin", "Close", "Prepare"],
        rule_id: "iface.sql.driver",
        name: "SQL driver (interface)",
        category: "database",
        interface: "database/sql/driver.Conn",
    },
    Fingerprint {
        methods: &["Close", "Exec", "NumInput", "Query"],
        rule_id: "iface.sql.driver",
        name: "SQL driver (interface)",
        category: "database",
        interface: "database/sql/driver.Stmt",
    },
    Fingerprint {
        methods: &["NonceSize", "Open", "Overhead", "Seal"],
        rule_id: "iface.crypto.aead",
        name: "AEAD cipher (interface)",
        category: "crypto",
        interface: "crypto/cipher.AEAD",
    },
    Fingerprint {
        methods: &["BlockSize", "Decrypt", "Encrypt"],
        rule_id: "iface.crypto.block",
        name: "block cipher (interface)",
        category: "crypto",
        interface: "crypto/cipher.Block",
    },
];

/// Up to this many evidence strings per capability, matching the rule engine.
const MAX_EVIDENCE: usize = 5;

/// Identify interface-backed capabilities from itab method sets. Returns one
/// capability per matched rule id, with the matching interfaces and itab
/// addresses as evidence.
pub fn identify(itabs: &[Itab]) -> Vec<Capability> {
    // Grouped by rule id, preserving first-seen order for a stable report.
    let mut order: Vec<&'static str> = Vec::new();
    let mut groups: std::collections::HashMap<&'static str, Capability> =
        std::collections::HashMap::new();

    for itab in itabs {
        let Some(fp) = match_fingerprint(itab) else {
            continue;
        };
        let cap = groups.entry(fp.rule_id).or_insert_with(|| {
            order.push(fp.rule_id);
            Capability {
                name: fp.name,
                category: fp.category,
                rule_id: fp.rule_id,
                evidence: Vec::new(),
            }
        });
        if cap.evidence.len() < MAX_EVIDENCE {
            let line = format!("{} @ 0x{:x}", fp.interface, itab.addr);
            if !cap.evidence.contains(&line) {
                cap.evidence.push(line);
            }
        }
    }

    order
        .into_iter()
        .map(|id| groups.remove(id).unwrap())
        .collect()
}

/// The fingerprint whose method set is exactly this itab's method set, if any.
/// The itab must have the same number of methods as the fingerprint (so no extra
/// unexported methods hide on it) and the same exported names.
fn match_fingerprint(itab: &Itab) -> Option<&'static Fingerprint> {
    if itab.methods.is_empty() {
        return None;
    }
    let mut exported: Vec<&str> = itab
        .methods
        .iter()
        .map(|m| m.interface_method.as_str())
        .filter(|n| is_exported(n))
        .collect();
    exported.sort_unstable();
    exported.dedup();

    FINGERPRINTS.iter().find(|fp| {
        // Equal total method count rules out a superset carrying extra (possibly
        // hashed) methods; equal exported set confirms the identity.
        itab.methods.len() == fp.methods.len()
            && exported.len() == fp.methods.len()
            && exported.iter().zip(fp.methods).all(|(a, b)| a == b)
    })
}

fn is_exported(name: &str) -> bool {
    name.chars().next().is_some_and(|c| c.is_ascii_uppercase())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::itabs::ItabMethod;

    #[test]
    fn fingerprints_are_well_formed() {
        let mut seen_sets: Vec<&[&str]> = Vec::new();
        for fp in FINGERPRINTS {
            assert!(
                fp.methods.len() >= 3,
                "{} has fewer than 3 methods; too common to be evidence",
                fp.interface
            );
            // Sorted, unique, exported: the match relies on all three.
            for w in fp.methods.windows(2) {
                assert!(w[0] < w[1], "{} methods not sorted/unique", fp.interface);
            }
            for m in fp.methods {
                assert!(is_exported(m), "{} has unexported method {m}", fp.interface);
            }
            assert!(
                fp.rule_id.starts_with("iface."),
                "{} rule id not in iface namespace",
                fp.interface
            );
            assert!(
                !seen_sets.contains(&fp.methods),
                "duplicate method set on {}",
                fp.interface
            );
            seen_sets.push(fp.methods);
        }
    }

    fn itab_with(methods: &[&str]) -> Itab {
        Itab {
            addr: 0x1000,
            interface_name: "*hashed".into(),
            concrete_name: "*hashed".into(),
            hash: 0,
            incomplete: false,
            methods: methods
                .iter()
                .map(|m| ItabMethod {
                    interface_method: (*m).into(),
                    concrete_fn: 0,
                })
                .collect(),
            stdlib_interface: None,
        }
    }

    #[test]
    fn exact_net_conn_set_fires() {
        let it = itab_with(&[
            "Read",
            "Write",
            "Close",
            "LocalAddr",
            "RemoteAddr",
            "SetDeadline",
            "SetReadDeadline",
            "SetWriteDeadline",
        ]);
        let caps = identify(&[it]);
        assert_eq!(caps.len(), 1);
        assert_eq!(caps[0].rule_id, "iface.net.conn");
    }

    #[test]
    fn missing_one_method_does_not_fire() {
        // net.Conn minus SetWriteDeadline: not an exact set, so no match.
        let it = itab_with(&[
            "Read",
            "Write",
            "Close",
            "LocalAddr",
            "RemoteAddr",
            "SetDeadline",
            "SetReadDeadline",
        ]);
        assert!(identify(&[it]).is_empty());
    }

    #[test]
    fn extra_unexported_method_does_not_fire() {
        // The exported set matches driver.Conn, but an extra hashed method means
        // it is some other, larger interface. The count guard rejects it.
        let mut it = itab_with(&["Begin", "Close", "Prepare"]);
        it.methods.push(ItabMethod {
            interface_method: "x7sdklj".into(),
            concrete_fn: 0,
        });
        assert!(identify(&[it]).is_empty());
    }

    #[test]
    fn single_method_never_fires() {
        assert!(identify(&[itab_with(&["Read"])]).is_empty());
        assert!(identify(&[itab_with(&["ServeHTTP"])]).is_empty());
    }

    #[test]
    fn ssh_conn_and_channel_collapse_to_one_capability() {
        let conn = itab_with(&[
            "ClientVersion",
            "Close",
            "LocalAddr",
            "OpenChannel",
            "RemoteAddr",
            "SendRequest",
            "ServerVersion",
            "SessionID",
            "User",
            "Wait",
        ]);
        let chan = itab_with(&[
            "Close",
            "CloseWrite",
            "Read",
            "SendRequest",
            "Stderr",
            "Write",
        ]);
        let caps = identify(&[conn, chan]);
        assert_eq!(caps.len(), 1, "both ssh interfaces share rule_id iface.ssh");
        assert_eq!(caps[0].rule_id, "iface.ssh");
        assert_eq!(caps[0].evidence.len(), 2);
    }
}
