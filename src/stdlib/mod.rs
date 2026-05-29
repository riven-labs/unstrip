//! Standard-library interface recognition.
//!
//! Stripped Go binaries don't expose interface names by package path; they
//! expose them as fully-qualified type names like `*io.Writer` or
//! `*net.Conn`. We carry a baked-in list of well-known stdlib interfaces
//! so we can classify itab entries and produce behavioral summaries:
//! "this binary implements `io.Reader` 47 times, `net.Conn` 14 times."
//!
//! The list is maintained by hand. Add entries when a new stdlib interface
//! shows up often enough in real binaries to be worth recognizing.

use std::collections::HashMap;

use crate::itabs::Itab;

/// Curated list of stdlib interfaces worth tracking for behavioral
/// classification. Names match what unstrip recovers via type lookup
/// (typically with a leading `*` because itab `inter` pointers reference
/// the pointer-to-interfacetype).
pub const STDLIB_INTERFACES: &[&str] = &[
    // io
    "*io.Reader",
    "*io.Writer",
    "*io.Closer",
    "*io.ReadWriter",
    "*io.ReadCloser",
    "*io.WriteCloser",
    "*io.ReadWriteCloser",
    "*io.Seeker",
    "*io.ReaderAt",
    "*io.WriterAt",
    "*io.ReaderFrom",
    "*io.WriterTo",
    "*io.StringWriter",
    "*io.ByteReader",
    "*io.ByteScanner",
    "*io.RuneReader",
    "*io.RuneScanner",
    // errors / fmt
    "*error",
    "*fmt.Stringer",
    "*fmt.GoStringer",
    "*fmt.Formatter",
    "*fmt.State",
    "*fmt.Scanner",
    "*fmt.ScanState",
    // net
    "*net.Conn",
    "*net.PacketConn",
    "*net.Listener",
    "*net.Addr",
    "*net.Error",
    // os / fs
    "*fs.File",
    "*fs.FileInfo",
    "*fs.DirEntry",
    "*fs.FS",
    "*fs.ReadDirFile",
    "*fs.ReadFileFS",
    "*fs.StatFS",
    "*fs.SubFS",
    "*fs.GlobFS",
    // hash / crypto
    "*hash.Hash",
    "*hash.Hash32",
    "*hash.Hash64",
    "*crypto.Signer",
    "*crypto.Decrypter",
    "*crypto.SignerOpts",
    "*crypto.PublicKey",
    "*crypto.PrivateKey",
    // encoding
    "*encoding.BinaryMarshaler",
    "*encoding.BinaryUnmarshaler",
    "*encoding.TextMarshaler",
    "*encoding.TextUnmarshaler",
    "*encoding/json.Marshaler",
    "*encoding/json.Unmarshaler",
    "*encoding/xml.Marshaler",
    "*encoding/xml.Unmarshaler",
    // sort / context / sync
    "*sort.Interface",
    "*context.Context",
    "*sync.Locker",
    // database
    "*database/sql/driver.Driver",
    "*database/sql/driver.Conn",
    "*database/sql/driver.Stmt",
    "*database/sql/driver.Rows",
    "*database/sql/driver.Result",
    "*database/sql/driver.Tx",
    "*database/sql.Scanner",
    "*driver.Valuer",
    // http / tls
    "*http.Handler",
    "*http.ResponseWriter",
    "*http.RoundTripper",
    "*http.CookieJar",
    "*http.Flusher",
    "*http.Hijacker",
    "*http.Pusher",
    "*tls.ClientSessionCache",
    // reflect
    "*reflect.Type",
];

/// Count, per known stdlib interface name, how many concrete implementations
/// the binary ships. Only interfaces with at least one impl are included.
/// The result is sorted by descending count for stable output.
pub fn classify_itabs(itabs: &[Itab]) -> Vec<(&'static str, usize)> {
    let interesting: HashMap<&str, &'static str> =
        STDLIB_INTERFACES.iter().map(|s| (*s, *s)).collect();
    let mut counts: HashMap<&'static str, usize> = HashMap::new();
    for itab in itabs {
        if let Some(canonical) = interesting.get(itab.interface_name.as_str()) {
            *counts.entry(canonical).or_insert(0) += 1;
        }
    }
    let mut sorted: Vec<(&'static str, usize)> = counts.into_iter().collect();
    sorted.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(b.0)));
    sorted
}

/// True if a name appears in the curated stdlib interface list.
pub fn is_stdlib_interface(name: &str) -> bool {
    STDLIB_INTERFACES.contains(&name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognizes_common_interfaces() {
        assert!(is_stdlib_interface("*io.Writer"));
        assert!(is_stdlib_interface("*net.Conn"));
        assert!(is_stdlib_interface("*sort.Interface"));
        assert!(!is_stdlib_interface("*main.MyInterface"));
        assert!(!is_stdlib_interface("io.Writer"));
    }
}
