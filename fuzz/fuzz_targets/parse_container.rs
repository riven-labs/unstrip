#![no_main]

//! The container loader: the first code to touch an untrusted file. ELF, Mach-O,
//! and PE headers, the section and segment tables, and the pclntab magic scan all
//! run over bytes the input fully controls. A malformed or hostile image must
//! return an error, never panic.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = unstrip::GoBinary::parse(data.to_vec());
});
