#![no_main]

//! The recovery stack over a parsed image: pclntab functions, the module data
//! and the type and itab catalogs it bounds, and the build info. Every offset
//! and length here is read from tables the input controls, so the goal is no
//! panic. Each pass takes a Result; we drop the value and only care that the
//! call returns.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(bin) = unstrip::GoBinary::parse(data.to_vec()) else {
        return;
    };
    if let Ok(pcln) = unstrip::pclntab::Pclntab::parse(&bin) {
        let _ = pcln.functions();
    }
    if let Ok(md) = unstrip::moduledata::ModuleData::locate(&bin) {
        let _ = unstrip::types::recover_all(&bin, &md);
        let _ = unstrip::itabs::recover_all(&bin, &md);
    }
    let _ = unstrip::buildinfo::BuildInfo::parse(&bin);
});
