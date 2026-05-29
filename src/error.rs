use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    #[error("not a recognized binary container (tried ELF, Mach-O, PE)")]
    UnknownContainer,

    #[error("Mach-O universal (fat) binary with {slice_count} arch slices, single-slice selection not yet supported; extract one slice with `lipo -extract <arch>` first")]
    FatBinary { slice_count: usize },

    #[error("goblin: {0}")]
    Goblin(#[from] goblin::error::Error),

    #[error("no pclntab section found and magic scan turned up nothing")]
    NoPclntab,

    #[error("pclntab at offset 0x{offset:x}: {reason}")]
    BadPclntab { offset: usize, reason: String },

    #[error("pclntab magic 0x{magic:08x} is not a supported Go version (want 0xfffffff1 for Go 1.20+)")]
    UnsupportedPclntabVersion { magic: u32 },

    #[error("read past end of pclntab: wanted {wanted} bytes at offset {offset}, have {available}")]
    ShortRead { wanted: usize, offset: usize, available: usize },

    #[error("string at offset {offset} is not valid utf-8")]
    BadString { offset: usize },

    #[error("moduledata: {0}")]
    ModuleData(String),

    #[error("buildinfo: {0}")]
    BuildInfo(String),

    #[error("types: {0}")]
    TypeRecovery(String),

    #[error("itabs: {0}")]
    ItabRecovery(String),

    #[error("plugin install: {0}")]
    PluginInstall(String),

    #[error("rewrite: {0}")]
    Rewrite(String),
}
