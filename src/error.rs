use thiserror::Error;

#[derive(Debug, Error)]
#[non_exhaustive]
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

    /// Not returned since every pclntab layout from Go 1.2 on is read. Kept so
    /// callers that match on it still build.
    #[error("pclntab magic 0x{magic:08x} is a Go layout this reader does not read ({version})")]
    UnsupportedPclntabVersion { magic: u32, version: &'static str },

    #[error(
        "read past end of pclntab: wanted {wanted} bytes at offset {offset}, have {available}"
    )]
    ShortRead {
        wanted: usize,
        offset: usize,
        available: usize,
    },

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

    #[error("goroutines: {0}")]
    Goroutines(String),

    #[error("xrefs: {0}")]
    Xrefs(String),

    /// The only pclntab found belongs to a Go program carried inside the file
    /// as data (a dropper's payload, an installer, an executable built with a
    /// Go binary in its resources), not to the file's own code. Reading it
    /// against the container would attach the embedded program's function names
    /// to unrelated machine code, so the parse stops here instead.
    ///
    /// When the embedded image's own ELF, PE, or Mach-O header was found, `len`
    /// is its extent and `bytes[offset..offset + len]` parses on its own with
    /// [`crate::GoBinary::parse`]. Without a header, `offset` is the embedded
    /// pclntab's file offset and `len` is `None`.
    #[error(
        "embedded Go program at file offset 0x{offset:x}{}, carried as data rather than run as this file's code",
        platform_suffix(.goos.as_deref(), .goarch.as_deref())
    )]
    #[non_exhaustive]
    EmbeddedGoImage {
        /// File offset of the embedded image's header, or of its pclntab when
        /// no header was found.
        offset: usize,
        /// Byte length of the embedded image, when its header was found.
        len: Option<usize>,
        /// File offset of the embedded program's pclntab.
        pclntab_offset: usize,
        /// The embedded program's `GOOS` (from its buildinfo or its container
        /// format), when known.
        goos: Option<String>,
        /// The embedded program's `GOARCH`, when known.
        goarch: Option<String>,
    },
}

fn platform_suffix(goos: Option<&str>, goarch: Option<&str>) -> String {
    match (goos, goarch) {
        (Some(os), Some(arch)) => format!(" ({os}/{arch})"),
        (Some(one), None) | (None, Some(one)) => format!(" ({one})"),
        (None, None) => String::new(),
    }
}
