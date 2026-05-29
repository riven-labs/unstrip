pub mod buildinfo;
pub mod diff;
pub mod error;
pub mod export;
pub mod fingerprint;
pub mod gobin;
pub mod goroutines;
pub mod itabs;
pub mod moduledata;
pub mod output;
pub mod pclntab;
pub mod plugin;
pub mod rewrite;
pub mod stdlib;
pub mod types;
pub mod xrefs;

pub use buildinfo::{BuildInfo, Module};
pub use error::Error;
pub use fingerprint::Fingerprint;
pub use gobin::{Container, GoBinary, Section, SectionKind};
pub use itabs::Itab;
pub use moduledata::{ModuleData, SliceHeader};
pub use pclntab::{Function, Pclntab};
pub use types::{KindName, Type};

pub type Result<T> = std::result::Result<T, Error>;
