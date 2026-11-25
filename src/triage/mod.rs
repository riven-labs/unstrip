//! The facts an analyst records first about a Go binary: the release that
//! built it, its build ID, the main module, the target platform, cgo, the VCS
//! stamp and the garble verdict. And, when the Go metadata does not read at
//! all, the reason, from the container probe.

use serde::Serialize;

use crate::buildinfo::{BuildInfo, Module};
use crate::error::Error;
use crate::garble::GarbleAssessment;
use crate::gobin::{Container, GoBinary};
use crate::pclntab::{Function, Pclntab};

/// What `--info` prints first. Every field is None when the binary does not
/// record it: build settings (platform, cgo, VCS) exist from Go 1.18, and
/// garble blanks the build ID and the module table.
#[derive(Debug, Clone, Serialize)]
#[non_exhaustive]
pub struct Triage {
    /// The Go release, as [`crate::output::go_version`] reads it.
    pub go_version: Option<String>,
    pub build_id: Option<String>,
    pub main_module: Option<Module>,
    pub goos: Option<String>,
    pub goarch: Option<String>,
    /// Where `goos` and `goarch` were read.
    pub platform_from: PlatformSource,
    /// The `CGO_ENABLED` build setting.
    pub cgo_enabled: Option<bool>,
    pub vcs: Option<Vcs>,
    /// The verdict `--detect-garble` gives.
    pub garble: GarbleAssessment,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum PlatformSource {
    /// The `GOOS` and `GOARCH` build settings (Go 1.18 and later).
    BuildInfo,
    /// The name of the entry point the linker chose, `_rt0_<goarch>_<goos>`.
    EntryPoint,
    /// The container: the machine field, and the OS for PE and Mach-O.
    Container,
}

/// The version control stamp `go build` records from Go 1.18 when it builds
/// inside a repository: the `vcs`, `vcs.revision`, `vcs.time` and
/// `vcs.modified` build settings.
#[derive(Debug, Clone, Serialize)]
#[non_exhaustive]
pub struct Vcs {
    pub system: Option<String>,
    pub revision: Option<String>,
    pub time: Option<String>,
    pub modified: Option<bool>,
}

/// Gathers the triage facts. `functions` is the pclntab's function list,
/// which the garble verdict and the entry-point platform read.
pub fn triage(bin: &GoBinary, pcln: &Pclntab<'_>, functions: &[Function]) -> Triage {
    let info = BuildInfo::parse(bin).ok();
    let go_version = crate::output::go_version_from(info.as_ref(), bin);
    let garble = crate::garble::assess(functions, go_version.as_deref(), pcln.magic_is_official());
    let setting = |key: &str| info.as_ref().and_then(|bi| bi.setting(key));

    let (goos, goarch, platform_from) = match (setting("GOOS"), setting("GOARCH")) {
        (Some(goos), Some(goarch)) => (
            Some(goos.to_string()),
            Some(goarch.to_string()),
            PlatformSource::BuildInfo,
        ),
        _ => match entry_point_platform(functions) {
            Some((goos, goarch)) => (Some(goos), Some(goarch), PlatformSource::EntryPoint),
            None => {
                let goos = match bin.container {
                    Container::Pe => Some("windows".to_string()),
                    Container::MachO => Some("darwin".to_string()),
                    Container::Elf => None,
                };
                let goarch = match bin.arch {
                    crate::gobin::Arch::Other => None,
                    arch => Some(arch.as_str().to_string()),
                };
                (goos, goarch, PlatformSource::Container)
            }
        },
    };

    let vcs = Vcs {
        system: setting("vcs").map(str::to_string),
        revision: setting("vcs.revision").map(str::to_string),
        time: setting("vcs.time").map(str::to_string),
        modified: setting("vcs.modified").map(|v| v == "true"),
    };
    let vcs_recorded = vcs.system.is_some() || vcs.revision.is_some();

    Triage {
        go_version,
        build_id: build_id(bin),
        main_module: info
            .as_ref()
            .and_then(|bi| bi.main.clone())
            .filter(|m| !m.path.is_empty()),
        goos,
        goarch,
        platform_from,
        cgo_enabled: setting("CGO_ENABLED").map(|v| v == "1"),
        vcs: if vcs_recorded { Some(vcs) } else { None },
        garble,
    }
}

/// The Go build ID (`go tool buildid`): the `Go` ELF note of type 4, or on PE
/// and Mach-O the `\xff Go build ID: "..."` string the linker puts at the
/// start of the text. Both sit in the first pages of the file. None when
/// neither is there or the ID is empty (garble writes an empty one).
pub fn build_id(bin: &GoBinary) -> Option<String> {
    const SEARCH: usize = 64 << 10;
    let head = &bin.bytes[..bin.bytes.len().min(SEARCH)];
    let id = match bin.container {
        Container::Elf => elf_build_id_note(head, bin.little_endian)?,
        Container::Pe | Container::MachO => {
            const MARKER: &[u8] = b"\xff Go build ID: \"";
            let at = head.windows(MARKER.len()).position(|w| w == MARKER)?;
            let rest = &head[at + MARKER.len()..];
            let end = rest.iter().position(|&b| b == b'"')?;
            &rest[..end]
        }
    };
    let id = std::str::from_utf8(id).ok()?;
    if id.is_empty() || id.chars().any(|c| c.is_control()) {
        return None;
    }
    Some(id.to_string())
}

/// The descriptor of the ELF note named `Go` with type 4
/// (`ELF_NOTE_GOBUILDID_TAG` in `cmd/link`). A note is namesz, descsz and type
/// (4 bytes each), the name padded to 4 bytes, then the descriptor.
fn elf_build_id_note(head: &[u8], little_endian: bool) -> Option<&[u8]> {
    const NAME: &[u8] = b"Go\0\0";
    const GO_BUILD_ID: u32 = 4;
    let word = |at: usize| -> Option<u32> {
        let b: [u8; 4] = head.get(at..at + 4)?.try_into().ok()?;
        Some(if little_endian {
            u32::from_le_bytes(b)
        } else {
            u32::from_be_bytes(b)
        })
    };
    let mut from = 12;
    while from + NAME.len() <= head.len() {
        let at = from + head[from..].windows(NAME.len()).position(|w| w == NAME)?;
        from = at + 1;
        let start = at - 12;
        let (Some(namesz), Some(descsz), Some(kind)) =
            (word(start), word(start + 4), word(start + 8))
        else {
            continue;
        };
        if namesz != 4 || kind != GO_BUILD_ID || descsz == 0 || descsz > 1024 {
            continue;
        }
        let desc = at + NAME.len();
        return head.get(desc..desc + descsz as usize);
    }
    None
}

/// GOOS and GOARCH from the entry point's name. The linker's entry point for a
/// program is `_rt0_<goarch>_<goos>` (`_rt0_amd64_linux`, `_rt0_386_windows`),
/// a function in the pclntab that garble leaves alone. Build modes add a
/// suffix (`_rt0_amd64_linux_lib`).
pub fn entry_point_platform(functions: &[Function]) -> Option<(String, String)> {
    const GOOS: &[&str] = &[
        "aix",
        "android",
        "darwin",
        "dragonfly",
        "freebsd",
        "illumos",
        "ios",
        "js",
        "linux",
        "netbsd",
        "openbsd",
        "plan9",
        "solaris",
        "wasip1",
        "windows",
    ];
    for f in functions {
        let Some(rest) = f.name.strip_prefix("_rt0_") else {
            continue;
        };
        let mut parts = rest.split('_');
        let (Some(goarch), Some(goos)) = (parts.next(), parts.next()) else {
            continue;
        };
        if !GOOS.contains(&goos) || goarch.is_empty() {
            continue;
        }
        return Some((goos.to_string(), goarch.to_string()));
    }
    None
}

/// Why a file gave no Go metadata, for `--info` and the error every other mode
/// prints.
#[derive(Debug, Clone, Serialize)]
#[non_exhaustive]
pub struct Unreadable {
    pub reason: Reason,
    /// One sentence for a person.
    pub detail: String,
    /// The container as the probe names it (`ELF`, `PE (header damaged)`).
    /// None when the bytes are no container.
    pub container: Option<String>,
    /// The machine as the probe names it (`x86-64`, `i386`).
    pub arch: Option<String>,
    pub file_size: usize,
    /// Shannon entropy of the whole file, bits per byte.
    pub file_entropy: f64,
    /// The probe's packer verdict, when it has one.
    pub packer: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum Reason {
    /// A packer the probe recognises (UPX by its magic or section names, others
    /// by section names), or a high-entropy layout.
    Packed,
    /// The only Go program in the file is carried as data
    /// ([`Error::EmbeddedGoImage`]).
    EmbeddedGoImage,
    /// The file is shorter than its headers say.
    Truncated,
    /// A container with no Go pclntab in it.
    NotGo,
    /// Not an ELF, PE or Mach-O file.
    NotAContainer,
    /// A Go table was found and did not decode.
    Damaged,
}

/// Explains `err`, the error opening `bytes` as a Go binary gave, from the
/// container probe. An I/O error is not about the bytes and has no
/// explanation here.
pub fn diagnose(bytes: &[u8], err: &Error) -> Option<Unreadable> {
    if matches!(err, Error::Io(_)) {
        return None;
    }
    let probe = crate::probe::probe(bytes).ok();
    let packer = probe.as_ref().and_then(|p| p.packer.clone());
    let truncated = match &probe {
        Some(p) if p.declared_size > p.file_size => Some((p.file_size, p.declared_size)),
        _ => None,
    };
    let (reason, detail) = match (err, &packer, truncated, &probe) {
        (Error::EmbeddedGoImage { .. }, ..) => (Reason::EmbeddedGoImage, err.to_string()),
        (_, Some(packer), ..) => {
            let mut detail = format!(
                "packed: {packer}; the Go tables are compressed or encrypted until the file is unpacked"
            );
            if packer.starts_with("UPX") {
                detail.push_str(" (`upx -d` unpacks it)");
            }
            (Reason::Packed, detail)
        }
        (_, None, Some((have, want)), _) => (
            Reason::Truncated,
            format!("truncated: the file is {have} bytes and its headers describe {want}"),
        ),
        (_, None, None, None) => (
            Reason::NotAContainer,
            "not an ELF, PE or Mach-O file".to_string(),
        ),
        (Error::NoPclntab, ..) => (
            Reason::NotGo,
            "no Go pclntab: not a Go program, or one whose tables were removed".to_string(),
        ),
        _ => (
            Reason::Damaged,
            format!("Go metadata does not decode: {err}"),
        ),
    };
    Some(Unreadable {
        reason,
        detail,
        container: probe.as_ref().map(|p| p.container.to_string()),
        arch: probe.as_ref().map(|p| p.arch.clone()),
        file_size: bytes.len(),
        file_entropy: crate::probe::entropy(bytes),
        packer,
    })
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
            size: None,
        }
    }

    #[test]
    fn entry_point_names_goos_and_goarch() {
        let functions = [
            func("_rt0_amd64"),
            func("runtime.main"),
            func("_rt0_arm64_linux_lib"),
        ];
        assert_eq!(
            entry_point_platform(&functions),
            Some(("linux".to_string(), "arm64".to_string())),
            "`_rt0_amd64` names no OS, the suffix after the OS is a build mode"
        );
        assert_eq!(
            entry_point_platform(&[func("_rt0_386_windows")]).unwrap().1,
            "386"
        );
        assert_eq!(entry_point_platform(&[func("_rt0_go_x")]), None);
    }

    #[test]
    fn elf_note_and_text_marker_give_the_build_id() {
        let mut head = vec![0u8; 256];
        let id = b"abc/def";
        head[100..104].copy_from_slice(&4u32.to_le_bytes());
        head[104..108].copy_from_slice(&(id.len() as u32).to_le_bytes());
        head[108..112].copy_from_slice(&4u32.to_le_bytes());
        head[112..116].copy_from_slice(b"Go\0\0");
        head[116..116 + id.len()].copy_from_slice(id);
        assert_eq!(elf_build_id_note(&head, true), Some(&id[..]));
        assert_eq!(elf_build_id_note(&head, false), None, "byte order matters");
        // A `Go\0\0` that is not a type 4 note is passed over.
        head[108..112].copy_from_slice(&1u32.to_le_bytes());
        assert_eq!(elf_build_id_note(&head, true), None);
    }

    #[test]
    fn a_container_without_go_is_not_go_and_noise_is_no_container() {
        let noise = vec![0x41u8; 4096];
        let res = diagnose(&noise, &Error::UnknownContainer).unwrap();
        assert_eq!(res.reason, Reason::NotAContainer);
        assert!(diagnose(&noise, &Error::Io(std::io::ErrorKind::NotFound.into())).is_none());
    }
}
