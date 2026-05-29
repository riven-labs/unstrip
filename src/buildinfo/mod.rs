use serde::Serialize;

use crate::error::Error;
use crate::gobin::GoBinary;
use crate::Result;

/// Parsed contents of a Go binary's buildinfo blob.
///
/// Format reference: `src/cmd/go/internal/modload/build.go` and
/// `src/debug/buildinfo/buildinfo.go` in the Go source tree.
#[derive(Debug, Clone, Serialize)]
pub struct BuildInfo {
    pub go_version: String,
    pub path: Option<String>,
    pub main: Option<Module>,
    pub deps: Vec<Module>,
    pub replaces: Vec<Replace>,
    pub settings: Vec<Setting>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Module {
    pub path: String,
    pub version: String,
    pub sum: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Replace {
    pub from: Module,
    pub to: Module,
}

#[derive(Debug, Clone, Serialize)]
pub struct Setting {
    pub key: String,
    pub value: String,
}

const MAGIC: &[u8] = b"\xff Go buildinf:";
const FLAG_VARINT_STRINGS: u8 = 2;

impl BuildInfo {
    pub fn parse(bin: &GoBinary) -> Result<Self> {
        let header_offset = find_buildinfo(&bin.bytes)
            .ok_or_else(|| Error::BuildInfo("buildinfo header not found".into()))?;
        decode(bin, header_offset)
    }
}

fn find_buildinfo(bytes: &[u8]) -> Option<usize> {
    for (i, window) in bytes.windows(MAGIC.len()).enumerate() {
        if window == MAGIC {
            if i + 16 > bytes.len() {
                return None;
            }
            let ptrsize = bytes[i + MAGIC.len()];
            if matches!(ptrsize, 4 | 8) {
                return Some(i);
            }
        }
    }
    None
}

fn decode(bin: &GoBinary, header_offset: usize) -> Result<BuildInfo> {
    let bytes = &bin.bytes;
    let _ptrsize = bytes[header_offset + MAGIC.len()] as usize;
    let flags = bytes[header_offset + MAGIC.len() + 1];

    if flags & FLAG_VARINT_STRINGS != 0 {
        return decode_inline(bytes, header_offset + 32);
    }

    // The pre-1.18 pointer-indirected format used vers_ptr/mod_ptr after the
    // header. We don't support it: we'd need pclntab parsing to reach this
    // code path on a pre-1.18 binary, and pclntab parsing requires the 1.20+
    // layout. When 1.18/1.19 pclntab support lands, the pointer-format
    // decoder lands with it (under fixture coverage).
    Err(Error::BuildInfo(
        "pre-Go-1.18 pointer-indirected buildinfo format is not supported (need Go 1.18+ binary)"
            .into(),
    ))
}

fn decode_inline(bytes: &[u8], mut pos: usize) -> Result<BuildInfo> {
    let go_version_bytes = read_varint_bytes(bytes, &mut pos)?;
    let modinfo_bytes = read_varint_bytes(bytes, &mut pos)?;
    let go_version = std::str::from_utf8(go_version_bytes)
        .map_err(|_| Error::BuildInfo("go version string is not valid utf-8".into()))?
        .to_string();
    let modinfo = trim_modinfo_framing(modinfo_bytes)?;
    let mut info = parse_modinfo(modinfo);
    info.go_version = go_version;
    Ok(info)
}

fn read_varint_bytes<'a>(bytes: &'a [u8], pos: &mut usize) -> Result<&'a [u8]> {
    let (len, n) = read_varint(&bytes[*pos..])
        .ok_or_else(|| Error::BuildInfo("unterminated varint in inline buildinfo".into()))?;
    *pos += n;
    let end = *pos + len as usize;
    if end > bytes.len() {
        return Err(Error::BuildInfo(format!(
            "varint string of length {len} overruns buffer (start={pos}, end={end}, buf={})",
            bytes.len()
        )));
    }
    let slice = &bytes[*pos..end];
    *pos = end;
    Ok(slice)
}

/// The linker frames the modinfo blob with 16 bytes of sentinel data at each
/// end (`cmd/go/internal/modload.infoStart` and `infoEnd`). The runtime trims
/// them in `ReadBuildInfo`. The bytes inside the frame are valid UTF-8;
/// the framing itself contains arbitrary bytes that aren't.
fn trim_modinfo_framing(raw: &[u8]) -> Result<&str> {
    if raw.len() < 32 || raw[raw.len() - 17] != b'\n' {
        return Err(Error::BuildInfo(format!(
            "modinfo too short or missing expected newline before end sentinel (len={})",
            raw.len()
        )));
    }
    let inner = &raw[16..raw.len() - 16];
    std::str::from_utf8(inner)
        .map_err(|_| Error::BuildInfo("modinfo body is not valid utf-8".into()))
}

fn read_varint(buf: &[u8]) -> Option<(u64, usize)> {
    // A varint encoding a u64 needs at most 10 bytes. Anything longer is
    // malformed input and we reject rather than overshift.
    const MAX_BYTES: usize = 10;
    let mut result: u64 = 0;
    let mut shift = 0;
    for (i, &b) in buf.iter().take(MAX_BYTES).enumerate() {
        result |= ((b & 0x7f) as u64) << shift;
        if b & 0x80 == 0 {
            return Some((result, i + 1));
        }
        shift += 7;
        if shift >= 64 {
            return None;
        }
    }
    None
}

/// Parses the `modinfo` string emitted by the linker. Format is one record
/// per line, tab-separated:
///   path\t<main package import path>
///   mod\t<module path>\t<version>\t<h1 sum>
///   dep\t<module path>\t<version>\t<h1 sum>
///   =>\t<replacement path>\t<version>\t<h1 sum>
///   build\t<setting key>\t<setting value>      (in newer formats)
///   build\t-<key>=<value>                       (in older formats)
///
/// Wrapped in `\xa1\xa2\xa3\xa4 ... \xa4\xa3\xa2\xa1` markers we strip.
fn parse_modinfo(trimmed: &str) -> BuildInfo {
    let mut info = BuildInfo {
        go_version: String::new(),
        path: None,
        main: None,
        deps: Vec::new(),
        replaces: Vec::new(),
        settings: Vec::new(),
    };

    // We process line by line and pair `=>` lines with the dep they replace
    // (the `=>` always immediately follows its parent `dep`/`mod`).
    let mut last_module: Option<Module> = None;

    for line in trimmed.lines() {
        let mut parts = line.splitn(4, '\t');
        let tag = match parts.next() {
            Some(t) => t,
            None => continue,
        };
        match tag {
            "path" => {
                info.path = parts.next().map(|s| s.to_string());
            }
            "mod" => {
                let m = read_module(&mut parts);
                last_module = Some(m.clone());
                info.main = Some(m);
            }
            "dep" => {
                let m = read_module(&mut parts);
                last_module = Some(m.clone());
                info.deps.push(m);
            }
            "=>" => {
                let to = read_module(&mut parts);
                if let Some(from) = last_module.take() {
                    info.replaces.push(Replace { from, to });
                }
            }
            "build" => {
                // Modern format: `build\t<key>\t<value>`. Older: `build\t-key=value`.
                let rest = parts.next().unwrap_or("");
                let value = parts.next();
                let (k, v) = match value {
                    Some(v) => (rest.to_string(), v.to_string()),
                    None => match rest.split_once('=') {
                        Some((k, v)) => (k.trim_start_matches('-').to_string(), v.to_string()),
                        None => (rest.trim_start_matches('-').to_string(), String::new()),
                    },
                };
                info.settings.push(Setting { key: k, value: v });
            }
            _ => {}
        }
    }

    info
}

fn read_module<'a>(parts: &mut impl Iterator<Item = &'a str>) -> Module {
    let path = parts.next().unwrap_or("").to_string();
    let version = parts.next().unwrap_or("").to_string();
    let sum_raw = parts.next().unwrap_or("");
    let sum = if sum_raw.is_empty() {
        None
    } else {
        Some(sum_raw.to_string())
    };
    Module { path, version, sum }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_modinfo_with_main_and_deps() {
        let raw = "path\texample.com/cli\nmod\texample.com/cli\t(devel)\t\ndep\tgithub.com/spf13/cobra\tv1.8.0\th1:abc\ndep\tgolang.org/x/sys\tv0.20.0\th1:def\nbuild\tCGO_ENABLED\t0\nbuild\tGOOS\tlinux\n";
        let info = parse_modinfo(raw);
        assert_eq!(info.path.as_deref(), Some("example.com/cli"));
        assert_eq!(info.main.as_ref().unwrap().path, "example.com/cli");
        assert_eq!(info.deps.len(), 2);
        assert_eq!(info.deps[0].path, "github.com/spf13/cobra");
        assert_eq!(info.deps[0].version, "v1.8.0");
        assert_eq!(info.deps[0].sum.as_deref(), Some("h1:abc"));
        assert_eq!(info.settings.len(), 2);
    }

    #[test]
    fn parses_replace_directive() {
        let raw = "dep\texample.com/orig\tv1.0.0\th1:aaa\n=>\texample.com/fork\tv1.0.1\th1:bbb\n";
        let info = parse_modinfo(raw);
        assert_eq!(info.deps.len(), 1);
        assert_eq!(info.replaces.len(), 1);
        assert_eq!(info.replaces[0].from.path, "example.com/orig");
        assert_eq!(info.replaces[0].to.path, "example.com/fork");
    }

    #[test]
    fn parses_old_format_build_setting() {
        let raw = "build\t-compiler=gc\nbuild\t-trimpath=true\n";
        let info = parse_modinfo(raw);
        assert_eq!(info.settings.len(), 2);
        assert_eq!(info.settings[0].key, "compiler");
        assert_eq!(info.settings[0].value, "gc");
    }
}
