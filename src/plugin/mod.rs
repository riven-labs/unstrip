//! Install wrapper plugins/scripts into the user's RE tool plugin
//! directories so unstrip shows up as a menu item, not a script-run.
//!
//! For IDA: writes `~/.idapro/plugins/unstrip_plugin.py` (Linux/macOS) or
//! `%APPDATA%/Hex-Rays/IDA Pro/plugins/unstrip_plugin.py` (Windows). The
//! plugin adds a "File -> Load Go symbols (unstrip)" menu item that
//! shells out to the unstrip binary on the currently-loaded file and runs
//! the generated IDC script inline.
//!
//! For Ghidra: writes a script into `~/ghidra_scripts/` that the user
//! invokes from Script Manager (Ghidra has no menu-item-from-script API
//! that survives upgrades).
//!
//! For Binary Ninja: writes a plugin into `~/.binaryninja/plugins/` that
//! registers a `PluginCommand.register("Load Go symbols (unstrip)", ...)`.

use std::fs;
use std::io::Write;
use std::path::PathBuf;

use crate::export::Target;
use crate::Result;

/// Result of an install: where the file went and what the user should do
/// to activate it (usually a restart or rescan).
#[derive(Debug)]
pub struct InstallReport {
    pub target: Target,
    pub installed_at: PathBuf,
    pub activation_step: &'static str,
}

/// Install the wrapper for the given target. Honors `UNSTRIP_PLUGIN_DIR` as
/// an override (used by tests and by users with non-standard plugin paths).
pub fn install(target: Target) -> Result<InstallReport> {
    let dir = if let Ok(custom) = std::env::var("UNSTRIP_PLUGIN_DIR") {
        PathBuf::from(custom)
    } else {
        default_plugin_dir(target)?
    };
    fs::create_dir_all(&dir).map_err(crate::error::Error::Io)?;

    let (filename, contents, activation) = match target {
        Target::Ida => (
            "unstrip_plugin.py",
            include_str!("plugin_ida.py.tmpl"),
            "Restart IDA. The menu item appears under Edit -> Plugins -> Load Go symbols (unstrip).",
        ),
        Target::Ghidra => (
            "UnstripGoSymbols.py",
            include_str!("plugin_ghidra.py.tmpl"),
            "In Ghidra: Window -> Script Manager, refresh, then run UnstripGoSymbols.py.",
        ),
        Target::BinaryNinja => (
            "unstrip_plugin.py",
            include_str!("plugin_binja.py.tmpl"),
            "Restart Binary Ninja. The menu item appears under Plugins -> Load Go symbols (unstrip).",
        ),
    };

    let installed_at = dir.join(filename);
    let mut f = fs::File::create(&installed_at).map_err(crate::error::Error::Io)?;
    f.write_all(contents.as_bytes())
        .map_err(crate::error::Error::Io)?;

    Ok(InstallReport {
        target,
        installed_at,
        activation_step: activation,
    })
}

/// Resolve the default plugin directory for the user's host OS.
fn default_plugin_dir(target: Target) -> Result<PathBuf> {
    let home = dirs_like_home()?;
    let dir = match target {
        Target::Ida => {
            if cfg!(target_os = "windows") {
                std::env::var("APPDATA")
                    .map(|a| {
                        PathBuf::from(a)
                            .join("Hex-Rays")
                            .join("IDA Pro")
                            .join("plugins")
                    })
                    .unwrap_or_else(|_| home.join(".idapro").join("plugins"))
            } else {
                home.join(".idapro").join("plugins")
            }
        }
        Target::Ghidra => home.join("ghidra_scripts"),
        Target::BinaryNinja => {
            if cfg!(target_os = "windows") {
                std::env::var("APPDATA")
                    .map(|a| PathBuf::from(a).join("Binary Ninja").join("plugins"))
                    .unwrap_or_else(|_| home.join(".binaryninja").join("plugins"))
            } else if cfg!(target_os = "macos") {
                home.join("Library")
                    .join("Application Support")
                    .join("Binary Ninja")
                    .join("plugins")
            } else {
                home.join(".binaryninja").join("plugins")
            }
        }
    };
    Ok(dir)
}

fn dirs_like_home() -> Result<PathBuf> {
    if cfg!(target_os = "windows") {
        std::env::var("USERPROFILE")
            .or_else(|_| std::env::var("HOME"))
            .map(PathBuf::from)
            .map_err(|_| {
                crate::error::Error::PluginInstall("no USERPROFILE or HOME env var".into())
            })
    } else {
        std::env::var("HOME")
            .map(PathBuf::from)
            .map_err(|_| crate::error::Error::PluginInstall("no HOME env var".into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn install_respects_env_override() {
        let tmpdir =
            std::env::temp_dir().join(format!("unstrip-plugin-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&tmpdir);
        std::env::set_var("UNSTRIP_PLUGIN_DIR", &tmpdir);
        for target in [Target::Ida, Target::Ghidra, Target::BinaryNinja] {
            let report = install(target).expect("install");
            assert!(
                report.installed_at.exists(),
                "plugin file must exist after install"
            );
            assert!(report.installed_at.starts_with(&tmpdir));
            // File must be non-empty (template embedded successfully).
            let size = fs::metadata(&report.installed_at).unwrap().len();
            assert!(
                size > 200,
                "plugin script too small ({size} bytes) for {target:?}"
            );
        }
        std::env::remove_var("UNSTRIP_PLUGIN_DIR");
        let _ = fs::remove_dir_all(&tmpdir);
    }
}
