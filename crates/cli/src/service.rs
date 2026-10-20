//! `netorch service install|remove`: the launchd helper for people who have
//! the command line tool but not the app. The helper is *copied* out of the
//! user-writable bundle into a root-owned location and registered under its
//! own label, so what launchd runs as root cannot be swapped afterwards. The
//! app registers the same helper through `SMAppService`; the two never run
//! together (the socket answers for one owner).
use serde::Serialize;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;

pub const LABEL: &str = "com.netmanager.app.helper.cli";
const TOOLS_DIR: &str = "Library/PrivilegedHelperTools";
const DAEMONS_DIR: &str = "Library/LaunchDaemons";
const MAX_HELPER_BYTES: u64 = 128 * 1024 * 1024;

/// The bundle `netorch` was started from.
#[derive(Debug, PartialEq, Eq)]
pub struct Layout {
    pub contents: PathBuf,
    pub helper: PathBuf,
    pub clients: Vec<PathBuf>,
}

/// `exe` must be `<name>.app/Contents/MacOS/netorch`, symlinks resolved.
pub fn layout_of(exe: &Path) -> Result<Layout, String> {
    let macos = exe.parent().ok_or("netorch must run from the app bundle")?;
    let contents = macos
        .parent()
        .ok_or("netorch must run from the app bundle")?;
    let in_bundle = macos.file_name().and_then(|n| n.to_str()) == Some("MacOS")
        && contents.file_name().and_then(|n| n.to_str()) == Some("Contents")
        && contents
            .parent()
            .and_then(|app| app.extension())
            .and_then(|ext| ext.to_str())
            == Some("app");
    if !in_bundle {
        return Err(
            "The helper is installed from the Network Orchestrator app bundle: \
             run the netorch inside it (Contents/MacOS/netorch)"
                .into(),
        );
    }
    Ok(Layout {
        contents: contents.to_path_buf(),
        helper: macos.join("network-orchestrator-helper"),
        clients: vec![macos.join("NetworkOrchestrator"), macos.join("netorch")],
    })
}

#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
struct Daemon<'a> {
    label: &'a str,
    program_arguments: Vec<String>,
    run_at_load: bool,
    keep_alive: bool,
    process_type: &'a str,
    standard_error_path: &'a str,
}

fn text(path: &Path) -> Result<String, String> {
    path.to_str()
        .map(str::to_string)
        .ok_or_else(|| "A path in the bundle is not valid UTF-8".to_string())
}

pub fn launch_plist(program: &Path, layout: &Layout) -> Result<Vec<u8>, String> {
    let mut arguments = vec![text(program)?];
    for client in &layout.clients {
        arguments.push("--client".into());
        arguments.push(text(client)?);
    }
    arguments.push("--bundle".into());
    arguments.push(text(&layout.contents)?);
    let mut out = Vec::new();
    plist::to_writer_xml(
        &mut out,
        &Daemon {
            label: LABEL,
            program_arguments: arguments,
            run_at_load: true,
            keep_alive: true,
            process_type: "Interactive",
            standard_error_path: "/var/log/network-orchestrator-helper.log",
        },
    )
    .map_err(|_| "The launch description could not be written".to_string())?;
    Ok(out)
}

pub trait Launchctl {
    fn bootstrap(&self, plist: &Path) -> Result<(), String>;
    fn bootout(&self) -> Result<(), String>;
}

pub struct SystemLaunchctl;

impl Launchctl for SystemLaunchctl {
    fn bootstrap(&self, plist: &Path) -> Result<(), String> {
        let status = Command::new("/bin/launchctl")
            .arg("bootstrap")
            .arg("system")
            .arg(plist)
            .status()
            .map_err(|_| "launchctl could not run".to_string())?;
        status
            .success()
            .then_some(())
            .ok_or_else(|| "launchctl refused the helper".to_string())
    }

    fn bootout(&self) -> Result<(), String> {
        let status = Command::new("/bin/launchctl")
            .arg("bootout")
            .arg(format!("system/{LABEL}"))
            .status()
            .map_err(|_| "launchctl could not run".to_string())?;
        status
            .success()
            .then_some(())
            .ok_or_else(|| "the helper was not loaded".to_string())
    }
}

/// Installs under `prefix` (`/` for real, a temp directory in tests).
pub struct Installer<'a> {
    pub prefix: PathBuf,
    pub launchctl: &'a dyn Launchctl,
}

fn root_owned(path: &Path, mode: u32, privileged: bool) -> Result<(), String> {
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
        .map_err(|_| "A file could not be secured".to_string())?;
    if privileged {
        std::os::unix::fs::chown(path, Some(0), Some(0))
            .map_err(|_| "A file could not be given to root".to_string())?;
    }
    Ok(())
}

impl Installer<'_> {
    pub fn binary(&self) -> PathBuf {
        self.prefix.join(TOOLS_DIR).join(LABEL)
    }

    pub fn plist(&self) -> PathBuf {
        self.prefix.join(DAEMONS_DIR).join(format!("{LABEL}.plist"))
    }

    pub fn is_installed(&self) -> bool {
        self.plist().exists()
    }

    fn write_atomic(
        &self,
        target: &Path,
        bytes: &[u8],
        mode: u32,
        privileged: bool,
    ) -> Result<(), String> {
        let directory = target.parent().ok_or("Bad install path")?;
        std::fs::create_dir_all(directory)
            .map_err(|_| "A system directory could not be created".to_string())?;
        let temp = target.with_extension("tmp");
        let _ = std::fs::remove_file(&temp);
        std::fs::write(&temp, bytes).map_err(|_| "A file could not be written".to_string())?;
        root_owned(&temp, mode, privileged)?;
        std::fs::rename(&temp, target).map_err(|_| "A file could not be put in place".to_string())
    }

    /// Copies the helper out of the bundle and registers it with launchd.
    /// `privileged` is true when running as root (files are given to root).
    pub fn install(&self, layout: &Layout, privileged: bool) -> Result<(), String> {
        let metadata = std::fs::symlink_metadata(&layout.helper)
            .map_err(|_| "The helper is missing from the app bundle".to_string())?;
        if !metadata.file_type().is_file()
            || metadata.len() == 0
            || metadata.len() > MAX_HELPER_BYTES
        {
            return Err("The helper in the app bundle is not a regular file".into());
        }
        if privileged && metadata.mode() & 0o022 != 0 {
            return Err("The helper in the app bundle is writable by others".into());
        }
        let bytes = std::fs::read(&layout.helper)
            .map_err(|_| "The helper could not be read".to_string())?;
        let binary = self.binary();
        let plist = self.plist();
        // A stale registration must not block a reinstall.
        let _ = self.launchctl.bootout();
        self.write_atomic(&binary, &bytes, 0o755, privileged)?;
        self.write_atomic(&plist, &launch_plist(&binary, layout)?, 0o644, privileged)?;
        if let Err(error) = self.launchctl.bootstrap(&plist) {
            let _ = std::fs::remove_file(&plist);
            let _ = std::fs::remove_file(&binary);
            return Err(error);
        }
        Ok(())
    }

    pub fn remove(&self) -> Result<bool, String> {
        let installed = self.is_installed() || self.binary().exists();
        let _ = self.launchctl.bootout();
        for path in [self.plist(), self.binary()] {
            match std::fs::remove_file(&path) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(_) => return Err("A helper file could not be removed".into()),
            }
        }
        Ok(installed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    #[derive(Default)]
    struct FakeLaunchctl {
        calls: RefCell<Vec<String>>,
        refuse: bool,
    }

    impl Launchctl for FakeLaunchctl {
        fn bootstrap(&self, plist: &Path) -> Result<(), String> {
            self.calls
                .borrow_mut()
                .push(format!("bootstrap {}", plist.display()));
            if self.refuse {
                Err("launchctl refused the helper".into())
            } else {
                Ok(())
            }
        }

        fn bootout(&self) -> Result<(), String> {
            self.calls.borrow_mut().push("bootout".into());
            Ok(())
        }
    }

    fn bundle(root: &Path) -> Layout {
        let macos = root.join("N.app/Contents/MacOS");
        std::fs::create_dir_all(&macos).unwrap();
        std::fs::write(
            macos.join("network-orchestrator-helper"),
            b"\xcf\xfa\xed\xfehelper",
        )
        .unwrap();
        layout_of(&macos.join("netorch")).unwrap()
    }

    #[test]
    fn only_the_tool_inside_an_app_bundle_can_install_the_helper() {
        let layout = layout_of(Path::new("/Applications/N.app/Contents/MacOS/netorch")).unwrap();
        assert_eq!(layout.contents, Path::new("/Applications/N.app/Contents"));
        assert_eq!(
            layout.helper,
            Path::new("/Applications/N.app/Contents/MacOS/network-orchestrator-helper")
        );
        assert!(layout_of(Path::new("/usr/local/bin/netorch")).is_err());
        assert!(layout_of(Path::new("/tmp/Contents/MacOS/netorch")).is_err());
    }

    #[test]
    fn the_launch_description_names_the_copy_the_clients_and_the_bundle() {
        let layout = layout_of(Path::new("/Applications/N.app/Contents/MacOS/netorch")).unwrap();
        let xml = String::from_utf8(
            launch_plist(Path::new("/Library/PrivilegedHelperTools/x"), &layout).unwrap(),
        )
        .unwrap();
        for expected in [
            LABEL,
            "/Library/PrivilegedHelperTools/x",
            "--client",
            "/Applications/N.app/Contents/MacOS/netorch",
            "/Applications/N.app/Contents/MacOS/NetworkOrchestrator",
            "--bundle",
            "/Applications/N.app/Contents",
            "<key>KeepAlive</key>",
        ] {
            assert!(xml.contains(expected), "missing {expected}: {xml}");
        }
    }

    #[test]
    fn install_copies_the_helper_registers_it_and_remove_undoes_both() {
        let dir = tempfile::tempdir().unwrap();
        let layout = bundle(dir.path());
        let launchctl = FakeLaunchctl::default();
        let installer = Installer {
            prefix: dir.path().join("root"),
            launchctl: &launchctl,
        };
        installer.install(&layout, false).unwrap();
        assert_eq!(
            std::fs::read(installer.binary()).unwrap(),
            std::fs::read(&layout.helper).unwrap()
        );
        assert_eq!(
            std::fs::metadata(installer.binary()).unwrap().mode() & 0o777,
            0o755
        );
        assert_eq!(
            std::fs::metadata(installer.plist()).unwrap().mode() & 0o777,
            0o644
        );
        assert!(installer.is_installed());
        assert!(launchctl
            .calls
            .borrow()
            .last()
            .unwrap()
            .starts_with("bootstrap "));
        assert!(installer.remove().unwrap());
        assert!(!installer.is_installed());
        assert!(!installer.binary().exists());
        assert!(!installer.remove().unwrap());
    }

    #[test]
    fn a_refusal_by_launchd_leaves_nothing_behind() {
        let dir = tempfile::tempdir().unwrap();
        let layout = bundle(dir.path());
        let launchctl = FakeLaunchctl {
            refuse: true,
            ..Default::default()
        };
        let installer = Installer {
            prefix: dir.path().join("root"),
            launchctl: &launchctl,
        };
        assert!(installer.install(&layout, false).is_err());
        assert!(!installer.plist().exists());
        assert!(!installer.binary().exists());
    }

    #[test]
    fn a_missing_or_symlinked_helper_is_refused_before_anything_is_written() {
        let dir = tempfile::tempdir().unwrap();
        let layout = bundle(dir.path());
        let launchctl = FakeLaunchctl::default();
        let installer = Installer {
            prefix: dir.path().join("root"),
            launchctl: &launchctl,
        };
        let real = dir.path().join("real-helper");
        std::fs::write(&real, b"x").unwrap();
        std::fs::remove_file(&layout.helper).unwrap();
        assert!(installer.install(&layout, false).is_err());
        std::os::unix::fs::symlink(&real, &layout.helper).unwrap();
        assert!(installer.install(&layout, false).is_err());
        assert!(!installer.binary().exists());
        assert!(launchctl.calls.borrow().is_empty());
    }
}
