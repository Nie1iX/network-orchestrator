#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn main() -> std::io::Result<()> {
    use net_manager_core::managed_xray::{
        install_verified_linux_archive, verify_managed_linux_executable, LINUX_XRAY_SHA256,
        LINUX_XRAY_URL, LINUX_XRAY_VERSION, MAX_XRAY_ARCHIVE_BYTES,
    };
    use std::fs::{self, File};
    use std::io::{self, Read};
    use std::path::PathBuf;

    let mut args = std::env::args_os().skip(1);
    let command = args.next().and_then(|arg| arg.into_string().ok());
    match command.as_deref() {
        Some("url") => println!("{LINUX_XRAY_URL}"),
        Some("sha256") => println!("{LINUX_XRAY_SHA256}"),
        Some("version") => println!("{LINUX_XRAY_VERSION}"),
        Some("install") => {
            let archive_path = PathBuf::from(args.next().ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, "archive path is required")
            })?);
            let root = PathBuf::from(args.next().ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, "staging root is required")
            })?);
            if args.next().is_some() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "unexpected packaging argument",
                ));
            }
            let mut archive = Vec::new();
            File::open(archive_path)?
                .take(MAX_XRAY_ARCHIVE_BYTES as u64 + 1)
                .read_to_end(&mut archive)?;
            let installed = install_verified_linux_archive(&root, &archive)?;
            verify_managed_linux_executable(&root, &installed.executable)?;
            let mut reader = zip::ZipArchive::new(std::io::Cursor::new(&archive))?;
            for name in ["LICENSE", "README.md"] {
                let path = installed.version_dir.join(name);
                let metadata = fs::symlink_metadata(&path)?;
                if !metadata.is_file() || metadata.file_type().is_symlink() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "Xray release notice is not a regular file",
                    ));
                }
                let mut expected = Vec::new();
                reader.by_name(name)?.read_to_end(&mut expected)?;
                if fs::read(path)? != expected {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "Xray release notice failed integrity verification",
                    ));
                }
            }
        }
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "usage: package_linux_xray {url|sha256|version|install ARCHIVE STAGING_ROOT}",
            ))
        }
    }
    Ok(())
}

#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
fn main() {
    eprintln!("Xray packaging supports Linux x86_64 only");
    std::process::exit(2);
}
