// Shared by the build scripts of crates that more than one release line
// ships (crates/cli, src-tauri). Included with `include!`, not a module, so
// build scripts need no dependency. Sets NETORCH_VERSION to the version of the
// line that matches the target operating system, read from versions.toml.

fn emit_product_version() {
    use std::path::PathBuf;
    let mut dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").expect("manifest dir"));
    let file = loop {
        let candidate = dir.join("versions.toml");
        if candidate.is_file() {
            break candidate;
        }
        if !dir.pop() {
            panic!("versions.toml not found above the crate");
        }
    };
    println!("cargo:rerun-if-changed={}", file.display());
    let line = match std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default().as_str() {
        "macos" | "ios" => "macos",
        "windows" => "windows",
        _ => "linux",
    };
    let text = std::fs::read_to_string(&file).expect("versions.toml is readable");
    let mut section = String::new();
    let mut version = None;
    for raw in text.lines() {
        let item = raw.split('#').next().unwrap_or("").trim();
        if let Some(name) = item.strip_prefix('[').and_then(|rest| rest.strip_suffix(']')) {
            section = name.to_string();
        } else if section == line {
            if let Some(value) = item
                .strip_prefix("version")
                .map(|rest| rest.trim_start().trim_start_matches('=').trim())
                .and_then(|rest| rest.strip_prefix('"')?.strip_suffix('"'))
            {
                version = Some(value.to_string());
            }
        }
    }
    let version = version.unwrap_or_else(|| panic!("versions.toml has no [{line}] version"));
    println!("cargo:rustc-env=NETORCH_VERSION={version}");
}
