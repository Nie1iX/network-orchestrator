//! Text output: aligned tables and the JSON rows shared with `--json`.
use net_manager_core::models::{Profile, TunnelBackend, TunnelRole, XrayMode};
use serde::Serialize;

/// One profile as `ls` shows it. Deliberately small: no paths, links, keys or
/// subscription URLs ever reach the terminal.
#[derive(Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ProfileRow {
    pub id: String,
    pub name: String,
    pub kind: &'static str,
    pub role: &'static str,
    pub subscription: bool,
}

pub fn kind_of(profile: &Profile) -> &'static str {
    match (profile.backend, profile.xray_mode) {
        (TunnelBackend::Xray, XrayMode::Tun) => "xray-tun",
        (TunnelBackend::Xray, _) => "xray-socks",
        (TunnelBackend::WireGuard, _) => "wireguard",
        (TunnelBackend::OpenVpn, _) => "openvpn",
        (TunnelBackend::None, _) => "static",
    }
}

pub fn row_of(profile: &Profile) -> ProfileRow {
    ProfileRow {
        id: profile.id.clone(),
        name: profile.name.clone(),
        kind: kind_of(profile),
        role: if profile.tunnel_role == TunnelRole::Secondary {
            "secondary"
        } else {
            "primary"
        },
        subscription: profile.subscription.is_some(),
    }
}

/// Columns padded to the widest cell; the last column is left unpadded.
pub fn table(headers: &[&str], rows: &[Vec<String>]) -> String {
    let columns = headers.len();
    let mut widths: Vec<usize> = headers.iter().map(|h| h.chars().count()).collect();
    for row in rows {
        for (index, cell) in row.iter().enumerate().take(columns) {
            widths[index] = widths[index].max(cell.chars().count());
        }
    }
    let line = |cells: Vec<&str>| {
        let mut out = String::new();
        for (index, cell) in cells.iter().enumerate() {
            if index + 1 == columns {
                out.push_str(cell);
            } else {
                out.push_str(&format!("{cell:<width$}  ", width = widths[index]));
            }
        }
        out.trim_end().to_string()
    };
    let mut lines = vec![line(headers.to_vec())];
    lines.extend(
        rows.iter()
            .map(|row| line(row.iter().map(String::as_str).collect())),
    );
    lines.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tables_align_columns_and_leave_the_last_one_ragged() {
        let text = table(
            &["ID", "NAME"],
            &[
                vec!["a".into(), "Home".into()],
                vec!["long-id".into(), "X".into()],
            ],
        );
        assert_eq!(text, "ID       NAME\na        Home\nlong-id  X");
    }

    #[test]
    fn rows_name_the_connection_kind_and_hide_everything_else() {
        let mut profile = Profile {
            id: "p".into(),
            name: "P".into(),
            backend: TunnelBackend::Xray,
            xray_mode: XrayMode::Tun,
            ..Default::default()
        };
        assert_eq!(row_of(&profile).kind, "xray-tun");
        profile.xray_mode = XrayMode::Socks;
        assert_eq!(row_of(&profile).kind, "xray-socks");
        profile.tunnel_role = TunnelRole::Secondary;
        assert_eq!(row_of(&profile).role, "secondary");
        let json = serde_json::to_string(&row_of(&profile)).unwrap();
        assert!(!json.contains("configPath"));
    }
}
