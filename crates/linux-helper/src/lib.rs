//! Privileged helper invoked via `pkexec` to apply/remove policy routes on
//! Linux. Deliberately narrow: it knows exactly two verbs (`route-add`,
//! `route-del`), validates every argument itself (never trusts the caller,
//! since polkit only authorizes *this binary*, not its arguments), and
//! shells out to `ip` with an explicit argv — never a shell string, so
//! there is no injection surface regardless of how strict the validation
//! above it is.

use ipnet::IpNet;
use std::process::Command;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HelperCommand {
    RouteAdd {
        dest: IpNet,
        iface: String,
        metric: u32,
    },
    RouteDel {
        dest: IpNet,
        iface: String,
        metric: u32,
    },
}

pub fn parse_args(args: &[String]) -> Result<HelperCommand, String> {
    let [verb, dest, iface, metric] = args else {
        return Err(format!(
            "usage: linux-helper <route-add|route-del> <cidr> <iface> <metric>, got {} argument(s)",
            args.len()
        ));
    };
    let dest: IpNet = dest
        .parse()
        .map_err(|e| format!("invalid destination CIDR '{dest}': {e}"))?;
    validate_iface_name(iface)?;
    let metric: u32 = metric
        .parse()
        .map_err(|_| format!("invalid metric '{metric}': must be a non-negative integer"))?;
    match verb.as_str() {
        "route-add" => Ok(HelperCommand::RouteAdd {
            dest,
            iface: iface.clone(),
            metric,
        }),
        "route-del" => Ok(HelperCommand::RouteDel {
            dest,
            iface: iface.clone(),
            metric,
        }),
        other => Err(format!(
            "unknown command '{other}' (expected 'route-add' or 'route-del')"
        )),
    }
}

/// Linux interface names are limited to `IFNAMSIZ - 1` = 15 bytes. Beyond
/// that we accept only characters that can never be mistaken for an `ip`
/// flag or a shell metacharacter, even though nothing here ever touches a
/// shell — defense in depth costs nothing.
pub fn validate_iface_name(name: &str) -> Result<(), String> {
    if name.is_empty() || name.len() > 15 {
        return Err(format!(
            "interface name '{name}' must be 1-15 bytes, got {}",
            name.len()
        ));
    }
    if name.starts_with('-') {
        return Err(format!("interface name '{name}' must not start with '-'"));
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
    {
        return Err(format!(
            "interface name '{name}' contains unsupported characters"
        ));
    }
    Ok(())
}

fn family_flag(dest: &IpNet) -> &'static str {
    match dest {
        IpNet::V4(_) => "-4",
        IpNet::V6(_) => "-6",
    }
}

/// Build the `ip` argv for a command, without executing it. `route-add` maps
/// to `ip route replace` (idempotent: installs or overwrites in one call,
/// matching the "ensure this route exists" semantics `RouteExecutor::
/// add_route` expects), `route-del` maps to `ip route del` with the same
/// destination/interface/metric triple that must have been used to add it.
pub fn ip_route_args(cmd: &HelperCommand) -> Vec<String> {
    let (verb, dest, iface, metric) = match cmd {
        HelperCommand::RouteAdd {
            dest,
            iface,
            metric,
        } => ("replace", dest, iface, metric),
        HelperCommand::RouteDel {
            dest,
            iface,
            metric,
        } => ("del", dest, iface, metric),
    };
    vec![
        family_flag(dest).to_string(),
        "route".to_string(),
        verb.to_string(),
        dest.to_string(),
        "dev".to_string(),
        iface.clone(),
        "metric".to_string(),
        metric.to_string(),
    ]
}

/// Actually run `ip` with the built argv. Not unit-tested (it mutates real
/// kernel routing state and needs root), matching the project convention of
/// keeping real mutations out of `cargo test` and covering only the pure
/// argument-building/validation above.
pub fn run(cmd: &HelperCommand) -> Result<(), String> {
    let args = ip_route_args(cmd);
    let output = Command::new("ip")
        .args(&args)
        .output()
        .map_err(|e| format!("failed to spawn 'ip': {e}"))?;
    if output.status.success() {
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        Err(format!("'ip {}' failed: {}", args.join(" "), stderr.trim()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn parses_valid_route_add() {
        let cmd = parse_args(&args(&["route-add", "10.8.0.0/24", "wg0", "10"])).unwrap();
        assert_eq!(
            cmd,
            HelperCommand::RouteAdd {
                dest: "10.8.0.0/24".parse().unwrap(),
                iface: "wg0".into(),
                metric: 10,
            }
        );
    }

    #[test]
    fn parses_valid_route_del_with_ipv6() {
        let cmd = parse_args(&args(&["route-del", "fd00::/8", "wg0", "0"])).unwrap();
        assert_eq!(
            cmd,
            HelperCommand::RouteDel {
                dest: "fd00::/8".parse().unwrap(),
                iface: "wg0".into(),
                metric: 0,
            }
        );
    }

    #[test]
    fn rejects_wrong_argument_count() {
        assert!(parse_args(&args(&["route-add", "10.0.0.0/8"])).is_err());
        assert!(parse_args(&args(&[])).is_err());
        assert!(parse_args(&args(&["route-add", "10.0.0.0/8", "wg0", "0", "extra"])).is_err());
    }

    #[test]
    fn rejects_invalid_cidr() {
        let err = parse_args(&args(&["route-add", "not-a-cidr", "wg0", "0"])).unwrap_err();
        assert!(err.contains("invalid destination CIDR"));
    }

    #[test]
    fn rejects_invalid_metric() {
        let err = parse_args(&args(&["route-add", "10.0.0.0/8", "wg0", "-1"])).unwrap_err();
        assert!(err.contains("invalid metric"));
        let err =
            parse_args(&args(&["route-add", "10.0.0.0/8", "wg0", "not-a-number"])).unwrap_err();
        assert!(err.contains("invalid metric"));
    }

    #[test]
    fn rejects_unknown_verb() {
        let err = parse_args(&args(&["route-frobnicate", "10.0.0.0/8", "wg0", "0"])).unwrap_err();
        assert!(err.contains("unknown command"));
    }

    #[test]
    fn iface_name_accepts_typical_linux_names() {
        for name in ["wg0", "eth0", "veth-abc123", "br_lan", "tun.100"] {
            assert!(validate_iface_name(name).is_ok(), "{name} should be valid");
        }
    }

    #[test]
    fn iface_name_rejects_empty_and_oversized() {
        assert!(validate_iface_name("").is_err());
        assert!(validate_iface_name("this-name-is-16c").is_err());
        assert!(validate_iface_name("exactly15chars.").is_ok());
    }

    #[test]
    fn iface_name_rejects_leading_dash_and_unsafe_characters() {
        assert!(
            validate_iface_name("-f").is_err(),
            "must not look like an ip flag"
        );
        assert!(validate_iface_name("wg0; rm -rf /").is_err());
        assert!(validate_iface_name("wg 0").is_err());
        assert!(validate_iface_name("wg0/24").is_err());
    }

    #[test]
    fn ip_route_args_builds_replace_for_add_ipv4() {
        let cmd = HelperCommand::RouteAdd {
            dest: "10.8.0.0/24".parse().unwrap(),
            iface: "wg0".into(),
            metric: 10,
        };
        assert_eq!(
            ip_route_args(&cmd),
            vec![
                "-4",
                "route",
                "replace",
                "10.8.0.0/24",
                "dev",
                "wg0",
                "metric",
                "10"
            ]
        );
    }

    #[test]
    fn ip_route_args_builds_del_for_remove() {
        let cmd = HelperCommand::RouteDel {
            dest: "10.8.0.0/24".parse().unwrap(),
            iface: "wg0".into(),
            metric: 10,
        };
        assert_eq!(
            ip_route_args(&cmd),
            vec![
                "-4",
                "route",
                "del",
                "10.8.0.0/24",
                "dev",
                "wg0",
                "metric",
                "10"
            ]
        );
    }

    #[test]
    fn ip_route_args_uses_ipv6_family_flag() {
        let cmd = HelperCommand::RouteAdd {
            dest: "fd00::/8".parse().unwrap(),
            iface: "wg0".into(),
            metric: 0,
        };
        assert_eq!(ip_route_args(&cmd)[0], "-6");
    }
}
