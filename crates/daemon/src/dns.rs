//! Per-link systemd-resolved settings for daemon-owned tunnel interfaces.
//!
//! The caller must verify ownership of the link before `apply` or `revert`.

use std::fmt;
use std::fs;
use std::io;
use std::net::IpAddr;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::process::{Command, Stdio};

const RESOLVECTL: &str = "/usr/bin/resolvectl";
const MAX_DNS_SERVERS: usize = 8;
const MAX_DNS_DOMAINS: usize = 16;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DnsApply {
    Applied,
    Unavailable,
    Skipped,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DnsError {
    Unavailable,
    Failed(&'static str),
}

impl DnsError {
    pub fn is_unavailable(self) -> bool {
        matches!(self, Self::Unavailable)
    }
}

impl fmt::Display for DnsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unavailable => f.write_str("systemd-resolved is unavailable"),
            Self::Failed(message) => f.write_str(message),
        }
    }
}

impl std::error::Error for DnsError {}

pub trait DnsExecutor: Send {
    fn apply(
        &mut self,
        link: &str,
        servers: &[IpAddr],
        domains: &[String],
        full: bool,
    ) -> Result<DnsApply, DnsError>;

    fn revert(&mut self, link: &str) -> Result<(), DnsError>;
}

struct CommandOutput {
    success: bool,
    stdout: String,
}

#[cfg(test)]
impl CommandOutput {
    fn success(stdout: &str) -> Self {
        Self {
            success: true,
            stdout: stdout.into(),
        }
    }

    fn failed() -> Self {
        Self {
            success: false,
            stdout: String::new(),
        }
    }
}

trait DnsCommandRunner: Send {
    fn verify_binary(&self) -> Result<(), DnsError>;
    fn run(&mut self, args: &[String]) -> io::Result<CommandOutput>;
}

pub struct SystemCommandRunner;

impl DnsCommandRunner for SystemCommandRunner {
    fn verify_binary(&self) -> Result<(), DnsError> {
        let metadata = match fs::metadata(RESOLVECTL) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Err(DnsError::Unavailable);
            }
            Err(_) => return Err(DnsError::Failed("cannot inspect resolvectl")),
        };
        if !metadata.is_file() || metadata.uid() != 0 || metadata.permissions().mode() & 0o022 != 0
        {
            return Err(DnsError::Failed("resolvectl binary is not trusted"));
        }
        Ok(())
    }

    fn run(&mut self, args: &[String]) -> io::Result<CommandOutput> {
        let mut command = Command::new(RESOLVECTL);
        command
            .args(args)
            .stdin(Stdio::null())
            .stderr(Stdio::null());
        if args == ["--help"] {
            let output = command.stdout(Stdio::piped()).output()?;
            Ok(CommandOutput {
                success: output.status.success(),
                stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            })
        } else {
            Ok(CommandOutput {
                success: command.stdout(Stdio::null()).status()?.success(),
                stdout: String::new(),
            })
        }
    }
}

pub struct ResolvectlDnsExecutor<R = SystemCommandRunner> {
    runner: R,
}

impl ResolvectlDnsExecutor {
    pub fn new() -> Self {
        Self {
            runner: SystemCommandRunner,
        }
    }
}

impl Default for ResolvectlDnsExecutor {
    fn default() -> Self {
        Self::new()
    }
}

fn available<R: DnsCommandRunner>(runner: &mut R) -> Result<bool, DnsError> {
    runner.verify_binary()?;
    match runner.run(&["status".into()]) {
        Ok(output) => Ok(output.success),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(_) => Err(DnsError::Failed("cannot check systemd-resolved")),
    }
}

fn command<R: DnsCommandRunner>(runner: &mut R, args: Vec<String>) -> Result<(), DnsError> {
    match runner.run(&args) {
        Ok(output) if output.success => Ok(()),
        _ => Err(DnsError::Failed("systemd-resolved DNS command failed")),
    }
}

fn revert_command<R: DnsCommandRunner>(runner: &mut R, link: &str) -> Result<(), DnsError> {
    command(runner, vec!["revert".into(), link.into()])
}

impl<R: DnsCommandRunner> DnsExecutor for ResolvectlDnsExecutor<R> {
    fn apply(
        &mut self,
        link: &str,
        servers: &[IpAddr],
        domains: &[String],
        full: bool,
    ) -> Result<DnsApply, DnsError> {
        validate_link(link)?;
        if servers.len() > MAX_DNS_SERVERS || domains.len() > MAX_DNS_DOMAINS {
            return Err(DnsError::Failed("too many DNS settings"));
        }
        if servers.is_empty() {
            return if domains.is_empty() {
                Ok(DnsApply::Skipped)
            } else {
                Err(DnsError::Failed("DNS domains require a server"))
            };
        }
        if !full && domains.is_empty() {
            return Ok(DnsApply::Skipped);
        }
        match available(&mut self.runner) {
            Ok(true) => {}
            Ok(false) | Err(DnsError::Unavailable) => return Ok(DnsApply::Unavailable),
            Err(error) => return Err(error),
        }
        let help = self
            .runner
            .run(&["--help".into()])
            .map_err(|_| DnsError::Failed("cannot inspect resolvectl commands"))?;
        if !help.success {
            return Err(DnsError::Failed("cannot inspect resolvectl commands"));
        }
        let has_default_route = help
            .stdout
            .lines()
            .any(|line| line.trim_start().starts_with("default-route "));

        let mut dns = vec!["dns".into(), link.into()];
        dns.extend(servers.iter().map(ToString::to_string));
        let mut domain = vec!["domain".into(), link.into()];
        if full {
            domain.push("~.".into());
        } else {
            domain.extend(domains.iter().map(|name| format!("~{name}")));
        }
        let result = command(&mut self.runner, dns)
            .and_then(|()| command(&mut self.runner, domain))
            .and_then(|()| {
                if has_default_route {
                    command(
                        &mut self.runner,
                        vec![
                            "default-route".into(),
                            link.into(),
                            if full { "yes" } else { "no" }.into(),
                        ],
                    )
                } else {
                    Ok(())
                }
            });
        if let Err(error) = result {
            return if revert_command(&mut self.runner, link).is_ok() {
                Err(error)
            } else {
                Err(DnsError::Failed("DNS setup and rollback failed"))
            };
        }
        Ok(DnsApply::Applied)
    }

    fn revert(&mut self, link: &str) -> Result<(), DnsError> {
        validate_link(link)?;
        if !available(&mut self.runner)? {
            return Err(DnsError::Unavailable);
        }
        revert_command(&mut self.runner, link)
    }
}

fn validate_link(link: &str) -> Result<(), DnsError> {
    let suffix = link
        .strip_prefix("wg-")
        .or_else(|| link.strip_prefix("ovpn-"))
        .or_else(|| link.strip_prefix("xray-"));
    if link.len() <= 15
        && suffix.is_some_and(|suffix| {
            !suffix.is_empty()
                && suffix
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
    {
        Ok(())
    } else {
        Err(DnsError::Failed("invalid tunnel link name"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xray_tun_link_is_accepted_for_per_link_dns() {
        assert!(validate_link("xray-123abc").is_ok());
    }
    use std::collections::VecDeque;

    #[derive(Default)]
    struct FakeRunner {
        seen: Vec<Vec<String>>,
        responses: VecDeque<io::Result<CommandOutput>>,
        verify_error: Option<DnsError>,
    }

    impl DnsCommandRunner for FakeRunner {
        fn verify_binary(&self) -> Result<(), DnsError> {
            self.verify_error.map_or(Ok(()), Err)
        }

        fn run(&mut self, args: &[String]) -> io::Result<CommandOutput> {
            self.seen.push(args.to_vec());
            self.responses
                .pop_front()
                .unwrap_or_else(|| Ok(CommandOutput::success("")))
        }
    }

    fn executor(responses: Vec<io::Result<CommandOutput>>) -> ResolvectlDnsExecutor<FakeRunner> {
        ResolvectlDnsExecutor {
            runner: FakeRunner {
                seen: Vec::new(),
                responses: responses.into(),
                verify_error: None,
            },
        }
    }

    fn help() -> io::Result<CommandOutput> {
        Ok(CommandOutput::success("  default-route [LINK [BOOL]]\n"))
    }

    fn ok() -> io::Result<CommandOutput> {
        Ok(CommandOutput::success(""))
    }

    #[test]
    fn split_dns_uses_only_route_only_domains_and_disables_default_route() {
        let mut dns = executor(vec![ok(), help(), ok(), ok(), ok()]);
        let result = dns.apply(
            "wg-owned",
            &["10.8.0.53".parse().unwrap()],
            &["corp.example".into()],
            false,
        );
        assert_eq!(result.unwrap(), DnsApply::Applied);
        assert_eq!(
            dns.runner.seen,
            vec![
                vec!["status"],
                vec!["--help"],
                vec!["dns", "wg-owned", "10.8.0.53"],
                vec!["domain", "wg-owned", "~corp.example"],
                vec!["default-route", "wg-owned", "no"],
            ]
        );
    }

    #[test]
    fn full_dns_uses_route_all_domain_and_enables_default_route() {
        let mut dns = executor(vec![ok(), help(), ok(), ok(), ok()]);
        assert_eq!(
            dns.apply(
                "wg-owned",
                &["10.8.0.53".parse().unwrap()],
                &["corp.example".into()],
                true,
            )
            .unwrap(),
            DnsApply::Applied
        );
        assert_eq!(dns.runner.seen[3], ["domain", "wg-owned", "~."]);
        assert_eq!(dns.runner.seen[4], ["default-route", "wg-owned", "yes"]);
    }

    #[test]
    fn openvpn_link_uses_same_per_link_dns_commands() {
        let mut dns = executor(vec![ok(), help(), ok(), ok(), ok()]);
        assert_eq!(
            dns.apply(
                "ovpn-1234567890",
                &["10.78.0.1".parse().unwrap()],
                &[],
                true
            )
            .unwrap(),
            DnsApply::Applied
        );
        assert_eq!(dns.runner.seen[2], ["dns", "ovpn-1234567890", "10.78.0.1"]);
    }

    #[test]
    fn split_dns_without_domains_does_not_set_global_dns() {
        let mut dns = executor(vec![]);
        assert_eq!(
            dns.apply("wg-owned", &["10.8.0.53".parse().unwrap()], &[], false)
                .unwrap(),
            DnsApply::Skipped
        );
        assert!(dns.runner.seen.is_empty());
    }

    #[test]
    fn unavailable_resolved_is_a_warning_without_mutation() {
        let mut dns = executor(vec![Ok(CommandOutput::failed())]);
        assert_eq!(
            dns.apply("wg-owned", &["10.8.0.53".parse().unwrap()], &[], true)
                .unwrap(),
            DnsApply::Unavailable
        );
        assert_eq!(dns.runner.seen, vec![vec!["status"]]);
    }

    #[test]
    fn missing_resolvectl_is_a_warning_without_running_any_command() {
        let mut dns = executor(vec![]);
        dns.runner.verify_error = Some(DnsError::Unavailable);
        assert_eq!(
            dns.apply("wg-owned", &["10.8.0.53".parse().unwrap()], &[], true)
                .unwrap(),
            DnsApply::Unavailable
        );
        assert!(dns.runner.seen.is_empty());
        assert!(dns.revert("wg-owned").unwrap_err().is_unavailable());
    }

    #[test]
    fn revert_targets_only_the_verified_owned_link() {
        let mut dns = executor(vec![ok(), ok()]);
        dns.revert("wg-owned").unwrap();
        assert_eq!(
            dns.runner.seen,
            vec![vec!["status"], vec!["revert", "wg-owned"]]
        );
    }

    #[test]
    fn missing_default_route_support_is_skipped() {
        let mut dns = executor(vec![
            ok(),
            Ok(CommandOutput::success("  dns [LINK [SERVER...]]\n")),
            ok(),
            ok(),
        ]);
        assert_eq!(
            dns.apply(
                "wg-owned",
                &["10.8.0.53".parse().unwrap()],
                &["corp.example".into()],
                false,
            )
            .unwrap(),
            DnsApply::Applied
        );
        assert_eq!(dns.runner.seen.len(), 4);
    }

    #[test]
    fn failed_domain_command_reverts_only_the_given_link_and_redacts_error() {
        let mut dns = executor(vec![ok(), help(), ok(), Ok(CommandOutput::failed()), ok()]);
        let error = dns
            .apply(
                "wg-owned",
                &["10.8.0.53".parse().unwrap()],
                &["secret.example".into()],
                false,
            )
            .unwrap_err();
        assert_eq!(dns.runner.seen[4], ["revert", "wg-owned"]);
        assert!(!error.to_string().contains("secret.example"));
        assert!(!error.to_string().contains("10.8.0.53"));
    }

    #[test]
    fn failed_default_route_and_failed_rollback_are_reported_without_settings() {
        let mut dns = executor(vec![
            ok(),
            help(),
            ok(),
            ok(),
            Ok(CommandOutput::failed()),
            Ok(CommandOutput::failed()),
        ]);
        let error = dns
            .apply(
                "wg-owned",
                &["10.8.0.53".parse().unwrap()],
                &["secret.example".into()],
                false,
            )
            .unwrap_err();
        assert_eq!(dns.runner.seen[5], ["revert", "wg-owned"]);
        assert_eq!(error, DnsError::Failed("DNS setup and rollback failed"));
    }

    #[test]
    fn rejects_non_tunnel_link_without_running_resolvectl() {
        let mut dns = executor(vec![]);
        assert!(dns
            .apply("eth0", &["10.8.0.53".parse().unwrap()], &[], true)
            .is_err());
        assert!(dns.revert("eth0").is_err());
        assert!(dns.revert("ovpn-").is_err());
        assert!(dns.revert("wg-").is_err());
        assert!(dns.runner.seen.is_empty());
    }
}
