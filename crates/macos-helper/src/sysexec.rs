//! Fixed-path system tools behind an injectable runner, so route and DNS
//! logic is testable without touching the machine.

use std::io;
use std::process::{Command, Stdio};

pub const ROUTE: &str = "/sbin/route";
pub const NETWORKSETUP: &str = "/usr/sbin/networksetup";
pub const IPCONFIG: &str = "/usr/sbin/ipconfig";

pub trait Runner: Send + Sync {
    /// Run `program` with `args`; stdout on success, `Err` on a non-zero exit.
    fn run(&self, program: &str, args: &[String]) -> io::Result<String>;
}

pub struct SystemRunner;

impl Runner for SystemRunner {
    fn run(&self, program: &str, args: &[String]) -> io::Result<String> {
        let output = Command::new(program)
            .args(args)
            .stdin(Stdio::null())
            .output()?;
        if output.status.success() {
            Ok(String::from_utf8_lossy(&output.stdout).into_owned())
        } else {
            // The tool's own message says why (e.g. "File exists"); it names
            // only routes and interfaces, never user data.
            let stderr = String::from_utf8_lossy(&output.stderr);
            let detail: String = stderr
                .trim()
                .lines()
                .last()
                .unwrap_or("")
                .chars()
                .take(160)
                .collect();
            Err(io::Error::other(format!(
                "{} exited with {}{}{}",
                program.rsplit('/').next().unwrap_or(program),
                output.status,
                if detail.is_empty() { "" } else { ": " },
                detail
            )))
        }
    }
}

#[cfg(test)]
pub mod fake {
    use super::*;
    use std::collections::VecDeque;
    use std::sync::Mutex;

    /// Records every call; answers from a script keyed by command prefix.
    #[derive(Default)]
    pub struct FakeRunner {
        pub calls: Mutex<Vec<String>>,
        replies: Mutex<Vec<(String, String)>>,
        fail_prefixes: Mutex<VecDeque<String>>,
    }

    impl FakeRunner {
        pub fn reply(&self, prefix: &str, output: &str) {
            self.replies
                .lock()
                .unwrap()
                .push((prefix.into(), output.into()));
        }
        pub fn fail(&self, prefix: &str) {
            self.fail_prefixes.lock().unwrap().push_back(prefix.into());
        }
        pub fn calls(&self) -> Vec<String> {
            self.calls.lock().unwrap().clone()
        }
    }

    impl Runner for FakeRunner {
        fn run(&self, program: &str, args: &[String]) -> io::Result<String> {
            let line = format!("{} {}", program.rsplit('/').next().unwrap(), args.join(" "));
            self.calls.lock().unwrap().push(line.clone());
            if self
                .fail_prefixes
                .lock()
                .unwrap()
                .iter()
                .any(|prefix| line.starts_with(prefix.as_str()))
            {
                return Err(io::Error::other("fake failure"));
            }
            for (prefix, reply) in self.replies.lock().unwrap().iter() {
                if line.starts_with(prefix.as_str()) {
                    return Ok(reply.clone());
                }
            }
            Ok(String::new())
        }
    }
}
