//! Authorization through polkit. Over SSH there is no graphical agent to ask
//! for the administrator password, so the CLI starts a terminal one when it
//! can, and otherwise says how to get past the prompt.
use net_manager_engine::linux_engine::is_polkit_denied;
use std::io::IsTerminal;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

/// How long the agent gets to register with polkit before the retry.
const AGENT_START: Duration = Duration::from_millis(500);

/// What to do about a refused authorization.
#[derive(Debug, PartialEq, Eq)]
pub enum Next {
    /// Start a terminal agent for this session and ask again.
    StartAgent,
    /// Not possible here: explain the options.
    Hint,
}

/// `None` when the error is not about authorization.
pub fn decide(error: &str, terminal: bool, root: bool, agent_found: bool) -> Option<Next> {
    if !is_polkit_denied(error) {
        return None;
    }
    Some(if terminal && !root && agent_found {
        Next::StartAgent
    } else {
        Next::Hint
    })
}

pub fn hint() -> &'static str {
    "polkit has no agent in this session to ask for the administrator password.\n\
     - Run this command in an interactive terminal: netorch then starts a text agent and asks.\n\
     - Or run it with sudo (root is not asked): sudo netorch ...\n\
     - Or let an administrator allow it without a prompt with a polkit rule for \
     com.netmanager.app.connect-profile-admin and com.netmanager.app.system-network."
}

fn find_in_path(name: &str) -> Option<PathBuf> {
    std::env::var_os("PATH")?
        .to_str()?
        .split(':')
        .map(|dir| PathBuf::from(dir).join(name))
        .find(|path| path.is_file())
}

/// A running `pkttyagent` for this process, stopped when dropped.
struct Agent(Child);

impl Agent {
    fn start(program: &PathBuf) -> Option<Self> {
        let child = Command::new(program)
            .args(["--process", &std::process::id().to_string(), "--fallback"])
            .stdin(Stdio::inherit())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .ok()?;
        std::thread::sleep(AGENT_START);
        Some(Self(child))
    }
}

impl Drop for Agent {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Runs `action`; if polkit refuses for lack of an agent, starts a terminal one
/// (when there is a terminal) and tries once more, otherwise adds the hint.
pub fn run<T>(root: bool, action: impl Fn() -> Result<T, String>) -> Result<T, String> {
    let error = match action() {
        Ok(value) => return Ok(value),
        Err(error) => error,
    };
    let terminal = std::io::stdin().is_terminal() && std::io::stderr().is_terminal();
    let agent_path = find_in_path("pkttyagent");
    match decide(&error, terminal, root, agent_path.is_some()) {
        None => Err(error),
        Some(Next::Hint) => Err(format!("{error}\n{}", hint())),
        Some(Next::StartAgent) => {
            eprintln!(
                "No polkit agent in this session; asking for your administrator password here."
            );
            let Some(_agent) = agent_path.as_ref().and_then(Agent::start) else {
                return Err(format!("{error}\n{}", hint()));
            };
            action()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use net_manager_engine::linux_engine::POLKIT_DENIED;

    #[test]
    fn only_a_polkit_refusal_is_handled() {
        assert_eq!(decide("daemon protocol error", true, false, true), None);
        assert_eq!(
            decide(
                "The polkit authorization dialog was dismissed.",
                true,
                false,
                true
            ),
            None
        );
    }

    #[test]
    fn a_terminal_with_an_agent_program_starts_one_else_hints() {
        assert_eq!(
            decide(POLKIT_DENIED, true, false, true),
            Some(Next::StartAgent)
        );
        assert_eq!(decide(POLKIT_DENIED, false, false, true), Some(Next::Hint));
        assert_eq!(decide(POLKIT_DENIED, true, false, false), Some(Next::Hint));
        assert_eq!(decide(POLKIT_DENIED, true, true, true), Some(Next::Hint));
    }

    #[test]
    fn without_a_terminal_the_error_gains_the_hint_and_is_not_retried() {
        let calls = std::cell::Cell::new(0);
        let error = run::<()>(false, || {
            calls.set(calls.get() + 1);
            Err(format!("{POLKIT_DENIED} (after rollback)"))
        })
        .unwrap_err();
        assert_eq!(calls.get(), 1);
        assert!(error.contains("sudo netorch") && error.contains("interactive terminal"));
    }

    #[test]
    fn other_errors_and_successes_pass_through_untouched() {
        assert_eq!(run(false, || Ok(7)), Ok(7));
        assert_eq!(
            run::<()>(false, || Err("boom".into())),
            Err("boom".to_string())
        );
    }
}
