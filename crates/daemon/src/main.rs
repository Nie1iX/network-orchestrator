use std::process::ExitCode;

fn main() -> ExitCode {
    eprintln!("network-orchestrator-daemon runs on Linux only");
    ExitCode::FAILURE
}
