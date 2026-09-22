use linux_helper::{parse_args, run};
use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match parse_args(&args) {
        Ok(cmd) => match run(&cmd) {
            Ok(()) => ExitCode::SUCCESS,
            Err(err) => {
                eprintln!("linux-helper: {err}");
                ExitCode::FAILURE
            }
        },
        Err(err) => {
            eprintln!("linux-helper: {err}");
            ExitCode::from(2)
        }
    }
}
