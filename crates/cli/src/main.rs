//! `netorch`: one command for VPN profiles, tunnels and routing.
//! Plan: docs/plans/2026-10-15-19-netorch-cli.md.

#[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
fn main() {
    eprintln!("netorch currently runs on macOS (Apple Silicon) only");
    std::process::exit(1);
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
mod args;
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
mod connect;
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
mod ctx;
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
mod inproc;
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
mod library;
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
mod lock;
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
mod prompt;
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
mod render;
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
mod route;
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
mod runstate;
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
mod service;
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
mod system;
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
mod target;

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn main() -> std::process::ExitCode {
    use args::{Cli, Command};
    use clap::{CommandFactory, Parser};
    let cli = Cli::parse();
    if let Command::Completions { shell } = &cli.command {
        clap_complete::generate(
            *shell,
            &mut Cli::command(),
            "netorch",
            &mut std::io::stdout(),
        );
        return std::process::ExitCode::SUCCESS;
    }
    let result = cli
        .data_dir
        .clone()
        .map(Ok)
        .unwrap_or_else(ctx::default_root)
        .and_then(|root| ctx::Ctx::new(root, cli.json))
        .and_then(|ctx| run(&ctx, cli.command));
    match result {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("netorch: {error}");
            std::process::ExitCode::FAILURE
        }
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn run(ctx: &ctx::Ctx, command: args::Command) -> Result<(), String> {
    use args::Command;
    match command {
        Command::Ls => library::ls(ctx),
        Command::Status { target } => library::status(ctx, target.as_deref()),
        Command::Add(args) => library::add(ctx, args),
        Command::Rm { target } => library::rm(ctx, &target),
        Command::Rename { target, name } => library::rename(ctx, &target, &name),
        Command::Up(args) => connect::up(ctx, args),
        Command::Down { target, all } => connect::down(ctx, target.as_deref(), all),
        Command::Logs { target } => library::logs(ctx, &target),
        Command::Test(args) => library::test(ctx, args),
        Command::Route(command) => route::run(ctx, command),
        Command::Doctor => system::doctor(ctx),
        Command::Backend(command) => system::backend(ctx, command),
        Command::Service(command) => system::service(ctx, command),
        Command::Completions { .. } => Ok(()),
    }
}
