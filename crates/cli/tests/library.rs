//! The real `netorch` binary against an isolated data directory. Nothing here
//! touches the network, the helper or the system proxy.
#![cfg(all(target_os = "macos", target_arch = "aarch64"))]
use serde_json::Value;
use std::process::{Command, Output};

const LINK: &str = "vless://11111111-2222-3333-4444-555555555555@example.com:443?type=tcp&security=tls&sni=example.com#Test%20One";

struct Sandbox {
    dir: tempfile::TempDir,
}

impl Sandbox {
    fn new() -> Self {
        Self {
            dir: tempfile::tempdir().unwrap(),
        }
    }

    fn run(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_netorch"))
            .args(args)
            .env("NETORCH_MACOS_DATA_DIR", self.dir.path().join("data"))
            // A socket that cannot exist keeps the test off the real helper.
            .env("NETORCH_HELPER_SOCKET", self.dir.path().join("none.sock"))
            .output()
            .unwrap()
    }

    fn ok(&self, args: &[&str]) -> String {
        let output = self.run(args);
        assert!(
            output.status.success(),
            "{args:?} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout).unwrap()
    }

    fn json(&self, args: &[&str]) -> Value {
        let mut all = vec!["--json"];
        all.extend_from_slice(args);
        serde_json::from_str(&self.ok(&all)).unwrap()
    }
}

#[test]
fn a_link_becomes_a_profile_that_can_be_renamed_and_removed() {
    let sandbox = Sandbox::new();
    assert!(sandbox.json(&["ls"]).as_array().unwrap().is_empty());
    sandbox.ok(&["add", LINK]);
    let rows = sandbox.json(&["ls"]);
    assert_eq!(rows[0]["name"], "Test One");
    assert_eq!(rows[0]["kind"], "xray-socks");
    let id = rows[0]["id"].as_str().unwrap().to_string();
    assert!(id.starts_with("test-one-"));
    sandbox.ok(&["rename", "test one", "Work"]);
    assert_eq!(sandbox.json(&["ls"])[0]["name"], "Work");
    let status = sandbox.json(&["status", "work"]);
    assert_eq!(status[0]["state"], "stopped");
    sandbox.ok(&["rm", &id]);
    assert!(sandbox.json(&["ls"]).as_array().unwrap().is_empty());
}

#[test]
fn listings_never_print_the_link_the_uuid_or_a_path() {
    let sandbox = Sandbox::new();
    sandbox.ok(&["add", LINK]);
    for args in [&["ls"][..], &["status"], &["doctor"]] {
        let output = sandbox.run(args);
        let text = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(!text.contains("11111111-2222"), "{args:?} leaked the UUID");
        assert!(!text.contains("example.com"), "{args:?} leaked the server");
        assert!(!text.contains("config.json"), "{args:?} leaked a path");
    }
}

#[test]
fn routing_rules_round_trip_and_decide_a_host() {
    let sandbox = Sandbox::new();
    sandbox.ok(&["add", LINK, "--name", "R"]);
    sandbox.ok(&[
        "route",
        "set",
        "r",
        "--block",
        "domain:ads.example",
        "--direct",
        "domain:corp.example",
    ]);
    let options = sandbox.json(&["route", "show", "r"]);
    assert_eq!(options["block"], "domain:ads.example");
    assert_eq!(options["direct"], "domain:corp.example");
    let verdict = sandbox.json(&["route", "check", "ads.example", "--profile", "r"]);
    assert_eq!(verdict["outbound"], "block");
    let verdict = sandbox.json(&["route", "check", "www.corp.example", "--profile", "r"]);
    assert_eq!(verdict["outbound"], "direct");
}

#[test]
fn mistakes_fail_with_a_message_and_a_nonzero_exit() {
    let sandbox = Sandbox::new();
    let output = sandbox.run(&["add", "not-a-link"]);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("not a vless://"));
    let output = sandbox.run(&["down", "nothing"]);
    assert!(!output.status.success());
    let output = sandbox.run(&["up", "nothing"]);
    assert!(String::from_utf8_lossy(&output.stderr).contains("No saved profile"));
}

#[test]
fn doctor_reports_an_absent_helper_as_a_warning_not_a_failure() {
    let sandbox = Sandbox::new();
    let report = sandbox.json(&["doctor"]);
    let helper = report
        .as_array()
        .unwrap()
        .iter()
        .find(|check| check["name"] == "helper")
        .unwrap();
    assert_eq!(helper["level"], "warn");
}

#[test]
fn completions_are_generated_for_zsh() {
    let sandbox = Sandbox::new();
    assert!(sandbox.ok(&["completions", "zsh"]).contains("netorch"));
}
