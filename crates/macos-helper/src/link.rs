//! Turning a network interface on or off for the app's Network page. The
//! request is from an unprivileged client, so the helper refuses what would
//! break its own work: loopback, and the device of a tunnel it runs.

use crate::sysexec::{Runner, IFCONFIG};
use crate::xray::Error;

/// macOS interface names: `en0`, `utun10`, `bridge100`, `awdl0`. A letter
/// first, then letters and digits; the kernel limit is 15 characters.
pub fn valid_name(name: &str) -> bool {
    let mut chars = name.chars();
    name.len() <= 15
        && chars.next().is_some_and(|c| c.is_ascii_alphabetic())
        && chars.all(|c| c.is_ascii_alphanumeric())
}

/// `ifconfig <name> up|down`. `own` are the devices of tunnels this helper
/// runs; those are stopped by disconnecting, not by switching the device off.
pub fn set_state(runner: &dyn Runner, name: &str, up: bool, own: &[String]) -> Result<(), Error> {
    if !valid_name(name) {
        return Err(Error::Invalid("invalid interface name".into()));
    }
    if !up && name == "lo0" {
        return Err(Error::Invalid(
            "the loopback interface cannot be turned off".into(),
        ));
    }
    if !up && own.iter().any(|device| device == name) {
        return Err(Error::Conflict(
            "this interface belongs to a connection the app runs; disconnect it instead".into(),
        ));
    }
    let existing = runner
        .run(IFCONFIG, &["-l".to_string()])
        .map_err(|_| Error::Unavailable("The interfaces could not be listed".into()))?;
    if !existing.split_whitespace().any(|known| known == name) {
        return Err(Error::NotFound(
            "There is no interface with that name".into(),
        ));
    }
    runner
        .run(
            IFCONFIG,
            &[name.to_string(), if up { "up" } else { "down" }.to_string()],
        )
        .map(|_| ())
        .map_err(|_| {
            Error::Unavailable(format!(
                "The interface could not be turned {}",
                if up { "on" } else { "off" }
            ))
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sysexec::fake::FakeRunner;

    fn runner() -> FakeRunner {
        let runner = FakeRunner::default();
        runner.reply(
            "ifconfig -l",
            "lo0 gif0 stf0 en0 en7 awdl0 utun0 utun5 bridge100\n",
        );
        runner
    }
    fn names(items: &[&str]) -> Vec<String> {
        items.iter().map(ToString::to_string).collect()
    }

    #[test]
    fn real_macos_interface_names_are_accepted_and_junk_is_not() {
        for good in [
            "en0",
            "utun10",
            "bridge100",
            "awdl0",
            "llw0",
            "ap1",
            "p2p0",
            "vmenet0",
        ] {
            assert!(valid_name(good), "{good}");
        }
        for bad in [
            "",
            "0en",
            "-en0",
            "en0 up",
            "en0;reboot",
            "en0\n",
            "a/b",
            "en0.1x2y3z4w5v6u7",
            "ünï0",
            "..",
            "en0&",
        ] {
            assert!(!valid_name(bad), "{bad:?}");
        }
    }

    #[test]
    fn turning_an_interface_off_and_on_runs_one_ifconfig_each() {
        let r = runner();
        set_state(&r, "en7", false, &[]).unwrap();
        set_state(&r, "en7", true, &[]).unwrap();
        assert_eq!(
            r.calls(),
            [
                "ifconfig -l",
                "ifconfig en7 down",
                "ifconfig -l",
                "ifconfig en7 up"
            ]
        );
    }

    #[test]
    fn loopback_can_never_be_turned_off_but_turning_it_on_is_harmless() {
        let r = runner();
        assert!(matches!(
            set_state(&r, "lo0", false, &[]),
            Err(Error::Invalid(_))
        ));
        assert!(r.calls().is_empty(), "nothing is run for a refused request");
        set_state(&r, "lo0", true, &[]).unwrap();
    }

    #[test]
    fn a_tunnel_this_helper_runs_must_be_disconnected_not_switched_off() {
        let r = runner();
        let own = names(&["utun5"]);
        let error = set_state(&r, "utun5", false, &own).unwrap_err();
        assert!(matches!(error, Error::Conflict(_)));
        assert!(error.to_string().contains("disconnect"));
        assert!(r.calls().is_empty());
        // Turning it on is a no-op for a running tunnel and stays allowed.
        set_state(&r, "utun5", true, &own).unwrap();
        // Another utun is fine.
        set_state(&r, "utun0", false, &own).unwrap();
    }

    #[test]
    fn an_unknown_interface_is_not_found_and_nothing_is_changed() {
        let r = runner();
        assert!(matches!(
            set_state(&r, "en99", false, &[]),
            Err(Error::NotFound(_))
        ));
        assert_eq!(r.calls(), ["ifconfig -l"]);
    }

    #[test]
    fn an_invalid_name_never_reaches_ifconfig() {
        let r = runner();
        assert!(matches!(
            set_state(&r, "en0; reboot", false, &[]),
            Err(Error::Invalid(_))
        ));
        assert!(matches!(
            set_state(&r, "-v", true, &[]),
            Err(Error::Invalid(_))
        ));
        assert!(r.calls().is_empty());
    }

    #[test]
    fn a_failing_ifconfig_is_reported_without_claiming_success() {
        let r = runner();
        r.fail("ifconfig en7 down");
        let error = set_state(&r, "en7", false, &[]).unwrap_err();
        assert!(matches!(error, Error::Unavailable(_)), "{error}");
        assert!(
            error.to_string().contains("could not be turned off"),
            "{error}"
        );
    }
}
