//! Credentials for OpenVPN: piped in on request, otherwise asked on the
//! terminal with echo off. Never taken from arguments, where `ps` shows them.
use net_manager_core::daemon_protocol::{OpenVpnCredentials, OpenVpnUserPass};
use std::io::{BufRead, IsTerminal, Write};

pub fn read_line(input: &mut impl BufRead) -> Result<String, String> {
    let mut line = String::new();
    input
        .read_line(&mut line)
        .map_err(|_| "Could not read from stdin".to_string())?;
    Ok(line.trim_end_matches(['\n', '\r']).to_string())
}

fn secret_from_terminal(prompt: &str) -> Result<String, String> {
    let mut stderr = std::io::stderr();
    let _ = write!(stderr, "{prompt}");
    let _ = stderr.flush();
    let fd = libc::STDIN_FILENO;
    // SAFETY: termios is plain data; tcgetattr fills it for a valid fd.
    let mut original: libc::termios = unsafe { std::mem::zeroed() };
    let have = unsafe { libc::tcgetattr(fd, &mut original) } == 0;
    if have {
        let mut quiet = original;
        quiet.c_lflag &= !libc::ECHO;
        unsafe { libc::tcsetattr(fd, libc::TCSANOW, &quiet) };
    }
    let result = read_line(&mut std::io::stdin().lock());
    if have {
        unsafe { libc::tcsetattr(fd, libc::TCSANOW, &original) };
        let _ = writeln!(stderr);
    }
    result
}

/// What the profile asked for, from stdin flags or the terminal.
pub fn collect(
    user_pass: bool,
    key_passphrase: bool,
    auth_stdin: bool,
    passphrase_stdin: bool,
) -> Result<Option<OpenVpnCredentials>, String> {
    if !user_pass && !key_passphrase {
        return Ok(None);
    }
    let interactive = std::io::stdin().is_terminal();
    let mut stdin = std::io::stdin().lock();
    let mut auth_user_pass = None;
    let mut private_key_passphrase = None;
    if user_pass {
        let (username, password) = if auth_stdin {
            (read_line(&mut stdin)?, read_line(&mut stdin)?)
        } else if interactive {
            drop(stdin);
            let mut stderr = std::io::stderr();
            let _ = write!(stderr, "OpenVPN username: ");
            let _ = stderr.flush();
            let username = read_line(&mut std::io::stdin().lock())?;
            let password = secret_from_terminal("OpenVPN password: ")?;
            stdin = std::io::stdin().lock();
            (username, password)
        } else {
            return Err("This connection needs a username and password: use --auth-stdin".into());
        };
        auth_user_pass = Some(OpenVpnUserPass { username, password });
    }
    if key_passphrase {
        let passphrase = if passphrase_stdin {
            read_line(&mut stdin)?
        } else if interactive {
            drop(stdin);
            secret_from_terminal("Private key passphrase: ")?
        } else {
            return Err("This connection needs a key passphrase: use --passphrase-stdin".into());
        };
        private_key_passphrase = Some(passphrase);
    }
    Ok(Some(OpenVpnCredentials {
        auth_user_pass,
        private_key_passphrase,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lines_lose_only_their_terminator() {
        let mut input = std::io::Cursor::new(b"user\r\n pass with spaces \n".to_vec());
        assert_eq!(read_line(&mut input).unwrap(), "user");
        assert_eq!(read_line(&mut input).unwrap(), " pass with spaces ");
        assert_eq!(read_line(&mut input).unwrap(), "");
    }

    #[test]
    fn nothing_is_asked_when_nothing_is_needed() {
        assert!(collect(false, false, false, false).unwrap().is_none());
    }
}
