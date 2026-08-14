//! The colour gate and the welcome screen, proven against the REAL binary.
//!
//! `colour_enabled()` caches its answer in a `OnceLock` for the life of the
//! process, so a unit test cannot set `NO_COLOR` and observe the effect:
//! whichever test touched colour first has already fixed the answer for the
//! whole suite, and the result depends on test order. The question is only
//! answerable one process at a time — the same reason `probe_inertness.rs`
//! runs the binary rather than the function.
//!
//! `Command::output()` hands the child a pipe, which makes every run here the
//! `termaxa ... > out.txt` case the gate exists for.

use std::process::Command;

/// Escape sequences start with ESC `[`; their presence is the whole question.
const ESC: &str = "\x1b[";

/// Bare `termaxa` (the welcome screen) with an explicit colour environment.
fn welcome_with(env: &[(&str, &str)]) -> String {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_termaxa"));
    // Start from a known state: whatever the developer or CI has set for
    // these must not decide what this test observes.
    cmd.env_remove("NO_COLOR")
        .env_remove("TERMAXA_NO_COLOR")
        .env_remove("CLICOLOR_FORCE");
    for (key, value) in env {
        cmd.env(key, value);
    }

    let out = cmd.output().expect("the binary must be runnable");
    assert!(
        out.status.success(),
        "bare `termaxa` should exit 0, got {:?}",
        out.status
    );
    String::from_utf8(out.stdout).expect("output must be UTF-8")
}

#[test]
fn the_welcome_screen_teaches_the_first_command() {
    let out = welcome_with(&[]);
    assert!(
        out.contains(env!("CARGO_PKG_VERSION")),
        "the welcome screen names the version: {out:?}"
    );
    assert!(out.contains("Predict what will happen."), "{out:?}");
    assert!(
        out.contains("termaxa check \"rm -rf /\""),
        "the one runnable command is the point of this screen: {out:?}"
    );
}

#[test]
fn redirected_output_carries_no_escape_sequences() {
    let out = welcome_with(&[]);
    assert!(
        !out.contains(ESC),
        "a pipe is not a terminal; escapes here end up in someone's log file: {out:?}"
    );
}

#[test]
fn clicolor_force_asks_for_colour_and_gets_it() {
    // CI that wants colour says so explicitly, and outranks TTY detection.
    let out = welcome_with(&[("CLICOLOR_FORCE", "1")]);
    assert!(out.contains(ESC), "expected escapes, got {out:?}");
}

#[test]
fn clicolor_force_set_to_zero_is_not_a_request() {
    let out = welcome_with(&[("CLICOLOR_FORCE", "0")]);
    assert!(!out.contains(ESC), "`0` means no, got {out:?}");
}

/// The other half of the contract: a real terminal DOES get colour.
///
/// `CLICOLOR_FORCE` cannot stand in for this — it returns before `is_tty` is
/// ever consulted, so the detection itself would go untested and a gate that
/// answered "never a terminal" would look perfectly healthy. Linux-only:
/// `ptsname_r` is a GNU extension, and one platform proving the branch is
/// enough.
#[cfg(target_os = "linux")]
#[test]
fn a_real_terminal_gets_colour() {
    use std::io::Read;
    use std::os::fd::{FromRawFd, OwnedFd};
    use std::process::Stdio;

    // SAFETY: the POSIX pty handshake, each step checked before the next is
    // made. Both descriptors are handed to OwnedFd, which closes them.
    let (master, slave) = unsafe {
        let master = libc::posix_openpt(libc::O_RDWR | libc::O_NOCTTY);
        assert!(master >= 0, "posix_openpt failed");
        assert_eq!(libc::grantpt(master), 0, "grantpt failed");
        assert_eq!(libc::unlockpt(master), 0, "unlockpt failed");

        let mut name = [0 as libc::c_char; 256];
        assert_eq!(
            libc::ptsname_r(master, name.as_mut_ptr(), name.len()),
            0,
            "ptsname_r failed"
        );
        let slave = libc::open(name.as_ptr(), libc::O_RDWR | libc::O_NOCTTY);
        assert!(slave >= 0, "opening the pty slave failed");
        (OwnedFd::from_raw_fd(master), OwnedFd::from_raw_fd(slave))
    };

    let mut child = Command::new(env!("CARGO_BIN_EXE_termaxa"))
        .env_remove("NO_COLOR")
        .env_remove("TERMAXA_NO_COLOR")
        .env_remove("CLICOLOR_FORCE")
        // Moving the slave end into Stdio also drops the parent's own handle
        // on it, which is what lets the read below finish.
        .stdout(Stdio::from(slave))
        .spawn()
        .expect("the binary must be runnable");
    assert!(
        child.wait().expect("the child must be waitable").success(),
        "bare `termaxa` should exit 0"
    );

    let mut out = String::new();
    // A pty master reports EIO rather than EOF once the slave end is gone;
    // whatever was read before that is still in the buffer.
    let _ = std::fs::File::from(master).read_to_string(&mut out);
    assert!(
        out.contains(ESC),
        "a terminal should get colour, got {out:?}"
    );
}

#[test]
fn either_no_color_variable_beats_clicolor_force() {
    // https://no-color.org: the user's opt-out wins over a tool's opt-in.
    for var in ["NO_COLOR", "TERMAXA_NO_COLOR"] {
        let out = welcome_with(&[(var, "1"), ("CLICOLOR_FORCE", "1")]);
        assert!(
            !out.contains(ESC),
            "{var} must win over CLICOLOR_FORCE, got {out:?}"
        );
    }
}
