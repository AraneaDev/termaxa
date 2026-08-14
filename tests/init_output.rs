//! What `termaxa init` tells you about the machine it just ran on.
//!
//! The detection block and the manual snippet are print-only: `run` returns
//! Ok(()) whether it found four harnesses or none. As in the doctor tests,
//! PATH is reduced to a shell and `which`, so "is Claude installed?" is a
//! fact each test sets rather than a property of the developer's laptop.

#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::process::Command;

fn scratch(tag: &str) -> PathBuf {
    let base = std::env::temp_dir().join(format!("termaxa-init-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&base);
    std::fs::create_dir_all(base.join("home")).expect("scratch root must be creatable");
    base
}

/// A PATH with a shell and `which` on it, and no agent CLI whatsoever.
fn controlled_path(root: &Path) -> PathBuf {
    let bin = root.join("bin");
    std::fs::create_dir_all(&bin).expect("bin dir must be creatable");
    for tool in ["sh", "which"] {
        let real = ["/bin", "/usr/bin"]
            .iter()
            .map(|d| Path::new(d).join(tool))
            .find(|p| p.exists())
            .unwrap_or_else(|| panic!("{tool} must exist somewhere standard"));
        std::os::unix::fs::symlink(&real, bin.join(tool)).expect("symlink must be creatable");
    }
    bin
}

fn init_in(home: &Path, dir: &Path, bin: &Path) -> String {
    let out = Command::new(env!("CARGO_BIN_EXE_termaxa"))
        .arg("init")
        .current_dir(dir)
        .env("TERMAXA_HOME", home)
        .env("NO_COLOR", "1")
        .env("PATH", bin)
        .output()
        .expect("the binary must be runnable");
    assert!(out.status.success(), "init should succeed: {:?}", out.status);
    String::from_utf8_lossy(&out.stdout).into_owned()
}

#[test]
fn a_harness_is_detected_by_its_directory_alone() {
    let tmp = scratch("detect");
    let bin = controlled_path(&tmp);
    let proj = tmp.join("proj");
    std::fs::create_dir_all(proj.join(".claude")).expect("agent dir must be creatable");

    let out = init_in(&tmp.join("home"), &proj, &bin);
    // The detection line specifically: "To wire Termaxa into Claude Code"
    // appears further down as advice whether or not anything was found.
    assert!(
        out.contains("✓ Claude Code"),
        "the directory is evidence even with no CLI on PATH: {out:?}"
    );
    assert!(
        !out.contains("none found"),
        "something was found, so it must not report otherwise: {out:?}"
    );
}

#[test]
fn an_empty_directory_is_told_it_has_no_harness() {
    let tmp = scratch("bare");
    let bin = controlled_path(&tmp);
    let proj = tmp.join("proj");
    std::fs::create_dir_all(&proj).expect("dir must be creatable");

    let out = init_in(&tmp.join("home"), &proj, &bin);
    assert!(
        out.contains("none found"),
        "an empty list needs saying, or the section just stops: {out:?}"
    );
    assert!(
        !out.contains("✓ Claude Code"),
        "nothing is installed here, so nothing may be ticked: {out:?}"
    );
}

#[test]
fn the_manual_snippet_is_printed_for_people_wiring_by_hand() {
    // The snippet is the fallback for anyone not using one of the --flags,
    // so it going missing would be silent.
    let tmp = scratch("snippet");
    let bin = controlled_path(&tmp);
    let proj = tmp.join("proj");
    std::fs::create_dir_all(&proj).expect("dir must be creatable");

    let out = init_in(&tmp.join("home"), &proj, &bin);
    assert!(
        out.contains(".claude/settings.json snippet:"),
        "{out:?}"
    );
    assert!(
        out.contains("\"command\": \"termaxa hook\""),
        "the snippet has to carry the command it is telling you to paste: {out:?}"
    );
}
