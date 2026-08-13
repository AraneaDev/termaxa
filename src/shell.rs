/// Shell-aware command splitting.
///
/// Field report, v0.6.1: a live Claude Code session ran
///   `git status && echo "---" && git branch -vv && ...`
/// and the whole line rode through as `allow` because the `git status*`
/// wildcard matched the STRING by prefix — while the shell would execute
/// five separate commands. Wildcards see one string; shells see many
/// commands. This module closes that gap: split on shell operators, judge
/// every segment, let the most dangerous one govern.
///
/// Scope (deliberate):
///   - Splits on `&&`, `||`, `;`, `|`, `&`, and newlines, outside quotes.
///   - A single `&` IS a separator. Until v0.14.1 it was not — the reasoning
///     was that `2>&1` is more common than backgrounding, which is true but
///     answered the wrong question: an allow rule only has to be wrong once.
///     Redirection forms are excluded by shape instead (see
///     `is_redirection_amp`), which costs nothing and closes the bypass.
///   - `$(...)` and backticks cannot be statically analyzed — their PRESENCE
///     is reported so the context engine can escalate, rather than
///     pretending the contents were checked.
pub fn split_segments(s: &str) -> Vec<String> {
    let mut segments = Vec::new();
    let mut cur = String::new();
    let chars: Vec<char> = s.chars().collect();
    let mut i = 0;
    let (mut in_single, mut in_double) = (false, false);

    while i < chars.len() {
        let c = chars[i];
        match c {
            '\'' if !in_double => {
                in_single = !in_single;
                cur.push(c);
            }
            '"' if !in_single => {
                in_double = !in_double;
                cur.push(c);
            }
            '\\' if in_double && i + 1 < chars.len() => {
                cur.push(c);
                cur.push(chars[i + 1]);
                i += 1;
            }
            _ if in_single || in_double => cur.push(c),
            '&' if i + 1 < chars.len() && chars[i + 1] == '&' => {
                flush(&mut segments, &mut cur);
                i += 1; // consume second &
            }
            // A lone `&` IS a separator — it backgrounds the segment to its
            // left and starts a new command to its right. Treating it as
            // ordinary text reopened the v0.6.1 bypass on one character:
            // `git status & rm -rf /` stayed a single segment and matched the
            // `git status*` allow rule. The redirection forms it also appears
            // in are `2>&1` / `>&2` / `<&-` (preceded by `>` or `<`) and
            // `&>file` / `&>>file` (followed by `>`); those are not separators.
            '&' if !is_redirection_amp(&chars, i) => flush(&mut segments, &mut cur),
            '|' => {
                flush(&mut segments, &mut cur);
                if i + 1 < chars.len() && chars[i + 1] == '|' {
                    i += 1; // `||` — consume second |
                }
            }
            ';' | '\n' => flush(&mut segments, &mut cur),
            _ => cur.push(c),
        }
        i += 1;
    }
    flush(&mut segments, &mut cur);
    segments
}

/// A file this command will write over, and how.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Overwrite {
    /// The path as written, before resolution.
    pub target: String,
    /// True when the write truncates (`>`), false when it appends (`>>`).
    /// Only truncation destroys, and the distinction is the whole point:
    /// a gate that treats `>>` as destructive fires on every log line.
    pub truncates: bool,
}

/// A write to one of these destroys nothing: they are discard devices, not
/// files. Excluding them here — the single extraction point — keeps every
/// engine consistent: no intent, no insurance, no breaker pressure for
/// `> /dev/null`, which is the most common redirect in existence.
fn is_sink(target: &str) -> bool {
    matches!(
        target.to_ascii_lowercase().as_str(),
        "/dev/null"
            | "/dev/zero"
            | "/dev/stdout"
            | "/dev/stderr"
            | "/dev/tty"
            | "/dev/full"
            | "nul"
    )
}

/// Extract the redirect targets from ONE segment.
///
/// v0.15. `>` and `>>` were lexed by `split_segments` and then thrown away, so
/// a command that destroys a file by writing over it was invisible to every
/// engine: no intent, no preview, no backup. `cat /dev/null > .env` matched the
/// read-only `cat *` allow rule and wiped a credentials file.
///
/// HONESTY NOTE: this is a second character walk over the same grammar
/// `split_segments` reads, kept in the same file so they drift together
/// loudly rather than apart quietly. The unification — one scan producing
/// segments that carry their redirects (the Segment struct, option 3 in the
/// v0.15 scope) — is the remaining overwrite work, alongside preview and the
/// cp/mv/tee/dd destinations. Two parsers for one grammar caused three bugs
/// here already; do not let this comment outlive the duplication.
///
/// Deliberately NOT treated as redirects, because they do not create or
/// truncate a file: `2>&1`, `>&2`, `<&-` (descriptor duplication), `&>` and
/// `&>>` (stream combination), `<>` (read-write open), `>(...)` (process
/// substitution — an operator, not a filename), `\>` outside quotes (a
/// literal character), anything inside quotes, and sinks (`/dev/null` and
/// friends — truncating one destroys nothing). `>|` (clobber past
/// noclobber) IS a truncation of the named file.
pub fn redirect_targets(segment: &str) -> Vec<Overwrite> {
    let chars: Vec<char> = segment.chars().collect();
    let mut out = Vec::new();
    let (mut in_single, mut in_double) = (false, false);
    let mut i = 0;

    while i < chars.len() {
        let c = chars[i];
        match c {
            '\'' if !in_double => in_single = !in_single,
            '"' if !in_single => in_double = !in_double,
            // Escape inside double quotes (as split_segments) and bare:
            // `echo a \> b` writes a literal `>`, it redirects nothing.
            '\\' if !in_single && i + 1 < chars.len() => i += 1,
            _ if in_single || in_double => {}
            '>' => {
                // `&>` / `&>>` combine streams; `2>&1` / `>&2` point one
                // descriptor at another; `<>` opens read-write. None truncate.
                let prev_is_amp = i > 0 && chars[i - 1] == '&';
                let prev_is_lt = i > 0 && chars[i - 1] == '<';
                let mut j = i + 1;
                let truncates = if chars.get(j) == Some(&'>') {
                    j += 1;
                    false
                } else {
                    true
                };
                // `>|` forces clobber past `set -o noclobber` — still a
                // truncation of the file that follows.
                if truncates && chars.get(j) == Some(&'|') {
                    j += 1;
                }
                if chars.get(j) == Some(&'&') {
                    i = j + 1;
                    continue;
                }
                while j < chars.len() && chars[j].is_whitespace() {
                    j += 1;
                }
                // `>(...)` is process substitution: `tee >(gzip)` hands tee a
                // pipe, not a file. The draft extracted "(gzip" as a
                // truncating target here.
                if chars.get(j) == Some(&'(') {
                    i = j;
                    continue;
                }
                let start = j;
                let mut quote: Option<char> = None;
                while j < chars.len() {
                    let d = chars[j];
                    match quote {
                        Some(q) if d == q => quote = None,
                        Some(_) => {}
                        None if d == '\'' || d == '"' => quote = Some(d),
                        None if d.is_whitespace() => break,
                        None => {}
                    }
                    j += 1;
                }
                let target: String = chars[start..j]
                    .iter()
                    .collect::<String>()
                    .trim_matches(|c| c == '\'' || c == '"')
                    .to_string();
                if !target.is_empty() && !prev_is_amp && !prev_is_lt && !is_sink(&target) {
                    out.push(Overwrite { target, truncates });
                }
                i = j;
                continue;
            }
            _ => {}
        }
        i += 1;
    }
    out
}

/// Is the `&` at `i` part of a redirection rather than a command separator?
/// `2>&1`, `1>&2`, `<&-` have `>` or `<` immediately before; `&>log` and
/// `&>>log` have `>` immediately after.
fn is_redirection_amp(chars: &[char], i: usize) -> bool {
    let prev_is_redirect = i > 0 && matches!(chars[i - 1], '>' | '<');
    let next_is_redirect = chars.get(i + 1) == Some(&'>');
    prev_is_redirect || next_is_redirect
}

fn flush(segments: &mut Vec<String>, cur: &mut String) {
    let t = cur.trim();
    if !t.is_empty() {
        segments.push(t.to_string());
    }
    cur.clear();
}

/// Does the command contain command substitution we cannot see inside?
pub fn has_substitution(s: &str) -> bool {
    let chars: Vec<char> = s.chars().collect();
    let mut in_single = false;
    let mut i = 0;
    while i < chars.len() {
        match chars[i] {
            '\'' => in_single = !in_single,
            '`' if !in_single => return true,
            '$' if !in_single && chars.get(i + 1) == Some(&'(') => return true,
            _ => {}
        }
        i += 1;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    /// #14. `>` was lexed and discarded, so a command that destroys a file by
    /// writing over it was invisible to every engine.
    #[test]
    fn truncating_redirects_are_extracted() {
        let r = redirect_targets("cat /dev/null > .env");
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].target, ".env");
        assert!(r[0].truncates);

        assert_eq!(
            redirect_targets("ls -la > /etc/hosts")[0].target,
            "/etc/hosts"
        );
        assert_eq!(
            redirect_targets("echo x >config.json")[0].target,
            "config.json"
        );
        assert_eq!(
            redirect_targets(r#"echo x > "my file.txt""#)[0].target,
            "my file.txt"
        );
    }

    /// Appending does not destroy. A gate that treats `>>` as destructive
    /// fires on every log line and gets uninstalled.
    #[test]
    fn appending_is_recorded_but_not_truncating() {
        let r = redirect_targets("echo entry >> app.log");
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].target, "app.log");
        assert!(!r[0].truncates, ">> appends, it does not destroy");
    }

    /// Descriptor plumbing names no file. This is the same distinction
    /// `is_redirection_amp` makes for `&`, and getting it wrong would fire
    /// on ordinary `2>&1`.
    #[test]
    fn descriptor_redirects_are_not_file_targets() {
        for cmd in [
            "make 2>&1",
            "cmd >&2",
            "cmd <&-",
            "cmd &> log",
            "cmd &>> log",
            "make 2>&1 | tee out",
        ] {
            assert!(
                redirect_targets(cmd).is_empty(),
                "{cmd} redirects a descriptor, it does not truncate a file"
            );
        }
    }

    /// A `>` inside quotes is text, not an operator — the same property the
    /// segment splitter already guarantees, from the same scanner.
    #[test]
    fn quoted_redirects_are_text() {
        assert!(redirect_targets(r#"echo "a > b""#).is_empty());
        assert!(redirect_targets("echo 'x > y'").is_empty());
        assert!(redirect_targets(r#"git commit -m "fix > bug""#).is_empty());
    }

    /// Sinks destroy nothing, and `> /dev/null` is the most common redirect
    /// in existence. Classifying it fed the breaker on every build command —
    /// the third redirected build log of any session was DENIED.
    #[test]
    fn sinks_are_not_targets() {
        for cmd in [
            "cargo test > /dev/null",
            "cmd 2> /dev/null",
            "make >/dev/null 2>&1",
            "cat big > /dev/zero",
            "echo x > NUL",
        ] {
            assert!(
                redirect_targets(cmd).is_empty(),
                "{cmd} truncates a sink, not a file"
            );
        }
    }

    /// `>(...)` is an operator: `tee >(gzip)` hands tee a pipe. The draft
    /// extracted "(gzip" as a truncating target.
    #[test]
    fn process_substitution_is_not_a_target() {
        for cmd in ["tee >(gzip -c) < data", "diff x >(sort)", "cmd > >(bar)"] {
            assert!(
                redirect_targets(cmd)
                    .iter()
                    .all(|o| !o.target.starts_with('(')),
                "{cmd}: a paren is an operator, not a filename"
            );
        }
        assert!(redirect_targets("tee >(gzip -c) < data").is_empty());
    }

    /// `\>` outside quotes is a literal; `>|` clobbers — a truncation of the
    /// named file; `<>` opens read-write and destroys nothing.
    #[test]
    fn escapes_clobber_and_read_write_open() {
        assert!(redirect_targets(r"echo a \> b").is_empty());
        let r = redirect_targets("cmd >| forced.txt");
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].target, "forced.txt");
        assert!(r[0].truncates);
        assert!(redirect_targets("cmd <> rw.txt").is_empty());
    }

    #[test]
    fn several_redirects_in_one_segment() {
        let r = redirect_targets("cmd > out.txt 2> err.txt");
        assert_eq!(r.len(), 2);
        assert_eq!(r[0].target, "out.txt");
        assert_eq!(r[1].target, "err.txt");
    }

    #[test]
    fn splits_the_field_report_command() {
        let cmd = r#"git status && echo "---" && git branch -vv && git log --oneline -5"#;
        let seg = split_segments(cmd);
        assert_eq!(
            seg,
            vec![
                "git status",
                r#"echo "---""#,
                "git branch -vv",
                "git log --oneline -5"
            ]
        );
    }

    #[test]
    fn splits_all_operators() {
        assert_eq!(
            split_segments("a; b | c || d && e"),
            vec!["a", "b", "c", "d", "e"]
        );
    }

    #[test]
    fn quotes_protect_operators() {
        assert_eq!(split_segments("echo 'a && b'"), vec!["echo 'a && b'"]);
        assert_eq!(split_segments(r#"echo "x; y""#), vec![r#"echo "x; y""#]);
    }

    #[test]
    fn redirections_survive() {
        // `&` inside a redirection is not an operator
        assert_eq!(split_segments("cmd 2>&1"), vec!["cmd 2>&1"]);
        assert_eq!(split_segments("cmd >&2"), vec!["cmd >&2"]);
        assert_eq!(split_segments("cmd &> log"), vec!["cmd &> log"]);
        assert_eq!(split_segments("cmd &>> log"), vec!["cmd &>> log"]);
        assert_eq!(split_segments("cmd <&-"), vec!["cmd <&-"]);
        assert_eq!(
            split_segments("make 2>&1 | tee log"),
            vec!["make 2>&1", "tee log"]
        );
    }

    /// Schipper review, finding 1. `&` backgrounds the left-hand command and
    /// starts a new one; leaving it unsplit meant the whole line matched the
    /// `git status*` allow rule and was ALLOWED.
    #[test]
    fn a_lone_ampersand_splits() {
        assert_eq!(
            split_segments("git status & rm -rf /"),
            vec!["git status", "rm -rf /"]
        );
        assert_eq!(split_segments("ls & rm -rf /"), vec!["ls", "rm -rf /"]);
        assert_eq!(split_segments("npm run dev &"), vec!["npm run dev"]);
        assert_eq!(split_segments("a & b & c"), vec!["a", "b", "c"]);
        // no spaces required, exactly as the shell reads it
        assert_eq!(
            split_segments("echo hi&rm -rf /"),
            vec!["echo hi", "rm -rf /"]
        );
    }

    /// The bypass was reachable because the two splitters disagreed about the
    /// same string. Since v0.14.1 `intent` calls this function, so the only
    /// way they can diverge again is if this test is deleted.
    #[test]
    fn newlines_split_too() {
        assert_eq!(
            split_segments("git status\nrm -rf /"),
            vec!["git status", "rm -rf /"]
        );
    }

    #[test]
    fn substitution_detected() {
        assert!(has_substitution("echo $(rm -rf /)"));
        assert!(has_substitution("echo `whoami`"));
        assert!(!has_substitution("echo '$(safe)'"));
        assert!(!has_substitution("git status"));
    }
}
